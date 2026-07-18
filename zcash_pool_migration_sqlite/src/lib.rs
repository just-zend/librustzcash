//! SQLite persistence for the Orchard -> Ironwood value-pool migration (ZIP 318).
//!
//! This crate implements [`zcash_pool_migration_backend`]'s [`PoolMigrationRead`] /
//! [`PoolMigrationWrite`] store traits over two SQLite tables, mirroring how
//! `zcash_client_sqlite` implements `zcash_client_backend`'s `WalletRead` / `WalletWrite`. A
//! committed migration is a set of pre-signed PCZTs plus their schedule and lifecycle state, so a
//! wallet resumes a migration entirely from these tables after being closed or restarted.
//!
//! # Dependency direction (no cycle)
//!
//! `zcash_client_sqlite` DEPENDS ON this crate, not the reverse. This crate depends only on
//! [`zcash_pool_migration_backend`] (the state types + traits) and `rusqlite`; it never names
//! `zcash_client_sqlite`. Because a `zcash_client_sqlite` schema migration's `up()` returns that
//! crate's `WalletMigrationError` and its `dependencies()` names
//! `ironwood_received_notes::MIGRATION_ID` (both defined there), this crate does NOT define the
//! `schemerz` migration itself. Instead it exposes the table DDL ([`init_migration_tables`], plus the
//! `CREATE_*` constants) and a canonical [`MIGRATION_ID`]; `zcash_client_sqlite` defines the thin
//! `schemerz::Migration` that runs the DDL, sets the `ironwood_received_notes` dependency, maps the
//! error, and exposes the store through its `WalletDb`. The pool-migration tables then live in the
//! same `wallet.db` and share its schema versioning.
//!
//! # Model
//!
//! There is at most one migration in progress, stored as a single row in [`pool_migrations`] keyed by
//! [`SINGLETON_ID`], with its transactions in [`pool_migration_transactions`]. [`PoolMigrations`] is
//! the store: construct it over a `rusqlite::Connection` (the same one `WalletDb` uses).
//!
//! [`pool_migrations`]: CREATE_POOL_MIGRATIONS
//! [`pool_migration_transactions`]: CREATE_POOL_MIGRATION_TRANSACTIONS

use std::borrow::{Borrow, BorrowMut};
use std::fmt;

use rusqlite::{Connection, OptionalExtension, named_params, params};
use uuid::Uuid;

use zcash_pool_migration_backend::engine::{
    MigrationState, MigrationStatus, MigrationTransaction, MigrationTxId, MigrationTxKind,
    MigrationTxState, PoolMigrationRead, PoolMigrationWrite,
};
use zcash_pool_migration_backend::note_splitting::NoteSplitPlan;
use zcash_pool_migration_backend::preparation::{
    PrepInput, PrepOutput, PrepTransaction, PreparationPlan,
};

/// The `schemerz` migration id for the pool-migration tables. `zcash_client_sqlite` registers its
/// (thin) migration under this id, depending on `ironwood_received_notes::MIGRATION_ID`.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0x7b2f6a41_9c3d_4e58_8a17_2f6b9d0c4e11);

/// The primary-key value of the single active migration. There is at most one migration in progress,
/// so it is stored as one row; a future multi-account model would replace this with an account key.
pub const SINGLETON_ID: i64 = 0;

/// DDL for the `pool_migrations` table: the note-split decomposition and overall status of the single
/// active migration. The `*_values` / `funding_notes` columns hold little-endian `u64` arrays (see
/// [`encode_u64s`]); the `preparation` column holds the tagged encoding of the preparation plan (see
/// [`encode_preparation`]), retained so deferred preparation layers can be rebuilt after their prior
/// layer mines; zatoshi and height scalars fit in SQLite's signed 64-bit integer.
pub const CREATE_POOL_MIGRATIONS: &str = "
    CREATE TABLE IF NOT EXISTS pool_migrations (
        id INTEGER PRIMARY KEY,
        status TEXT NOT NULL,
        note_fee_buffer_zatoshi INTEGER NOT NULL,
        crossing_values BLOB NOT NULL,
        change INTEGER,
        prep_fee_zatoshi INTEGER NOT NULL,
        total_input_zatoshi INTEGER NOT NULL,
        total_migratable_zatoshi INTEGER NOT NULL,
        funding_notes BLOB NOT NULL,
        preparation BLOB NOT NULL
    )";

/// DDL for the `pool_migration_transactions` table: one row per migration transaction, its pre-signed
/// PCZT (`pczt`, `NULL` until built/signed under two-phase signing), its dependency graph
/// (`depends_on`, a little-endian `u32` array of transaction ids), schedule, and lifecycle `state`.
/// `kind` is `'preparation'` (with `layer`/`tx_index`) or `'transfer'` (with `crossing`); `state`
/// carries `txid`/`mined_height` for the `broadcast`/`mined` states.
pub const CREATE_POOL_MIGRATION_TRANSACTIONS: &str = "
    CREATE TABLE IF NOT EXISTS pool_migration_transactions (
        migration_id INTEGER NOT NULL REFERENCES pool_migrations(id) ON DELETE CASCADE,
        tx_id INTEGER NOT NULL,
        kind TEXT NOT NULL,
        layer INTEGER,
        tx_index INTEGER,
        crossing INTEGER,
        pczt BLOB,
        depends_on BLOB NOT NULL,
        scheduled_height INTEGER NOT NULL,
        expiry_height INTEGER NOT NULL,
        anchor_boundary INTEGER,
        state TEXT NOT NULL,
        txid BLOB,
        mined_height INTEGER,
        PRIMARY KEY (migration_id, tx_id)
    )";

/// DDL for the index over `(state, scheduled_height)`, so the application can query the transactions
/// that are due to prove or broadcast without scanning the table.
pub const CREATE_TX_DUE_INDEX: &str = "
    CREATE INDEX IF NOT EXISTS idx_pool_migration_tx_due
        ON pool_migration_transactions (state, scheduled_height)";

/// Create the pool-migration tables (and the due-transaction index) on `conn`. This is the body a
/// `zcash_client_sqlite` `schemerz` migration's `up()` calls; it is idempotent (`IF NOT EXISTS`).
pub fn init_migration_tables(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(&format!(
        "{CREATE_POOL_MIGRATIONS};\n{CREATE_POOL_MIGRATION_TRANSACTIONS};\n{CREATE_TX_DUE_INDEX};"
    ))
}

/// A failure reading or writing the pool-migration store.
#[derive(Debug)]
pub enum Error {
    /// A `rusqlite` (SQLite) error.
    Db(rusqlite::Error),
    /// A stored value could not be decoded back into the engine's types (a corrupt or truncated blob,
    /// or an unrecognized enum tag). The `&'static str` names the field.
    Corrupt(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Db(e) => write!(f, "pool-migration store database error: {e}"),
            Error::Corrupt(field) => {
                write!(f, "pool-migration store: corrupt stored value for {field}")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Db(e) => Some(e),
            Error::Corrupt(_) => None,
        }
    }
}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Error::Db(e)
    }
}

/// The pool-migration store: a [`PoolMigrationRead`] / [`PoolMigrationWrite`] over a
/// `rusqlite::Connection`. Construct it with a connection borrow (`&Connection` for read-only access,
/// `&mut Connection` to also write); `zcash_client_sqlite` builds it over the same connection its
/// `WalletDb` uses, so the pool-migration tables share the wallet database.
pub struct PoolMigrations<C> {
    conn: C,
}

impl<C> PoolMigrations<C> {
    /// Wrap a connection borrow as the store.
    pub fn new(conn: C) -> Self {
        Self { conn }
    }

    /// Recover the wrapped connection borrow.
    pub fn into_inner(self) -> C {
        self.conn
    }
}

impl<C: Borrow<Connection>> PoolMigrationRead for PoolMigrations<C> {
    type Error = Error;

    fn get_migration(&self) -> Result<Option<MigrationState>, Self::Error> {
        read_migration(self.conn.borrow())
    }
}

impl<C: BorrowMut<Connection>> PoolMigrationWrite for PoolMigrations<C> {
    fn put_migration(&mut self, state: &MigrationState) -> Result<(), Self::Error> {
        let tx = self.conn.borrow_mut().transaction()?;
        write_migration(&tx, state)?;
        tx.commit()?;
        Ok(())
    }

    fn update_transaction(
        &mut self,
        id: MigrationTxId,
        state: MigrationTxState,
    ) -> Result<(), Self::Error> {
        let (state_str, txid, mined_height) = encode_tx_state(&state);
        let updated = self.conn.borrow().execute(
            "UPDATE pool_migration_transactions
                SET state = :state, txid = :txid, mined_height = :mined_height
              WHERE migration_id = :migration_id AND tx_id = :tx_id",
            named_params! {
                ":state": state_str,
                ":txid": txid,
                ":mined_height": mined_height,
                ":migration_id": SINGLETON_ID,
                ":tx_id": id.0,
            },
        )?;
        if updated == 0 {
            return Err(Error::Corrupt("update_transaction: no such transaction"));
        }
        Ok(())
    }
}

// --- (de)serialization of the engine types to/from rows ---

/// Encode a slice of `u64` as concatenated little-endian bytes (an 8-byte-aligned blob).
fn encode_u64s(values: &[u64]) -> Vec<u8> {
    let mut out = Vec::with_capacity(values.len() * 8);
    for v in values {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out
}

/// Decode a blob produced by [`encode_u64s`]; errors (naming `field`) if the length is not a multiple
/// of 8.
fn decode_u64s(blob: &[u8], field: &'static str) -> Result<Vec<u64>, Error> {
    if blob.len() % 8 != 0 {
        return Err(Error::Corrupt(field));
    }
    Ok(blob
        .chunks_exact(8)
        .map(|c| u64::from_le_bytes(c.try_into().expect("chunk is 8 bytes")))
        .collect())
}

/// Encode transaction ids (the `depends_on` graph) as concatenated little-endian `u32` bytes.
fn encode_dep_ids(ids: &[MigrationTxId]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ids.len() * 4);
    for id in ids {
        out.extend_from_slice(&id.0.to_le_bytes());
    }
    out
}

/// Decode a blob produced by [`encode_dep_ids`]; errors if the length is not a multiple of 4.
fn decode_dep_ids(blob: &[u8]) -> Result<Vec<MigrationTxId>, Error> {
    if blob.len() % 4 != 0 {
        return Err(Error::Corrupt("depends_on"));
    }
    Ok(blob
        .chunks_exact(4)
        .map(|c| MigrationTxId(u32::from_le_bytes(c.try_into().expect("chunk is 4 bytes"))))
        .collect())
}

// --- (de)serialization of the preparation plan (its layers and direct-funding notes) ---
//
// A tagged little-endian encoding of the `PreparationPlan`, so a resumed migration can rebuild its
// deferred preparation layers. Counts and indices are `u32` (a plan is small); note values are `u64`.
// Layout:
//   direct_funding: u32 count, then count * (u32 wallet index, u64 value)
//   layers: u32 layer count, then per layer: u32 tx count, then per transaction:
//     inputs:  u32 count, then per input: u8 tag (0=Wallet, 1=Prior)
//                Wallet: u32 index; Prior: u32 layer, u32 transaction, u32 output
//     outputs: u32 count, then per output: u8 tag (0=Funding, 1=Intermediate, 2=Change), u64 value

/// The input-tag byte for a [`PrepInput::Wallet`].
const INPUT_TAG_WALLET: u8 = 0;
/// The input-tag byte for a [`PrepInput::Prior`].
const INPUT_TAG_PRIOR: u8 = 1;
/// The output-tag byte for a [`PrepOutput::Funding`].
const OUTPUT_TAG_FUNDING: u8 = 0;
/// The output-tag byte for a [`PrepOutput::Intermediate`].
const OUTPUT_TAG_INTERMEDIATE: u8 = 1;
/// The output-tag byte for a [`PrepOutput::Change`].
const OUTPUT_TAG_CHANGE: u8 = 2;

/// Append a `u32` (usize narrowed) as little-endian bytes.
fn push_u32(out: &mut Vec<u8>, v: usize) {
    out.extend_from_slice(&(v as u32).to_le_bytes());
}

/// Encode a [`PreparationPlan`] into the tagged little-endian blob stored in the `preparation` column.
fn encode_preparation(plan: &PreparationPlan) -> Vec<u8> {
    let mut out = Vec::new();

    let direct = plan.direct_funding_notes();
    push_u32(&mut out, direct.len());
    for &(index, value) in direct {
        push_u32(&mut out, index);
        out.extend_from_slice(&value.to_le_bytes());
    }

    let layers = plan.layers();
    push_u32(&mut out, layers.len());
    for layer in layers {
        push_u32(&mut out, layer.len());
        for tx in layer {
            push_u32(&mut out, tx.inputs().len());
            for input in tx.inputs() {
                match input {
                    PrepInput::Wallet { index, value } => {
                        out.push(INPUT_TAG_WALLET);
                        push_u32(&mut out, *index);
                        out.extend_from_slice(&value.to_le_bytes());
                    }
                    PrepInput::Prior {
                        layer,
                        transaction,
                        output,
                        value,
                    } => {
                        out.push(INPUT_TAG_PRIOR);
                        push_u32(&mut out, *layer);
                        push_u32(&mut out, *transaction);
                        push_u32(&mut out, *output);
                        out.extend_from_slice(&value.to_le_bytes());
                    }
                }
            }
            push_u32(&mut out, tx.outputs().len());
            for output in tx.outputs() {
                let (tag, value) = match output {
                    PrepOutput::Funding(v) => (OUTPUT_TAG_FUNDING, *v),
                    PrepOutput::Intermediate(v) => (OUTPUT_TAG_INTERMEDIATE, *v),
                    PrepOutput::Change(v) => (OUTPUT_TAG_CHANGE, *v),
                };
                out.push(tag);
                out.extend_from_slice(&value.to_le_bytes());
            }
        }
    }
    out
}

/// A little cursor over a byte blob, reading the fixed-width fields [`encode_preparation`] wrote and
/// erroring (naming the field) on truncation or a bad tag.
struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Reader { bytes, pos: 0 }
    }

    fn take(&mut self, n: usize, field: &'static str) -> Result<&'a [u8], Error> {
        let end = self.pos.checked_add(n).ok_or(Error::Corrupt(field))?;
        let slice = self.bytes.get(self.pos..end).ok_or(Error::Corrupt(field))?;
        self.pos = end;
        Ok(slice)
    }

    fn u8(&mut self, field: &'static str) -> Result<u8, Error> {
        Ok(self.take(1, field)?[0])
    }

    fn u32(&mut self, field: &'static str) -> Result<u32, Error> {
        let b = self.take(4, field)?;
        Ok(u32::from_le_bytes(b.try_into().expect("chunk is 4 bytes")))
    }

    /// A `u32` count/index widened to `usize`.
    fn usize(&mut self, field: &'static str) -> Result<usize, Error> {
        Ok(self.u32(field)? as usize)
    }

    fn u64(&mut self, field: &'static str) -> Result<u64, Error> {
        let b = self.take(8, field)?;
        Ok(u64::from_le_bytes(b.try_into().expect("chunk is 8 bytes")))
    }

    /// All bytes have been consumed.
    fn at_end(&self) -> bool {
        self.pos == self.bytes.len()
    }
}

/// Decode a blob produced by [`encode_preparation`] back into a [`PreparationPlan`]; errors (naming the
/// field) on truncation, a bad tag, or trailing bytes.
fn decode_preparation(blob: &[u8]) -> Result<PreparationPlan, Error> {
    let mut r = Reader::new(blob);

    let direct_len = r.usize("preparation.direct_funding.len")?;
    let mut direct_funding = Vec::with_capacity(direct_len);
    for _ in 0..direct_len {
        let index = r.usize("preparation.direct_funding.index")?;
        let value = r.u64("preparation.direct_funding.value")?;
        direct_funding.push((index, value));
    }

    let layer_count = r.usize("preparation.layers.len")?;
    let mut layers = Vec::with_capacity(layer_count);
    for _ in 0..layer_count {
        let tx_count = r.usize("preparation.layer.len")?;
        let mut txs = Vec::with_capacity(tx_count);
        for _ in 0..tx_count {
            let in_count = r.usize("preparation.tx.inputs.len")?;
            let mut inputs = Vec::with_capacity(in_count);
            for _ in 0..in_count {
                let input = match r.u8("preparation.input.tag")? {
                    INPUT_TAG_WALLET => PrepInput::Wallet {
                        index: r.usize("preparation.input.wallet.index")?,
                        value: r.u64("preparation.input.wallet.value")?,
                    },
                    INPUT_TAG_PRIOR => PrepInput::Prior {
                        layer: r.usize("preparation.input.prior.layer")?,
                        transaction: r.usize("preparation.input.prior.transaction")?,
                        output: r.usize("preparation.input.prior.output")?,
                        value: r.u64("preparation.input.prior.value")?,
                    },
                    _ => return Err(Error::Corrupt("preparation.input.tag")),
                };
                inputs.push(input);
            }
            let out_count = r.usize("preparation.tx.outputs.len")?;
            let mut outputs = Vec::with_capacity(out_count);
            for _ in 0..out_count {
                let tag = r.u8("preparation.output.tag")?;
                let value = r.u64("preparation.output.value")?;
                let output = match tag {
                    OUTPUT_TAG_FUNDING => PrepOutput::Funding(value),
                    OUTPUT_TAG_INTERMEDIATE => PrepOutput::Intermediate(value),
                    OUTPUT_TAG_CHANGE => PrepOutput::Change(value),
                    _ => return Err(Error::Corrupt("preparation.output.tag")),
                };
                outputs.push(output);
            }
            txs.push(PrepTransaction::from_parts(inputs, outputs));
        }
        layers.push(txs);
    }

    if !r.at_end() {
        return Err(Error::Corrupt("preparation.trailing"));
    }
    Ok(PreparationPlan::from_parts(layers, direct_funding))
}

/// Split a transaction lifecycle state into its `(state, txid, mined_height)` column values. `txid` is
/// set only for `Broadcast`, `mined_height` only for `Mined`.
fn encode_tx_state(state: &MigrationTxState) -> (&'static str, Option<Vec<u8>>, Option<i64>) {
    match state {
        MigrationTxState::Planned => ("planned", None, None),
        MigrationTxState::AwaitingSignature => ("awaiting_signature", None, None),
        MigrationTxState::Signed => ("signed", None, None),
        MigrationTxState::Proved => ("proved", None, None),
        MigrationTxState::Broadcast { txid } => ("broadcast", Some(txid.to_vec()), None),
        MigrationTxState::Mined { height } => ("mined", None, Some(i64::from(*height))),
        MigrationTxState::Expired => ("expired", None, None),
    }
}

/// Reassemble a transaction lifecycle state from its column values.
fn decode_tx_state(
    state: &str,
    txid: Option<Vec<u8>>,
    mined_height: Option<i64>,
) -> Result<MigrationTxState, Error> {
    Ok(match state {
        "planned" => MigrationTxState::Planned,
        "awaiting_signature" => MigrationTxState::AwaitingSignature,
        "signed" => MigrationTxState::Signed,
        "proved" => MigrationTxState::Proved,
        "broadcast" => {
            let bytes = txid.ok_or(Error::Corrupt("state.broadcast.txid"))?;
            let arr: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| Error::Corrupt("state.broadcast.txid"))?;
            MigrationTxState::Broadcast { txid: arr }
        }
        "mined" => {
            let height = mined_height.ok_or(Error::Corrupt("state.mined.height"))?;
            MigrationTxState::Mined {
                height: u32::try_from(height).map_err(|_| Error::Corrupt("state.mined.height"))?,
            }
        }
        "expired" => MigrationTxState::Expired,
        _ => return Err(Error::Corrupt("state")),
    })
}

/// Split a transaction kind into its `(kind, layer, tx_index, crossing)` column values.
fn encode_tx_kind(kind: MigrationTxKind) -> (&'static str, Option<i64>, Option<i64>, Option<i64>) {
    match kind {
        MigrationTxKind::Preparation { layer, index } => {
            ("preparation", Some(layer as i64), Some(index as i64), None)
        }
        MigrationTxKind::Transfer { crossing } => ("transfer", None, None, Some(crossing as i64)),
    }
}

/// Reassemble a transaction kind from its column values.
fn decode_tx_kind(
    kind: &str,
    layer: Option<i64>,
    tx_index: Option<i64>,
    crossing: Option<i64>,
) -> Result<MigrationTxKind, Error> {
    let to_usize = |v: Option<i64>, field| {
        v.ok_or(Error::Corrupt(field))
            .and_then(|n| usize::try_from(n).map_err(|_| Error::Corrupt(field)))
    };
    Ok(match kind {
        "preparation" => MigrationTxKind::Preparation {
            layer: to_usize(layer, "kind.preparation.layer")?,
            index: to_usize(tx_index, "kind.preparation.index")?,
        },
        "transfer" => MigrationTxKind::Transfer {
            crossing: to_usize(crossing, "kind.transfer.crossing")?,
        },
        _ => return Err(Error::Corrupt("kind")),
    })
}

fn read_migration(conn: &Connection) -> Result<Option<MigrationState>, Error> {
    let row = conn
        .query_row(
            "SELECT status, note_fee_buffer_zatoshi, crossing_values, change, prep_fee_zatoshi,
                    total_input_zatoshi, total_migratable_zatoshi, funding_notes, preparation
               FROM pool_migrations WHERE id = ?",
            params![SINGLETON_ID],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                    row.get::<_, Vec<u8>>(8)?,
                ))
            },
        )
        .optional()?;

    let Some((
        status,
        note_fee_buffer,
        crossing_values,
        change,
        prep_fee,
        total_input,
        total_migratable,
        funding_notes,
        preparation,
    )) = row
    else {
        return Ok(None);
    };

    let note_split = NoteSplitPlan::from_stored_parts(
        decode_u64s(&crossing_values, "crossing_values")?,
        note_fee_buffer as u64,
        change.map(|c| c as u64),
        prep_fee as u64,
        total_input as u64,
        total_migratable as u64,
    );

    let transactions = read_transactions(conn)?;

    Ok(Some(MigrationState {
        status: MigrationStatus::try_from(status.as_str()).map_err(|_| Error::Corrupt("status"))?,
        note_split,
        funding_notes: decode_u64s(&funding_notes, "funding_notes")?,
        preparation: decode_preparation(&preparation)?,
        transactions,
    }))
}

fn read_transactions(conn: &Connection) -> Result<Vec<MigrationTransaction>, Error> {
    let mut stmt = conn.prepare(
        "SELECT tx_id, kind, layer, tx_index, crossing, pczt, depends_on, scheduled_height,
                expiry_height, anchor_boundary, state, txid, mined_height
           FROM pool_migration_transactions
          WHERE migration_id = ?
          ORDER BY tx_id",
    )?;
    let rows = stmt.query_map(params![SINGLETON_ID], |row| {
        Ok((
            row.get::<_, i64>(0)?,              // tx_id
            row.get::<_, String>(1)?,           // kind
            row.get::<_, Option<i64>>(2)?,      // layer
            row.get::<_, Option<i64>>(3)?,      // tx_index
            row.get::<_, Option<i64>>(4)?,      // crossing
            row.get::<_, Option<Vec<u8>>>(5)?,  // pczt
            row.get::<_, Vec<u8>>(6)?,          // depends_on
            row.get::<_, i64>(7)?,              // scheduled_height
            row.get::<_, i64>(8)?,              // expiry_height
            row.get::<_, Option<i64>>(9)?,      // anchor_boundary
            row.get::<_, String>(10)?,          // state
            row.get::<_, Option<Vec<u8>>>(11)?, // txid
            row.get::<_, Option<i64>>(12)?,     // mined_height
        ))
    })?;

    let mut out = Vec::new();
    for row in rows {
        let (
            tx_id,
            kind,
            layer,
            tx_index,
            crossing,
            pczt,
            depends_on,
            scheduled_height,
            expiry_height,
            anchor_boundary,
            state,
            txid,
            mined_height,
        ) = row?;

        let id = MigrationTxId(u32::try_from(tx_id).map_err(|_| Error::Corrupt("tx_id"))?);
        let scheduled_height =
            u32::try_from(scheduled_height).map_err(|_| Error::Corrupt("scheduled_height"))?;
        let expiry_height =
            u32::try_from(expiry_height).map_err(|_| Error::Corrupt("expiry_height"))?;
        let anchor_boundary = anchor_boundary
            .map(|h| u32::try_from(h).map_err(|_| Error::Corrupt("anchor_boundary")))
            .transpose()?;

        out.push(MigrationTransaction {
            id,
            kind: decode_tx_kind(&kind, layer, tx_index, crossing)?,
            pczt,
            depends_on: decode_dep_ids(&depends_on)?,
            scheduled_height,
            expiry_height,
            anchor_boundary,
            state: decode_tx_state(&state, txid, mined_height)?,
        });
    }
    Ok(out)
}

/// Persist `state` as the single active migration, replacing any existing one. Runs inside the
/// caller's transaction so the replacement is atomic.
fn write_migration(tx: &rusqlite::Transaction, state: &MigrationState) -> Result<(), Error> {
    // Replace semantics: the store holds at most one migration.
    tx.execute(
        "DELETE FROM pool_migration_transactions WHERE migration_id = ?",
        params![SINGLETON_ID],
    )?;
    tx.execute(
        "DELETE FROM pool_migrations WHERE id = ?",
        params![SINGLETON_ID],
    )?;

    let plan = &state.note_split;
    tx.execute(
        "INSERT INTO pool_migrations
            (id, status, note_fee_buffer_zatoshi, crossing_values, change, prep_fee_zatoshi,
             total_input_zatoshi, total_migratable_zatoshi, funding_notes, preparation)
         VALUES
            (:id, :status, :note_fee_buffer, :crossing_values, :change, :prep_fee,
             :total_input, :total_migratable, :funding_notes, :preparation)",
        named_params! {
            ":id": SINGLETON_ID,
            ":status": state.status.as_ref(),
            ":note_fee_buffer": plan.note_fee_buffer_zatoshi() as i64,
            ":crossing_values": encode_u64s(plan.crossing_values()),
            ":change": plan.change().map(|c| c as i64),
            ":prep_fee": plan.prep_fee_zatoshi() as i64,
            ":total_input": plan.total_input_zatoshi() as i64,
            ":total_migratable": plan.total_migratable_zatoshi() as i64,
            ":funding_notes": encode_u64s(&state.funding_notes),
            ":preparation": encode_preparation(&state.preparation),
        },
    )?;

    for mtx in &state.transactions {
        let (kind, layer, tx_index, crossing) = encode_tx_kind(mtx.kind);
        let (tx_state, txid, mined_height) = encode_tx_state(&mtx.state);
        tx.execute(
            "INSERT INTO pool_migration_transactions
                (migration_id, tx_id, kind, layer, tx_index, crossing, pczt, depends_on,
                 scheduled_height, expiry_height, anchor_boundary, state, txid, mined_height)
             VALUES
                (:migration_id, :tx_id, :kind, :layer, :tx_index, :crossing, :pczt, :depends_on,
                 :scheduled_height, :expiry_height, :anchor_boundary, :state, :txid, :mined_height)",
            named_params! {
                ":migration_id": SINGLETON_ID,
                ":tx_id": mtx.id.0,
                ":kind": kind,
                ":layer": layer,
                ":tx_index": tx_index,
                ":crossing": crossing,
                ":pczt": mtx.pczt.as_deref(),
                ":depends_on": encode_dep_ids(&mtx.depends_on),
                ":scheduled_height": i64::from(mtx.scheduled_height),
                ":expiry_height": i64::from(mtx.expiry_height),
                ":anchor_boundary": mtx.anchor_boundary.map(i64::from),
                ":state": tx_state,
                ":txid": txid,
                ":mined_height": mined_height,
            },
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> PoolMigrations<Connection> {
        let conn = Connection::open_in_memory().expect("in-memory db");
        init_migration_tables(&conn).expect("create tables");
        PoolMigrations::new(conn)
    }

    /// A two-layer preparation plan exercising every input tag (Wallet, Prior), every output tag
    /// (Funding, Intermediate, Change), multiple layers, and a direct-funding note.
    fn sample_preparation() -> PreparationPlan {
        let layer0 = vec![PrepTransaction::from_parts(
            vec![PrepInput::Wallet {
                index: 0,
                value: 224_321,
            }],
            vec![PrepOutput::Intermediate(220_000), PrepOutput::Change(4_321)],
        )];
        let layer1 = vec![PrepTransaction::from_parts(
            vec![PrepInput::Prior {
                layer: 0,
                transaction: 0,
                output: 0,
                value: 220_000,
            }],
            vec![PrepOutput::Funding(120_000), PrepOutput::Funding(100_000)],
        )];
        PreparationPlan::from_parts(vec![layer0, layer1], vec![(2, 220_000)])
    }

    fn sample_state() -> MigrationState {
        let note_split = NoteSplitPlan::from_stored_parts(
            vec![100_000, 200_000], // crossing_values
            20_000,                 // note_fee_buffer_zatoshi (outputs = crossings + buffer)
            Some(4_321),            // change
            10_000,                 // prep_fee_zatoshi
            424_321,                // total_input_zatoshi
            300_000,                // total_migratable_zatoshi
        );
        MigrationState {
            status: MigrationStatus::Committed,
            note_split,
            funding_notes: vec![120_000, 220_000],
            preparation: sample_preparation(),
            transactions: vec![
                MigrationTransaction {
                    id: MigrationTxId(0),
                    kind: MigrationTxKind::Preparation { layer: 0, index: 0 },
                    pczt: Some(vec![1, 2, 3, 4]),
                    depends_on: vec![],
                    scheduled_height: 210,
                    expiry_height: 250,
                    anchor_boundary: None,
                    state: MigrationTxState::Signed,
                },
                MigrationTransaction {
                    id: MigrationTxId(1),
                    kind: MigrationTxKind::Transfer { crossing: 0 },
                    pczt: None,
                    depends_on: vec![MigrationTxId(0)],
                    scheduled_height: 260,
                    expiry_height: 300,
                    anchor_boundary: Some(255),
                    state: MigrationTxState::Planned,
                },
            ],
        }
    }

    #[test]
    fn get_migration_empty_is_none() {
        assert!(store().get_migration().expect("read").is_none());
    }

    #[test]
    fn put_then_get_round_trips() {
        let mut s = store();
        let state = sample_state();
        s.put_migration(&state).expect("write");

        let read = s.get_migration().expect("read").expect("some migration");
        assert_eq!(read.status, state.status);
        assert_eq!(read.funding_notes, state.funding_notes);
        assert_eq!(
            read.note_split.migration_outputs(),
            state.note_split.migration_outputs()
        );
        assert_eq!(
            read.note_split.crossing_values(),
            state.note_split.crossing_values()
        );
        assert_eq!(read.note_split.change(), state.note_split.change());
        assert_eq!(
            read.note_split.prep_fee_zatoshi(),
            state.note_split.prep_fee_zatoshi()
        );
        assert_eq!(
            read.note_split.total_input_zatoshi(),
            state.note_split.total_input_zatoshi()
        );
        assert_eq!(
            read.note_split.total_migratable_zatoshi(),
            state.note_split.total_migratable_zatoshi()
        );
        assert_eq!(read.transactions, state.transactions);
        assert_eq!(read.preparation, state.preparation);
    }

    /// The two-layer preparation plan round-trips through the store byte-for-byte: every layer,
    /// transaction, tagged input, tagged output, and direct-funding note is preserved.
    #[test]
    fn preparation_plan_round_trips() {
        let plan = sample_preparation();
        let encoded = encode_preparation(&plan);
        let decoded = decode_preparation(&encoded).expect("decodes");
        assert_eq!(decoded, plan);
        assert_eq!(decoded.layers().len(), 2);
        assert_eq!(decoded.direct_funding_notes(), &[(2, 220_000)]);

        // A truncated blob and a bad tag are rejected, not silently accepted.
        assert!(matches!(
            decode_preparation(&encoded[..encoded.len() - 1]),
            Err(Error::Corrupt(_))
        ));
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(matches!(
            decode_preparation(&trailing),
            Err(Error::Corrupt("preparation.trailing"))
        ));
    }

    #[test]
    fn put_replaces_previous_migration() {
        let mut s = store();
        s.put_migration(&sample_state()).expect("first write");

        let mut second = sample_state();
        second.status = MigrationStatus::Complete;
        second.transactions.truncate(1);
        s.put_migration(&second).expect("second write");

        let read = s.get_migration().expect("read").expect("some migration");
        assert_eq!(read.status, MigrationStatus::Complete);
        assert_eq!(read.transactions.len(), 1);
    }

    #[test]
    fn update_transaction_advances_state() {
        let mut s = store();
        s.put_migration(&sample_state()).expect("write");

        let txid = [7u8; 32];
        s.update_transaction(MigrationTxId(1), MigrationTxState::Broadcast { txid })
            .expect("update");

        let read = s.get_migration().expect("read").expect("some migration");
        let transfer = read
            .transactions
            .iter()
            .find(|t| t.id == MigrationTxId(1))
            .expect("transfer present");
        assert_eq!(transfer.state, MigrationTxState::Broadcast { txid });
    }

    #[test]
    fn update_unknown_transaction_errors() {
        let mut s = store();
        s.put_migration(&sample_state()).expect("write");
        let err = s
            .update_transaction(MigrationTxId(99), MigrationTxState::Proved)
            .expect_err("no such transaction");
        assert!(matches!(err, Error::Corrupt(_)));
    }

    #[test]
    fn mined_state_round_trips() {
        let mut s = store();
        s.put_migration(&sample_state()).expect("write");
        s.update_transaction(MigrationTxId(0), MigrationTxState::Mined { height: 231 })
            .expect("update");
        let read = s.get_migration().expect("read").expect("some migration");
        let prep = read
            .transactions
            .iter()
            .find(|t| t.id == MigrationTxId(0))
            .expect("prep present");
        assert_eq!(prep.state, MigrationTxState::Mined { height: 231 });
    }
}
