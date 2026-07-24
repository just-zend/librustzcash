//! The generic, pool-agnostic SQLite pool-migration store.
//!
//! This module is entirely crate-internal: it holds the machinery shared by every pool migration
//! (the DDL builders and the [`Store`] type that carries the [`PoolMigrationRead`] /
//! [`PoolMigrationWrite`] SQL logic), parameterized over the table names in [`Tables`]. The schema is
//! fully NORMALIZED: every structured value is stored in typed columns and child-table rows, so the
//! store maps the engine types to and from columns directly. The `BLOB` columns are the pre-signed
//! transaction (`pczt`), which is genuinely unstructured, already-versioned bytes, and each
//! transaction's `lock_owner`, an opaque fixed-size token read and written directly as
//! `Option<[u8; 32]>` (no codec: `rusqlite`'s fixed-size-array `FromSql`/`ToSql` impls handle it,
//! and reject a non-NULL blob that is not exactly 32 bytes). All amounts are
//! zatoshi `INTEGER` columns; the broadcast `txid` is stored as hex `TEXT`.
//!
//! The preparation plan's layers/transactions grid has no tables of its own: each input and output
//! row carries its transaction's `(layer, tx_index)` coordinate, and every transaction a real plan
//! produces has at least one input and one output (and no layer is empty), so the store
//! reconstructs the grid from those rows (and rejects a state it could not reconstruct with
//! [`Error::Unrepresentable`]). Likewise the funding-note values have no table: the engine derives
//! them from the note split (each crossing value plus the fee buffer).
//!
//! The column set is the same for every pool; only the table and index names change.
//!
//! [`PoolMigrationRead`]: zcash_pool_migration::engine::PoolMigrationRead
//! [`PoolMigrationWrite`]: zcash_pool_migration::engine::PoolMigrationWrite

use std::borrow::{Borrow, BorrowMut};
use std::collections::BTreeSet;
#[cfg(feature = "migration-delivery")]
use std::num::NonZeroU32;
#[cfg(feature = "migration-delivery")]
use std::sync::OnceLock;
#[cfg(feature = "migration-delivery")]
use std::time::Instant;

#[cfg(feature = "migration-delivery")]
use blake2b_simd::Params;
#[cfg(feature = "migration-delivery")]
use pczt::roles::combiner::Combiner;
#[cfg(feature = "migration-delivery")]
use prost::Message;
use rusqlite::{Connection, OptionalExtension, named_params, params};

use zcash_client_backend::wallet::LockOwner;
use zcash_pool_migration::engine::{
    MigrationState, MigrationStatus, MigrationTransaction, MigrationTxId, MigrationTxKind,
    MigrationTxState,
};
use zcash_pool_migration::note_splitting::NoteSplitPlan;
use zcash_pool_migration::preparation::{PrepInput, PrepOutput, PrepTransaction, PreparationPlan};
#[cfg(feature = "migration-delivery")]
use zcash_protocol::{PoolType, ShieldedPool, TxId};
use zcash_protocol::{consensus::BlockHeight, value::Zatoshis};
#[cfg(feature = "migration-delivery")]
use {
    orchard::note::Nullifier,
    zcash_client_backend::{
        data_api::{
            scanning::ScanPriority,
            wallet::{
                ConfirmationsPolicy, TargetHeight,
                input_selection::{LockFilter, LockedInputPolicy},
            },
        },
        wallet::OutputRef,
    },
    zcash_pool_migration::delivery::LegacySchemaFingerprint,
    zcash_pool_migration::delivery::{
        AccountMigrationRuntime, CanonicalMaterializationPurpose, CanonicalMaterializationReceipt,
        CanonicalMaterializationTransition, ClaimKind, ClaimStatus, ClaimToken,
        DeliveryArtifactEvidence, DeliveryArtifactIdentity, DeliveryClaim, DeliveryFailureReason,
        DeliveryLane, DeliveryLease, DeliveryPhase, DeliveryRevision, DeliveryRunFingerprint,
        DeliverySchemaProvenance, DeliverySchemaVersion, DeliverySnapshot, DestinationSpendability,
        ExactTransaction, ExpiredTransferRebuild, ExpiredTransferRebuildReceipt,
        ExternalSigningPczt, FinalityArchive, FinalityAuditResult, FinalizedTransferEvidence,
        ImmediateArtifactEvidence, ImmediateArtifactIdentity, ImmediateProposal, LeaseClockSession,
        LeaseDuration, LeaseValidity, LegacyCutoverStatus, LegacySchemaObjectCount,
        MAX_SUBMISSION_POLICY_BYTES, MigrationRunIdentity, MigrationRuntimeSnapshot,
        MigrationStateFingerprint, MigrationTransactionFingerprint, MonotonicLeaseInstant,
        PcztDigest, PolicyFingerprint, PolicyValidationFailure, ReservationRelease,
        ReservationRollover, ReservationRolloverReceipt, RetainedMigrationRun, RunFinalityAudit,
        SignedPcztEvidence, SignerOwnership, SourceReservationOwner, StorageFinality,
        StorageRecoveryReason, SubmissionContext, SubmissionOutcome, SubmissionPolicy,
        decode_exact_immediate_transaction, decode_migration_state_archive,
        encode_migration_state_archive, exact_scheduled_transaction_from_pczt, exact_transaction,
        migration_state_fingerprint, migration_transaction_fingerprint,
        scheduled_artifact_evidence,
    },
    zcash_pool_migration::wallet::{
        ActiveOrchardLock, ActiveOrchardReservation, ActiveOrchardSpend, ExactReceivedOutput,
        MigrationFinalizationAudit, MigrationOutputAvailability, ReceivedOutputAvailability,
        ReceivedOutputUnavailable,
    },
    zcash_primitives::transaction::fees::zip317,
};

use crate::AccountRef;
#[cfg(feature = "migration-delivery")]
use crate::AccountUuid;

#[cfg(feature = "migration-delivery")]
const MIGRATION_STORAGE_FINALITY_CONFIRMATIONS: u32 = crate::PRUNING_DEPTH + 1;

#[cfg(feature = "migration-delivery")]
const DELIVERY_RUN_AUTHORITY_PERSONAL: &[u8; 16] = b"ZendRunAuthV1!!!";

#[cfg(feature = "migration-delivery")]
const DELIVERY_RUN_AUTHORITY_CODEC_VERSION: u8 = 1;

/// Binds every stable authority field of a delivery run. Status is deliberately excluded because
/// it advances in place; canonical migration linkage is included and its only mutation (retiring
/// a predecessor during rollover) rewrites this fingerprint in the same exact CAS transaction.
#[cfg(feature = "migration-delivery")]
pub(super) fn delivery_run_authority_fingerprint(
    run_identity: &[u8; 32],
    account_id: i64,
    lane: &str,
    canonical_migration_id: Option<i64>,
    source_owner: &[u8; 32],
    canonical_lock_owner: Option<&[u8; 32]>,
) -> Result<[u8; 32], Error> {
    let lane = match lane {
        "canonical" => b"canonical".as_slice(),
        "immediate" => b"immediate".as_slice(),
        _ => return Err(Error::Corrupt("delivery run lane")),
    };
    let mut state = Params::new()
        .hash_length(32)
        .personal(DELIVERY_RUN_AUTHORITY_PERSONAL)
        .to_state();
    state.update(&[DELIVERY_RUN_AUTHORITY_CODEC_VERSION]);
    let mut field = |tag: u8, value: Option<&[u8]>| {
        state.update(&[tag, u8::from(value.is_some())]);
        let len = value.map_or(0, <[u8]>::len);
        state.update(&u32::try_from(len).unwrap_or(u32::MAX).to_le_bytes());
        if let Some(value) = value {
            state.update(value);
        }
    };
    field(1, Some(run_identity));
    field(2, Some(&account_id.to_le_bytes()));
    field(3, Some(lane));
    field(4, Some(source_owner));
    let canonical_migration_id = canonical_migration_id.map(i64::to_le_bytes);
    field(5, canonical_migration_id.as_ref().map(<[u8; 8]>::as_slice));
    field(6, canonical_lock_owner.map(<[u8; 32]>::as_slice));
    Ok(state
        .finalize()
        .as_bytes()
        .try_into()
        .expect("configured delivery authority digest is 32 bytes"))
}

/// Returns a process-session-bound monotonic instant owned entirely by Rust.
///
/// The session identity changes on every process start, so a persisted lease from a prior process
/// expires closed. Callers across FFI can request a duration but can never choose the clock epoch
/// or current tick used as authority.
#[cfg(feature = "migration-delivery")]
pub(super) fn delivery_clock_now() -> MonotonicLeaseInstant {
    static DELIVERY_CLOCK: OnceLock<(LeaseClockSession, Instant)> = OnceLock::new();
    let (session, started_at) = DELIVERY_CLOCK.get_or_init(|| {
        (
            LeaseClockSession::random(&mut rand::rngs::OsRng),
            Instant::now(),
        )
    });
    let elapsed = started_at.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
    MonotonicLeaseInstant::new(*session, elapsed)
}

use super::error::Error;

/// The per-pool table and index names a [`Store`] operates over. A concrete migration submodule
/// supplies a `'static` value of this for its own pool; the generic store interpolates these into
/// every DDL and query, so one implementation serves every pool.
#[cfg_attr(not(feature = "migration-delivery"), allow(dead_code))]
pub(crate) struct Tables {
    /// The migration-state table (one row per account; holds the note-split scalars).
    pub migrations: &'static str,
    /// The note-split crossing values (an ordered list).
    pub crossing_values: &'static str,
    /// The inputs of each preparation transaction, keyed by the transaction's `(layer, tx_index)`
    /// grid coordinate.
    pub prep_inputs: &'static str,
    /// The outputs of each preparation transaction, keyed like the inputs.
    pub prep_outputs: &'static str,
    /// The preparation plan's direct-funding wallet notes (an ordered list).
    pub prep_direct_funding: &'static str,
    /// The per-migration-transaction table.
    pub transactions: &'static str,
    /// The dependency edges between migration transactions.
    pub transaction_deps: &'static str,
    /// The index over `(state, scheduled_height)` on the transactions table.
    pub tx_due_index: &'static str,
    /// The unique index over `account_id` on the migrations table, enforcing at most one
    /// migration per account.
    pub account_index: &'static str,
    /// Zend's additive delivery-control schema metadata table.
    pub delivery_meta: &'static str,
    /// Stable Rust-owned parent for canonical and immediate delivery runs.
    pub delivery_runs: &'static str,
    /// At most one active/recovery delivery run per account across both alternative lanes.
    pub delivery_active_lane_index: &'static str,
    /// Prevents the same source output being active in two delivery runs.
    pub delivery_active_source_index: &'static str,
    /// Prevents ordinary deletion of runs that still own delivery authority or evidence.
    pub delivery_run_delete_guard: &'static str,
    /// Prevents account deletion from erasing unresolved delivery authority.
    pub delivery_account_delete_guard: &'static str,
    /// One delivery-control row per canonical migration.
    pub delivery_control: &'static str,
    /// Exact-PCZT claim/lease records keyed by canonical migration transaction id.
    pub delivery_claims: &'static str,
    /// Efficient lease expiry/relaunch reconciliation for scheduled claims.
    pub delivery_claim_lease_index: &'static str,
    /// Durable exact Orchard source reservations retained through storage finality.
    pub delivery_reservations: &'static str,
    /// Efficient ordinary-spend reservation exclusion and finality transitions.
    pub delivery_reservation_status_index: &'static str,
    /// Immutable terminal evidence archived before a canonical parent is reused.
    pub delivery_evidence: &'static str,
    /// Immutable superseded exact attempts retained across expired-artifact rebuilds.
    pub delivery_attempt_archive: &'static str,
    /// Immutable full canonical/delivery metadata for a retained predecessor run.
    pub delivery_run_archive: &'static str,
    /// Rust-owned reservation/delivery state for the SDK's immediate proposal lane.
    pub immediate_delivery: &'static str,
    /// Versioned user-confirmed gross ceiling for each immediate proposal run.
    pub immediate_gross_authorization: &'static str,
    /// Efficient lease expiry/relaunch reconciliation for immediate claims.
    pub immediate_lease_index: &'static str,
    /// One-time safety quarantine for legacy standalone-engine rows.
    pub legacy_quarantine: &'static str,
}

// ---------------------------------------------------------------------------
// DDL
// ---------------------------------------------------------------------------

fn create_migrations_sql(t: &Tables) -> String {
    // `account_id` is a foreign key into the wallet's `accounts` table: the pool-migration tables
    // live in the wallet database alongside `accounts`, so an account's migration is owned by its
    // account row and removed with it. Deleting an account cascades to its migration here, whose
    // child rows in turn cascade from the parent migration row. The `accounts` table name is the
    // same for every pool, so it is referenced directly rather than through `Tables`.
    format!(
        "CREATE TABLE IF NOT EXISTS {} (
            id INTEGER PRIMARY KEY,
            account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
            status TEXT NOT NULL,
            note_split_fee_buffer INTEGER NOT NULL,
            note_split_change INTEGER,
            note_split_prep_fees INTEGER NOT NULL,
            note_split_total_input INTEGER NOT NULL,
            note_split_total_migratable INTEGER NOT NULL
        )",
        t.migrations
    )
}

fn create_crossing_values_sql(t: &Tables) -> String {
    format!(
        "CREATE TABLE IF NOT EXISTS {} (
            migration_id INTEGER NOT NULL REFERENCES {}(id) ON DELETE CASCADE,
            ordinal INTEGER NOT NULL,
            value INTEGER NOT NULL,
            PRIMARY KEY (migration_id, ordinal)
        )",
        t.crossing_values, t.migrations
    )
}

fn create_prep_inputs_sql(t: &Tables) -> String {
    format!(
        "CREATE TABLE IF NOT EXISTS {} (
            migration_id INTEGER NOT NULL REFERENCES {}(id) ON DELETE CASCADE,
            layer INTEGER NOT NULL,
            tx_index INTEGER NOT NULL,
            ordinal INTEGER NOT NULL,
            source TEXT NOT NULL,
            wallet_index INTEGER,
            prior_layer INTEGER,
            prior_transaction INTEGER,
            prior_output INTEGER,
            value INTEGER NOT NULL,
            PRIMARY KEY (migration_id, layer, tx_index, ordinal)
        )",
        t.prep_inputs, t.migrations
    )
}

fn create_prep_outputs_sql(t: &Tables) -> String {
    format!(
        "CREATE TABLE IF NOT EXISTS {} (
            migration_id INTEGER NOT NULL REFERENCES {}(id) ON DELETE CASCADE,
            layer INTEGER NOT NULL,
            tx_index INTEGER NOT NULL,
            ordinal INTEGER NOT NULL,
            role TEXT NOT NULL,
            value INTEGER NOT NULL,
            PRIMARY KEY (migration_id, layer, tx_index, ordinal)
        )",
        t.prep_outputs, t.migrations
    )
}

fn create_prep_direct_funding_sql(t: &Tables) -> String {
    format!(
        "CREATE TABLE IF NOT EXISTS {} (
            migration_id INTEGER NOT NULL REFERENCES {}(id) ON DELETE CASCADE,
            ordinal INTEGER NOT NULL,
            wallet_index INTEGER NOT NULL,
            value INTEGER NOT NULL,
            PRIMARY KEY (migration_id, ordinal)
        )",
        t.prep_direct_funding, t.migrations
    )
}

fn create_transactions_sql(t: &Tables) -> String {
    format!(
        "CREATE TABLE IF NOT EXISTS {} (
            migration_id INTEGER NOT NULL REFERENCES {}(id) ON DELETE CASCADE,
            tx_id INTEGER NOT NULL,
            kind TEXT NOT NULL,
            kind_layer INTEGER,
            kind_index INTEGER,
            kind_crossing INTEGER,
            pczt BLOB NOT NULL,
            scheduled_height INTEGER NOT NULL,
            expiry_height INTEGER NOT NULL,
            anchor_boundary INTEGER,
            state TEXT NOT NULL,
            txid TEXT,
            mined_height INTEGER,
            lock_owner BLOB,
            PRIMARY KEY (migration_id, tx_id)
        )",
        t.transactions, t.migrations
    )
}

fn create_transaction_deps_sql(t: &Tables) -> String {
    format!(
        "CREATE TABLE IF NOT EXISTS {} (
            migration_id INTEGER NOT NULL,
            tx_id INTEGER NOT NULL,
            ordinal INTEGER NOT NULL,
            depends_on_tx_id INTEGER NOT NULL,
            PRIMARY KEY (migration_id, tx_id, ordinal),
            FOREIGN KEY (migration_id, tx_id)
                REFERENCES {}(migration_id, tx_id) ON DELETE CASCADE
        )",
        t.transaction_deps, t.transactions
    )
}

fn create_tx_due_index_sql(t: &Tables) -> String {
    format!(
        "CREATE INDEX IF NOT EXISTS {} ON {} (state, scheduled_height)",
        t.tx_due_index, t.transactions
    )
}

fn create_account_index_sql(t: &Tables) -> String {
    format!(
        "CREATE UNIQUE INDEX IF NOT EXISTS {} ON {} (account_id)",
        t.account_index, t.migrations
    )
}

/// Create the pool-migration tables (and the due-transaction and account indexes) named by `t` on
/// `conn`. This is the body the pool's schema migration's `up()` calls; it is idempotent (`IF NOT
/// EXISTS`). Tables are created in dependency order so each foreign-key target exists first.
pub(crate) fn init(conn: &Connection, t: &Tables) -> rusqlite::Result<()> {
    conn.execute_batch(&format!(
        "{};\n{};\n{};\n{};\n{};\n{};\n{};\n{};\n{};",
        create_migrations_sql(t),
        create_crossing_values_sql(t),
        create_prep_inputs_sql(t),
        create_prep_outputs_sql(t),
        create_prep_direct_funding_sql(t),
        create_transactions_sql(t),
        create_transaction_deps_sql(t),
        create_tx_due_index_sql(t),
        create_account_index_sql(t),
    ))
}

/// Create Zend's additive, versioned delivery-control tables. This is intentionally called by a
/// distinct wallet-schema migration after the canonical pool-migration tables already exist.
#[cfg(feature = "migration-delivery")]
fn immediate_gross_authorization_schema_sql(t: &Tables) -> String {
    let authorization_version = DELIVERY_SCHEMA_V2_GROSS_AUTHORIZATION_VERSION;
    let max_money = DELIVERY_SCHEMA_V2_MAX_MONEY;
    format!(
        "CREATE TABLE IF NOT EXISTS {} (
             run_identity BLOB PRIMARY KEY REFERENCES {}(run_identity) ON DELETE CASCADE,
             authorization_version INTEGER NOT NULL CHECK (
                 authorization_version = {authorization_version}
             ),
             maximum_gross_amount INTEGER NOT NULL CHECK (
                 maximum_gross_amount BETWEEN 0 AND {max_money}
             )
         )",
        t.immediate_gross_authorization, t.immediate_delivery,
    )
}

#[cfg(feature = "migration-delivery")]
fn delivery_control_schema_sql(t: &Tables) -> String {
    let immediate_gross_authorization_schema = format!(
        "{};\n         ",
        immediate_gross_authorization_schema_sql(t)
    );
    delivery_control_schema_sql_for(
        t,
        DELIVERY_SCHEMA_VERSION,
        DELIVERY_SCHEMA_IMPLEMENTATION,
        &immediate_gross_authorization_schema,
        DELIVERY_SCHEMA_V2_MAX_IMMEDIATE_PROPOSAL_ENVELOPE,
        DELIVERY_SCHEMA_V2_MAX_EXACT_TRANSACTION,
        DELIVERY_SCHEMA_V2_MAX_FINALITY_ARCHIVE,
    )
}

#[cfg(feature = "migration-delivery")]
fn delivery_control_schema_v1_sql(t: &Tables) -> String {
    // These are schema constants, not runtime tuning knobs. They are frozen to the exact values
    // emitted by migration d14c3f72 at commit 98b51b18; changing the domain-layer limits later
    // must not rewrite an already-published migration node.
    const V1_MAX_IMMEDIATE_PROPOSAL_ENVELOPE: usize = 4_194_322;
    const V1_MAX_EXACT_TRANSACTION: usize = 4_194_304;
    const V1_MAX_FINALITY_ARCHIVE: usize = 16_777_216;
    delivery_control_schema_sql_for(
        t,
        PREVIOUS_DELIVERY_SCHEMA_VERSION,
        PREVIOUS_DELIVERY_SCHEMA_IMPLEMENTATION,
        "",
        V1_MAX_IMMEDIATE_PROPOSAL_ENVELOPE,
        V1_MAX_EXACT_TRANSACTION,
        V1_MAX_FINALITY_ARCHIVE,
    )
}

#[cfg(feature = "migration-delivery")]
fn delivery_control_schema_sql_for(
    t: &Tables,
    delivery_schema_version: u32,
    delivery_schema_implementation: &str,
    immediate_gross_authorization_schema: &str,
    max_immediate_proposal_envelope: usize,
    max_exact_transaction: usize,
    max_finality_archive: usize,
) -> String {
    let immediate_finality_check = if delivery_schema_version == PREVIOUS_DELIVERY_SCHEMA_VERSION {
        "(storage_finality = 'active' AND observed_mined_height IS NULL
                     AND destination_output_index IS NULL
                     AND expected_ironwood_amount IS NULL
                     AND release_at_height IS NULL AND finalized_tip_height IS NULL)
                 OR (storage_finality = 'complete_pending_finality'
                     AND status = 'confirmed' AND observed_mined_height IS NOT NULL
                     AND destination_output_index IS NOT NULL
                     AND expected_ironwood_amount IS NOT NULL
                     AND release_at_height IS NOT NULL
                     AND release_at_height >= observed_mined_height
                     AND finalized_tip_height IS NULL)
                 OR (storage_finality = 'finalized' AND status = 'confirmed'
                     AND observed_mined_height IS NOT NULL
                     AND destination_output_index IS NOT NULL
                     AND expected_ironwood_amount IS NOT NULL
                     AND release_at_height IS NOT NULL
                     AND release_at_height >= observed_mined_height
                     AND finalized_tip_height IS NOT NULL
                     AND finalized_tip_height >= release_at_height)
                 OR (storage_finality = 'recovery_required'
                     AND storage_recovery_reason IS NOT NULL
                     AND (finalized_tip_height IS NULL
                         OR (release_at_height IS NOT NULL
                             AND finalized_tip_height >= release_at_height)))"
    } else {
        "(storage_finality = 'active' AND observed_mined_height IS NULL
                     AND ((destination_output_index IS NULL
                           AND expected_ironwood_amount IS NULL)
                          OR (destination_output_index IS NOT NULL
                              AND expected_ironwood_amount IS NOT NULL))
                     AND release_at_height IS NULL AND finalized_tip_height IS NULL)
                 OR (storage_finality = 'complete_pending_finality'
                     AND status = 'confirmed' AND observed_mined_height IS NOT NULL
                     AND destination_output_index IS NOT NULL
                     AND expected_ironwood_amount IS NOT NULL
                     AND release_at_height IS NOT NULL
                     AND release_at_height >= observed_mined_height
                     AND finalized_tip_height IS NULL)
                 OR (storage_finality = 'finalized'
                     AND release_at_height IS NOT NULL
                     AND finalized_tip_height IS NOT NULL
                     AND finalized_tip_height >= release_at_height
                     AND ((status = 'confirmed'
                           AND observed_mined_height IS NOT NULL
                           AND destination_output_index IS NOT NULL
                           AND expected_ironwood_amount IS NOT NULL
                           AND release_at_height >= observed_mined_height)
                          OR (status = 'expired_unmined'
                              AND observed_mined_height IS NULL
                              AND destination_output_index IS NOT NULL
                              AND expected_ironwood_amount IS NOT NULL)
                          OR (status IN ('external_signing_expired_unmined', 'abandoned')
                              AND observed_mined_height IS NULL
                              AND destination_output_index IS NULL
                              AND expected_ironwood_amount IS NULL)))
                 OR (storage_finality = 'recovery_required'
                     AND storage_recovery_reason IS NOT NULL
                     AND (finalized_tip_height IS NULL
                         OR (release_at_height IS NOT NULL
                             AND finalized_tip_height >= release_at_height)))"
    };
    format!(
        "CREATE TABLE IF NOT EXISTS {} (
             singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
             schema_version INTEGER NOT NULL CHECK (schema_version >= 1),
             implementation TEXT NOT NULL CHECK (length(implementation) BETWEEN 1 AND 128)
         );
         INSERT OR IGNORE INTO {} (singleton, schema_version, implementation)
             VALUES (1, {delivery_schema_version}, '{delivery_schema_implementation}');
         CREATE TABLE IF NOT EXISTS {} (
             run_identity BLOB PRIMARY KEY CHECK (length(run_identity) = 32),
             account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
             lane TEXT NOT NULL CHECK (lane IN ('canonical', 'immediate')),
             canonical_migration_id INTEGER,
             source_owner BLOB NOT NULL CHECK (length(source_owner) = 32),
             canonical_lock_owner BLOB CHECK (
                 canonical_lock_owner IS NULL OR length(canonical_lock_owner) = 32
             ),
             authority_fingerprint BLOB NOT NULL CHECK (length(authority_fingerprint) = 32),
             status TEXT NOT NULL CHECK (status IN (
                 'active', 'finalized', 'abandoned', 'recovery_required'
             )),
             CHECK (
                 (lane = 'canonical' AND canonical_lock_owner IS NOT NULL
                     AND source_owner != canonical_lock_owner
                     AND ((status IN ('active', 'recovery_required')
                           AND canonical_migration_id IS NOT NULL)
                          OR status IN ('finalized', 'abandoned')))
                 OR (lane = 'immediate' AND canonical_migration_id IS NULL
                     AND canonical_lock_owner IS NOT NULL
                     AND source_owner != canonical_lock_owner)
             )
         );
         CREATE TABLE IF NOT EXISTS {} (
             migration_id INTEGER PRIMARY KEY REFERENCES {}(id) ON DELETE CASCADE,
             run_identity BLOB NOT NULL UNIQUE REFERENCES {}(run_identity) ON DELETE CASCADE,
             revision INTEGER NOT NULL CHECK (revision >= 1),
             state_fingerprint BLOB NOT NULL CHECK (length(state_fingerprint) = 32),
             phase TEXT NOT NULL CHECK (phase IN ('active', 'paused', 'abandoning', 'abandoned')),
             storage_finality TEXT NOT NULL DEFAULT 'active' CHECK (storage_finality IN (
                 'active', 'complete_pending_finality', 'finalized', 'recovery_required'
             )),
             storage_recovery_reason TEXT CHECK (
                 storage_recovery_reason IS NULL OR storage_recovery_reason IN (
                     'transfer_evidence_lost', 'rewound_beyond_finality_horizon',
                     'corrupt_finality_evidence',
                     'external_signing_exposure_unresolved'
                 )
             ),
             release_at_height INTEGER CHECK (
                 release_at_height IS NULL OR release_at_height >= 0
             ),
             finalized_tip_height INTEGER CHECK (
                 finalized_tip_height IS NULL OR finalized_tip_height >= 0
             ),
             policy BLOB,
             policy_fingerprint BLOB,
             policy_validation_failure TEXT CHECK (
                 policy_validation_failure IS NULL OR policy_validation_failure IN (
                     'invalid_encoding', 'policy_too_large',
                     'network_mismatch', 'consensus_mismatch'
                 )
             ),
             CHECK (
                 (policy IS NULL AND policy_fingerprint IS NULL)
                 OR (policy IS NOT NULL AND length(policy) <= 4096
                     AND policy_fingerprint IS NOT NULL
                     AND length(policy_fingerprint) = 32)
             ),
             CHECK (
                 policy IS NULL OR policy_validation_failure IS NULL
             ),
             CHECK (
                 (storage_finality = 'active' AND release_at_height IS NULL
                     AND finalized_tip_height IS NULL)
                 OR (storage_finality = 'complete_pending_finality'
                     AND release_at_height IS NOT NULL AND finalized_tip_height IS NULL)
                 OR (storage_finality = 'finalized' AND release_at_height IS NOT NULL
                     AND finalized_tip_height IS NOT NULL
                     AND finalized_tip_height >= release_at_height)
                 OR (storage_finality = 'recovery_required'
                     AND storage_recovery_reason IS NOT NULL
                     AND (finalized_tip_height IS NULL
                         OR (release_at_height IS NOT NULL
                             AND finalized_tip_height >= release_at_height)))
             ),
             CHECK (
                 storage_finality = 'recovery_required'
                 OR storage_recovery_reason IS NULL
             )
         );
         CREATE TABLE IF NOT EXISTS {} (
             run_identity BLOB NOT NULL REFERENCES {}(run_identity) ON DELETE CASCADE,
             source_txid BLOB NOT NULL CHECK (length(source_txid) = 32),
             source_index INTEGER NOT NULL CHECK (source_index >= 0),
             status TEXT NOT NULL CHECK (status IN (
                 'active', 'recovery_required', 'abandoned', 'finality_released'
             )),
             release_at_height INTEGER CHECK (
                 release_at_height IS NULL OR release_at_height >= 0
             ),
             released_tip_height INTEGER CHECK (
                 released_tip_height IS NULL OR released_tip_height >= 0
             ),
             CHECK (
                 (status = 'active' AND released_tip_height IS NULL)
                 OR (status = 'recovery_required'
                     AND (released_tip_height IS NULL
                         OR (release_at_height IS NOT NULL
                             AND released_tip_height >= release_at_height)))
                 OR (status = 'abandoned' AND release_at_height IS NULL
                     AND released_tip_height IS NOT NULL)
                 OR (status = 'finality_released' AND release_at_height IS NOT NULL
                     AND released_tip_height IS NOT NULL
                     AND released_tip_height >= release_at_height)
             ),
             PRIMARY KEY (run_identity, source_txid, source_index)
         );
         CREATE TABLE IF NOT EXISTS {} (
             migration_id INTEGER NOT NULL,
             tx_id INTEGER NOT NULL CHECK (tx_id >= 0),
             pczt_digest BLOB NOT NULL CHECK (length(pczt_digest) = 32),
             transaction_fingerprint BLOB NOT NULL CHECK (length(transaction_fingerprint) = 32),
             status TEXT NOT NULL CHECK (status IN (
                 'materializing', 'materialization_failed', 'awaiting_external_signature',
                 'staged', 'submitting', 'outcome_unknown', 'broadcasted', 'confirmed',
                 'expired_unmined', 'external_signing_expired_unmined'
             )),
             signer_ownership TEXT NOT NULL CHECK (
                 signer_ownership IN ('sdk', 'external')
             ),
             claim_kind TEXT,
             attempt_token BLOB CHECK (attempt_token IS NULL OR length(attempt_token) = 32),
             lease_clock_session BLOB CHECK (
                 lease_clock_session IS NULL OR length(lease_clock_session) = 32
             ),
             lease_acquired_at_ms INTEGER CHECK (
                 lease_acquired_at_ms IS NULL OR lease_acquired_at_ms >= 0
             ),
             lease_expires_at_ms INTEGER CHECK (
                 lease_expires_at_ms IS NULL OR lease_expires_at_ms >= 0
             ),
             txid BLOB,
             exact_tx BLOB,
             external_signing_pczt_digest BLOB CHECK (
                 external_signing_pczt_digest IS NULL
                 OR length(external_signing_pczt_digest) = 32
             ),
             canonical_external_signing_pczt BLOB CHECK (
                 canonical_external_signing_pczt IS NULL
                 OR length(canonical_external_signing_pczt) BETWEEN 1 AND 4194304
             ),
             signed_pczt_digest BLOB CHECK (
                 signed_pczt_digest IS NULL OR length(signed_pczt_digest) = 32
             ),
             canonical_signed_pczt BLOB CHECK (
                 canonical_signed_pczt IS NULL
                 OR length(canonical_signed_pczt) BETWEEN 1 AND 4194304
             ),
             signed_pczt_binding BLOB CHECK (
                 signed_pczt_binding IS NULL OR length(signed_pczt_binding) = 32
             ),
             policy_fingerprint BLOB NOT NULL CHECK (length(policy_fingerprint) = 32),
             last_error TEXT CHECK (last_error IS NULL OR last_error IN (
                 'materialization_failed', 'materialization_lease_expired',
                 'signing_cancelled', 'transport_setup_failed', 'transport_did_not_begin',
                 'submission_lease_expired', 'transport_outcome_unknown'
             )),
             PRIMARY KEY (migration_id, tx_id),
             FOREIGN KEY (migration_id, tx_id)
                 REFERENCES {}(migration_id, tx_id) ON DELETE CASCADE,
             CHECK (
                 (claim_kind IS NULL AND attempt_token IS NULL
                     AND lease_clock_session IS NULL AND lease_acquired_at_ms IS NULL
                     AND lease_expires_at_ms IS NULL)
                 OR (claim_kind IN ('materialization', 'submission', 'outcome_resolution')
                     AND attempt_token IS NOT NULL AND lease_clock_session IS NOT NULL
                     AND lease_acquired_at_ms IS NOT NULL AND lease_expires_at_ms IS NOT NULL
                     AND lease_expires_at_ms > lease_acquired_at_ms)
             ),
             CHECK (
                 (status = 'materializing' AND claim_kind = 'materialization')
                 OR (status = 'awaiting_external_signature'
                     AND (claim_kind IS NULL OR claim_kind = 'materialization'))
                 OR (status = 'submitting' AND claim_kind = 'submission')
                 OR (status IN ('materialization_failed', 'staged', 'confirmed',
                                'expired_unmined', 'external_signing_expired_unmined')
                     AND claim_kind IS NULL)
                 OR (status IN ('outcome_unknown', 'broadcasted') AND claim_kind IS NULL)
                 OR (claim_kind = 'outcome_resolution'
                     AND status IN ('outcome_unknown', 'broadcasted'))
             ),
             CHECK (
                 (status IN ('materializing', 'materialization_failed')
                     AND txid IS NULL AND exact_tx IS NULL)
                 OR (status IN ('awaiting_external_signature',
                                'external_signing_expired_unmined')
                     AND txid IS NULL AND exact_tx IS NULL)
                 OR (status NOT IN ('materializing', 'materialization_failed',
                                    'awaiting_external_signature',
                                    'external_signing_expired_unmined')
                     AND txid IS NOT NULL AND length(txid) = 32
                     AND exact_tx IS NOT NULL
                     AND length(exact_tx) BETWEEN 1 AND {max_exact_transaction})
             ),
             CHECK (
                 (signer_ownership = 'sdk'
                     AND external_signing_pczt_digest IS NULL
                     AND canonical_external_signing_pczt IS NULL
                     AND signed_pczt_digest IS NULL AND canonical_signed_pczt IS NULL
                     AND signed_pczt_binding IS NULL)
                 OR (signer_ownership = 'external'
                     AND ((status IN ('materializing', 'materialization_failed')
                           AND external_signing_pczt_digest IS NULL
                           AND canonical_external_signing_pczt IS NULL
                           AND signed_pczt_digest IS NULL
                           AND canonical_signed_pczt IS NULL
                           AND signed_pczt_binding IS NULL)
                          OR (status IN ('awaiting_external_signature',
                                        'external_signing_expired_unmined')
                              AND external_signing_pczt_digest IS NOT NULL
                              AND canonical_external_signing_pczt IS NOT NULL
                              AND length(canonical_external_signing_pczt) > 0
                              AND ((signed_pczt_digest IS NULL
                                    AND canonical_signed_pczt IS NULL
                                    AND signed_pczt_binding IS NULL)
                                   OR (signed_pczt_digest IS NOT NULL
                                       AND canonical_signed_pczt IS NOT NULL
                                       AND length(canonical_signed_pczt) > 0
                                       AND signed_pczt_binding IS NOT NULL)))
                          OR (status IN ('staged', 'submitting', 'outcome_unknown',
                                        'broadcasted', 'confirmed', 'expired_unmined')
                              AND external_signing_pczt_digest IS NOT NULL
                              AND canonical_external_signing_pczt IS NOT NULL
                              AND length(canonical_external_signing_pczt) > 0
                              AND signed_pczt_digest IS NOT NULL
                              AND canonical_signed_pczt IS NOT NULL
                              AND length(canonical_signed_pczt) > 0
                              AND signed_pczt_binding IS NOT NULL)))
             )
         );
         CREATE TABLE IF NOT EXISTS {} (
             run_identity BLOB NOT NULL REFERENCES {}(run_identity) ON DELETE CASCADE,
             tx_id INTEGER NOT NULL CHECK (tx_id >= 0),
             pczt_digest BLOB NOT NULL CHECK (length(pczt_digest) = 32),
             transaction_fingerprint BLOB NOT NULL CHECK (length(transaction_fingerprint) = 32),
             canonical_pczt BLOB NOT NULL CHECK (
                 length(canonical_pczt) BETWEEN 1 AND 4194304
             ),
             transaction_kind TEXT NOT NULL CHECK (
                 transaction_kind IN ('preparation', 'transfer')
             ),
             terminal_status TEXT NOT NULL CHECK (terminal_status IN (
                 'materialization_failed', 'confirmed', 'expired_unmined',
                 'external_signing_expired_unmined'
             )),
             signer_ownership TEXT NOT NULL CHECK (
                 signer_ownership IN ('sdk', 'external')
             ),
             txid BLOB CHECK (txid IS NULL OR length(txid) = 32),
             exact_tx BLOB,
             expiry_height INTEGER NOT NULL CHECK (expiry_height >= 0),
             external_signing_pczt_digest BLOB CHECK (
                 external_signing_pczt_digest IS NULL
                 OR length(external_signing_pczt_digest) = 32
             ),
             canonical_external_signing_pczt BLOB CHECK (
                 canonical_external_signing_pczt IS NULL
                 OR length(canonical_external_signing_pczt) BETWEEN 1 AND 4194304
             ),
             signed_pczt_digest BLOB CHECK (
                 signed_pczt_digest IS NULL OR length(signed_pczt_digest) = 32
             ),
             canonical_signed_pczt BLOB CHECK (
                 canonical_signed_pczt IS NULL
                 OR length(canonical_signed_pczt) BETWEEN 1 AND 4194304
             ),
             signed_pczt_binding BLOB CHECK (
                 signed_pczt_binding IS NULL OR length(signed_pczt_binding) = 32
             ),
             policy_fingerprint BLOB NOT NULL CHECK (length(policy_fingerprint) = 32),
             last_error TEXT CHECK (last_error IS NULL OR last_error IN (
                 'materialization_failed', 'materialization_lease_expired',
                 'signing_cancelled', 'transport_setup_failed', 'transport_did_not_begin',
                 'submission_lease_expired', 'transport_outcome_unknown'
             )),
             destination_txid BLOB CHECK (
                 destination_txid IS NULL OR length(destination_txid) = 32
             ),
             destination_output_index INTEGER CHECK (
                 destination_output_index IS NULL OR destination_output_index >= 0
             ),
             expected_ironwood_amount INTEGER CHECK (
                 expected_ironwood_amount IS NULL OR expected_ironwood_amount >= 0
             ),
             observed_mined_height INTEGER CHECK (
                 observed_mined_height IS NULL OR observed_mined_height >= 0
             ),
             release_at_height INTEGER CHECK (
                 release_at_height IS NULL OR release_at_height >= 0
             ),
             CHECK (
                 (txid IS NULL AND exact_tx IS NULL)
                 OR (txid IS NOT NULL AND length(txid) = 32
                     AND exact_tx IS NOT NULL
                     AND length(exact_tx) BETWEEN 1 AND {max_exact_transaction})
             ),
             CHECK (
                 (terminal_status IN ('materialization_failed',
                                      'external_signing_expired_unmined')
                     AND txid IS NULL AND exact_tx IS NULL)
                 OR (terminal_status IN ('confirmed', 'expired_unmined')
                     AND txid IS NOT NULL AND exact_tx IS NOT NULL
                     AND length(exact_tx) BETWEEN 1 AND {max_exact_transaction})
             ),
             CHECK (
                 (signer_ownership = 'sdk'
                     AND external_signing_pczt_digest IS NULL
                     AND canonical_external_signing_pczt IS NULL
                     AND signed_pczt_digest IS NULL
                     AND canonical_signed_pczt IS NULL
                     AND signed_pczt_binding IS NULL)
                 OR (signer_ownership = 'external'
                     AND ((terminal_status = 'materialization_failed'
                           AND external_signing_pczt_digest IS NULL
                           AND canonical_external_signing_pczt IS NULL
                           AND signed_pczt_digest IS NULL
                           AND canonical_signed_pczt IS NULL
                           AND signed_pczt_binding IS NULL)
                          OR (external_signing_pczt_digest IS NOT NULL
                              AND canonical_external_signing_pczt IS NOT NULL
                              AND ((signed_pczt_digest IS NULL
                                    AND canonical_signed_pczt IS NULL
                                    AND signed_pczt_binding IS NULL)
                                   OR (signed_pczt_digest IS NOT NULL
                                       AND canonical_signed_pczt IS NOT NULL
                                       AND signed_pczt_binding IS NOT NULL)))))
             ),
             CHECK (
                 (destination_txid IS NULL AND destination_output_index IS NULL
                     AND expected_ironwood_amount IS NULL AND observed_mined_height IS NULL
                     AND release_at_height IS NULL)
                 OR (destination_txid IS NOT NULL AND destination_output_index IS NOT NULL
                     AND expected_ironwood_amount IS NOT NULL
                     AND observed_mined_height IS NOT NULL
                     AND release_at_height IS NOT NULL
                     AND release_at_height >= observed_mined_height)
             ),
             CHECK (
                 (terminal_status = 'confirmed' AND transaction_kind = 'transfer'
                     AND destination_txid IS NOT NULL)
                 OR ((terminal_status != 'confirmed' OR transaction_kind != 'transfer')
                     AND destination_txid IS NULL)
             ),
             PRIMARY KEY (run_identity, tx_id)
         );
         CREATE TABLE IF NOT EXISTS {} (
             run_identity BLOB NOT NULL REFERENCES {}(run_identity) ON DELETE CASCADE,
             tx_id INTEGER NOT NULL CHECK (tx_id >= 0),
             transaction_fingerprint BLOB NOT NULL CHECK (length(transaction_fingerprint) = 32),
             pczt_digest BLOB NOT NULL CHECK (length(pczt_digest) = 32),
             canonical_pczt BLOB NOT NULL CHECK (length(canonical_pczt) > 0),
             signer_ownership TEXT NOT NULL CHECK (signer_ownership IN ('sdk', 'external')),
             archived_revision INTEGER NOT NULL CHECK (archived_revision >= 1),
             terminal_status TEXT NOT NULL CHECK (terminal_status IN (
                 'expired_unmined', 'external_signing_expired_unmined'
             )),
             txid BLOB CHECK (txid IS NULL OR length(txid) = 32),
             exact_tx BLOB,
             expiry_height INTEGER NOT NULL CHECK (expiry_height >= 0),
             external_signing_pczt_digest BLOB CHECK (
                 external_signing_pczt_digest IS NULL
                 OR length(external_signing_pczt_digest) = 32
             ),
             canonical_external_signing_pczt BLOB CHECK (
                 canonical_external_signing_pczt IS NULL
                 OR length(canonical_external_signing_pczt) BETWEEN 1 AND 4194304
             ),
             signed_pczt_digest BLOB CHECK (
                 signed_pczt_digest IS NULL OR length(signed_pczt_digest) = 32
             ),
             canonical_signed_pczt BLOB CHECK (
                 canonical_signed_pczt IS NULL
                 OR length(canonical_signed_pczt) BETWEEN 1 AND 4194304
             ),
             signed_pczt_binding BLOB CHECK (
                 signed_pczt_binding IS NULL OR length(signed_pczt_binding) = 32
             ),
             policy_fingerprint BLOB NOT NULL CHECK (length(policy_fingerprint) = 32),
             last_error TEXT CHECK (last_error IS NULL OR last_error IN (
                 'materialization_failed', 'materialization_lease_expired',
                 'signing_cancelled', 'transport_setup_failed', 'transport_did_not_begin',
                 'submission_lease_expired', 'transport_outcome_unknown'
             )),
             CHECK (
                 (terminal_status = 'expired_unmined'
                     AND txid IS NOT NULL AND exact_tx IS NOT NULL
                     AND length(exact_tx) BETWEEN 1 AND {max_exact_transaction})
                 OR (terminal_status = 'external_signing_expired_unmined'
                     AND txid IS NULL AND exact_tx IS NULL
                     AND external_signing_pczt_digest IS NOT NULL
                     AND canonical_external_signing_pczt IS NOT NULL)
             ),
             PRIMARY KEY (run_identity, tx_id, transaction_fingerprint)
         );
         CREATE TABLE IF NOT EXISTS {} (
             run_identity BLOB PRIMARY KEY REFERENCES {}(run_identity) ON DELETE CASCADE,
             revision INTEGER NOT NULL CHECK (revision >= 1),
             phase TEXT NOT NULL CHECK (phase IN ('active', 'paused', 'abandoning', 'abandoned')),
             artifact_identity BLOB NOT NULL UNIQUE CHECK (length(artifact_identity) = 32),
             proposal_fingerprint BLOB NOT NULL CHECK (length(proposal_fingerprint) = 32),
             canonical_proposal BLOB NOT NULL CHECK (
                 length(canonical_proposal) BETWEEN 1 AND {max_immediate_proposal_envelope}
             ),
             signer_ownership TEXT NOT NULL CHECK (
                 signer_ownership IN ('sdk', 'external')
             ),
             status TEXT NOT NULL CHECK (status IN (
                 'materializing', 'materialization_failed', 'awaiting_external_signature',
                 'staged', 'submitting', 'outcome_unknown', 'broadcasted', 'confirmed',
                 'expired_unmined', 'external_signing_expired_unmined', 'abandoned'
             )),
             claim_kind TEXT CHECK (
                 claim_kind IS NULL OR claim_kind IN (
                     'materialization', 'submission', 'outcome_resolution'
                 )
             ),
             attempt_token BLOB CHECK (attempt_token IS NULL OR length(attempt_token) = 32),
             lease_clock_session BLOB CHECK (
                 lease_clock_session IS NULL OR length(lease_clock_session) = 32
             ),
             lease_acquired_at_ms INTEGER CHECK (
                 lease_acquired_at_ms IS NULL OR lease_acquired_at_ms >= 0
             ),
             lease_expires_at_ms INTEGER CHECK (
                 lease_expires_at_ms IS NULL OR lease_expires_at_ms >= 0
             ),
             txid BLOB CHECK (txid IS NULL OR length(txid) = 32),
             exact_tx BLOB,
             exact_tx_digest BLOB CHECK (
                 exact_tx_digest IS NULL OR length(exact_tx_digest) = 32
             ),
             unsigned_pczt_digest BLOB CHECK (
                 unsigned_pczt_digest IS NULL OR length(unsigned_pczt_digest) = 32
             ),
             canonical_unsigned_pczt BLOB CHECK (
                 canonical_unsigned_pczt IS NULL
                 OR length(canonical_unsigned_pczt) BETWEEN 1 AND 4194304
             ),
             signed_pczt_digest BLOB CHECK (
                 signed_pczt_digest IS NULL OR length(signed_pczt_digest) = 32
             ),
             canonical_signed_pczt BLOB CHECK (
                 canonical_signed_pczt IS NULL
                 OR length(canonical_signed_pczt) BETWEEN 1 AND 4194304
             ),
             signed_pczt_binding BLOB CHECK (
                 signed_pczt_binding IS NULL OR length(signed_pczt_binding) = 32
             ),
             last_error TEXT CHECK (last_error IS NULL OR last_error IN (
                 'materialization_failed', 'materialization_lease_expired',
                 'signing_cancelled', 'transport_setup_failed', 'transport_did_not_begin',
                 'submission_lease_expired', 'transport_outcome_unknown'
             )),
             expiry_height INTEGER NOT NULL CHECK (expiry_height >= 0),
             storage_finality TEXT NOT NULL DEFAULT 'active' CHECK (storage_finality IN (
                 'active', 'complete_pending_finality', 'finalized', 'recovery_required'
             )),
             storage_recovery_reason TEXT CHECK (
                 storage_recovery_reason IS NULL OR storage_recovery_reason IN (
                     'transfer_evidence_lost', 'rewound_beyond_finality_horizon',
                     'corrupt_finality_evidence',
                     'external_signing_exposure_unresolved'
                 )
             ),
             observed_mined_height INTEGER CHECK (
                 observed_mined_height IS NULL OR observed_mined_height >= 0
             ),
             destination_output_index INTEGER CHECK (
                 destination_output_index IS NULL OR destination_output_index >= 0
             ),
             expected_ironwood_amount INTEGER CHECK (
                 expected_ironwood_amount IS NULL OR expected_ironwood_amount >= 0
             ),
             release_at_height INTEGER CHECK (
                 release_at_height IS NULL OR release_at_height >= 0
             ),
             finalized_tip_height INTEGER CHECK (
                 finalized_tip_height IS NULL OR finalized_tip_height >= 0
             ),
             policy BLOB,
             policy_fingerprint BLOB,
             policy_validation_failure TEXT CHECK (
                 policy_validation_failure IS NULL OR policy_validation_failure IN (
                     'invalid_encoding', 'policy_too_large',
                     'network_mismatch', 'consensus_mismatch'
                 )
             ),
             CHECK (
                 (policy IS NULL AND policy_fingerprint IS NULL)
                 OR (policy IS NOT NULL AND length(policy) <= 4096
                     AND policy_fingerprint IS NOT NULL
                     AND length(policy_fingerprint) = 32)
             ),
             CHECK (
                 policy IS NULL OR policy_validation_failure IS NULL
             ),
             CHECK (
                 (claim_kind IS NULL AND attempt_token IS NULL
                     AND lease_clock_session IS NULL AND lease_acquired_at_ms IS NULL
                     AND lease_expires_at_ms IS NULL)
                 OR (claim_kind IN ('materialization', 'submission', 'outcome_resolution')
                     AND attempt_token IS NOT NULL AND lease_clock_session IS NOT NULL
                     AND lease_acquired_at_ms IS NOT NULL AND lease_expires_at_ms IS NOT NULL
                     AND lease_expires_at_ms > lease_acquired_at_ms)
             ),
             CHECK (
                 (status = 'materializing' AND claim_kind = 'materialization')
                 OR (status = 'awaiting_external_signature'
                     AND (claim_kind IS NULL OR claim_kind = 'materialization'))
                 OR (status = 'submitting' AND claim_kind = 'submission')
                 OR (claim_kind = 'outcome_resolution'
                     AND status IN ('outcome_unknown', 'broadcasted'))
                 OR (status IN ('materialization_failed', 'staged',
                                'outcome_unknown', 'broadcasted',
                                'confirmed', 'expired_unmined',
                                'external_signing_expired_unmined', 'abandoned')
                     AND claim_kind IS NULL)
             ),
             CHECK (
                 status NOT IN ('awaiting_external_signature',
                                'external_signing_expired_unmined')
                 OR signer_ownership = 'external'
             ),
             CHECK (
                 (status IN ('materializing', 'materialization_failed',
                             'awaiting_external_signature',
                             'external_signing_expired_unmined')
                     AND txid IS NULL AND exact_tx IS NULL AND exact_tx_digest IS NULL)
                 OR (status NOT IN ('materializing', 'materialization_failed',
                                    'awaiting_external_signature',
                                    'external_signing_expired_unmined')
                     AND txid IS NOT NULL AND length(txid) = 32
                     AND exact_tx IS NOT NULL
                     AND length(exact_tx) BETWEEN 1 AND {max_exact_transaction}
                     AND exact_tx_digest IS NOT NULL)
                 OR (status = 'abandoned'
                     AND ((txid IS NULL AND exact_tx IS NULL AND exact_tx_digest IS NULL)
                         OR (txid IS NOT NULL AND length(txid) = 32
                             AND exact_tx IS NOT NULL
                             AND length(exact_tx) BETWEEN 1 AND {max_exact_transaction}
                             AND exact_tx_digest IS NOT NULL)))
             ),
             CHECK (
                 (signer_ownership = 'sdk'
                     AND unsigned_pczt_digest IS NULL AND canonical_unsigned_pczt IS NULL)
                 OR (status IN ('materializing', 'materialization_failed')
                     AND unsigned_pczt_digest IS NULL AND canonical_unsigned_pczt IS NULL)
                 OR (signer_ownership = 'external' AND status != 'materializing'
                     AND unsigned_pczt_digest IS NOT NULL
                     AND canonical_unsigned_pczt IS NOT NULL
                     AND length(canonical_unsigned_pczt) > 0)
                 OR (status = 'abandoned'
                     AND ((unsigned_pczt_digest IS NULL
                           AND canonical_unsigned_pczt IS NULL)
                         OR (unsigned_pczt_digest IS NOT NULL
                             AND canonical_unsigned_pczt IS NOT NULL
                             AND length(canonical_unsigned_pczt) > 0)))
             ),
             CHECK (
                 (signer_ownership = 'sdk'
                     AND signed_pczt_digest IS NULL AND canonical_signed_pczt IS NULL
                     AND signed_pczt_binding IS NULL)
                 OR (status IN ('materializing', 'materialization_failed')
                     AND signed_pczt_digest IS NULL AND canonical_signed_pczt IS NULL
                     AND signed_pczt_binding IS NULL)
                 OR (signer_ownership = 'external'
                     AND status IN ('staged', 'submitting', 'outcome_unknown',
                                    'broadcasted', 'confirmed', 'expired_unmined')
                     AND signed_pczt_digest IS NOT NULL
                     AND canonical_signed_pczt IS NOT NULL
                     AND length(canonical_signed_pczt) > 0
                     AND signed_pczt_binding IS NOT NULL)
                 OR (signer_ownership = 'external'
                     AND status IN ('awaiting_external_signature',
                                    'external_signing_expired_unmined', 'abandoned')
                     AND ((signed_pczt_digest IS NULL AND canonical_signed_pczt IS NULL
                           AND signed_pczt_binding IS NULL)
                         OR (signed_pczt_digest IS NOT NULL
                             AND canonical_signed_pczt IS NOT NULL
                             AND length(canonical_signed_pczt) > 0
                             AND signed_pczt_binding IS NOT NULL)))
             ),
             CHECK (
                 signed_pczt_digest IS NULL OR unsigned_pczt_digest IS NOT NULL
             ),
             CHECK (
                 signer_ownership = 'sdk' OR exact_tx IS NULL
                 OR signed_pczt_digest IS NOT NULL
             ),
             CHECK (
                 {immediate_finality_check}
             ),
             CHECK (
                 storage_finality = 'recovery_required'
                 OR storage_recovery_reason IS NULL
             )
         );
         {immediate_gross_authorization_schema}CREATE TABLE IF NOT EXISTS {} (
             run_identity BLOB PRIMARY KEY REFERENCES {}(run_identity) ON DELETE CASCADE,
             revision INTEGER NOT NULL CHECK (revision >= 1),
             state_fingerprint BLOB NOT NULL CHECK (length(state_fingerprint) = 32),
             canonical_state_archive BLOB NOT NULL CHECK (
                 length(canonical_state_archive) BETWEEN 1 AND 67108864
             ),
             phase TEXT NOT NULL CHECK (
                 phase IN ('active', 'paused', 'abandoning', 'abandoned')
             ),
             storage_finality TEXT NOT NULL CHECK (storage_finality IN (
                 'active', 'complete_pending_finality', 'finalized', 'recovery_required'
             )),
             storage_recovery_reason TEXT CHECK (
                 storage_recovery_reason IS NULL OR storage_recovery_reason IN (
                     'transfer_evidence_lost', 'rewound_beyond_finality_horizon',
                     'corrupt_finality_evidence',
                     'external_signing_exposure_unresolved'
                 )
             ),
             release_at_height INTEGER CHECK (
                 release_at_height IS NULL OR release_at_height >= 0
             ),
             finalized_tip_height INTEGER CHECK (
                 finalized_tip_height IS NULL OR (
                     release_at_height IS NOT NULL
                     AND finalized_tip_height >= release_at_height
                 )
             ),
             finality_archive BLOB,
             finality_archive_fingerprint BLOB CHECK (
                 finality_archive_fingerprint IS NULL
                 OR length(finality_archive_fingerprint) = 32
             ),
             policy BLOB,
             policy_fingerprint BLOB,
             destination_spendability TEXT NOT NULL CHECK (
                 destination_spendability IN (
                     'not_applicable', 'not_spendable', 'spendable', 'already_spent'
                 )
             ),
             CHECK (
                 (policy IS NULL AND policy_fingerprint IS NULL)
                 OR (policy IS NOT NULL AND length(policy) BETWEEN 1 AND 4096
                     AND policy_fingerprint IS NOT NULL
                     AND length(policy_fingerprint) = 32)
             ),
             CHECK (
                 (storage_finality = 'active'
                     AND release_at_height IS NULL
                     AND finalized_tip_height IS NULL
                     AND finality_archive IS NULL
                     AND finality_archive_fingerprint IS NULL)
                 OR (storage_finality = 'complete_pending_finality'
                     AND release_at_height IS NOT NULL
                     AND finalized_tip_height IS NULL
                     AND finality_archive IS NULL
                     AND finality_archive_fingerprint IS NULL)
                 OR (storage_finality = 'finalized'
                     AND release_at_height IS NOT NULL
                     AND finalized_tip_height IS NOT NULL
                     AND ((finality_archive IS NULL
                           AND finality_archive_fingerprint IS NULL)
                          OR (finality_archive IS NOT NULL
                              AND length(finality_archive)
                                  BETWEEN 1 AND {max_finality_archive}
                              AND finality_archive_fingerprint IS NOT NULL)))
                 OR (storage_finality = 'recovery_required'
                     AND storage_recovery_reason IS NOT NULL)
             ),
             CHECK (
                 storage_finality = 'recovery_required'
                 OR storage_recovery_reason IS NULL
             )
         );
         CREATE TABLE IF NOT EXISTS {} (
             source_object TEXT NOT NULL CHECK (length(source_object) BETWEEN 1 AND 255),
             object_type TEXT NOT NULL CHECK (object_type IN ('table', 'index', 'trigger', 'view')),
             schema_fingerprint BLOB NOT NULL CHECK (length(schema_fingerprint) = 32),
             detected_rows INTEGER NOT NULL CHECK (detected_rows >= 0),
             disposition TEXT NOT NULL CHECK (disposition = 'recovery_required'),
             reason TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 1024),
             PRIMARY KEY (source_object, schema_fingerprint)
         );
         CREATE UNIQUE INDEX IF NOT EXISTS {} ON {} (account_id)
             WHERE status IN ('active', 'recovery_required');
         CREATE UNIQUE INDEX IF NOT EXISTS {} ON {} (source_txid, source_index)
             WHERE status IN ('active', 'recovery_required');
         CREATE INDEX IF NOT EXISTS {} ON {} (lease_clock_session, lease_expires_at_ms)
             WHERE claim_kind IS NOT NULL;
         CREATE INDEX IF NOT EXISTS {} ON {} (status, run_identity);
         CREATE INDEX IF NOT EXISTS {} ON {} (lease_clock_session, lease_expires_at_ms)
             WHERE claim_kind IS NOT NULL;
         CREATE TRIGGER IF NOT EXISTS {} BEFORE DELETE ON {}
         WHEN EXISTS(SELECT 1 FROM accounts WHERE id = OLD.account_id)
          AND (
              EXISTS(SELECT 1 FROM {} WHERE run_identity = OLD.run_identity)
              OR EXISTS(SELECT 1 FROM {} WHERE run_identity = OLD.run_identity)
              OR EXISTS(SELECT 1 FROM {} WHERE run_identity = OLD.run_identity)
              OR EXISTS(SELECT 1 FROM {} WHERE run_identity = OLD.run_identity)
              OR EXISTS(SELECT 1 FROM {} WHERE run_identity = OLD.run_identity)
              OR EXISTS(SELECT 1 FROM {} WHERE run_identity = OLD.run_identity)
          )
         BEGIN
             SELECT RAISE(ABORT, 'delivery run retains authority or evidence');
         END;
         CREATE TRIGGER IF NOT EXISTS {} BEFORE DELETE ON accounts
         WHEN EXISTS(
             SELECT 1 FROM {} runs
              WHERE runs.account_id = OLD.id
                AND (
                    runs.status IN ('active', 'recovery_required')
                    OR EXISTS(
                        SELECT 1 FROM {} reservations
                         WHERE reservations.run_identity = runs.run_identity
                           AND reservations.status IN ('active', 'recovery_required')
                    )
                    OR EXISTS(
                        SELECT 1 FROM {} control
                         WHERE control.run_identity = runs.run_identity
                           AND control.storage_finality = 'recovery_required'
                    )
                    OR EXISTS(
                        SELECT 1
                          FROM {} control
                          JOIN {} claims
                            ON claims.migration_id = control.migration_id
                         WHERE control.run_identity = runs.run_identity
                           AND claims.status IN (
                               'awaiting_external_signature', 'submitting',
                               'outcome_unknown', 'broadcasted'
                           )
                    )
                    OR EXISTS(
                        SELECT 1 FROM {} immediate
                         WHERE immediate.run_identity = runs.run_identity
                           AND (immediate.storage_finality = 'recovery_required'
                                OR immediate.status IN (
                                    'awaiting_external_signature', 'submitting',
                                    'outcome_unknown', 'broadcasted'
                                ))
                    )
                    OR EXISTS(
                        SELECT 1 FROM {} archive
                         WHERE archive.run_identity = runs.run_identity
                           AND archive.storage_finality = 'recovery_required'
                    )
                )
         )
         BEGIN
             SELECT RAISE(ABORT, 'account retains unresolved delivery authority');
         END;",
        t.delivery_meta,
        t.delivery_meta,
        t.delivery_runs,
        t.delivery_control,
        t.migrations,
        t.delivery_runs,
        t.delivery_reservations,
        t.delivery_runs,
        t.delivery_claims,
        t.transactions,
        t.delivery_evidence,
        t.delivery_runs,
        t.delivery_attempt_archive,
        t.delivery_runs,
        t.immediate_delivery,
        t.delivery_runs,
        t.delivery_run_archive,
        t.delivery_runs,
        t.legacy_quarantine,
        t.delivery_active_lane_index,
        t.delivery_runs,
        t.delivery_active_source_index,
        t.delivery_reservations,
        t.delivery_claim_lease_index,
        t.delivery_claims,
        t.delivery_reservation_status_index,
        t.delivery_reservations,
        t.immediate_lease_index,
        t.immediate_delivery,
        t.delivery_run_delete_guard,
        t.delivery_runs,
        t.delivery_control,
        t.delivery_reservations,
        t.delivery_evidence,
        t.delivery_attempt_archive,
        t.immediate_delivery,
        t.delivery_run_archive,
        t.delivery_account_delete_guard,
        t.delivery_runs,
        t.delivery_reservations,
        t.delivery_control,
        t.delivery_control,
        t.delivery_claims,
        t.immediate_delivery,
        t.delivery_run_archive,
    )
}

/// Creates the immutable v1 schema owned by the original delivery-control wallet migration.
/// Later migration nodes must advance this schema instead of changing the historical node's body.
#[cfg(feature = "migration-delivery")]
pub(crate) fn init_delivery_control(conn: &Connection, t: &Tables) -> rusqlite::Result<()> {
    conn.execute_batch(&delivery_control_schema_v1_sql(t))
}

/// Creates the current schema directly for focused runtime tests.
#[cfg(all(feature = "migration-delivery", test))]
pub(crate) fn init_current_delivery_control(conn: &Connection, t: &Tables) -> rusqlite::Result<()> {
    conn.execute_batch(&delivery_control_schema_sql(t))
}

#[cfg(feature = "migration-delivery")]
fn upgrade_immediate_delivery_table_v2(
    transaction: &rusqlite::Transaction<'_>,
    t: &Tables,
) -> Result<(), Error> {
    const COLUMNS: &str = "run_identity, revision, phase, artifact_identity,
        proposal_fingerprint, canonical_proposal, signer_ownership, status, claim_kind,
        attempt_token, lease_clock_session, lease_acquired_at_ms, lease_expires_at_ms, txid,
        exact_tx, exact_tx_digest, unsigned_pczt_digest, canonical_unsigned_pczt,
        signed_pczt_digest, canonical_signed_pczt, signed_pczt_binding, last_error, expiry_height,
        storage_finality, storage_recovery_reason, observed_mined_height,
        destination_output_index, expected_ironwood_amount, release_at_height,
        finalized_tip_height, policy, policy_fingerprint, policy_validation_failure";

    let backup = format!("{}_v1_upgrade", t.immediate_delivery);
    if sqlite_object_exists(transaction, &backup)? {
        return Err(Error::Corrupt("delivery v1 immediate upgrade residue"));
    }
    let batch = delivery_control_schema_sql(t);
    let create_table = compiled_table_sql(&batch, t.immediate_delivery)
        .ok_or(Error::Corrupt("compiled immediate delivery schema"))?;
    let create_index = compiled_index_sql(&batch, t.immediate_lease_index)
        .ok_or(Error::Corrupt("compiled immediate lease index"))?;
    let run_delete_guard = compiled_trigger_sql(&batch, t.delivery_run_delete_guard)
        .ok_or(Error::Corrupt("compiled delivery run delete guard"))?;
    let account_delete_guard = compiled_trigger_sql(&batch, t.delivery_account_delete_guard)
        .ok_or(Error::Corrupt("compiled delivery account delete guard"))?;
    let expected_rows: u64 = transaction.query_row(
        &format!("SELECT COUNT(*) FROM {}", t.immediate_delivery),
        [],
        |row| row.get(0),
    )?;
    transaction.execute_batch(&format!(
        "DROP TRIGGER {};
         DROP TRIGGER {};
         DROP INDEX {};
         ALTER TABLE {} RENAME TO {};
         {create_table};",
        t.delivery_run_delete_guard,
        t.delivery_account_delete_guard,
        t.immediate_lease_index,
        t.immediate_delivery,
        backup,
    ))?;
    let copied_rows = transaction.execute(
        &format!(
            "INSERT INTO {} ({COLUMNS}) SELECT {COLUMNS} FROM {}",
            t.immediate_delivery, backup,
        ),
        [],
    )?;
    let actual_rows: u64 = transaction.query_row(
        &format!("SELECT COUNT(*) FROM {}", t.immediate_delivery),
        [],
        |row| row.get(0),
    )?;
    let copy_differs: bool = transaction.query_row(
        &format!(
            "SELECT EXISTS(SELECT {COLUMNS} FROM {backup}
                            EXCEPT SELECT {COLUMNS} FROM {})
                 OR EXISTS(SELECT {COLUMNS} FROM {}
                            EXCEPT SELECT {COLUMNS} FROM {backup})",
            t.immediate_delivery, t.immediate_delivery,
        ),
        [],
        |row| row.get(0),
    )?;
    if u64::try_from(copied_rows).ok() != Some(expected_rows)
        || actual_rows != expected_rows
        || copy_differs
    {
        return Err(Error::Corrupt("delivery v2 immediate row copy"));
    }
    transaction.execute_batch(&format!(
        "DROP TABLE {backup};
         {create_index};
         {run_delete_guard};
         {account_delete_guard};",
    ))?;
    Ok(())
}

/// Advances the exact Zend delivery schema from v1 to v2 without inventing spend authority for
/// legacy immediate rows.
///
/// The immediate table is rebuilt with v2's coherent active exact-evidence constraint and the
/// companion authorization table is created empty before provenance advances. Because wallet
/// migrations pass their transaction directly, any failure rolls back the table replacement, the
/// new authorization table, and the provenance CAS. The v1 authority schema is fully audited
/// first; missing or malformed objects are never repaired by replaying the full schema.
#[cfg(feature = "migration-delivery")]
pub(crate) fn upgrade_immediate_gross_authorization(
    transaction: &rusqlite::Transaction<'_>,
    t: &Tables,
) -> Result<(), Error> {
    let rows = {
        let mut stmt = transaction.prepare(&format!(
            "SELECT singleton, schema_version, implementation FROM {}",
            t.delivery_meta
        ))?;
        stmt.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?
    };
    let [(singleton, version, implementation)] = rows.as_slice() else {
        return Err(Error::Corrupt("delivery schema provenance"));
    };
    if *singleton != 1 {
        return Err(Error::Corrupt("delivery schema provenance"));
    }

    match (*version, implementation.as_str()) {
        (version, implementation)
            if version == i64::from(DELIVERY_SCHEMA_VERSION)
                && implementation == DELIVERY_SCHEMA_IMPLEMENTATION =>
        {
            return if delivery_schema_v2_integrity_matches(transaction, t)? {
                Ok(())
            } else {
                Err(Error::DeliverySchemaIncompatible)
            };
        }
        (version, implementation)
            if version == i64::from(PREVIOUS_DELIVERY_SCHEMA_VERSION)
                && implementation == PREVIOUS_DELIVERY_SCHEMA_IMPLEMENTATION =>
        {
            if sqlite_object_exists(transaction, t.immediate_gross_authorization)? {
                return Err(Error::Corrupt("delivery v1 unexpected gross authorization"));
            }
            if !delivery_lock_schema_matches(transaction)? {
                return Err(Error::Corrupt("delivery v1 lock schema"));
            }
            if !delivery_schema_shape_matches_with_authorization(transaction, t, false)? {
                return Err(Error::Corrupt("delivery v1 schema shape"));
            }
            if !delivery_run_authority_matches(transaction, t)? {
                return Err(Error::Corrupt("delivery v1 run authority"));
            }
            if !delivery_relations_are_coherent(transaction, t)? {
                return Err(Error::Corrupt("delivery v1 relations"));
            }
            if delivery_authority_has_foreign_key_violation(transaction, t, false)? {
                return Err(Error::Corrupt("delivery v1 foreign-key integrity"));
            }
            upgrade_immediate_delivery_table_v2(transaction, t)?;
            transaction
                .execute_batch(&format!("{};", immediate_gross_authorization_schema_sql(t)))?;
            let changed = transaction.execute(
                &format!(
                    "UPDATE {} SET schema_version = ?, implementation = ?
                     WHERE singleton = 1 AND schema_version = ? AND implementation = ?",
                    t.delivery_meta
                ),
                params![
                    DELIVERY_SCHEMA_VERSION,
                    DELIVERY_SCHEMA_IMPLEMENTATION,
                    PREVIOUS_DELIVERY_SCHEMA_VERSION,
                    PREVIOUS_DELIVERY_SCHEMA_IMPLEMENTATION,
                ],
            )?;
            if changed != 1 {
                return Err(Error::Corrupt("delivery schema provenance transition"));
            }
        }
        _ => return Err(Error::DeliverySchemaIncompatible),
    }

    if delivery_schema_v2_integrity_matches(transaction, t)? {
        Ok(())
    } else {
        Err(Error::DeliverySchemaIncompatible)
    }
}

/// Records immutable detection evidence for every retired standalone-engine SQLite object. The old
/// tables remain untouched and authoritative for an explicitly reviewed recovery. No plan, PCZT,
/// transaction bytes, or lock reference is copied into the canonical engine or delivery schema:
/// any legacy object is incompatible provenance and blocks runtime use until recovery.
#[cfg(feature = "migration-delivery")]
pub(crate) fn quarantine_legacy_engine_state(
    conn: &Connection,
    t: &Tables,
) -> rusqlite::Result<()> {
    let mut stmt = conn.prepare(
        r"SELECT type, name, IFNULL(sql, '')
           FROM sqlite_schema
          WHERE (name GLOB 'ext_ironwood_migration_*'
              OR name GLOB 'ironwood_migration_*'
              OR name IN ('sdk_invalid_marks', 'sdk_immediate_runs'))
            AND type IN ('table', 'index', 'trigger', 'view')
          ORDER BY type, name",
    )?;
    let objects = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    for (object_type, name, schema_sql) in objects {
        // Empty retired objects are quarantined too. Their exact schema is authority/provenance
        // evidence even when no row happens to survive, and silently treating them as fresh would
        // make the cutover decision depend on deletion timing rather than the database lineage.
        let detected_rows = if object_type == "table" {
            let quoted = name.replace('"', "\"\"");
            conn.query_row(&format!("SELECT COUNT(*) FROM \"{quoted}\""), [], |row| {
                row.get::<_, u64>(0)
            })?
        } else {
            0
        };
        let mut evidence = Vec::new();
        evidence.extend_from_slice(object_type.as_bytes());
        evidence.push(0);
        evidence.extend_from_slice(name.as_bytes());
        evidence.push(0);
        evidence.extend_from_slice(schema_sql.as_bytes());
        let fingerprint = LegacySchemaFingerprint::from_schema_sql(&evidence);
        conn.execute(
            &format!(
                "INSERT OR IGNORE INTO {} (
                     source_object, object_type, schema_fingerprint, detected_rows,
                     disposition, reason
                 ) VALUES (?, ?, ?, ?, 'recovery_required', ?)",
                t.legacy_quarantine
            ),
            params![
                name,
                object_type,
                fingerprint.as_bytes(),
                detected_rows,
                "retired standalone Ironwood engine detected; explicit recovery is required"
            ],
        )?;
    }
    Ok(())
}

#[cfg(feature = "migration-delivery")]
const DELIVERY_SCHEMA_VERSION: u32 = 2;

#[cfg(feature = "migration-delivery")]
const DELIVERY_SCHEMA_IMPLEMENTATION: &str = "just-zend/librustzcash-delivery-v2";

#[cfg(feature = "migration-delivery")]
const PREVIOUS_DELIVERY_SCHEMA_VERSION: u32 = 1;

#[cfg(feature = "migration-delivery")]
const PREVIOUS_DELIVERY_SCHEMA_IMPLEMENTATION: &str = "just-zend/librustzcash-delivery-v1";

#[cfg(feature = "migration-delivery")]
const IMMEDIATE_GROSS_AUTHORIZATION_VERSION: u32 = 1;

// The v2 DDL is immutable once published. Runtime/domain constants are asserted against these
// values in tests, but changing a runtime bound must produce a v3 migration rather than silently
// changing provenance for already-installed v2 wallets.
#[cfg(feature = "migration-delivery")]
const DELIVERY_SCHEMA_V2_GROSS_AUTHORIZATION_VERSION: u32 = 1;
#[cfg(feature = "migration-delivery")]
const DELIVERY_SCHEMA_V2_MAX_MONEY: u64 = 2_100_000_000_000_000;
#[cfg(feature = "migration-delivery")]
const DELIVERY_SCHEMA_V2_MAX_IMMEDIATE_PROPOSAL_ENVELOPE: usize = 4_194_322;
#[cfg(feature = "migration-delivery")]
const DELIVERY_SCHEMA_V2_MAX_EXACT_TRANSACTION: usize = 4_194_304;
#[cfg(feature = "migration-delivery")]
const DELIVERY_SCHEMA_V2_MAX_FINALITY_ARCHIVE: usize = 16_777_216;

#[cfg(feature = "migration-delivery")]
fn sqlite_object_exists(conn: &Connection, name: &str) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name = ?)",
        params![name],
        |row| row.get(0),
    )
}

#[cfg(feature = "migration-delivery")]
fn normalized_schema_sql(sql: &str) -> String {
    // SQLite omits `IF NOT EXISTS` from stored schema SQL and is free to change insignificant
    // whitespace. Preserve every other byte's case, especially quoted CHECK literals: SQLite
    // string comparison is case-sensitive, so lowercasing the whole declaration would accept a
    // behaviorally different look-alike schema.
    sql.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replace("CREATE TABLE IF NOT EXISTS ", "CREATE TABLE ")
        .replace("CREATE TRIGGER IF NOT EXISTS ", "CREATE TRIGGER ")
        .replace("CREATE UNIQUE INDEX IF NOT EXISTS ", "CREATE UNIQUE INDEX ")
        .replace("CREATE INDEX IF NOT EXISTS ", "CREATE INDEX ")
}

#[cfg(feature = "migration-delivery")]
fn compiled_trigger_sql<'a>(batch: &'a str, name: &str) -> Option<&'a str> {
    let prefix = format!("CREATE TRIGGER IF NOT EXISTS {name} ");
    let start = batch.find(&prefix)?;
    let tail = &batch[start..];
    let end = tail.find("END;")? + "END".len();
    Some(tail[..end].trim())
}

#[cfg(feature = "migration-delivery")]
fn compiled_table_sql<'a>(batch: &'a str, name: &str) -> Option<&'a str> {
    let prefix = format!("CREATE TABLE IF NOT EXISTS {name} ");
    batch
        .split(';')
        .map(str::trim)
        .find(|statement| statement.starts_with(&prefix))
}

#[cfg(feature = "migration-delivery")]
fn compiled_index_sql<'a>(batch: &'a str, name: &str) -> Option<&'a str> {
    let unique_prefix = format!("CREATE UNIQUE INDEX IF NOT EXISTS {name} ");
    let prefix = format!("CREATE INDEX IF NOT EXISTS {name} ");
    batch
        .split(';')
        .map(str::trim)
        .find(|statement| statement.starts_with(&unique_prefix) || statement.starts_with(&prefix))
}

/// Verifies the exact current DDL, rather than accepting a collection of look-alike object names. This
/// pins column order/types/nullability/defaults, every CHECK expression, primary/unique keys, and
/// declared foreign-key targets/actions to the Rust-owned schema text used by the migration.
#[cfg(feature = "migration-delivery")]
fn delivery_schema_shape_matches(conn: &Connection, t: &Tables) -> Result<bool, Error> {
    delivery_schema_shape_matches_with_authorization(conn, t, true)
}

#[cfg(feature = "migration-delivery")]
fn delivery_schema_shape_matches_with_authorization(
    conn: &Connection,
    t: &Tables,
    require_gross_authorization_table: bool,
) -> Result<bool, Error> {
    let batch = if require_gross_authorization_table {
        delivery_control_schema_sql(t)
    } else {
        delivery_control_schema_v1_sql(t)
    };
    let mut tables = vec![
        t.delivery_meta,
        t.delivery_runs,
        t.delivery_control,
        t.delivery_reservations,
        t.delivery_claims,
        t.delivery_evidence,
        t.delivery_attempt_archive,
        t.immediate_delivery,
        t.delivery_run_archive,
        t.legacy_quarantine,
    ];
    if require_gross_authorization_table {
        tables.push(t.immediate_gross_authorization);
    }
    for table in tables {
        let prefix = format!("CREATE TABLE IF NOT EXISTS {table} ");
        let expected = batch
            .split(';')
            .map(str::trim)
            .find(|statement| statement.starts_with(&prefix))
            .ok_or(Error::Corrupt("compiled delivery schema"))?;
        let actual = conn
            .query_row(
                "SELECT type, sql FROM sqlite_schema WHERE name = ?",
                params![table],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
            )
            .optional()?;
        let Some((object_type, Some(actual))) = actual else {
            return Ok(false);
        };
        if object_type != "table"
            || normalized_schema_sql(&actual) != normalized_schema_sql(expected)
        {
            return Ok(false);
        }
    }

    for trigger in [t.delivery_run_delete_guard, t.delivery_account_delete_guard] {
        let expected_trigger = compiled_trigger_sql(&batch, trigger)
            .ok_or(Error::Corrupt("compiled delivery delete guard"))?;
        let actual_trigger = conn
            .query_row(
                "SELECT type, sql FROM sqlite_schema WHERE name = ?",
                params![trigger],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
            )
            .optional()?;
        let Some((object_type, Some(actual_trigger))) = actual_trigger else {
            return Ok(false);
        };
        if object_type != "trigger"
            || normalized_schema_sql(&actual_trigger) != normalized_schema_sql(expected_trigger)
        {
            return Ok(false);
        }
    }
    for (index, prefix) in [
        (
            t.delivery_active_lane_index,
            "CREATE UNIQUE INDEX IF NOT EXISTS",
        ),
        (
            t.delivery_active_source_index,
            "CREATE UNIQUE INDEX IF NOT EXISTS",
        ),
        (t.delivery_claim_lease_index, "CREATE INDEX IF NOT EXISTS"),
        (
            t.delivery_reservation_status_index,
            "CREATE INDEX IF NOT EXISTS",
        ),
        (t.immediate_lease_index, "CREATE INDEX IF NOT EXISTS"),
    ] {
        let expected_prefix = format!("{prefix} {index} ");
        let expected = batch
            .split(';')
            .map(str::trim)
            .find(|statement| statement.starts_with(&expected_prefix))
            .ok_or(Error::Corrupt("compiled delivery index"))?;
        let actual = conn
            .query_row(
                "SELECT type, sql FROM sqlite_schema WHERE name = ?",
                params![index],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
            )
            .optional()?;
        let Some((object_type, Some(actual))) = actual else {
            return Ok(false);
        };
        if object_type != "index"
            || normalized_schema_sql(&actual) != normalized_schema_sql(expected)
        {
            return Ok(false);
        }
    }

    let mut unique_keys = vec![
        (t.delivery_runs, &["run_identity"][..]),
        (t.delivery_control, &["run_identity"][..]),
        (
            t.delivery_reservations,
            &["run_identity", "source_txid", "source_index"][..],
        ),
        (t.delivery_claims, &["migration_id", "tx_id"][..]),
        (t.delivery_evidence, &["run_identity", "tx_id"][..]),
        (
            t.delivery_attempt_archive,
            &["run_identity", "tx_id", "transaction_fingerprint"][..],
        ),
        (t.immediate_delivery, &["run_identity"][..]),
        (t.delivery_run_archive, &["run_identity"][..]),
        (
            t.legacy_quarantine,
            &["source_object", "schema_fingerprint"][..],
        ),
    ];
    if require_gross_authorization_table {
        unique_keys.push((t.immediate_gross_authorization, &["run_identity"][..]));
    }
    for (table, columns) in unique_keys {
        if !has_unique_index(conn, table, columns)? {
            return Ok(false);
        }
    }
    if !has_unique_index(conn, t.immediate_delivery, &["artifact_identity"])? {
        return Ok(false);
    }
    if !has_unique_index(conn, t.delivery_runs, &["account_id"])? {
        return Ok(false);
    }
    if !has_unique_index(
        conn,
        t.delivery_reservations,
        &["source_txid", "source_index"],
    )? {
        return Ok(false);
    }
    Ok(true)
}

#[cfg(feature = "migration-delivery")]
fn has_unique_index(conn: &Connection, table: &str, columns: &[&str]) -> Result<bool, Error> {
    let quoted_table = table.replace('"', "\"\"");
    let mut indexes = conn.prepare(&format!("PRAGMA index_list(\"{quoted_table}\")"))?;
    let indexes = indexes
        .query_map([], |row| {
            Ok((row.get::<_, String>(1)?, row.get::<_, bool>(2)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    for (name, unique) in indexes {
        if !unique {
            continue;
        }
        let quoted_name = name.replace('"', "\"\"");
        let mut info = conn.prepare(&format!("PRAGMA index_info(\"{quoted_name}\")"))?;
        let indexed = info
            .query_map([], |row| row.get::<_, String>(2))?
            .collect::<Result<Vec<_>, _>>()?;
        if indexed
            .iter()
            .map(String::as_str)
            .eq(columns.iter().copied())
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Delivery authority relies on the canonical note-locking migration, not only on the additive
/// delivery tables. Pin the nullable storage contract for every wallet input table so a database
/// with delivery DDL but without its lock prerequisites is never reported as compatible.
#[cfg(feature = "migration-delivery")]
fn delivery_lock_schema_matches(conn: &Connection) -> Result<bool, Error> {
    for table in [
        "sapling_received_notes",
        "orchard_received_notes",
        "ironwood_received_notes",
        "transparent_received_outputs",
    ] {
        let quoted_table = table.replace('"', "\"\"");
        let mut columns = conn.prepare(&format!("PRAGMA table_info(\"{quoted_table}\")"))?;
        let columns = columns
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, bool>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, bool>(5)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        for (required_name, required_type) in
            [("lock_expiry_height", "INTEGER"), ("lock_owner", "BLOB")]
        {
            if !columns
                .iter()
                .any(|(name, ty, not_null, default, primary_key)| {
                    name == required_name
                        && ty.eq_ignore_ascii_case(required_type)
                        && !not_null
                        && default.is_none()
                        && !primary_key
                })
            {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

#[cfg(feature = "migration-delivery")]
fn delivery_run_authority_matches(conn: &Connection, t: &Tables) -> Result<bool, Error> {
    let mut rows = conn.prepare(&format!(
        "SELECT run_identity, account_id, lane, canonical_migration_id, source_owner,
                canonical_lock_owner, authority_fingerprint
           FROM {} ORDER BY run_identity",
        t.delivery_runs
    ))?;
    let rows = rows
        .query_map([], |row| {
            Ok((
                row.get::<_, [u8; 32]>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<i64>>(3)?,
                row.get::<_, [u8; 32]>(4)?,
                row.get::<_, Option<[u8; 32]>>(5)?,
                row.get::<_, [u8; 32]>(6)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    for (run, account, lane, canonical, source_owner, lock_owner, stored) in rows {
        let expected = delivery_run_authority_fingerprint(
            &run,
            account,
            &lane,
            canonical,
            &source_owner,
            lock_owner.as_ref(),
        )?;
        if stored != expected {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(feature = "migration-delivery")]
fn resolvable_canonical_source_bindings(
    conn: &Connection,
    account_id: AccountRef,
    canonical: &MigrationState,
) -> Result<Vec<(OutputRef, MigrationTxId)>, Error> {
    let mut outputs = BTreeSet::new();
    let mut bindings = Vec::new();
    for transaction in canonical.transactions() {
        let pczt =
            pczt::Pczt::parse(transaction.pczt()).map_err(|_| Error::DeliveryArtifactMismatch)?;
        let mut matched = 0usize;
        for action in pczt.orchard().actions() {
            let matches = {
                let mut stmt = conn.prepare(
                    "SELECT rn.account_id, source.txid, rn.action_index
                       FROM orchard_received_notes rn
                       JOIN transactions source ON source.id_tx = rn.transaction_id
                      WHERE rn.nf = ? ORDER BY rn.id",
                )?;
                stmt.query_map(params![action.spend().nullifier()], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, [u8; 32]>(1)?,
                        row.get::<_, u32>(2)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?
            };
            match matches.as_slice() {
                [] => {}
                [(owner_account, txid, index)] if *owner_account == account_id.0 => {
                    matched += 1;
                    let output = OutputRef::new(
                        TxId::from_bytes(*txid),
                        PoolType::Shielded(ShieldedPool::Orchard),
                        *index,
                    );
                    if !outputs.insert(output) {
                        return Err(Error::DeliveryArtifactMismatch);
                    }
                    bindings.push((output, transaction.id()));
                }
                [_] => {
                    return Err(Error::OutputNotOwned(OutputRef::new(
                        TxId::from_bytes(matches[0].1),
                        PoolType::Shielded(ShieldedPool::Orchard),
                        matches[0].2,
                    )));
                }
                _ => return Err(Error::Corrupt("duplicate Orchard nullifier ownership")),
            }
        }
        let expected_root_inputs =
            transaction
                .kind()
                .transfer_crossing()
                .map(|_| 1)
                .or_else(|| {
                    transaction
                        .kind()
                        .preparation_indices()
                        .and_then(|(layer, index)| {
                            canonical.preparation().layers().get(layer)?.get(index)
                        })
                        .map(|preparation| preparation.inputs().len())
                });
        if transaction.depends_on().is_empty()
            && expected_root_inputs.is_none_or(|expected| expected != matched)
        {
            return Err(Error::DeliveryArtifactMismatch);
        }
    }
    bindings.sort_by_key(|(output, _)| *output);
    Ok(bindings)
}

#[cfg(feature = "migration-delivery")]
fn resolvable_canonical_sources(
    conn: &Connection,
    account_id: AccountRef,
    canonical: &MigrationState,
) -> Result<Vec<OutputRef>, Error> {
    resolvable_canonical_source_bindings(conn, account_id, canonical)
        .map(|bindings| bindings.into_iter().map(|(output, _)| output).collect())
}

/// Proves that the typed reservation set for every live scheduled run is exactly the set of
/// currently resolvable wallet-owned Orchard sources in its canonical PCZTs. This is intentionally
/// part of schema provenance: ordinary selection must fail closed if one reservation was deleted,
/// an unrelated/wrong-account source was inserted, or the canonical advisory lock owner drifted.
#[cfg(feature = "migration-delivery")]
fn scheduled_reservations_are_complete(conn: &Connection, t: &Tables) -> Result<bool, Error> {
    let mut runs = conn.prepare(&format!(
        "SELECT run_identity, account_id, canonical_migration_id,
                canonical_lock_owner, status
           FROM {} WHERE lane = 'canonical'
             AND status IN ('active', 'recovery_required')
          ORDER BY run_identity",
        t.delivery_runs
    ))?;
    let runs = runs
        .query_map([], |row| {
            Ok((
                row.get::<_, [u8; 32]>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Option<i64>>(2)?,
                row.get::<_, Option<[u8; 32]>>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    for (run_identity, account_id, migration_id, canonical_owner, run_status) in runs {
        let Some(migration_id) = migration_id else {
            return Ok(false);
        };
        let Some(canonical_owner) = canonical_owner else {
            return Ok(false);
        };
        if resolve_migration_id(conn, t, AccountRef(account_id))? != Some(migration_id) {
            return Ok(false);
        }
        let Some(canonical) = read_migration(conn, t, AccountRef(account_id))? else {
            return Ok(false);
        };

        // Reuse the canonical source resolver so provenance applies the same per-transaction
        // root-input cardinality proof as rollover/rebuild. An unmatched nullifier is only
        // admissible for a dependent transaction (whose source is another migration artifact) or
        // for protocol padding; every root transaction must resolve exactly its engine-declared
        // wallet input count. This prevents deleting a wallet note and its reservation together
        // from shrinking both sides of the comparison into a false match.
        let canonical_sources =
            match resolvable_canonical_source_bindings(conn, AccountRef(account_id), &canonical) {
                Ok(sources) => sources,
                Err(Error::Db(error)) => return Err(Error::Db(error)),
                Err(_) => return Ok(false),
            };
        if canonical_sources.is_empty() {
            return Ok(false);
        }
        let mut expected = BTreeSet::new();
        let claims = read_delivery_claims(conn, t, migration_id)?;
        for (output, transaction_id) in canonical_sources {
            let (lock_owner, all_spenders) = {
                let mut stmt = conn.prepare(
                    "SELECT rn.lock_owner, spender.txid
                       FROM orchard_received_notes rn
                       JOIN transactions source ON source.id_tx = rn.transaction_id
                       LEFT JOIN orchard_received_note_spends spends
                         ON spends.orchard_received_note_id = rn.id
                       LEFT JOIN transactions spender ON spender.id_tx = spends.transaction_id
                      WHERE source.txid = ? AND rn.action_index = ?
                      ORDER BY spender.id_tx",
                )?;
                let rows = stmt
                    .query_map(
                        params![output.txid().as_ref(), output.output_index()],
                        |row| {
                            Ok((
                                row.get::<_, Option<[u8; 32]>>(0)?,
                                row.get::<_, Option<[u8; 32]>>(1)?,
                            ))
                        },
                    )?
                    .collect::<Result<Vec<_>, _>>()?;
                let Some((lock_owner, _)) = rows.first() else {
                    return Ok(false);
                };
                (
                    *lock_owner,
                    rows.into_iter()
                        .filter_map(|(_, txid)| txid.map(TxId::from_bytes))
                        .collect::<Vec<_>>(),
                )
            };
            if run_status == "active" && lock_owner.is_some_and(|owner| owner != canonical_owner) {
                return Ok(false);
            }

            let exact_txid = claims
                .iter()
                .find(|claim| claim.transaction_id() == transaction_id)
                .and_then(DeliveryClaim::exact_transaction)
                .map(ExactTransaction::txid);
            let active_spenders = if all_spenders.is_empty() {
                Vec::new()
            } else {
                let target_height = canonical_wallet_target_height(conn)?;
                let mut stmt = conn.prepare(&format!(
                    "SELECT spender.txid
                       FROM orchard_received_notes rn
                       JOIN transactions source ON source.id_tx = rn.transaction_id
                       JOIN orchard_received_note_spends spends
                         ON spends.orchard_received_note_id = rn.id
                       JOIN transactions spender ON spender.id_tx = spends.transaction_id
                      WHERE source.txid = :source_txid AND rn.action_index = :source_index
                        AND ({})
                      ORDER BY spender.id_tx",
                    crate::wallet::common::tx_unexpired_condition("spender")
                ))?;
                stmt.query_map(
                    named_params! {
                        ":source_txid": output.txid().as_ref(),
                        ":source_index": output.output_index(),
                        ":target_height": u32::from(target_height),
                    },
                    |row| row.get::<_, [u8; 32]>(0).map(TxId::from_bytes),
                )?
                .collect::<Result<Vec<_>, _>>()?
            };
            if !active_spenders.is_empty()
                && exact_txid.is_none_or(|expected| {
                    active_spenders.iter().any(|spender| *spender != expected)
                })
            {
                return Ok(false);
            }
            if run_status == "active"
                && lock_owner != Some(canonical_owner)
                && exact_txid.is_none_or(|expected| !all_spenders.contains(&expected))
            {
                // Wallet transaction ingestion legitimately clears the advisory lock. The durable
                // reservation stays coherent only when the source-to-spender relation names the
                // exact transaction bytes already retained by this run.
                return Ok(false);
            }
            expected.insert((*output.txid().as_ref(), output.output_index()));
        }

        let reservations = {
            let mut stmt = conn.prepare(&format!(
                "SELECT source_txid, source_index, status FROM {}
                  WHERE run_identity = ? ORDER BY source_txid, source_index",
                t.delivery_reservations
            ))?;
            stmt.query_map(params![run_identity], |row| {
                Ok((
                    row.get::<_, [u8; 32]>(0)?,
                    row.get::<_, u32>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?
        };
        if reservations
            .iter()
            .any(|(_, _, status)| !matches!(status.as_str(), "active" | "recovery_required"))
        {
            return Ok(false);
        }
        let actual = reservations
            .into_iter()
            .map(|(txid, index, _)| (txid, index))
            .collect::<BTreeSet<_>>();
        if actual != expected {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(feature = "migration-delivery")]
fn delivery_relations_are_coherent(conn: &Connection, t: &Tables) -> Result<bool, Error> {
    let invalid: bool = conn.query_row(
        &format!(
            "SELECT EXISTS(
                 SELECT 1
                   FROM {} control
                   LEFT JOIN {} runs ON runs.run_identity = control.run_identity
                   LEFT JOIN {} canonical ON canonical.id = control.migration_id
                  WHERE runs.run_identity IS NULL OR canonical.id IS NULL
                     OR runs.lane != 'canonical'
                     OR runs.canonical_migration_id != control.migration_id
                     OR runs.source_owner IS NULL
                     OR runs.account_id != canonical.account_id
                     OR EXISTS(
                         SELECT 1 FROM {} transactions
                          WHERE transactions.migration_id = control.migration_id
                            AND transactions.lock_owner IS NOT NULL
                            AND transactions.lock_owner != runs.canonical_lock_owner
                     )
                 UNION ALL
                 SELECT 1 FROM {} reservations
                   LEFT JOIN {} runs ON runs.run_identity = reservations.run_identity
                  WHERE runs.run_identity IS NULL
                 UNION ALL
                 SELECT 1 FROM {} claims
                   LEFT JOIN {} control ON control.migration_id = claims.migration_id
                  WHERE control.migration_id IS NULL
                 UNION ALL
                 SELECT 1 FROM {} evidence
                   LEFT JOIN {} runs ON runs.run_identity = evidence.run_identity
                  WHERE runs.run_identity IS NULL OR runs.lane != 'canonical'
                 UNION ALL
                 SELECT 1 FROM {} attempts
                   LEFT JOIN {} runs ON runs.run_identity = attempts.run_identity
                  WHERE runs.run_identity IS NULL OR runs.lane != 'canonical'
                 UNION ALL
                 SELECT 1 FROM {} immediate
                   LEFT JOIN {} runs ON runs.run_identity = immediate.run_identity
                  WHERE runs.run_identity IS NULL OR runs.lane != 'immediate'
                     OR NOT EXISTS(
                         SELECT 1 FROM {} reservations
                          WHERE reservations.run_identity = immediate.run_identity
                     )
                 UNION ALL
                 SELECT 1 FROM {} archive
                   LEFT JOIN {} runs ON runs.run_identity = archive.run_identity
                  WHERE runs.run_identity IS NULL OR runs.lane != 'canonical'
                 UNION ALL
                 SELECT 1 FROM {} runs
                   LEFT JOIN {} control ON control.run_identity = runs.run_identity
                   LEFT JOIN {} archive ON archive.run_identity = runs.run_identity
                   LEFT JOIN {} immediate ON immediate.run_identity = runs.run_identity
                   LEFT JOIN {} canonical ON canonical.id = runs.canonical_migration_id
                  WHERE (runs.lane = 'canonical' AND (
                            (control.run_identity IS NULL) = (archive.run_identity IS NULL)
                            OR immediate.run_identity IS NOT NULL
                            OR (runs.canonical_migration_id IS NOT NULL
                                AND canonical.id IS NULL)
                        ))
                     OR (runs.lane = 'immediate' AND (
                            control.run_identity IS NOT NULL
                            OR archive.run_identity IS NOT NULL
                            OR immediate.run_identity IS NULL
                            OR runs.canonical_migration_id IS NOT NULL
                        ))
                     OR (runs.status IN ('active', 'recovery_required') AND NOT EXISTS(
                            SELECT 1 FROM {} reservations
                             WHERE reservations.run_identity = runs.run_identity
                               AND reservations.status IN ('active', 'recovery_required')
                        ))
             )",
            t.delivery_control,
            t.delivery_runs,
            t.migrations,
            t.transactions,
            t.delivery_reservations,
            t.delivery_runs,
            t.delivery_claims,
            t.delivery_control,
            t.delivery_evidence,
            t.delivery_runs,
            t.delivery_attempt_archive,
            t.delivery_runs,
            t.immediate_delivery,
            t.delivery_runs,
            t.delivery_reservations,
            t.delivery_run_archive,
            t.delivery_runs,
            t.delivery_runs,
            t.delivery_control,
            t.delivery_run_archive,
            t.immediate_delivery,
            t.migrations,
            t.delivery_reservations,
        ),
        [],
        |row| row.get(0),
    )?;
    if invalid || !scheduled_reservations_are_complete(conn, t)? {
        return Ok(false);
    }
    let immediate_runs = {
        let mut stmt = conn.prepare(&format!(
            "SELECT run_identity FROM {} WHERE lane = 'immediate' ORDER BY run_identity",
            t.delivery_runs
        ))?;
        stmt.query_map([], |row| row.get::<_, [u8; 32]>(0))?
            .collect::<Result<Vec<_>, _>>()?
    };
    for run_identity in immediate_runs {
        let run_identity = MigrationRunIdentity::read(run_identity.as_slice())
            .map_err(|_| Error::Corrupt("immediate provenance run identity"))?;
        if !immediate_reservations_are_complete(conn, t, run_identity)? {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(feature = "migration-delivery")]
fn delivery_authority_has_foreign_key_violation(
    conn: &Connection,
    t: &Tables,
    include_gross_authorization_table: bool,
) -> Result<bool, Error> {
    let mut authority_tables = vec![
        t.delivery_runs,
        t.delivery_control,
        t.delivery_claims,
        t.delivery_reservations,
        t.delivery_evidence,
        t.delivery_attempt_archive,
        t.immediate_delivery,
        t.delivery_run_archive,
    ];
    if include_gross_authorization_table {
        authority_tables.push(t.immediate_gross_authorization);
    }
    let mut stmt = conn.prepare("PRAGMA foreign_key_check")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let table = row.get::<_, String>(0)?;
        if authority_tables.contains(&table.as_str()) {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(feature = "migration-delivery")]
fn immediate_gross_authorizations_are_coherent(
    conn: &Connection,
    t: &Tables,
) -> Result<bool, Error> {
    let rows = {
        let mut stmt = conn.prepare(&format!(
            "SELECT authorization.authorization_version,
                    authorization.maximum_gross_amount, immediate.canonical_proposal
               FROM {} authorization
               JOIN {} immediate ON immediate.run_identity = authorization.run_identity
              ORDER BY authorization.run_identity",
            t.immediate_gross_authorization, t.immediate_delivery
        ))?;
        stmt.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?
    };
    for (version, maximum, canonical_proposal) in rows {
        if version != i64::from(IMMEDIATE_GROSS_AUTHORIZATION_VERSION) {
            return Ok(false);
        }
        let Ok(maximum) = u64::try_from(maximum) else {
            return Ok(false);
        };
        let Ok(maximum) = Zatoshis::from_u64(maximum) else {
            return Ok(false);
        };
        let Ok((_, proposal_gross_amount)) = immediate_proposal_authority(&canonical_proposal)
        else {
            return Ok(false);
        };
        if proposal_gross_amount > maximum {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Performs the exact v2 structural and relational audit used inside wallet migrations, where
/// SQLite's foreign-key enforcement pragma may be temporarily disabled and cannot be changed until
/// the surrounding transaction commits. Declared foreign keys and their data integrity are still
/// checked exactly; only the connection-level enforcement state is omitted here. Runtime
/// provenance separately requires enforcement to be active.
#[cfg(feature = "migration-delivery")]
fn delivery_schema_v2_integrity_matches(conn: &Connection, t: &Tables) -> Result<bool, Error> {
    let provenance_rows = {
        let mut stmt = conn.prepare(&format!(
            "SELECT singleton, schema_version, implementation FROM {}",
            t.delivery_meta
        ))?;
        stmt.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?
    };
    let [(singleton, version, implementation)] = provenance_rows.as_slice() else {
        return Ok(false);
    };
    Ok(*singleton == 1
        && *version == i64::from(DELIVERY_SCHEMA_VERSION)
        && implementation == DELIVERY_SCHEMA_IMPLEMENTATION
        && delivery_lock_schema_matches(conn)?
        && delivery_schema_shape_matches(conn, t)?
        && delivery_run_authority_matches(conn, t)?
        && delivery_relations_are_coherent(conn, t)?
        && immediate_gross_authorizations_are_coherent(conn, t)?
        && !delivery_authority_has_foreign_key_violation(conn, t, true)?)
}

#[cfg(feature = "migration-delivery")]
pub(super) fn delivery_schema_provenance(
    conn: &Connection,
    t: &Tables,
) -> Result<DeliverySchemaProvenance, Error> {
    let foreign_keys: bool = conn.query_row("PRAGMA foreign_keys", [], |row| row.get(0))?;
    if !foreign_keys {
        return Ok(DeliverySchemaProvenance::Corrupt);
    }
    if !sqlite_object_exists(conn, t.delivery_meta)? {
        return Ok(DeliverySchemaProvenance::Unavailable);
    }
    let rows = {
        let mut stmt = conn.prepare(&format!(
            "SELECT singleton, schema_version, implementation FROM {}",
            t.delivery_meta
        ))?;
        stmt.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?
    };
    let [(singleton, version, implementation)] = rows.as_slice() else {
        return Ok(DeliverySchemaProvenance::Corrupt);
    };
    if *singleton != 1 || *version < 1 || implementation.is_empty() {
        return Ok(DeliverySchemaProvenance::Corrupt);
    }
    let Ok(version) = u32::try_from(*version) else {
        return Ok(DeliverySchemaProvenance::Corrupt);
    };
    let version = DeliverySchemaVersion::from_u32(version)
        .ok_or(Error::Corrupt("delivery schema version"))?;
    let provenance = if version.as_u32() == DELIVERY_SCHEMA_VERSION {
        if implementation == DELIVERY_SCHEMA_IMPLEMENTATION {
            DeliverySchemaProvenance::Compatible(version)
        } else {
            DeliverySchemaProvenance::Corrupt
        }
    } else if version.as_u32() > DELIVERY_SCHEMA_VERSION {
        DeliverySchemaProvenance::Future(version)
    } else {
        DeliverySchemaProvenance::Corrupt
    };
    if !matches!(provenance, DeliverySchemaProvenance::Compatible(_)) {
        return Ok(provenance);
    }
    if !delivery_lock_schema_matches(conn)?
        || !delivery_schema_shape_matches(conn, t)?
        || !delivery_run_authority_matches(conn, t)?
        || !delivery_relations_are_coherent(conn, t)?
        || !immediate_gross_authorizations_are_coherent(conn, t)?
    {
        return Ok(DeliverySchemaProvenance::Corrupt);
    }
    let foreign_key_violation = delivery_authority_has_foreign_key_violation(conn, t, true)?;
    Ok(if foreign_key_violation {
        DeliverySchemaProvenance::Corrupt
    } else {
        provenance
    })
}

#[cfg(feature = "migration-delivery")]
fn legacy_cutover_status(conn: &Connection, t: &Tables) -> Result<LegacyCutoverStatus, Error> {
    let signals: u64 = if sqlite_object_exists(conn, t.legacy_quarantine)? {
        conn.query_row(
            &format!(
                r"SELECT COUNT(*) FROM (
                     SELECT name AS source_object FROM sqlite_schema
                      WHERE name GLOB 'ext_ironwood_migration_*'
                         OR name GLOB 'ironwood_migration_*'
                         OR name IN ('sdk_invalid_marks', 'sdk_immediate_runs')
                     UNION
                     SELECT source_object FROM {}
                 )",
                t.legacy_quarantine
            ),
            [],
            |row| row.get(0),
        )?
    } else {
        conn.query_row(
            r"SELECT COUNT(*) FROM sqlite_schema
              WHERE name GLOB 'ext_ironwood_migration_*'
                 OR name GLOB 'ironwood_migration_*'
                 OR name IN ('sdk_invalid_marks', 'sdk_immediate_runs')",
            [],
            |row| row.get(0),
        )?
    };
    if signals == 0 {
        Ok(LegacyCutoverStatus::Fresh)
    } else {
        let count = u32::try_from(signals).unwrap_or(u32::MAX);
        Ok(LegacyCutoverStatus::RecoveryRequired(
            LegacySchemaObjectCount::new(
                NonZeroU32::new(count).expect("the nonzero legacy-object count remains nonzero"),
            ),
        ))
    }
}

#[cfg(feature = "migration-delivery")]
#[derive(Clone)]
struct StoredDeliveryControl {
    migration_id: i64,
    run_identity: MigrationRunIdentity,
    source_reservation_owner: SourceReservationOwner,
    canonical_lock_owner: LockOwner,
    revision: DeliveryRevision,
    state_fingerprint: MigrationStateFingerprint,
    phase: DeliveryPhase,
    storage_finality: StorageFinality,
    release_at_height: Option<BlockHeight>,
    finalized_tip_height: Option<BlockHeight>,
    policy: Option<SubmissionPolicy>,
    policy_validation_failure: Option<PolicyValidationFailure>,
}

#[cfg(feature = "migration-delivery")]
fn delivery_control_exists(
    conn: &Connection,
    t: &Tables,
    migration_id: i64,
) -> Result<bool, Error> {
    conn.query_row(
        &format!(
            "SELECT EXISTS(SELECT 1 FROM {} WHERE migration_id = ?)",
            t.delivery_control
        ),
        params![migration_id],
        |row| row.get(0),
    )
    .map_err(Error::Db)
}

#[cfg(feature = "migration-delivery")]
fn read_delivery_control(
    conn: &Connection,
    t: &Tables,
    migration_id: i64,
    submission_context: Option<SubmissionContext>,
) -> Result<Option<StoredDeliveryControl>, Error> {
    let row = conn
        .query_row(
            &format!(
                "SELECT control.run_identity, runs.source_owner, runs.canonical_lock_owner,
                        control.revision, control.state_fingerprint, control.phase,
                        control.storage_finality, control.storage_recovery_reason,
                        control.release_at_height, control.finalized_tip_height, control.policy,
                        control.policy_fingerprint, control.policy_validation_failure,
                        runs.lane, runs.canonical_migration_id, runs.account_id,
                        canonical.account_id
                   FROM {} control
                   JOIN {} runs ON runs.run_identity = control.run_identity
                   JOIN {} canonical ON canonical.id = control.migration_id
                  WHERE control.migration_id = ?",
                t.delivery_control, t.delivery_runs, t.migrations
            ),
            params![migration_id],
            |row| {
                Ok((
                    row.get::<_, [u8; 32]>(0)?,
                    row.get::<_, [u8; 32]>(1)?,
                    row.get::<_, Option<[u8; 32]>>(2)?,
                    row.get::<_, u64>(3)?,
                    row.get::<_, [u8; 32]>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<u32>>(8)?,
                    row.get::<_, Option<u32>>(9)?,
                    row.get::<_, Option<Vec<u8>>>(10)?,
                    row.get::<_, Option<[u8; 32]>>(11)?,
                    row.get::<_, Option<String>>(12)?,
                    row.get::<_, String>(13)?,
                    row.get::<_, Option<i64>>(14)?,
                    row.get::<_, i64>(15)?,
                    row.get::<_, i64>(16)?,
                ))
            },
        )
        .optional()?;
    let Some((
        run,
        source_owner,
        canonical_lock_owner,
        revision,
        fingerprint,
        phase,
        storage_finality,
        storage_recovery_reason,
        release_at_height,
        finalized_tip_height,
        policy,
        policy_fingerprint,
        failure,
        lane,
        run_migration_id,
        run_account_id,
        canonical_account_id,
    )) = row
    else {
        return Ok(None);
    };
    if lane != "canonical"
        || run_migration_id != Some(migration_id)
        || run_account_id != canonical_account_id
    {
        return Err(Error::Corrupt("delivery run authority"));
    }
    let canonical_lock_owner = canonical_lock_owner
        .map(LockOwner::new)
        .ok_or(Error::Corrupt("canonical delivery lock owner"))?;
    let phase = DeliveryPhase::from_stored(&phase).ok_or(Error::Corrupt("delivery phase"))?;
    let release_at_height = release_at_height.map(BlockHeight::from_u32);
    let finalized_tip_height = finalized_tip_height.map(BlockHeight::from_u32);
    let recovery_reason = match storage_recovery_reason.as_deref() {
        None => None,
        Some("transfer_evidence_lost") => Some(StorageRecoveryReason::TransferEvidenceLost),
        Some("rewound_beyond_finality_horizon") => {
            Some(StorageRecoveryReason::RewoundBeyondFinalityHorizon)
        }
        Some("corrupt_finality_evidence") => Some(StorageRecoveryReason::CorruptFinalityEvidence),
        Some("external_signing_exposure_unresolved") => {
            Some(StorageRecoveryReason::ExternalSigningExposureUnresolved)
        }
        Some(_) => return Err(Error::Corrupt("delivery storage recovery reason")),
    };
    let storage_finality = match storage_finality.as_str() {
        "active" if release_at_height.is_none() && finalized_tip_height.is_none() => {
            StorageFinality::Active
        }
        "complete_pending_finality" if finalized_tip_height.is_none() => {
            StorageFinality::CompletePendingFinality(ReservationRelease::at(
                release_at_height.ok_or(Error::Corrupt("delivery release height"))?,
            ))
        }
        "finalized" if finalized_tip_height.is_some() => {
            StorageFinality::Finalized(ReservationRelease::at(
                release_at_height.ok_or(Error::Corrupt("delivery release height"))?,
            ))
        }
        "recovery_required" => StorageFinality::RecoveryRequired(
            recovery_reason.ok_or(Error::Corrupt("delivery storage recovery reason"))?,
        ),
        _ => return Err(Error::Corrupt("delivery storage finality")),
    };
    let policy = match (policy, policy_fingerprint) {
        (None, None) => None,
        (Some(bytes), Some(fingerprint)) => {
            let context = submission_context.ok_or(Error::DeliveryContextUnavailable)?;
            let fingerprint = PolicyFingerprint::read(fingerprint.as_slice())
                .map_err(|_| Error::Corrupt("delivery policy fingerprint"))?;
            Some(
                SubmissionPolicy::decode(bytes, fingerprint, context)
                    .map_err(|_| Error::Corrupt("delivery policy binding"))?,
            )
        }
        _ => return Err(Error::Corrupt("delivery policy binding")),
    };
    let failure = match failure.as_deref() {
        Some(value) => Some(
            PolicyValidationFailure::from_stored(value)
                .ok_or(Error::Corrupt("policy validation failure"))?,
        ),
        None => None,
    };
    Ok(Some(StoredDeliveryControl {
        migration_id,
        run_identity: MigrationRunIdentity::read(run.as_slice())
            .map_err(|_| Error::Corrupt("delivery run identity"))?,
        source_reservation_owner: SourceReservationOwner::read(source_owner.as_slice())
            .map_err(|_| Error::Corrupt("delivery source owner"))?,
        canonical_lock_owner,
        revision: DeliveryRevision::read(revision.to_le_bytes().as_slice())
            .map_err(|_| Error::Corrupt("delivery revision"))?,
        state_fingerprint: MigrationStateFingerprint::read(fingerprint.as_slice())
            .map_err(|_| Error::Corrupt("delivery state fingerprint"))?,
        phase,
        storage_finality,
        release_at_height,
        finalized_tip_height,
        policy,
        policy_validation_failure: failure,
    }))
}

#[cfg(feature = "migration-delivery")]
fn canonical_lock_owner(state: &MigrationState) -> Result<Option<LockOwner>, Error> {
    let owners = state
        .transactions()
        .iter()
        .filter_map(|transaction| transaction.lock_owner())
        .collect::<BTreeSet<_>>();
    if owners.is_empty() {
        return Ok(None);
    }
    if owners.len() != 1
        || state
            .transactions()
            .iter()
            .any(|transaction| transaction.lock_owner().is_none())
    {
        return Err(Error::DeliveryRunUnavailable);
    }
    Ok(owners.iter().next().copied().map(LockOwner::new))
}

#[cfg(feature = "migration-delivery")]
fn read_delivery_claims(
    conn: &Connection,
    t: &Tables,
    migration_id: i64,
) -> Result<Vec<DeliveryClaim>, Error> {
    let account_id = conn.query_row(
        &format!("SELECT account_id FROM {} WHERE id = ?", t.migrations),
        params![migration_id],
        |row| row.get::<_, i64>(0).map(AccountRef),
    )?;
    let canonical_state = read_migration(conn, t, account_id)?
        .ok_or(Error::Corrupt("delivery canonical migration"))?;
    let mut stmt = conn.prepare(&format!(
        "SELECT claims.tx_id, claims.pczt_digest, claims.transaction_fingerprint,
                claims.status, claims.signer_ownership, claims.claim_kind,
                claims.attempt_token, claims.lease_clock_session,
                claims.lease_acquired_at_ms, claims.lease_expires_at_ms,
                claims.txid, claims.exact_tx,
                claims.external_signing_pczt_digest,
                claims.canonical_external_signing_pczt,
                claims.signed_pczt_digest, claims.canonical_signed_pczt,
                claims.signed_pczt_binding,
                claims.policy_fingerprint, claims.last_error
           FROM {} claims
          WHERE claims.migration_id = ?
          ORDER BY claims.tx_id",
        t.delivery_claims
    ))?;
    let rows = stmt.query_map(params![migration_id], |row| {
        Ok((
            row.get::<_, u32>(0)?,
            row.get::<_, [u8; 32]>(1)?,
            row.get::<_, [u8; 32]>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, Option<String>>(5)?,
            row.get::<_, Option<[u8; 32]>>(6)?,
            row.get::<_, Option<[u8; 32]>>(7)?,
            row.get::<_, Option<u64>>(8)?,
            row.get::<_, Option<u64>>(9)?,
            row.get::<_, Option<[u8; 32]>>(10)?,
            row.get::<_, Option<Vec<u8>>>(11)?,
            row.get::<_, Option<[u8; 32]>>(12)?,
            row.get::<_, Option<Vec<u8>>>(13)?,
            row.get::<_, Option<[u8; 32]>>(14)?,
            row.get::<_, Option<Vec<u8>>>(15)?,
            row.get::<_, Option<[u8; 32]>>(16)?,
            row.get::<_, [u8; 32]>(17)?,
            row.get::<_, Option<String>>(18)?,
        ))
    })?;
    let mut claims = Vec::new();
    for row in rows {
        let (
            id,
            digest,
            tx_fingerprint,
            status,
            signer_ownership,
            kind,
            token,
            lease_session,
            lease_acquired,
            lease_expires,
            txid,
            exact_tx,
            external_pczt_digest,
            external_pczt,
            signed_pczt_digest,
            signed_pczt,
            signed_pczt_binding,
            policy,
            error,
        ) = row?;
        let status = ClaimStatus::from_stored(&status).ok_or(Error::Corrupt("claim status"))?;
        let kind = match kind.as_deref() {
            Some(value) => Some(ClaimKind::from_stored(value).ok_or(Error::Corrupt("claim kind"))?),
            None => None,
        };
        let lease = match (kind, token, lease_session, lease_acquired, lease_expires) {
            (None, None, None, None, None) => None,
            (Some(kind), Some(token), Some(session), Some(acquired), Some(expires)) => {
                let token = ClaimToken::read(token.as_slice())
                    .map_err(|_| Error::Corrupt("claim token"))?;
                let session = LeaseClockSession::read(session.as_slice())
                    .map_err(|_| Error::Corrupt("claim clock session"))?;
                Some(
                    DeliveryLease::from_parts(
                        kind,
                        token,
                        MonotonicLeaseInstant::new(session, acquired),
                        MonotonicLeaseInstant::new(session, expires),
                    )
                    .map_err(|_| Error::Corrupt("claim lease tuple"))?,
                )
            }
            _ => return Err(Error::Corrupt("claim lease tuple")),
        };
        let signer_ownership = match signer_ownership.as_str() {
            "sdk" => SignerOwnership::Sdk,
            "external" => SignerOwnership::External,
            _ => return Err(Error::Corrupt("claim signer ownership")),
        };
        let error = match error.as_deref() {
            Some(value) => Some(
                DeliveryFailureReason::from_stored(value)
                    .ok_or(Error::Corrupt("delivery failure reason"))?,
            ),
            None => None,
        };
        let transaction_id = MigrationTxId::new(id);
        let evidence = scheduled_artifact_evidence(&canonical_state, transaction_id)
            .ok_or(Error::Corrupt("claim canonical evidence"))?;
        let stored_digest =
            PcztDigest::read(digest.as_slice()).map_err(|_| Error::Corrupt("claim PCZT digest"))?;
        let stored_fingerprint = MigrationTransactionFingerprint::read(tx_fingerprint.as_slice())
            .map_err(|_| Error::Corrupt("claim transaction fingerprint"))?;
        if evidence.pczt_digest() != stored_digest
            || evidence.transaction_fingerprint() != stored_fingerprint
        {
            return Err(Error::DeliveryArtifactMismatch);
        }
        let evidence = DeliveryArtifactEvidence::Scheduled(evidence);
        let external_signing_pczt = match (external_pczt_digest, external_pczt) {
            (None, None) => None,
            (Some(digest), Some(bytes)) => {
                let staged = ExternalSigningPczt::parse(bytes)
                    .map_err(|_| Error::Corrupt("claim external-signing PCZT"))?;
                let stored = PcztDigest::read(digest.as_slice())
                    .map_err(|_| Error::Corrupt("claim external-signing PCZT digest"))?;
                if staged.digest() != stored {
                    return Err(Error::DeliveryArtifactMismatch);
                }
                Some(staged)
            }
            _ => return Err(Error::Corrupt("claim external-signing PCZT tuple")),
        };
        let signed_pczt = match (signed_pczt_digest, signed_pczt, signed_pczt_binding) {
            (None, None, None) => None,
            (Some(digest), Some(bytes), Some(binding)) => {
                let staged = external_signing_pczt
                    .as_ref()
                    .ok_or(Error::Corrupt("claim signed PCZT without staged PCZT"))?;
                let signed = SignedPcztEvidence::decode(staged, bytes)
                    .map_err(|_| Error::Corrupt("claim signed PCZT"))?;
                let stored_digest = PcztDigest::read(digest.as_slice())
                    .map_err(|_| Error::Corrupt("claim signed PCZT digest"))?;
                let stored_binding = PcztDigest::read(binding.as_slice())
                    .map_err(|_| Error::Corrupt("claim signed PCZT binding"))?;
                if signed.signed_digest() != stored_digest
                    || signed.staged_digest() != stored_binding
                {
                    return Err(Error::DeliveryArtifactMismatch);
                }
                Some(signed)
            }
            _ => return Err(Error::Corrupt("claim signed PCZT tuple")),
        };
        let exact_transaction = match (txid, exact_tx) {
            (None, None) => None,
            (Some(txid), Some(bytes)) => {
                let exact = exact_transaction(&canonical_state, transaction_id)
                    .map_err(|_| Error::DeliveryArtifactMismatch)?;
                if exact.txid().as_ref() != txid.as_slice() || exact.bytes() != bytes {
                    return Err(Error::DeliveryArtifactMismatch);
                }
                Some(exact)
            }
            _ => return Err(Error::Corrupt("claim exact transaction tuple")),
        };
        let policy = PolicyFingerprint::read(policy.as_slice())
            .map_err(|_| Error::Corrupt("claim policy fingerprint"))?;
        claims.push(
            DeliveryClaim::from_parts(
                evidence,
                signer_ownership,
                status,
                lease,
                external_signing_pczt,
                signed_pczt,
                exact_transaction,
                policy,
                error,
            )
            .map_err(|_| Error::Corrupt("claim semantic invariants"))?,
        );
    }
    Ok(claims)
}

#[cfg(feature = "migration-delivery")]
fn claim_status_is_unresolved(status: ClaimStatus) -> bool {
    matches!(
        status,
        ClaimStatus::Submitting | ClaimStatus::OutcomeUnknown | ClaimStatus::Broadcasted
    )
}

#[cfg(feature = "migration-delivery")]
trait ScheduledDeliveryClaimExt {
    fn transaction_id(&self) -> MigrationTxId;
    fn kind(&self) -> Option<ClaimKind>;
    fn exact_tx(&self) -> Option<&[u8]>;
}

#[cfg(feature = "migration-delivery")]
impl ScheduledDeliveryClaimExt for DeliveryClaim {
    fn transaction_id(&self) -> MigrationTxId {
        self.scheduled_transaction_id()
            .expect("the scheduled SQLite claim table only contains scheduled artifacts")
    }

    fn kind(&self) -> Option<ClaimKind> {
        self.claim_kind()
    }

    fn exact_tx(&self) -> Option<&[u8]> {
        self.exact_transaction().map(ExactTransaction::bytes)
    }
}

#[cfg(feature = "migration-delivery")]
fn build_delivery_snapshot(
    conn: &Connection,
    t: &Tables,
    control: StoredDeliveryControl,
) -> Result<DeliverySnapshot, Error> {
    let claims = read_delivery_claims(conn, t, control.migration_id)?;
    let account_id = conn.query_row(
        &format!("SELECT account_id FROM {} WHERE id = ?", t.migrations),
        params![control.migration_id],
        |row| row.get::<_, i64>(0).map(AccountRef),
    )?;
    let canonical = read_migration(conn, t, account_id)?
        .ok_or(Error::Corrupt("delivery canonical migration"))?;
    let finality_archive = read_finality_archive(conn, t, &control, &canonical)?;
    let active_source_reservation_count = conn.query_row(
        &format!(
            "SELECT COUNT(*) FROM {}
              WHERE run_identity = ? AND status IN ('active', 'recovery_required')",
            t.delivery_reservations
        ),
        params![control.run_identity.as_bytes()],
        |row| row.get::<_, u64>(0),
    )?;
    DeliverySnapshot::from_parts(
        control.revision,
        control.run_identity,
        DeliveryRunFingerprint::Scheduled(control.state_fingerprint),
        control.source_reservation_owner,
        control.phase,
        control.storage_finality,
        active_source_reservation_count,
        finality_archive,
        control.policy,
        control.policy_validation_failure,
        claims,
    )
    .map_err(|_| Error::Corrupt("delivery snapshot invariants"))
}

#[cfg(feature = "migration-delivery")]
fn read_finality_archive(
    conn: &Connection,
    t: &Tables,
    control: &StoredDeliveryControl,
    canonical: &MigrationState,
) -> Result<Option<FinalityArchive>, Error> {
    let release = match control.storage_finality {
        StorageFinality::Finalized(_)
        | StorageFinality::RecoveryRequired(StorageRecoveryReason::RewoundBeyondFinalityHorizon) => {
            ReservationRelease::at(
                control
                    .release_at_height
                    .ok_or(Error::Corrupt("delivery finality release height"))?,
            )
        }
        StorageFinality::NoRun
        | StorageFinality::Active
        | StorageFinality::CompletePendingFinality(_)
        | StorageFinality::RecoveryRequired(_) => return Ok(None),
    };
    scheduled_finality_archive_from_evidence(conn, t, control.run_identity, release, canonical)
}

/// Reconstructs exact finalized-transfer evidence from the immutable archive rows. The complete
/// destination tuple is checked along with the transaction bytes, preventing a syntactically
/// valid but incomplete subset from authorizing source-reservation release.
#[cfg(feature = "migration-delivery")]
fn scheduled_finality_archive_from_evidence(
    conn: &Connection,
    t: &Tables,
    run_identity: MigrationRunIdentity,
    release: ReservationRelease,
    canonical: &MigrationState,
) -> Result<Option<FinalityArchive>, Error> {
    let rows = {
        let mut stmt = conn.prepare(&format!(
            "SELECT tx_id, txid, exact_tx, destination_txid,
                    destination_output_index, expected_ironwood_amount,
                    observed_mined_height, release_at_height
               FROM {}
              WHERE run_identity = ? AND transaction_kind = 'transfer'
                AND terminal_status = 'confirmed'
              ORDER BY tx_id",
            t.delivery_evidence
        ))?;
        stmt.query_map(params![run_identity.as_bytes()], |row| {
            Ok((
                row.get::<_, u32>(0)?,
                row.get::<_, Option<[u8; 32]>>(1)?,
                row.get::<_, Option<Vec<u8>>>(2)?,
                row.get::<_, Option<[u8; 32]>>(3)?,
                row.get::<_, Option<u32>>(4)?,
                row.get::<_, Option<u64>>(5)?,
                row.get::<_, Option<u32>>(6)?,
                row.get::<_, Option<u32>>(7)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?
    };
    // Abandoned unexposed and positively resolved-unmined tombstones intentionally have no mined
    // transfer archive. DeliverySnapshot validates those two exact shapes from their retained
    // claims, phase, release horizon, and zero live-reservation count; every other finalized shape
    // still requires non-empty immutable mined evidence below.
    if rows.is_empty() {
        return Ok(None);
    }
    if canonical.status() != MigrationStatus::Complete
        || canonical_transfer_release_height(canonical)? != Some(release.release_at())
    {
        return Err(Error::Corrupt("delivery finality canonical state"));
    }
    let expected_transfer_ids = canonical
        .transactions()
        .iter()
        .filter(|transaction| matches!(transaction.kind(), MigrationTxKind::Transfer { .. }))
        .map(|transaction| u32::from(transaction.id()))
        .collect::<BTreeSet<_>>();
    let actual_transfer_ids = rows.iter().map(|(id, ..)| *id).collect::<BTreeSet<_>>();
    if rows.len() != expected_transfer_ids.len() || actual_transfer_ids != expected_transfer_ids {
        return Err(Error::Corrupt("incomplete delivery finality archive"));
    }
    let mut transfers = Vec::with_capacity(rows.len());
    for (
        id,
        txid,
        exact_bytes,
        destination_txid,
        destination_index,
        amount,
        mined_height,
        release_at_height,
    ) in rows
    {
        let (
            Some(txid),
            Some(exact_bytes),
            Some(destination_txid),
            Some(destination_index),
            Some(amount),
            Some(mined_height),
            Some(release_at_height),
        ) = (
            txid,
            exact_bytes,
            destination_txid,
            destination_index,
            amount,
            mined_height,
            release_at_height,
        )
        else {
            return Err(Error::Corrupt("incomplete delivery finality evidence"));
        };
        if destination_txid != txid
            || destination_index != 0
            || BlockHeight::from_u32(release_at_height) != release.release_at()
        {
            return Err(Error::Corrupt("delivery finality archive release"));
        }
        let id = MigrationTxId::new(id);
        let canonical_transaction = canonical
            .transactions()
            .iter()
            .find(|transaction| transaction.id() == id)
            .ok_or(Error::Corrupt("delivery finality canonical transaction"))?;
        let exact = exact_transaction(canonical, id)
            .map_err(|_| Error::Corrupt("delivery finality exact transaction"))?;
        if exact.txid().as_ref() != txid.as_slice()
            || exact.bytes() != exact_bytes
            || canonical
                .transfer_amount(canonical_transaction)
                .map(u64::from)
                != Some(amount)
            || canonical_transaction.state().mined_height()
                != Some(BlockHeight::from_u32(mined_height))
        {
            return Err(Error::Corrupt("delivery finality exact transaction"));
        }
        let evidence = scheduled_artifact_evidence(canonical, id)
            .ok_or(Error::Corrupt("delivery finality artifact identity"))?;
        transfers.push(FinalizedTransferEvidence::new(
            DeliveryArtifactIdentity::Scheduled(evidence.identity()),
            exact.txid(),
            exact.digest(),
            BlockHeight::from_u32(mined_height),
        ));
    }
    FinalityArchive::new(release, transfers)
        .map(Some)
        .map_err(|_| Error::Corrupt("delivery finality archive"))
}

#[cfg(feature = "migration-delivery")]
fn decode_storage_recovery_reason(
    value: Option<&str>,
) -> Result<Option<StorageRecoveryReason>, Error> {
    value
        .map(|value| match value {
            "transfer_evidence_lost" => Ok(StorageRecoveryReason::TransferEvidenceLost),
            "rewound_beyond_finality_horizon" => {
                Ok(StorageRecoveryReason::RewoundBeyondFinalityHorizon)
            }
            "corrupt_finality_evidence" => Ok(StorageRecoveryReason::CorruptFinalityEvidence),
            "external_signing_exposure_unresolved" => {
                Ok(StorageRecoveryReason::ExternalSigningExposureUnresolved)
            }
            _ => Err(Error::Corrupt("delivery storage recovery reason")),
        })
        .transpose()
}

#[cfg(feature = "migration-delivery")]
fn decode_storage_finality(
    value: &str,
    recovery_reason: Option<&str>,
    release_at_height: Option<u32>,
    finalized_tip_height: Option<u32>,
) -> Result<StorageFinality, Error> {
    let release = release_at_height.map(BlockHeight::from_u32);
    let finalized_tip = finalized_tip_height.map(BlockHeight::from_u32);
    match value {
        "active" if release.is_none() && finalized_tip.is_none() && recovery_reason.is_none() => {
            Ok(StorageFinality::Active)
        }
        "complete_pending_finality"
            if release.is_some() && finalized_tip.is_none() && recovery_reason.is_none() =>
        {
            Ok(StorageFinality::CompletePendingFinality(
                ReservationRelease::at(release.expect("guarded above")),
            ))
        }
        "finalized"
            if release.is_some()
                && finalized_tip.is_some_and(|tip| tip >= release.expect("guarded above"))
                && recovery_reason.is_none() =>
        {
            Ok(StorageFinality::Finalized(ReservationRelease::at(
                release.expect("guarded above"),
            )))
        }
        "recovery_required" => Ok(StorageFinality::RecoveryRequired(
            decode_storage_recovery_reason(recovery_reason)?
                .ok_or(Error::Corrupt("delivery storage recovery reason"))?,
        )),
        _ => Err(Error::Corrupt("delivery storage finality")),
    }
}

/// Reconstructs exact terminal claims for one retained scheduled predecessor. Unexposed claims
/// are intentionally absent from the immutable archive; only their absence plus an abandoned,
/// finalized tombstone can authorize generic cleanup. Every exposed claim retains the complete
/// PCZT/signature/transaction/policy evidence needed to prevent successor state from hiding it.
#[cfg(feature = "migration-delivery")]
fn read_archived_delivery_claims(
    conn: &Connection,
    t: &Tables,
    run_identity: MigrationRunIdentity,
    canonical: &MigrationState,
) -> Result<Vec<DeliveryClaim>, Error> {
    let mut stmt = conn.prepare(&format!(
        "SELECT tx_id, pczt_digest, transaction_fingerprint, canonical_pczt,
                terminal_status, signer_ownership, txid, exact_tx,
                external_signing_pczt_digest, canonical_external_signing_pczt,
                signed_pczt_digest, canonical_signed_pczt, signed_pczt_binding,
                policy_fingerprint, last_error
           FROM {} WHERE run_identity = ? ORDER BY tx_id",
        t.delivery_evidence
    ))?;
    let rows = stmt
        .query_map(params![run_identity.as_bytes()], |row| {
            Ok((
                row.get::<_, u32>(0)?,
                row.get::<_, [u8; 32]>(1)?,
                row.get::<_, [u8; 32]>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, Option<[u8; 32]>>(6)?,
                row.get::<_, Option<Vec<u8>>>(7)?,
                row.get::<_, Option<[u8; 32]>>(8)?,
                row.get::<_, Option<Vec<u8>>>(9)?,
                row.get::<_, Option<[u8; 32]>>(10)?,
                row.get::<_, Option<Vec<u8>>>(11)?,
                row.get::<_, Option<[u8; 32]>>(12)?,
                row.get::<_, [u8; 32]>(13)?,
                row.get::<_, Option<String>>(14)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    let mut claims = Vec::with_capacity(rows.len());
    for (
        id,
        stored_pczt_digest,
        stored_transaction_fingerprint,
        stored_canonical_pczt,
        status,
        signer,
        txid,
        exact_tx,
        external_digest,
        external_pczt,
        signed_digest,
        signed_pczt,
        signed_binding,
        policy_fingerprint,
        last_error,
    ) in rows
    {
        let transaction_id = MigrationTxId::new(id);
        let evidence = scheduled_artifact_evidence(canonical, transaction_id)
            .ok_or(Error::Corrupt("archived claim canonical evidence"))?;
        if evidence.pczt_digest().as_bytes() != &stored_pczt_digest
            || evidence.transaction_fingerprint().as_bytes() != &stored_transaction_fingerprint
            || evidence.canonical_pczt() != stored_canonical_pczt
        {
            return Err(Error::Corrupt("archived claim canonical binding"));
        }
        let evidence = DeliveryArtifactEvidence::Scheduled(evidence);
        let status =
            ClaimStatus::from_stored(&status).ok_or(Error::Corrupt("archived claim status"))?;
        if !matches!(
            status,
            ClaimStatus::MaterializationFailed
                | ClaimStatus::Confirmed
                | ClaimStatus::ExpiredUnmined
                | ClaimStatus::ExternalSigningExpiredUnmined
        ) {
            return Err(Error::Corrupt("nonterminal archived claim"));
        }
        let signer = match signer.as_str() {
            "sdk" => SignerOwnership::Sdk,
            "external" => SignerOwnership::External,
            _ => return Err(Error::Corrupt("archived claim signer ownership")),
        };
        let external_pczt = match (external_digest, external_pczt) {
            (None, None) => None,
            (Some(stored_digest), Some(bytes)) => {
                let value = ExternalSigningPczt::parse(bytes)
                    .map_err(|_| Error::Corrupt("archived external-signing PCZT"))?;
                if value.digest().as_bytes() != &stored_digest {
                    return Err(Error::Corrupt("archived external-signing PCZT digest"));
                }
                Some(value)
            }
            _ => return Err(Error::Corrupt("archived external-signing PCZT tuple")),
        };
        let signed_pczt = match (signed_digest, signed_pczt, signed_binding) {
            (None, None, None) => None,
            (Some(stored_digest), Some(bytes), Some(stored_binding)) => {
                let staged = external_pczt
                    .as_ref()
                    .ok_or(Error::Corrupt("archived signed PCZT without staged PCZT"))?;
                let value = SignedPcztEvidence::decode(staged, bytes)
                    .map_err(|_| Error::Corrupt("archived signed PCZT"))?;
                if value.signed_digest().as_bytes() != &stored_digest
                    || value.staged_digest().as_bytes() != &stored_binding
                {
                    return Err(Error::Corrupt("archived signed PCZT binding"));
                }
                Some(value)
            }
            _ => return Err(Error::Corrupt("archived signed PCZT tuple")),
        };
        let exact_transaction = match (txid, exact_tx) {
            (None, None) => None,
            (Some(stored_txid), Some(stored_bytes)) => {
                let value = exact_transaction(canonical, transaction_id)
                    .map_err(|_| Error::Corrupt("archived exact transaction"))?;
                if *value.txid().as_ref() != stored_txid || value.bytes() != stored_bytes {
                    return Err(Error::Corrupt("archived exact transaction binding"));
                }
                Some(value)
            }
            _ => return Err(Error::Corrupt("archived exact transaction tuple")),
        };
        let policy_fingerprint = PolicyFingerprint::read(policy_fingerprint.as_slice())
            .map_err(|_| Error::Corrupt("archived claim policy fingerprint"))?;
        let last_error = last_error
            .as_deref()
            .map(|value| {
                DeliveryFailureReason::from_stored(value)
                    .ok_or(Error::Corrupt("archived delivery failure reason"))
            })
            .transpose()?;
        claims.push(
            DeliveryClaim::from_parts(
                evidence,
                signer,
                status,
                None,
                external_pczt,
                signed_pczt,
                exact_transaction,
                policy_fingerprint,
                last_error,
            )
            .map_err(|_| Error::Corrupt("archived claim semantic invariants"))?,
        );
    }
    Ok(claims)
}

#[cfg(feature = "migration-delivery")]
fn read_retained_predecessors(
    conn: &Connection,
    t: &Tables,
    account_id: AccountRef,
    submission_context: SubmissionContext,
) -> Result<Vec<RetainedMigrationRun>, Error> {
    let mut stmt = conn.prepare(&format!(
        "SELECT archive.run_identity, archive.revision, archive.state_fingerprint,
                archive.canonical_state_archive, archive.phase, archive.storage_finality,
                archive.storage_recovery_reason, archive.release_at_height,
                archive.finalized_tip_height, archive.finality_archive,
                archive.finality_archive_fingerprint, archive.policy,
                archive.policy_fingerprint, archive.destination_spendability,
                runs.source_owner, runs.lane, runs.canonical_migration_id
           FROM {} archive
           JOIN {} runs ON runs.run_identity = archive.run_identity
          WHERE runs.account_id = ?
          ORDER BY archive.rowid",
        t.delivery_run_archive, t.delivery_runs
    ))?;
    let rows = stmt
        .query_map(params![account_id.0], |row| {
            Ok((
                row.get::<_, [u8; 32]>(0)?,
                row.get::<_, u64>(1)?,
                row.get::<_, [u8; 32]>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, Option<u32>>(7)?,
                row.get::<_, Option<u32>>(8)?,
                row.get::<_, Option<Vec<u8>>>(9)?,
                row.get::<_, Option<[u8; 32]>>(10)?,
                row.get::<_, Option<Vec<u8>>>(11)?,
                row.get::<_, Option<[u8; 32]>>(12)?,
                row.get::<_, String>(13)?,
                row.get::<_, [u8; 32]>(14)?,
                row.get::<_, String>(15)?,
                row.get::<_, Option<i64>>(16)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    let mut retained = Vec::with_capacity(rows.len());
    for (
        run_identity,
        revision,
        state_fingerprint,
        canonical_archive,
        phase,
        storage_finality,
        recovery_reason,
        release_at_height,
        finalized_tip_height,
        finality_archive,
        finality_fingerprint,
        policy,
        policy_fingerprint,
        destination,
        source_owner,
        lane,
        canonical_migration_id,
    ) in rows
    {
        if lane != "canonical" || canonical_migration_id.is_some() {
            return Err(Error::Corrupt("retained run authority"));
        }
        let run_identity = MigrationRunIdentity::read(run_identity.as_slice())
            .map_err(|_| Error::Corrupt("retained run identity"))?;
        let revision = DeliveryRevision::read(revision.to_le_bytes().as_slice())
            .map_err(|_| Error::Corrupt("retained delivery revision"))?;
        let state_fingerprint = MigrationStateFingerprint::read(state_fingerprint.as_slice())
            .map_err(|_| Error::Corrupt("retained state fingerprint"))?;
        let canonical = decode_migration_state_archive(&canonical_archive, state_fingerprint)
            .map_err(|_| Error::Corrupt("retained canonical state archive"))?;
        let phase =
            DeliveryPhase::from_stored(&phase).ok_or(Error::Corrupt("retained delivery phase"))?;
        let storage_finality = decode_storage_finality(
            &storage_finality,
            recovery_reason.as_deref(),
            release_at_height,
            finalized_tip_height,
        )?;
        let policy = match (policy, policy_fingerprint) {
            (None, None) => None,
            (Some(bytes), Some(fingerprint)) => {
                let fingerprint = PolicyFingerprint::read(fingerprint.as_slice())
                    .map_err(|_| Error::Corrupt("retained policy fingerprint"))?;
                Some(
                    SubmissionPolicy::decode(bytes, fingerprint, submission_context)
                        .map_err(|_| Error::Corrupt("retained policy binding"))?,
                )
            }
            _ => return Err(Error::Corrupt("retained policy tuple")),
        };
        let finality_archive = match (finality_archive, finality_fingerprint) {
            (None, None) => None,
            (Some(bytes), Some(fingerprint)) => {
                let archive = FinalityArchive::decode(&bytes)
                    .map_err(|_| Error::Corrupt("retained finality archive"))?;
                if archive.fingerprint().as_bytes() != &fingerprint {
                    return Err(Error::Corrupt("retained finality archive fingerprint"));
                }
                Some(archive)
            }
            _ => return Err(Error::Corrupt("retained finality archive tuple")),
        };
        if matches!(
            storage_finality,
            StorageFinality::Finalized(_)
                | StorageFinality::RecoveryRequired(
                    StorageRecoveryReason::RewoundBeyondFinalityHorizon
                )
        ) {
            let release = ReservationRelease::at(BlockHeight::from_u32(
                release_at_height.ok_or(Error::Corrupt("retained finality release height"))?,
            ));
            let evidence_archive = scheduled_finality_archive_from_evidence(
                conn,
                t,
                run_identity,
                release,
                &canonical,
            )?;
            if evidence_archive != finality_archive {
                return Err(Error::Corrupt("retained finality evidence binding"));
            }
        }
        let destination = match destination.as_str() {
            "not_applicable" => DestinationSpendability::NotApplicable,
            "not_spendable" => DestinationSpendability::NotSpendable,
            "spendable" => DestinationSpendability::Spendable,
            "already_spent" => DestinationSpendability::AlreadySpent,
            _ => return Err(Error::Corrupt("retained destination spendability")),
        };
        let claims = read_archived_delivery_claims(conn, t, run_identity, &canonical)?;
        if !claims.is_empty() && policy.is_none() {
            return Err(Error::Corrupt("retained claims without policy"));
        }
        let active_source_reservation_count = conn.query_row(
            &format!(
                "SELECT COUNT(*) FROM {} WHERE run_identity = ?
                  AND status IN ('active', 'recovery_required')",
                t.delivery_reservations
            ),
            params![run_identity.as_bytes()],
            |row| row.get::<_, u64>(0),
        )?;
        let source_owner = SourceReservationOwner::read(source_owner.as_slice())
            .map_err(|_| Error::Corrupt("retained source owner"))?;
        let delivery = DeliverySnapshot::from_parts(
            revision,
            run_identity,
            DeliveryRunFingerprint::Scheduled(state_fingerprint),
            source_owner,
            phase,
            storage_finality,
            active_source_reservation_count,
            finality_archive,
            policy,
            None,
            claims,
        )
        .map_err(|_| Error::Corrupt("retained delivery snapshot invariants"))?;
        retained.push(
            RetainedMigrationRun::from_observed(Some(canonical), delivery, destination)
                .map_err(|_| Error::Corrupt("retained migration runtime invariants"))?,
        );
    }
    Ok(retained)
}

#[cfg(feature = "migration-delivery")]
fn bump_delivery_revision(conn: &Connection, t: &Tables, migration_id: i64) -> Result<(), Error> {
    let changed = conn.execute(
        &format!(
            "UPDATE {} SET revision = revision + 1
              WHERE migration_id = ? AND revision < {}",
            t.delivery_control,
            i64::MAX
        ),
        params![migration_id],
    )?;
    if changed != 1 {
        return Err(Error::Corrupt("delivery revision"));
    }
    Ok(())
}

#[cfg(feature = "migration-delivery")]
fn current_wallet_mined_height(
    conn: &Connection,
    txid: TxId,
) -> Result<Option<BlockHeight>, Error> {
    conn.query_row(
        "SELECT block FROM transactions WHERE txid = ? AND block IS NOT NULL",
        params![txid.as_ref()],
        |row| row.get::<_, u32>(0).map(BlockHeight::from_u32),
    )
    .optional()
    .map_err(Error::Db)
}

#[cfg(feature = "migration-delivery")]
fn canonical_transfer_release_height(state: &MigrationState) -> Result<Option<BlockHeight>, Error> {
    let mut latest = None;
    for transaction in state
        .transactions()
        .iter()
        .filter(|transaction| matches!(transaction.kind(), MigrationTxKind::Transfer { .. }))
    {
        let Some(mined) = transaction.state().mined_height() else {
            return Ok(None);
        };
        latest = Some(latest.map_or(mined, |height: BlockHeight| height.max(mined)));
    }
    let latest = latest.ok_or(Error::Corrupt("migration has no transfer transaction"))?;
    u32::from(latest)
        .checked_add(MIGRATION_STORAGE_FINALITY_CONFIRMATIONS - 1)
        .map(BlockHeight::from_u32)
        .map(Some)
        .ok_or(Error::DeliveryValueTooLarge)
}

/// Positively proves that every source retained by `run_identity` is still an unspent Orchard
/// output in the fully scanned active-chain view. Absence, partial reconstruction, an inactive
/// reservation, or any current-chain/unexpired spender is deliberately indistinguishable from a
/// spend here: all of those cases require recovery after an externally exposed PCZT expires.
#[cfg(feature = "migration-delivery")]
fn reserved_sources_proven_unspent(
    conn: &Connection,
    t: &Tables,
    account_id: AccountRef,
    run_identity: MigrationRunIdentity,
    fully_scanned: BlockHeight,
    target_height: BlockHeight,
) -> Result<bool, Error> {
    let rows = {
        let mut stmt = conn.prepare(&format!(
            "SELECT reservations.status, rn.id, source.block, rn.nf,
                    EXISTS(
                        SELECT 1
                          FROM orchard_received_note_spends spends
                          JOIN transactions spender ON spender.id_tx = spends.transaction_id
                         WHERE spends.orchard_received_note_id = rn.id
                           AND (spender.block IS NOT NULL OR ({}))
                    )
               FROM {} reservations
               LEFT JOIN transactions source ON source.txid = reservations.source_txid
               LEFT JOIN orchard_received_notes rn
                 ON rn.transaction_id = source.id_tx
                AND rn.action_index = reservations.source_index
                AND rn.account_id = :account_id
              WHERE reservations.run_identity = :run_identity
              ORDER BY reservations.source_txid, reservations.source_index",
            crate::wallet::common::tx_unexpired_condition("spender"),
            t.delivery_reservations,
        ))?;
        stmt.query_map(
            named_params! {
                ":account_id": account_id.0,
                ":run_identity": run_identity.as_bytes(),
                ":target_height": u32::from(target_height),
            },
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<i64>>(1)?,
                    row.get::<_, Option<u32>>(2)?,
                    row.get::<_, Option<Vec<u8>>>(3)?,
                    row.get::<_, bool>(4)?,
                ))
            },
        )?
        .collect::<Result<Vec<_>, _>>()?
    };

    if rows.is_empty() {
        return Ok(false);
    }
    Ok(rows
        .into_iter()
        .all(|(status, note_id, source_height, nullifier, has_spender)| {
            status == "active"
                && note_id.is_some()
                && source_height.is_some_and(|height| height <= u32::from(fully_scanned))
                && nullifier.is_some_and(|bytes| bytes.len() == 32)
                && !has_spender
        }))
}

#[cfg(feature = "migration-delivery")]
fn delete_delivery_claim(
    conn: &Connection,
    t: &Tables,
    migration_id: i64,
    transaction_id: MigrationTxId,
) -> Result<(), Error> {
    let changed = conn.execute(
        &format!(
            "DELETE FROM {} WHERE migration_id = ? AND tx_id = ?",
            t.delivery_claims
        ),
        params![migration_id, u32::from(transaction_id)],
    )?;
    if changed != 1 {
        return Err(Error::DeliveryClaimUnavailable);
    }
    Ok(())
}

#[cfg(feature = "migration-delivery")]
fn set_reconciled_claim_status(
    conn: &Connection,
    t: &Tables,
    migration_id: i64,
    transaction_id: MigrationTxId,
    status: ClaimStatus,
) -> Result<(), Error> {
    let changed = conn.execute(
        &format!(
            "UPDATE {} SET status = ?, claim_kind = NULL, attempt_token = NULL,
                 lease_clock_session = NULL, lease_acquired_at_ms = NULL,
                 lease_expires_at_ms = NULL
             WHERE migration_id = ? AND tx_id = ?",
            t.delivery_claims
        ),
        params![status.as_str(), migration_id, u32::from(transaction_id)],
    )?;
    if changed != 1 {
        return Err(Error::Corrupt("reconciled delivery claim"));
    }
    if changed != 1 {
        return Err(Error::DeliveryClaimUnavailable);
    }
    Ok(())
}

/// Reconciles canonical state, run ownership, fingerprints, and expired attempt leases inside the
/// caller's IMMEDIATE transaction. Every caller observes one revision-consistent view.
#[cfg(feature = "migration-delivery")]
fn reconcile_delivery(
    conn: &Connection,
    t: &Tables,
    account_id: AccountRef,
    submission_context: Option<SubmissionContext>,
    now: MonotonicLeaseInstant,
    initial_outputs: Option<&[OutputRef]>,
) -> Result<Option<DeliverySnapshot>, Error> {
    if !matches!(
        delivery_schema_provenance(conn, t)?,
        DeliverySchemaProvenance::Compatible(version)
            if version.as_u32() == DELIVERY_SCHEMA_VERSION
    ) {
        return Err(Error::DeliverySchemaIncompatible);
    }
    if !matches!(legacy_cutover_status(conn, t)?, LegacyCutoverStatus::Fresh) {
        return Err(Error::LegacyRecoveryRequired);
    }

    let Some(state) = read_migration(conn, t, account_id)? else {
        return Ok(None);
    };
    let migration_id = resolve_migration_id(conn, t, account_id)?
        .ok_or(Error::Corrupt("delivery canonical migration"))?;
    let fingerprint = migration_state_fingerprint(&state);
    let canonical_owner = canonical_lock_owner(&state)?;
    let mut control = read_delivery_control(conn, t, migration_id, submission_context)?;

    if control.is_none() {
        let initial_outputs = initial_outputs
            .filter(|outputs| !outputs.is_empty())
            .ok_or(Error::DeliveryRunUnavailable)?;
        let owner = canonical_owner.ok_or(Error::DeliveryRunUnavailable)?;
        let live_run_exists = conn.query_row(
            &format!(
                "SELECT EXISTS(SELECT 1 FROM {} WHERE account_id = ?
                    AND status IN ('active', 'recovery_required'))",
                t.delivery_runs
            ),
            params![account_id.0],
            |row| row.get::<_, bool>(0),
        )?;
        if live_run_exists {
            return Err(Error::DeliveryLaneConflict);
        }
        // Run identities and attempt tokens are generated only inside Rust from the operating
        // system CSPRNG; callers can observe and echo them but cannot choose them.
        let run = MigrationRunIdentity::random(&mut rand::rngs::OsRng);
        let source_owner = SourceReservationOwner::random(&mut rand::rngs::OsRng);
        let authority_fingerprint = delivery_run_authority_fingerprint(
            run.as_bytes(),
            account_id.0,
            "canonical",
            Some(migration_id),
            source_owner.as_bytes(),
            Some(owner.as_bytes()),
        )?;
        conn.execute(
            &format!(
                "INSERT INTO {} (
                     run_identity, account_id, lane, canonical_migration_id,
                     source_owner, canonical_lock_owner, authority_fingerprint, status
                 ) VALUES (?, ?, 'canonical', ?, ?, ?, ?, 'active')",
                t.delivery_runs
            ),
            params![
                run.as_bytes(),
                account_id.0,
                migration_id,
                source_owner.as_bytes(),
                owner.as_bytes(),
                authority_fingerprint,
            ],
        )?;
        conn.execute(
            &format!(
                "INSERT INTO {} (
                     migration_id, run_identity, revision, state_fingerprint, phase
                 ) VALUES (?, ?, 1, ?, 'active')",
                t.delivery_control
            ),
            params![migration_id, run.as_bytes(), fingerprint.as_bytes()],
        )?;
        upsert_source_reservations(conn, t, initial_outputs, run)?;
        control = read_delivery_control(conn, t, migration_id, submission_context)?;
    }
    let mut control = control.ok_or(Error::Corrupt("delivery control"))?;

    if let Some(owner) = canonical_owner {
        if owner != control.canonical_lock_owner {
            // A new canonical owner is a new run. Only the explicit run-transition/reorg-recovery
            // operation may reset policy and evidence; snapshot reconciliation never does so.
            return Err(Error::DeliveryRunMismatch);
        }
    } else {
        match state.status() {
            MigrationStatus::Complete
                if matches!(control.storage_finality, StorageFinality::Finalized(_)) => {}
            MigrationStatus::Failed if control.phase == DeliveryPhase::Abandoned => {}
            _ => return Err(Error::DeliveryRunUnavailable),
        }
    }

    let mut reconciled = false;
    let expiring = {
        let mut stmt = conn.prepare(&format!(
            "SELECT tx_id, status, claim_kind
               FROM {} WHERE migration_id = ? AND claim_kind IS NOT NULL
                AND (lease_clock_session != ? OR lease_acquired_at_ms > ?
                     OR lease_expires_at_ms <= ?)",
            t.delivery_claims
        ))?;
        stmt.query_map(
            params![
                migration_id,
                now.session().as_bytes(),
                now.tick_millis(),
                now.tick_millis()
            ],
            |row| {
                Ok((
                    row.get::<_, u32>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )?
        .collect::<Result<Vec<_>, _>>()?
    };
    for (id, status, kind) in expiring {
        match (status.as_str(), kind.as_str()) {
            ("materializing", "materialization") => {
                conn.execute(
                    &format!(
                        "UPDATE {} SET status = 'materialization_failed', claim_kind = NULL,
                             attempt_token = NULL, lease_clock_session = NULL,
                             lease_acquired_at_ms = NULL, lease_expires_at_ms = NULL,
                             last_error = ?
                         WHERE migration_id = ? AND tx_id = ?",
                        t.delivery_claims
                    ),
                    params![
                        DeliveryFailureReason::MaterializationLeaseExpired.as_str(),
                        migration_id,
                        id
                    ],
                )?;
            }
            ("awaiting_external_signature", "materialization") => {
                conn.execute(
                    &format!(
                        "UPDATE {} SET claim_kind = NULL, attempt_token = NULL,
                             lease_clock_session = NULL, lease_acquired_at_ms = NULL,
                             lease_expires_at_ms = NULL
                         WHERE migration_id = ? AND tx_id = ?",
                        t.delivery_claims
                    ),
                    params![migration_id, id],
                )?;
            }
            ("submitting", "submission") => {
                // A worker may have crossed the transport boundary before dying. Never return this
                // to Staged merely because the lease elapsed.
                conn.execute(
                    &format!(
                        "UPDATE {} SET status = 'outcome_unknown', claim_kind = NULL,
                             attempt_token = NULL, lease_clock_session = NULL,
                             lease_acquired_at_ms = NULL, lease_expires_at_ms = NULL,
                             last_error = ?
                         WHERE migration_id = ? AND tx_id = ?",
                        t.delivery_claims
                    ),
                    params![
                        DeliveryFailureReason::TransportOutcomeUnknown.as_str(),
                        migration_id,
                        id
                    ],
                )?;
            }
            ("outcome_unknown" | "broadcasted", "outcome_resolution") => {
                conn.execute(
                    &format!(
                        "UPDATE {} SET claim_kind = NULL, attempt_token = NULL,
                             lease_clock_session = NULL, lease_acquired_at_ms = NULL,
                             lease_expires_at_ms = NULL
                         WHERE migration_id = ? AND tx_id = ?",
                        t.delivery_claims
                    ),
                    params![migration_id, id],
                )?;
            }
            _ => return Err(Error::Corrupt("delivery claim lease lifecycle")),
        }
        reconciled = true;
    }

    // Re-audit every claim on every snapshot. Fingerprint equality is not enough: current-chain
    // mining evidence can disappear on a reorg without changing canonical delivery rows.
    let claims = read_delivery_claims(conn, t, migration_id)?;
    let mut post_finality_evidence_lost = false;
    let mut external_signing_exposure_unresolved = false;
    for claim in &claims {
        let Some(canonical) = state
            .transactions()
            .iter()
            .find(|transaction| transaction.id() == claim.transaction_id())
        else {
            if claim.has_exposure_history() {
                return Err(Error::DeliveryExposedStateChanged(claim.transaction_id()));
            }
            delete_delivery_claim(conn, t, migration_id, claim.transaction_id())?;
            reconciled = true;
            continue;
        };

        let immutable_matches = Some(PcztDigest::from_pczt(canonical.pczt()))
            == claim.pczt_digest()
            && Some(migration_transaction_fingerprint(&state, canonical))
                == claim.transaction_fingerprint();
        if !immutable_matches {
            if claim.has_exposure_history() {
                return Err(Error::DeliveryExposedStateChanged(claim.transaction_id()));
            }
            delete_delivery_claim(conn, t, migration_id, claim.transaction_id())?;
            reconciled = true;
            continue;
        }

        let policy_matches = control
            .policy
            .as_ref()
            .is_some_and(|policy| policy.fingerprint() == claim.policy_fingerprint());
        if !policy_matches {
            return Err(Error::DeliveryPolicyMismatch);
        }

        match claim.status() {
            ClaimStatus::Materializing | ClaimStatus::MaterializationFailed => {
                match (claim.signer_ownership(), canonical.state()) {
                    (SignerOwnership::Sdk, MigrationTxState::Signed | MigrationTxState::Proved)
                    | (
                        SignerOwnership::External,
                        MigrationTxState::AwaitingSignature | MigrationTxState::Signed,
                    ) => {}
                    (_, MigrationTxState::Broadcast { .. } | MigrationTxState::Mined { .. }) => {
                        return Err(Error::DeliveryUntrackedExposure(canonical.id()));
                    }
                    _ => {
                        delete_delivery_claim(conn, t, migration_id, claim.transaction_id())?;
                        reconciled = true;
                    }
                }
                continue;
            }
            ClaimStatus::AwaitingExternalSignature => {
                if !matches!(
                    canonical.state(),
                    MigrationTxState::AwaitingSignature | MigrationTxState::Signed
                ) {
                    return Err(Error::DeliveryExposedStateChanged(canonical.id()));
                }
                let expiry = claim.expiry_height();
                if u32::from(expiry) != 0
                    && fully_scanned_height(conn)?.is_some_and(|height| height > expiry)
                {
                    let target_height = canonical_wallet_target_height(conn)?;
                    if reserved_sources_proven_unspent(
                        conn,
                        t,
                        account_id,
                        control.run_identity,
                        fully_scanned_height(conn)?
                            .ok_or(Error::Corrupt("fully scanned height changed"))?,
                        target_height,
                    )? {
                        set_reconciled_claim_status(
                            conn,
                            t,
                            migration_id,
                            claim.transaction_id(),
                            ClaimStatus::ExternalSigningExpiredUnmined,
                        )?;
                    } else {
                        external_signing_exposure_unresolved = true;
                    }
                    reconciled = true;
                }
                continue;
            }
            ClaimStatus::ExternalSigningExpiredUnmined => {
                if !matches!(
                    canonical.state(),
                    MigrationTxState::AwaitingSignature | MigrationTxState::Signed
                ) {
                    return Err(Error::DeliveryExposedStateChanged(canonical.id()));
                }
                continue;
            }
            ClaimStatus::Staged => match canonical.state() {
                MigrationTxState::Proved => {}
                MigrationTxState::Broadcast { .. } | MigrationTxState::Mined { .. } => {
                    return Err(Error::DeliveryUntrackedExposure(canonical.id()));
                }
                MigrationTxState::AwaitingSignature | MigrationTxState::Signed => {
                    if claim.has_exposure_history() {
                        return Err(Error::DeliveryExposedStateChanged(canonical.id()));
                    }
                    delete_delivery_claim(conn, t, migration_id, claim.transaction_id())?;
                    reconciled = true;
                    continue;
                }
            },
            ClaimStatus::Submitting
            | ClaimStatus::OutcomeUnknown
            | ClaimStatus::Broadcasted
            | ClaimStatus::Confirmed
            | ClaimStatus::ExpiredUnmined => {}
        }

        let artifact = exact_transaction(&state, claim.transaction_id())
            .map_err(|_| Error::DeliveryExposedStateChanged(claim.transaction_id()))?;
        let artifact_matches = artifact.txid()
            == claim.txid().ok_or(Error::Corrupt("delivery exact txid"))?
            && artifact.consensus_expiry_height() == claim.expiry_height()
            && claim.exact_tx() == Some(artifact.bytes());
        if !artifact_matches {
            if claim.has_exposure_history() {
                return Err(Error::DeliveryExposedStateChanged(claim.transaction_id()));
            }
            delete_delivery_claim(conn, t, migration_id, claim.transaction_id())?;
            reconciled = true;
            continue;
        }

        if let MigrationTxState::Broadcast { txid } = canonical.state()
            && txid != artifact.txid()
        {
            return Err(Error::DeliveryExposedStateChanged(claim.transaction_id()));
        }

        match current_wallet_mined_height(conn, artifact.txid())? {
            Some(wallet_height) => {
                // Canonical lifecycle and delivery evidence must advance in one typed CAS. Leave
                // drift visible for `reconcile_canonical_chain` instead of committing half of the
                // transition from this snapshot/lease reconciliation path.
                let _canonical_is_current = matches!(
                    canonical.state(),
                    MigrationTxState::Mined { height } if height == wallet_height
                ) && claim.status() == ClaimStatus::Confirmed;
            }
            None => {
                if matches!(canonical.state(), MigrationTxState::Mined { .. }) {
                    if matches!(control.storage_finality, StorageFinality::Finalized(_)) {
                        // Finalized evidence is still authoritative. Losing it after release is a
                        // deep rewind: the transition below reacquires source-reservation
                        // exclusion while retaining the exact finality archive.
                        post_finality_evidence_lost = true;
                        continue;
                    }
                    // A shallow reorg remains an active delivery transition. The explicit chain
                    // CAS demotes Mined -> Broadcast and retains/reacquires reservations atomically.
                    continue;
                }
            }
        }
    }

    // A canonical Broadcast/Mined transition without exact Rust-owned delivery evidence is an
    // alternate exposure path and must fail closed instead of making cancellation appear safe.
    for canonical in state.transactions().iter().filter(|transaction| {
        matches!(
            transaction.state(),
            MigrationTxState::Broadcast { .. } | MigrationTxState::Mined { .. }
        )
    }) {
        if !claims.iter().any(|claim| {
            claim.transaction_id() == canonical.id()
                && matches!(
                    claim.status(),
                    ClaimStatus::Submitting
                        | ClaimStatus::OutcomeUnknown
                        | ClaimStatus::Broadcasted
                        | ClaimStatus::Confirmed
                        | ClaimStatus::ExpiredUnmined
                )
        }) {
            return Err(Error::DeliveryUntrackedExposure(canonical.id()));
        }
    }

    let computed_release_at_height = if matches!(state.status(), MigrationStatus::Complete) {
        canonical_transfer_release_height(&state)?
    } else {
        None
    };
    let next_storage_finality = if external_signing_exposure_unresolved {
        StorageFinality::RecoveryRequired(StorageRecoveryReason::ExternalSigningExposureUnresolved)
    } else {
        match control.storage_finality {
            StorageFinality::Finalized(_release) if post_finality_evidence_lost => {
                StorageFinality::RecoveryRequired(
                    StorageRecoveryReason::RewoundBeyondFinalityHorizon,
                )
            }
            StorageFinality::Finalized(release) => StorageFinality::Finalized(release),
            StorageFinality::RecoveryRequired(reason) => StorageFinality::RecoveryRequired(reason),
            StorageFinality::NoRun => {
                return Err(Error::Corrupt("canonical delivery has no run"));
            }
            StorageFinality::Active | StorageFinality::CompletePendingFinality(_) => {
                if matches!(
                    control.storage_finality,
                    StorageFinality::CompletePendingFinality(_)
                ) && (!matches!(state.status(), MigrationStatus::Complete)
                    || state.transactions().iter().any(|transaction| {
                        !matches!(transaction.state(), MigrationTxState::Mined { .. })
                    }))
                {
                    StorageFinality::RecoveryRequired(StorageRecoveryReason::TransferEvidenceLost)
                } else if matches!(state.status(), MigrationStatus::Complete)
                    && state.transactions().iter().all(|transaction| {
                        matches!(transaction.state(), MigrationTxState::Mined { .. })
                    })
                {
                    StorageFinality::CompletePendingFinality(ReservationRelease::at(
                        computed_release_at_height
                            .ok_or(Error::Corrupt("delivery release height"))?,
                    ))
                } else {
                    StorageFinality::Active
                }
            }
        }
    };
    let next_release_at_height = match next_storage_finality {
        StorageFinality::NoRun | StorageFinality::Active => None,
        StorageFinality::CompletePendingFinality(release) | StorageFinality::Finalized(release) => {
            Some(release.release_at())
        }
        StorageFinality::RecoveryRequired(_) => {
            control.release_at_height.or(computed_release_at_height)
        }
    };
    if next_storage_finality != control.storage_finality
        || next_release_at_height != control.release_at_height
    {
        conn.execute(
            &format!(
                "UPDATE {} SET storage_finality = ?, storage_recovery_reason = ?,
                     release_at_height = ?
                 WHERE migration_id = ?",
                t.delivery_control
            ),
            params![
                next_storage_finality.as_str(),
                match next_storage_finality {
                    StorageFinality::RecoveryRequired(
                        StorageRecoveryReason::TransferEvidenceLost,
                    ) => Some("transfer_evidence_lost"),
                    StorageFinality::RecoveryRequired(
                        StorageRecoveryReason::RewoundBeyondFinalityHorizon,
                    ) => Some("rewound_beyond_finality_horizon"),
                    StorageFinality::RecoveryRequired(
                        StorageRecoveryReason::CorruptFinalityEvidence,
                    ) => Some("corrupt_finality_evidence"),
                    StorageFinality::RecoveryRequired(
                        StorageRecoveryReason::ExternalSigningExposureUnresolved,
                    ) => Some("external_signing_exposure_unresolved"),
                    _ => None,
                },
                next_release_at_height.map(u32::from),
                migration_id
            ],
        )?;
        if matches!(
            next_storage_finality,
            StorageFinality::CompletePendingFinality(_)
        ) {
            conn.execute(
                &format!(
                    "UPDATE {} SET release_at_height = ?
                     WHERE run_identity = ? AND status = 'active'",
                    t.delivery_reservations
                ),
                params![
                    next_release_at_height.map(u32::from),
                    control.run_identity.as_bytes()
                ],
            )?;
        }
        if matches!(next_storage_finality, StorageFinality::RecoveryRequired(_)) {
            conn.execute(
                &format!(
                    "UPDATE {} SET status = 'recovery_required'
                     WHERE run_identity = ? AND status IN ('active', 'finality_released')",
                    t.delivery_reservations
                ),
                params![control.run_identity.as_bytes()],
            )?;
            conn.execute(
                &format!(
                    "UPDATE {} SET status = 'recovery_required' WHERE run_identity = ?",
                    t.delivery_runs
                ),
                params![control.run_identity.as_bytes()],
            )?;
        }
        reconciled = true;
    }

    if fingerprint != control.state_fingerprint {
        conn.execute(
            &format!(
                "UPDATE {} SET state_fingerprint = ? WHERE migration_id = ?",
                t.delivery_control
            ),
            params![fingerprint.as_bytes(), migration_id],
        )?;
        reconciled = true;
    }

    if reconciled {
        bump_delivery_revision(conn, t, migration_id)?;
    }
    control = read_delivery_control(conn, t, migration_id, submission_context)?
        .ok_or(Error::Corrupt("delivery control"))?;
    build_delivery_snapshot(conn, t, control).map(Some)
}

#[cfg(feature = "migration-delivery")]
// Each argument is an independently authenticated part of the scheduled-delivery CAS boundary;
// grouping them would make the required state, revision, run, context, and lease checks less clear.
#[allow(clippy::too_many_arguments)]
fn require_delivery_context(
    conn: &Connection,
    t: &Tables,
    account_id: AccountRef,
    expected_state: &MigrationState,
    expected_revision: DeliveryRevision,
    run_identity: MigrationRunIdentity,
    submission_context: SubmissionContext,
    now: MonotonicLeaseInstant,
) -> Result<(i64, DeliverySnapshot), Error> {
    require_canonical_state(conn, t, account_id, Some(expected_state))?;
    let snapshot = reconcile_delivery(conn, t, account_id, Some(submission_context), now, None)?
        .ok_or(Error::Corrupt("delivery canonical migration"))?;
    if snapshot.revision() != expected_revision {
        return Err(Error::DeliveryRevisionMismatch);
    }
    if snapshot.run_identity() != run_identity {
        return Err(Error::DeliveryRunMismatch);
    }
    let migration_id = resolve_migration_id(conn, t, account_id)?
        .ok_or(Error::Corrupt("delivery canonical migration"))?;
    Ok((migration_id, snapshot))
}

#[cfg(feature = "migration-delivery")]
fn require_bound_policy(
    snapshot: &DeliverySnapshot,
    expected_policy_fingerprint: PolicyFingerprint,
) -> Result<(), Error> {
    let policy = snapshot
        .submission_policy()
        .ok_or(Error::DeliveryPolicyMissing)?;
    if policy.fingerprint() != expected_policy_fingerprint {
        return Err(Error::DeliveryPolicyMismatch);
    }
    Ok(())
}

#[cfg(feature = "migration-delivery")]
fn require_scheduled_artifact_identity(
    state: &MigrationState,
    artifact_identity: DeliveryArtifactIdentity,
) -> Result<MigrationTxId, Error> {
    let DeliveryArtifactIdentity::Scheduled(identity) = artifact_identity else {
        return Err(Error::DeliveryArtifactMismatch);
    };
    let evidence = scheduled_artifact_evidence(state, identity.transaction_id())
        .ok_or(Error::DeliveryArtifactMismatch)?;
    if evidence.identity() != identity {
        return Err(Error::DeliveryArtifactMismatch);
    }
    Ok(identity.transaction_id())
}

#[cfg(feature = "migration-delivery")]
fn require_canonical_pczt_extension(predecessor: &[u8], successor: &[u8]) -> Result<(), Error> {
    let predecessor =
        pczt::Pczt::parse(predecessor).map_err(|_| Error::DeliveryArtifactMismatch)?;
    let successor_pczt =
        pczt::Pczt::parse(successor).map_err(|_| Error::DeliveryArtifactMismatch)?;
    let merged = Combiner::new(vec![predecessor, successor_pczt])
        .combine()
        .map_err(|_| Error::DeliveryArtifactMismatch)?
        .serialize()
        .map_err(|_| Error::DeliveryArtifactMismatch)?;
    if merged != successor {
        return Err(Error::DeliveryArtifactMismatch);
    }
    Ok(())
}

#[cfg(feature = "migration-delivery")]
fn with_canonical_transaction_state(
    state: &MigrationState,
    transaction_id: MigrationTxId,
    next_state: MigrationTxState,
) -> Result<MigrationState, Error> {
    let mut found = false;
    let transactions = state
        .transactions()
        .iter()
        .map(|transaction| {
            let transaction_state = if transaction.id() == transaction_id {
                found = true;
                next_state
            } else {
                transaction.state()
            };
            MigrationTransaction::from_parts(
                transaction.id(),
                transaction.kind(),
                transaction.pczt().clone(),
                transaction.depends_on().to_vec(),
                transaction.scheduled_height(),
                transaction.expiry_height(),
                transaction.anchor_boundary(),
                transaction_state,
                transaction.lock_owner(),
            )
        })
        .collect::<Vec<_>>();
    if !found {
        return Err(Error::DeliveryArtifactMismatch);
    }

    let all_mined = !transactions.is_empty()
        && transactions
            .iter()
            .all(|transaction| matches!(transaction.state(), MigrationTxState::Mined { .. }));
    let any_started = transactions.iter().any(|transaction| {
        matches!(
            transaction.state(),
            MigrationTxState::Broadcast { .. } | MigrationTxState::Mined { .. }
        )
    });
    let status = if all_mined {
        MigrationStatus::Complete
    } else if any_started {
        MigrationStatus::InProgress
    } else {
        match state.status() {
            MigrationStatus::Planning => MigrationStatus::Planning,
            MigrationStatus::Failed => MigrationStatus::Failed,
            _ => MigrationStatus::Committed,
        }
    };
    Ok(MigrationState::from_parts(
        status,
        state.note_split().clone(),
        state.preparation().clone(),
        transactions,
    ))
}

#[cfg(feature = "migration-delivery")]
fn with_canonical_transaction_pczt_and_state(
    state: &MigrationState,
    transaction_id: MigrationTxId,
    canonical_pczt: &[u8],
    next_state: MigrationTxState,
) -> Result<MigrationState, Error> {
    let mut found = false;
    let transactions = state
        .transactions()
        .iter()
        .map(|transaction| {
            if transaction.id() == transaction_id {
                found = true;
                MigrationTransaction::from_parts(
                    transaction.id(),
                    transaction.kind(),
                    canonical_pczt.to_vec(),
                    transaction.depends_on().to_vec(),
                    transaction.scheduled_height(),
                    transaction.expiry_height(),
                    transaction.anchor_boundary(),
                    next_state,
                    transaction.lock_owner(),
                )
            } else {
                transaction.clone()
            }
        })
        .collect::<Vec<_>>();
    if !found {
        return Err(Error::DeliveryArtifactMismatch);
    }
    let all_mined = !transactions.is_empty()
        && transactions
            .iter()
            .all(|transaction| matches!(transaction.state(), MigrationTxState::Mined { .. }));
    let any_started = transactions.iter().any(|transaction| {
        matches!(
            transaction.state(),
            MigrationTxState::Broadcast { .. } | MigrationTxState::Mined { .. }
        )
    });
    let status = if all_mined {
        MigrationStatus::Complete
    } else if any_started {
        MigrationStatus::InProgress
    } else {
        match state.status() {
            MigrationStatus::Planning => MigrationStatus::Planning,
            MigrationStatus::Failed => MigrationStatus::Failed,
            _ => MigrationStatus::Committed,
        }
    };
    Ok(MigrationState::from_parts(
        status,
        state.note_split().clone(),
        state.preparation().clone(),
        transactions,
    ))
}

#[cfg(feature = "migration-delivery")]
fn require_exact_finalized_successor(
    expected: &MigrationState,
    finalized: &MigrationState,
    owners: &BTreeSet<LockOwner>,
) -> Result<(), Error> {
    if expected.status() != MigrationStatus::Complete
        || finalized.status() != MigrationStatus::Complete
        || expected.note_split() != finalized.note_split()
        || expected.preparation() != finalized.preparation()
        || expected.transactions().len() != finalized.transactions().len()
    {
        return Err(Error::DeliveryArtifactMismatch);
    }
    for (before, after) in expected.transactions().iter().zip(finalized.transactions()) {
        if before.id() != after.id()
            || before.kind() != after.kind()
            || before.pczt() != after.pczt()
            || before.depends_on() != after.depends_on()
            || before.scheduled_height() != after.scheduled_height()
            || before.expiry_height() != after.expiry_height()
            || before.anchor_boundary() != after.anchor_boundary()
            || before.state() != after.state()
            || after.lock_owner().is_some()
            || before
                .lock_owner()
                .is_some_and(|owner| !owners.contains(&LockOwner::new(owner)))
        {
            return Err(Error::DeliveryArtifactMismatch);
        }
    }
    Ok(())
}

#[cfg(feature = "migration-delivery")]
fn require_active(snapshot: &DeliverySnapshot) -> Result<(), Error> {
    if matches!(
        snapshot.storage_finality(),
        StorageFinality::RecoveryRequired(_)
    ) {
        return Err(Error::DeliveryRecoveryRequired);
    }
    if snapshot.phase() != DeliveryPhase::Active {
        return Err(Error::DeliveryPhaseMismatch);
    }
    Ok(())
}

#[cfg(feature = "migration-delivery")]
fn delivery_snapshot_after_mutation(
    conn: &Connection,
    t: &Tables,
    migration_id: i64,
    submission_context: SubmissionContext,
) -> Result<DeliverySnapshot, Error> {
    let control = read_delivery_control(conn, t, migration_id, Some(submission_context))?
        .ok_or(Error::Corrupt("delivery control"))?;
    build_delivery_snapshot(conn, t, control)
}

#[cfg(feature = "migration-delivery")]
pub(super) fn checked_delivery_lease(
    kind: ClaimKind,
    duration: zcash_pool_migration::delivery::LeaseDuration,
) -> Result<DeliveryLease, Error> {
    DeliveryLease::new(
        kind,
        ClaimToken::random(&mut rand::rngs::OsRng),
        delivery_clock_now(),
        duration,
    )
    .ok_or(Error::DeliveryValueTooLarge)
}

#[cfg(feature = "migration-delivery")]
fn canonical_wallet_target_height(conn: &Connection) -> Result<BlockHeight, Error> {
    let tip = crate::wallet::chain_tip_height(conn)
        .map_err(crate::error::SqliteClientError::DbError)
        .map_err(Error::Wallet)?
        .ok_or_else(|| Error::Wallet(crate::error::SqliteClientError::ChainHeightUnknown))?;
    u32::from(tip)
        .checked_add(1)
        .map(BlockHeight::from_u32)
        .ok_or(Error::Corrupt("wallet target height overflow"))
}

#[cfg(feature = "migration-delivery")]
fn fully_scanned_height(conn: &Connection) -> Result<Option<BlockHeight>, Error> {
    let Some(birthday) = crate::wallet::wallet_birthday(conn)
        .map_err(crate::error::SqliteClientError::DbError)
        .map_err(Error::Wallet)?
    else {
        return Ok(None);
    };
    let range = conn
        .query_row(
            "SELECT block_range_start, block_range_end
               FROM scan_queue
              WHERE priority = ?
              ORDER BY block_range_start ASC
              LIMIT 1",
            params![crate::wallet::scanning::priority_code(
                &ScanPriority::Scanned
            )],
            |row| Ok((row.get::<_, u32>(0)?, row.get::<_, u32>(1)?)),
        )
        .optional()?;
    Ok(range.and_then(|(start, end)| {
        (BlockHeight::from_u32(start) <= birthday && end > 0)
            .then(|| BlockHeight::from_u32(end - 1))
    }))
}

#[cfg(feature = "migration-delivery")]
pub(super) fn account_ref(
    conn: &Connection,
    account: &AccountUuid,
) -> Result<Option<AccountRef>, Error> {
    conn.query_row(
        "SELECT id FROM accounts WHERE uuid = ?",
        params![account.expose_uuid()],
        |row| row.get::<_, i64>(0).map(AccountRef),
    )
    .optional()
    .map_err(Error::Db)
}

#[cfg(feature = "migration-delivery")]
fn canonical_destination_spendability(
    conn: &Connection,
    account_id: AccountRef,
    canonical: Option<&MigrationState>,
    delivery: Option<&DeliverySnapshot>,
) -> Result<DestinationSpendability, Error> {
    let Some(canonical) = canonical else {
        return Ok(
            if delivery.is_none()
                || delivery.is_some_and(DeliverySnapshot::released_without_exposure)
            {
                DestinationSpendability::NotApplicable
            } else {
                DestinationSpendability::NotSpendable
            },
        );
    };
    let Some(delivery) = delivery else {
        return Ok(DestinationSpendability::NotSpendable);
    };
    if delivery.released_without_exposure() {
        return Ok(DestinationSpendability::NotApplicable);
    }
    if canonical.status() != MigrationStatus::Complete {
        return Ok(DestinationSpendability::NotSpendable);
    }

    let target = TargetHeight::from(canonical_wallet_target_height(conn)?);
    let confirmations = ConfirmationsPolicy::default();
    let lock_policy = LockedInputPolicy::Exclude;
    let mut transfer_count = 0usize;
    let mut any_spendable = false;
    for transaction in canonical
        .transactions()
        .iter()
        .filter(|transaction| matches!(transaction.kind(), MigrationTxKind::Transfer { .. }))
    {
        transfer_count += 1;
        let Some(claim) = delivery
            .claims()
            .iter()
            .find(|claim| claim.transaction_id() == transaction.id())
        else {
            return Ok(DestinationSpendability::NotSpendable);
        };
        let Some(exact) = claim.exact_transaction() else {
            return Ok(DestinationSpendability::NotSpendable);
        };
        if claim.status() != ClaimStatus::Confirmed {
            return Ok(DestinationSpendability::NotSpendable);
        }
        let Some(amount) = canonical.transfer_amount(transaction) else {
            return Err(Error::Corrupt("migration transfer amount"));
        };
        let output = ExactReceivedOutput::new(
            OutputRef::new(exact.txid(), PoolType::Shielded(ShieldedPool::Ironwood), 0),
            amount,
        );
        match received_output_availability(
            conn,
            account_id,
            output,
            target,
            confirmations,
            LockFilter::Policy(&lock_policy),
        )? {
            ReceivedOutputAvailability::Spendable => any_spendable = true,
            ReceivedOutputAvailability::Spent { .. } => {}
            ReceivedOutputAvailability::Unknown | ReceivedOutputAvailability::Unavailable(_) => {
                return Ok(DestinationSpendability::NotSpendable);
            }
        }
    }
    if transfer_count == 0 {
        return Err(Error::Corrupt("completed migration without transfers"));
    }
    Ok(if any_spendable {
        DestinationSpendability::Spendable
    } else {
        DestinationSpendability::AlreadySpent
    })
}

/// Reads one canonical migration runtime from a caller-owned atomic SQLite view. This function
/// intentionally does not open or commit a transaction; WalletDb adapters call it either inside
/// their existing `SqlTransaction` or from a newly opened IMMEDIATE transaction.
#[cfg(feature = "migration-delivery")]
pub(super) fn load_account_migration_runtime(
    conn: &Connection,
    tables: &Tables,
    account: AccountUuid,
    submission_context: SubmissionContext,
) -> Result<Option<AccountMigrationRuntime<AccountUuid>>, Error> {
    let Some(account_id) = account_ref(conn, &account)? else {
        return Ok(None);
    };
    let canonical = read_migration(conn, tables, account_id)?;
    let provenance = delivery_schema_provenance(conn, tables)?;
    let legacy = legacy_cutover_status(conn, tables)?;
    let scheduled_delivery = if matches!(provenance, DeliverySchemaProvenance::Compatible(_))
        && matches!(legacy, LegacyCutoverStatus::Fresh)
    {
        match resolve_migration_id(conn, tables, account_id)? {
            Some(migration_id) if delivery_control_exists(conn, tables, migration_id)? => {
                reconcile_delivery(
                    conn,
                    tables,
                    account_id,
                    Some(submission_context),
                    delivery_clock_now(),
                    None,
                )?
            }
            _ => None,
        }
    } else {
        None
    };

    let (immediate_current, mut retained_immediate) =
        if matches!(provenance, DeliverySchemaProvenance::Compatible(_))
            && matches!(legacy, LegacyCutoverStatus::Fresh)
        {
            load_immediate_delivery_runtime_parts(conn, tables, account_id, submission_context)?
        } else {
            (None, Vec::new())
        };
    if immediate_current.is_some() && (canonical.is_some() || scheduled_delivery.is_some()) {
        return Err(Error::Corrupt(
            "simultaneous scheduled and immediate delivery authority",
        ));
    }
    let mut retained_predecessors = if matches!(provenance, DeliverySchemaProvenance::Compatible(_))
        && matches!(legacy, LegacyCutoverStatus::Fresh)
    {
        read_retained_predecessors(conn, tables, account_id, submission_context)?
    } else {
        Vec::new()
    };
    retained_predecessors.append(&mut retained_immediate);
    let (delivery, destination) = match immediate_current {
        Some((delivery, destination)) => (Some(delivery), destination),
        None => {
            let destination = canonical_destination_spendability(
                conn,
                account_id,
                canonical.as_ref(),
                scheduled_delivery.as_ref(),
            )?;
            (scheduled_delivery, destination)
        }
    };
    Ok(Some(AccountMigrationRuntime::new(
        account,
        MigrationRuntimeSnapshot::from_observed(
            canonical,
            delivery,
            retained_predecessors,
            provenance,
            legacy,
            destination,
        ),
    )))
}

#[cfg(feature = "migration-delivery")]
pub(super) fn load_all_account_migration_runtimes(
    conn: &Connection,
    tables: &Tables,
    submission_context: SubmissionContext,
) -> Result<Vec<AccountMigrationRuntime<AccountUuid>>, Error> {
    let accounts = {
        let mut stmt = conn.prepare("SELECT uuid FROM accounts ORDER BY id")?;
        stmt.query_map([], |row| {
            row.get::<_, uuid::Uuid>(0).map(AccountUuid::from_uuid)
        })?
        .collect::<Result<Vec<_>, _>>()?
    };
    accounts
        .into_iter()
        .map(|account| {
            load_account_migration_runtime(conn, tables, account, submission_context)?
                .ok_or(Error::AccountUnknown)
        })
        .collect()
}

#[cfg(feature = "migration-delivery")]
fn confirmed_transfer_outputs(
    canonical: &MigrationState,
    snapshot: &DeliverySnapshot,
) -> Result<Vec<(MigrationTxId, ExactReceivedOutput)>, Error> {
    if canonical.status() != MigrationStatus::Complete {
        return Ok(Vec::new());
    }
    canonical
        .transactions()
        .iter()
        .filter(|transaction| matches!(transaction.kind(), MigrationTxKind::Transfer { .. }))
        .map(|transaction| {
            let claim = snapshot
                .claims()
                .iter()
                .find(|claim| claim.transaction_id() == transaction.id())
                .ok_or(Error::DeliveryArtifactMismatch)?;
            let exact = claim
                .exact_transaction()
                .filter(|_| claim.status() == ClaimStatus::Confirmed)
                .ok_or(Error::DeliveryArtifactMismatch)?;
            let value = canonical
                .transfer_amount(transaction)
                .ok_or(Error::DeliveryArtifactMismatch)?;
            Ok((
                transaction.id(),
                ExactReceivedOutput::new(
                    OutputRef::new(exact.txid(), PoolType::Shielded(ShieldedPool::Ironwood), 0),
                    value,
                ),
            ))
        })
        .collect()
}

/// Archives and replaces one terminal scheduled run inside a caller-owned IMMEDIATE transaction.
/// The predecessor's canonical bytes, terminal claims, policy, finality, destination evidence and
/// source reservations remain independently reconstructible before the canonical parent is reused.
#[cfg(feature = "migration-delivery")]
pub(super) fn rollover_account_source_reservations(
    conn: &Connection,
    t: &Tables,
    account: AccountUuid,
    request: ReservationRollover,
    policy: &SubmissionPolicy,
    submission_context: SubmissionContext,
) -> Result<ReservationRolloverReceipt, Error> {
    if !matches!(
        delivery_schema_provenance(conn, t)?,
        DeliverySchemaProvenance::Compatible(version)
            if version.as_u32() == DELIVERY_SCHEMA_VERSION
    ) {
        return Err(Error::DeliverySchemaIncompatible);
    }
    if !matches!(legacy_cutover_status(conn, t)?, LegacyCutoverStatus::Fresh) {
        return Err(Error::LegacyRecoveryRequired);
    }
    let account_id = account_ref(conn, &account)?.ok_or(Error::AccountUnknown)?;
    let canonical = read_migration(conn, t, account_id)?.ok_or(Error::CanonicalStateMismatch)?;
    let migration_id =
        resolve_migration_id(conn, t, account_id)?.ok_or(Error::CanonicalStateMismatch)?;
    let snapshot = reconcile_delivery(
        conn,
        t,
        account_id,
        Some(submission_context),
        delivery_clock_now(),
        None,
    )?
    .ok_or(Error::CanonicalStateMismatch)?;
    let control = read_delivery_control(conn, t, migration_id, Some(submission_context))?
        .ok_or(Error::Corrupt("delivery control"))?;
    if snapshot.revision() != request.expected_revision() {
        return Err(Error::DeliveryRevisionMismatch);
    }
    if snapshot.run_identity() != request.predecessor_run_identity() {
        return Err(Error::DeliveryRunMismatch);
    }
    if snapshot.source_reservation_owner() != request.predecessor_reservation_owner() {
        return Err(Error::CanonicalOwnerMismatch);
    }
    if migration_state_fingerprint(&canonical) != request.expected_predecessor_fingerprint()
        || snapshot.state_fingerprint() != Some(request.expected_predecessor_fingerprint())
        || !canonical.is_terminal()
    {
        return Err(Error::CanonicalStateMismatch);
    }
    if !snapshot.safe_to_cancel()
        || matches!(
            snapshot.storage_finality(),
            StorageFinality::NoRun | StorageFinality::Active | StorageFinality::RecoveryRequired(_)
        )
    {
        return Err(Error::DeliveryNotSafeToAbandon);
    }

    let confirmed_outputs = confirmed_transfer_outputs(&canonical, &snapshot)?;
    let release = snapshot
        .storage_finality()
        .release()
        .ok_or(Error::Corrupt("rollover predecessor release horizon"))?;
    archive_delivery_evidence(
        conn,
        t,
        migration_id,
        snapshot.run_identity(),
        (!confirmed_outputs.is_empty())
            .then_some((confirmed_outputs.as_slice(), release.release_at())),
    )?;
    let canonical_archive = encode_migration_state_archive(&canonical)
        .map_err(|_| Error::Corrupt("rollover canonical state archive"))?;
    if canonical_archive.fingerprint() != request.expected_predecessor_fingerprint() {
        return Err(Error::CanonicalStateMismatch);
    }
    let destination =
        canonical_destination_spendability(conn, account_id, Some(&canonical), Some(&snapshot))?;
    let destination = match destination {
        DestinationSpendability::NotApplicable => "not_applicable",
        DestinationSpendability::NotSpendable => "not_spendable",
        DestinationSpendability::Spendable => "spendable",
        DestinationSpendability::AlreadySpent => "already_spent",
    };
    let (storage_finality, recovery_reason) = match snapshot.storage_finality() {
        StorageFinality::CompletePendingFinality(_) => ("complete_pending_finality", None),
        StorageFinality::Finalized(_) => ("finalized", None),
        StorageFinality::RecoveryRequired(reason) => (
            "recovery_required",
            Some(match reason {
                StorageRecoveryReason::TransferEvidenceLost => "transfer_evidence_lost",
                StorageRecoveryReason::RewoundBeyondFinalityHorizon => {
                    "rewound_beyond_finality_horizon"
                }
                StorageRecoveryReason::CorruptFinalityEvidence => "corrupt_finality_evidence",
                StorageRecoveryReason::ExternalSigningExposureUnresolved => {
                    "external_signing_exposure_unresolved"
                }
            }),
        ),
        StorageFinality::NoRun | StorageFinality::Active => {
            return Err(Error::DeliveryPhaseMismatch);
        }
    };
    let predecessor_policy = snapshot.submission_policy();
    if !snapshot.claims().is_empty() && predecessor_policy.is_none() {
        return Err(Error::DeliveryPolicyMissing);
    }
    let finality_bytes = snapshot
        .finality_archive()
        .map(FinalityArchive::canonical_bytes);
    let finality_fingerprint = snapshot
        .finality_archive()
        .map(|archive| *archive.fingerprint().as_bytes());
    conn.execute(
        &format!(
            "INSERT INTO {} (
                 run_identity, revision, state_fingerprint, canonical_state_archive,
                 phase, storage_finality, storage_recovery_reason, release_at_height,
                 finalized_tip_height, finality_archive, finality_archive_fingerprint,
                 policy, policy_fingerprint, destination_spendability
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            t.delivery_run_archive
        ),
        params![
            snapshot.run_identity().as_bytes(),
            snapshot.revision().as_u64(),
            canonical_archive.fingerprint().as_bytes(),
            canonical_archive.canonical_bytes(),
            snapshot.phase().as_str(),
            storage_finality,
            recovery_reason,
            u32::from(release.release_at()),
            control.finalized_tip_height.map(u32::from),
            finality_bytes,
            finality_fingerprint,
            predecessor_policy.map(SubmissionPolicy::canonical_bytes),
            predecessor_policy.map(|policy| *policy.fingerprint().as_bytes()),
            destination,
        ],
    )?;

    let successor_lock_owner = LockOwner::random(&mut rand::rngs::OsRng);
    let successor_state = request.successor_state_with_lock_owner(successor_lock_owner);
    let successor_sources = resolvable_canonical_sources(conn, account_id, &successor_state)?;
    if successor_sources.is_empty() {
        return Err(Error::DeliveryRunUnavailable);
    }
    let mut successor_run = MigrationRunIdentity::random(&mut rand::rngs::OsRng);
    while successor_run == snapshot.run_identity() {
        successor_run = MigrationRunIdentity::random(&mut rand::rngs::OsRng);
    }
    let mut successor_source_owner = SourceReservationOwner::random(&mut rand::rngs::OsRng);
    while successor_source_owner == snapshot.source_reservation_owner()
        || successor_source_owner.as_bytes() == successor_lock_owner.as_bytes()
    {
        successor_source_owner = SourceReservationOwner::random(&mut rand::rngs::OsRng);
    }
    let successor_revision = snapshot
        .revision()
        .checked_next()
        .ok_or(Error::DeliveryValueTooLarge)?;
    let successor_fingerprint = migration_state_fingerprint(&successor_state);

    // Retire the predecessor's canonical-delivery authority only after all immutable archive rows
    // exist. Its source reservation rows remain under the predecessor run until their own release.
    conn.execute(
        &format!("DELETE FROM {} WHERE migration_id = ?", t.delivery_claims),
        params![migration_id],
    )?;
    conn.execute(
        &format!("DELETE FROM {} WHERE migration_id = ?", t.delivery_control),
        params![migration_id],
    )?;
    let retired_status = if snapshot.phase() == DeliveryPhase::Abandoned {
        "abandoned"
    } else {
        "finalized"
    };
    let retired_authority_fingerprint = delivery_run_authority_fingerprint(
        snapshot.run_identity().as_bytes(),
        account_id.0,
        "canonical",
        None,
        snapshot.source_reservation_owner().as_bytes(),
        Some(control.canonical_lock_owner.as_bytes()),
    )?;
    let retired = conn.execute(
        &format!(
            "UPDATE {} SET canonical_migration_id = NULL, authority_fingerprint = ?, status = ?
              WHERE run_identity = ? AND account_id = ? AND lane = 'canonical'",
            t.delivery_runs
        ),
        params![
            retired_authority_fingerprint,
            retired_status,
            snapshot.run_identity().as_bytes(),
            account_id.0
        ],
    )?;
    if retired != 1 {
        return Err(Error::DeliveryRunMismatch);
    }

    lock_outputs(
        conn,
        account_id,
        &successor_sources,
        successor_lock_owner,
        BlockHeight::from_u32(u32::MAX),
    )?;
    replace_migration(
        conn,
        t,
        account_id,
        &successor_state,
        CanonicalMutationAuthority::DeliveryCas,
    )?;
    let successor_authority_fingerprint = delivery_run_authority_fingerprint(
        successor_run.as_bytes(),
        account_id.0,
        "canonical",
        Some(migration_id),
        successor_source_owner.as_bytes(),
        Some(successor_lock_owner.as_bytes()),
    )?;
    conn.execute(
        &format!(
            "INSERT INTO {} (
                 run_identity, account_id, lane, canonical_migration_id,
                 source_owner, canonical_lock_owner, authority_fingerprint, status
             ) VALUES (?, ?, 'canonical', ?, ?, ?, ?, 'active')",
            t.delivery_runs
        ),
        params![
            successor_run.as_bytes(),
            account_id.0,
            migration_id,
            successor_source_owner.as_bytes(),
            successor_lock_owner.as_bytes(),
            successor_authority_fingerprint,
        ],
    )?;
    conn.execute(
        &format!(
            "INSERT INTO {} (
                 migration_id, run_identity, revision, state_fingerprint, phase,
                 policy, policy_fingerprint
             ) VALUES (?, ?, ?, ?, 'active', ?, ?)",
            t.delivery_control
        ),
        params![
            migration_id,
            successor_run.as_bytes(),
            successor_revision.as_u64(),
            successor_fingerprint.as_bytes(),
            policy.canonical_bytes(),
            policy.fingerprint().as_bytes(),
        ],
    )?;
    upsert_source_reservations(conn, t, &successor_sources, successor_run)?;
    let successor = delivery_snapshot_after_mutation(conn, t, migration_id, submission_context)?;
    ReservationRolloverReceipt::from_committed_parts(request, successor_state, successor)
        .ok_or(Error::Corrupt("reservation rollover receipt"))
}

/// Rebuild materialization capabilities are store-selected and intentionally never caller-sized.
#[cfg(feature = "migration-delivery")]
const REBUILD_MATERIALIZATION_LEASE_MILLIS: u64 = LeaseDuration::MAX_MILLIS;

/// Replaces one exact positively-expired transfer attempt while retaining the existing run and
/// source owner. The old generation is archived before the canonical row id is reused, so delayed
/// callbacks cannot authenticate against the replacement artifact.
#[cfg(feature = "migration-delivery")]
pub(super) fn rebuild_account_expired_transfer_attempt(
    conn: &Connection,
    t: &Tables,
    account: AccountUuid,
    request: ExpiredTransferRebuild,
    policy: &SubmissionPolicy,
    submission_context: SubmissionContext,
) -> Result<ExpiredTransferRebuildReceipt, Error> {
    if !matches!(
        delivery_schema_provenance(conn, t)?,
        DeliverySchemaProvenance::Compatible(version)
            if version.as_u32() == DELIVERY_SCHEMA_VERSION
    ) {
        return Err(Error::DeliverySchemaIncompatible);
    }
    if !matches!(legacy_cutover_status(conn, t)?, LegacyCutoverStatus::Fresh) {
        return Err(Error::LegacyRecoveryRequired);
    }
    let account_id = account_ref(conn, &account)?.ok_or(Error::AccountUnknown)?;
    let canonical = read_migration(conn, t, account_id)?.ok_or(Error::CanonicalStateMismatch)?;
    let migration_id =
        resolve_migration_id(conn, t, account_id)?.ok_or(Error::CanonicalStateMismatch)?;
    let snapshot = reconcile_delivery(
        conn,
        t,
        account_id,
        Some(submission_context),
        delivery_clock_now(),
        None,
    )?
    .ok_or(Error::CanonicalStateMismatch)?;
    if snapshot.revision() != request.expected_revision() {
        return Err(Error::DeliveryRevisionMismatch);
    }
    if snapshot.run_identity() != request.run_identity() {
        return Err(Error::DeliveryRunMismatch);
    }
    if snapshot.source_reservation_owner() != request.source_reservation_owner() {
        return Err(Error::CanonicalOwnerMismatch);
    }
    if migration_state_fingerprint(&canonical) != request.expected_state_fingerprint()
        || snapshot.state_fingerprint() != Some(request.expected_state_fingerprint())
    {
        return Err(Error::CanonicalStateMismatch);
    }
    require_active(&snapshot)?;
    require_bound_policy(&snapshot, policy.fingerprint())?;
    let prior_identity = request.prior_artifact();
    let prior = snapshot
        .claims()
        .iter()
        .find(|claim| {
            claim.artifact_identity() == DeliveryArtifactIdentity::Scheduled(prior_identity)
        })
        .cloned()
        .ok_or(Error::DeliveryClaimUnavailable)?;
    if !matches!(
        prior.status(),
        ClaimStatus::ExpiredUnmined | ClaimStatus::ExternalSigningExpiredUnmined
    ) || prior.lease().is_some()
    {
        return Err(Error::DeliveryClaimUnavailable);
    }
    let fully_scanned = fully_scanned_height(conn)?
        .filter(|height| u32::from(prior.expiry_height()) != 0 && *height > prior.expiry_height())
        .ok_or(Error::DeliveryClaimUnavailable)?;
    let target_height = canonical_wallet_target_height(conn)?;
    if !reserved_sources_proven_unspent(
        conn,
        t,
        account_id,
        snapshot.run_identity(),
        fully_scanned,
        target_height,
    )? {
        return Err(Error::DeliveryRecoveryRequired);
    }

    let successor_sources =
        resolvable_canonical_sources(conn, account_id, request.successor_state())?
            .into_iter()
            .collect::<BTreeSet<_>>();
    let reserved_sources = {
        let mut stmt = conn.prepare(&format!(
            "SELECT source_txid, source_index FROM {} WHERE run_identity = ?
              AND status = 'active' ORDER BY source_txid, source_index",
            t.delivery_reservations
        ))?;
        stmt.query_map(params![snapshot.run_identity().as_bytes()], |row| {
            Ok(OutputRef::new(
                TxId::from_bytes(row.get::<_, [u8; 32]>(0)?),
                PoolType::Shielded(ShieldedPool::Orchard),
                row.get::<_, u32>(1)?,
            ))
        })?
        .collect::<Result<BTreeSet<_>, _>>()?
    };
    if successor_sources != reserved_sources {
        return Err(Error::DeliveryArtifactMismatch);
    }
    let successor_owner =
        canonical_lock_owner(request.successor_state())?.ok_or(Error::DeliveryRunUnavailable)?;
    let successor_sources = successor_sources.into_iter().collect::<Vec<_>>();
    lock_outputs(
        conn,
        account_id,
        &successor_sources,
        successor_owner,
        BlockHeight::from_u32(u32::MAX),
    )?;

    let transaction_id = prior_identity.transaction_id();
    let canonical_transaction = canonical
        .transactions()
        .iter()
        .find(|transaction| transaction.id() == transaction_id)
        .ok_or(Error::DeliveryArtifactMismatch)?;
    let signer = match prior.signer_ownership() {
        SignerOwnership::Sdk => "sdk",
        SignerOwnership::External => "external",
    };
    let external_pczt = prior.external_signing_pczt();
    let signed_pczt = prior.signed_pczt();
    let exact = prior.exact_transaction();
    conn.execute(
        &format!(
            "INSERT INTO {} (
                 run_identity, tx_id, transaction_fingerprint, pczt_digest,
                 canonical_pczt, signer_ownership, archived_revision, terminal_status,
                 txid, exact_tx, expiry_height, external_signing_pczt_digest,
                 canonical_external_signing_pczt, signed_pczt_digest,
                 canonical_signed_pczt, signed_pczt_binding, policy_fingerprint, last_error
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            t.delivery_attempt_archive
        ),
        params![
            snapshot.run_identity().as_bytes(),
            u32::from(transaction_id),
            prior_identity.transaction_fingerprint().as_bytes(),
            prior
                .pczt_digest()
                .ok_or(Error::DeliveryArtifactMismatch)?
                .as_bytes(),
            canonical_transaction.pczt(),
            signer,
            snapshot.revision().as_u64(),
            prior.status().as_str(),
            exact.map(|exact| *exact.txid().as_ref()),
            exact.map(ExactTransaction::bytes),
            u32::from(prior.expiry_height()),
            external_pczt.map(|pczt| *pczt.digest().as_bytes()),
            external_pczt.map(ExternalSigningPczt::bytes),
            signed_pczt.map(|pczt| *pczt.signed_digest().as_bytes()),
            signed_pczt.map(SignedPcztEvidence::bytes),
            signed_pczt.map(|pczt| *pczt.staged_digest().as_bytes()),
            prior.policy_fingerprint().as_bytes(),
            prior.last_error().map(DeliveryFailureReason::as_str),
        ],
    )?;

    let lease = checked_delivery_lease(
        ClaimKind::Materialization,
        LeaseDuration::from_millis(REBUILD_MATERIALIZATION_LEASE_MILLIS)
            .expect("the store-selected rebuild lease is within the semantic maximum"),
    )?;
    let successor_state = request.successor_state().clone();
    let successor_evidence = scheduled_artifact_evidence(&successor_state, transaction_id)
        .ok_or(Error::DeliveryArtifactMismatch)?;
    if successor_evidence.identity() != request.successor_artifact() {
        return Err(Error::DeliveryArtifactMismatch);
    }
    conn.execute(
        &format!(
            "DELETE FROM {} WHERE migration_id = ? AND tx_id = ?",
            t.delivery_claims
        ),
        params![migration_id, u32::from(transaction_id)],
    )?;
    replace_migration(
        conn,
        t,
        account_id,
        &successor_state,
        CanonicalMutationAuthority::DeliveryCas,
    )?;
    conn.execute(
        &format!(
            "INSERT INTO {} (
                 migration_id, tx_id, pczt_digest, transaction_fingerprint,
                 status, signer_ownership, claim_kind, attempt_token,
                 lease_clock_session, lease_acquired_at_ms, lease_expires_at_ms,
                 policy_fingerprint
             ) VALUES (?, ?, ?, ?, 'materializing', ?, 'materialization', ?, ?, ?, ?, ?)",
            t.delivery_claims
        ),
        params![
            migration_id,
            u32::from(transaction_id),
            successor_evidence.pczt_digest().as_bytes(),
            successor_evidence.transaction_fingerprint().as_bytes(),
            match request.signer_ownership() {
                SignerOwnership::Sdk => "sdk",
                SignerOwnership::External => "external",
            },
            lease.token().as_bytes(),
            lease.acquired_at().session().as_bytes(),
            lease.acquired_at().tick_millis(),
            lease.expires_at().tick_millis(),
            policy.fingerprint().as_bytes(),
        ],
    )?;
    conn.execute(
        &format!(
            "UPDATE {} SET revision = revision + 1, state_fingerprint = ?
              WHERE migration_id = ? AND revision = ? AND revision < ?",
            t.delivery_control
        ),
        params![
            migration_state_fingerprint(&successor_state).as_bytes(),
            migration_id,
            request.expected_revision().as_u64(),
            i64::MAX,
        ],
    )?;
    let delivery = delivery_snapshot_after_mutation(conn, t, migration_id, submission_context)?;
    ExpiredTransferRebuildReceipt::from_committed_parts(request, delivery)
        .ok_or(Error::Corrupt("expired transfer rebuild receipt"))
}

#[cfg(feature = "migration-delivery")]
fn retained_pending_reservation_authority(
    conn: &Connection,
    t: &Tables,
    account_id: AccountRef,
    canonical: &MigrationState,
    snapshot: &DeliverySnapshot,
    release: ReservationRelease,
) -> Result<LockOwner, Error> {
    let run = conn
        .query_row(
            &format!(
                "SELECT account_id, lane, canonical_migration_id, source_owner,
                        canonical_lock_owner, status
                   FROM {} WHERE run_identity = ?",
                t.delivery_runs
            ),
            params![snapshot.run_identity().as_bytes()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                    row.get::<_, [u8; 32]>(3)?,
                    row.get::<_, Option<[u8; 32]>>(4)?,
                    row.get::<_, String>(5)?,
                ))
            },
        )
        .optional()?;
    let Some((stored_account, lane, migration_id, source_owner, stored_lock_owner, status)) = run
    else {
        return Err(Error::Corrupt("retained finality run"));
    };
    let canonical_owner = canonical_lock_owner(canonical)?
        .ok_or(Error::Corrupt("retained finality canonical owner"))?;
    if stored_account != account_id.0
        || lane != "canonical"
        || migration_id.is_some()
        || status != "finalized"
        || source_owner != *snapshot.source_reservation_owner().as_bytes()
        || stored_lock_owner != Some(*canonical_owner.as_bytes())
    {
        return Err(Error::Corrupt("retained finality run authority"));
    }

    let bindings = resolvable_canonical_source_bindings(conn, account_id, canonical)?;
    if bindings.is_empty() {
        return Err(Error::Corrupt("retained finality sources"));
    }
    let reservations = {
        let mut stmt = conn.prepare(&format!(
            "SELECT source_txid, source_index, status, release_at_height,
                    released_tip_height
               FROM {} WHERE run_identity = ?
              ORDER BY source_txid, source_index",
            t.delivery_reservations
        ))?;
        stmt.query_map(params![snapshot.run_identity().as_bytes()], |row| {
            Ok((
                row.get::<_, [u8; 32]>(0)?,
                row.get::<_, u32>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<u32>>(3)?,
                row.get::<_, Option<u32>>(4)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?
    };
    let expected = bindings
        .iter()
        .map(|(output, _)| (*output.txid().as_ref(), output.output_index()))
        .collect::<BTreeSet<_>>();
    let actual = reservations
        .iter()
        .map(|(txid, index, ..)| (*txid, *index))
        .collect::<BTreeSet<_>>();
    if reservations.len() != expected.len()
        || actual != expected
        || reservations
            .iter()
            .any(|(_, _, status, release_height, released_tip)| {
                status != "active"
                    || release_height.map(BlockHeight::from_u32) != Some(release.release_at())
                    || released_tip.is_some()
            })
        || snapshot.active_source_reservation_count()
            != u64::try_from(expected.len()).unwrap_or(u64::MAX)
    {
        return Err(Error::Corrupt("retained finality reservations"));
    }

    let target_height = canonical_wallet_target_height(conn)?;
    for (output, transaction_id) in bindings {
        let claim = snapshot
            .claims()
            .iter()
            .find(|claim| claim.transaction_id() == transaction_id)
            .filter(|claim| claim.status() == ClaimStatus::Confirmed)
            .ok_or(Error::Corrupt("retained finality source claim"))?;
        let expected_spender = claim
            .exact_transaction()
            .map(ExactTransaction::txid)
            .ok_or(Error::Corrupt("retained finality source transaction"))?;
        let lock_owner = conn
            .query_row(
                "SELECT rn.lock_owner
                   FROM orchard_received_notes rn
                   JOIN transactions source ON source.id_tx = rn.transaction_id
                  WHERE rn.account_id = ? AND source.txid = ? AND rn.action_index = ?",
                params![account_id.0, output.txid().as_ref(), output.output_index()],
                |row| row.get::<_, Option<[u8; 32]>>(0),
            )
            .optional()?
            .ok_or(Error::Corrupt("retained finality source note"))?;
        if lock_owner.is_some_and(|owner| owner != *canonical_owner.as_bytes()) {
            return Err(Error::Corrupt("retained finality source lock"));
        }
        let active_spenders = {
            let mut stmt = conn.prepare(&format!(
                "SELECT spender.txid
                   FROM orchard_received_notes rn
                   JOIN transactions source ON source.id_tx = rn.transaction_id
                   JOIN orchard_received_note_spends spends
                     ON spends.orchard_received_note_id = rn.id
                   JOIN transactions spender ON spender.id_tx = spends.transaction_id
                  WHERE rn.account_id = :account_id
                    AND source.txid = :source_txid AND rn.action_index = :source_index
                    AND (spender.block IS NOT NULL OR ({}))
                  ORDER BY spender.id_tx",
                crate::wallet::common::tx_unexpired_condition("spender")
            ))?;
            stmt.query_map(
                named_params! {
                    ":account_id": account_id.0,
                    ":source_txid": output.txid().as_ref(),
                    ":source_index": output.output_index(),
                    ":target_height": u32::from(target_height),
                },
                |row| row.get::<_, [u8; 32]>(0).map(TxId::from_bytes),
            )?
            .collect::<Result<Vec<_>, _>>()?
        };
        if active_spenders.as_slice() != [expected_spender] {
            return Err(Error::Corrupt("retained finality source spender"));
        }
    }
    Ok(canonical_owner)
}

#[cfg(feature = "migration-delivery")]
fn audit_retained_pending_finality(
    conn: &Connection,
    t: &Tables,
    account_id: AccountRef,
    retained: &RetainedMigrationRun,
) -> Result<Option<FinalityAuditResult>, Error> {
    let snapshot = retained.delivery();
    let StorageFinality::CompletePendingFinality(release) = snapshot.storage_finality() else {
        return Ok(None);
    };
    let Some(fully_scanned) = fully_scanned_height(conn)? else {
        return Ok(None);
    };
    if fully_scanned < release.release_at() {
        return Ok(None);
    }
    let canonical = retained
        .canonical_state()
        .ok_or(Error::Corrupt("retained finality canonical state"))?;
    let archive = match scheduled_finality_archive_from_evidence(
        conn,
        t,
        snapshot.run_identity(),
        release,
        canonical,
    ) {
        Ok(Some(archive)) => archive,
        Ok(None) | Err(Error::Corrupt(_) | Error::DeliveryArtifactMismatch) => {
            let reason = StorageRecoveryReason::CorruptFinalityEvidence;
            mark_delivery_run_recovery_required(conn, t, snapshot.run_identity(), reason)?;
            return Ok(Some(FinalityAuditResult::RecoveryRequired(reason)));
        }
        Err(error) => return Err(error),
    };
    let canonical_owner = match retained_pending_reservation_authority(
        conn, t, account_id, canonical, snapshot, release,
    ) {
        Ok(owner) => owner,
        Err(
            Error::Corrupt(_)
            | Error::DeliveryArtifactMismatch
            | Error::OutputNotOwned(_)
            | Error::DeliveryRunUnavailable,
        ) => {
            let reason = StorageRecoveryReason::CorruptFinalityEvidence;
            mark_delivery_run_recovery_required(conn, t, snapshot.run_identity(), reason)?;
            return Ok(Some(FinalityAuditResult::RecoveryRequired(reason)));
        }
        Err(error) => return Err(error),
    };
    let mut observed = Vec::with_capacity(archive.transfers().len());
    for transfer in archive.transfers() {
        if let Some(mined_height) = current_wallet_mined_height(conn, transfer.txid())? {
            observed.push(FinalizedTransferEvidence::new(
                transfer.artifact_identity(),
                transfer.txid(),
                transfer.exact_transaction_digest(),
                mined_height,
            ));
        }
    }
    let result = archive.audit(fully_scanned, &observed);
    if let FinalityAuditResult::RecoveryRequired(reason) = result {
        mark_delivery_run_recovery_required(conn, t, snapshot.run_identity(), reason)?;
        return Ok(Some(result));
    }

    let changed = conn.execute(
        &format!(
            "UPDATE {} SET revision = revision + 1, storage_finality = 'finalized',
                 storage_recovery_reason = NULL, finalized_tip_height = ?,
                 finality_archive = ?, finality_archive_fingerprint = ?
             WHERE run_identity = ? AND revision = ? AND revision < ?
               AND storage_finality = 'complete_pending_finality'
               AND release_at_height = ? AND finalized_tip_height IS NULL
               AND finality_archive IS NULL AND finality_archive_fingerprint IS NULL",
            t.delivery_run_archive
        ),
        params![
            u32::from(fully_scanned),
            archive.canonical_bytes(),
            archive.fingerprint().as_bytes(),
            snapshot.run_identity().as_bytes(),
            snapshot.revision().as_u64(),
            i64::MAX,
            u32::from(release.release_at()),
        ],
    )?;
    if changed != 1 {
        return Err(Error::DeliveryRevisionMismatch);
    }
    transition_source_reservations(
        conn,
        t,
        snapshot.run_identity(),
        snapshot.source_reservation_owner(),
        "finality_released",
        Some(release.release_at()),
        Some(fully_scanned),
    )?;
    release_locks(conn, account_id, &BTreeSet::from([canonical_owner]))?;
    Ok(Some(FinalityAuditResult::Consistent))
}

#[cfg(feature = "migration-delivery")]
fn audit_delivery_snapshot_finality(
    conn: &Connection,
    snapshot: &DeliverySnapshot,
) -> Result<Option<FinalityAuditResult>, Error> {
    match snapshot.storage_finality() {
        StorageFinality::RecoveryRequired(reason) => {
            Ok(Some(FinalityAuditResult::RecoveryRequired(reason)))
        }
        StorageFinality::Finalized(release) => {
            if let Some(archive) = snapshot.finality_archive() {
                let fully_scanned = fully_scanned_height(conn)?.unwrap_or(BlockHeight::from_u32(0));
                let mut observed = Vec::with_capacity(archive.transfers().len());
                for transfer in archive.transfers() {
                    if let Some(mined_height) = current_wallet_mined_height(conn, transfer.txid())?
                    {
                        observed.push(FinalizedTransferEvidence::new(
                            transfer.artifact_identity(),
                            transfer.txid(),
                            transfer.exact_transaction_digest(),
                            mined_height,
                        ));
                    }
                }
                Ok(Some(archive.audit(fully_scanned, &observed)))
            } else if snapshot.released_without_exposure() {
                Ok(Some(FinalityAuditResult::Consistent))
            } else if snapshot.released_after_resolved_unmined_exposure() {
                Ok(Some(
                    if fully_scanned_height(conn)?
                        .is_some_and(|height| height >= release.release_at())
                    {
                        FinalityAuditResult::Consistent
                    } else {
                        FinalityAuditResult::RecoveryRequired(
                            StorageRecoveryReason::RewoundBeyondFinalityHorizon,
                        )
                    },
                ))
            } else {
                Err(Error::Corrupt("missing finality audit evidence"))
            }
        }
        StorageFinality::NoRun
        | StorageFinality::Active
        | StorageFinality::CompletePendingFinality(_) => Ok(None),
    }
}

#[cfg(feature = "migration-delivery")]
fn mark_delivery_run_recovery_required(
    conn: &Connection,
    t: &Tables,
    run_identity: MigrationRunIdentity,
    reason: StorageRecoveryReason,
) -> Result<(), Error> {
    let reason = match reason {
        StorageRecoveryReason::TransferEvidenceLost => "transfer_evidence_lost",
        StorageRecoveryReason::RewoundBeyondFinalityHorizon => "rewound_beyond_finality_horizon",
        StorageRecoveryReason::CorruptFinalityEvidence => "corrupt_finality_evidence",
        StorageRecoveryReason::ExternalSigningExposureUnresolved => {
            "external_signing_exposure_unresolved"
        }
    };
    let current = conn.execute(
        &format!(
            "UPDATE {} SET storage_finality = 'recovery_required',
                 storage_recovery_reason = ?, revision = revision + 1
             WHERE run_identity = ? AND storage_finality != 'recovery_required'
               AND revision < ?",
            t.delivery_control
        ),
        params![reason, run_identity.as_bytes(), i64::MAX],
    )?;
    let retained = conn.execute(
        &format!(
            "UPDATE {} SET storage_finality = 'recovery_required',
                 storage_recovery_reason = ?, revision = revision + 1
             WHERE run_identity = ? AND storage_finality != 'recovery_required'
               AND revision < ?",
            t.delivery_run_archive
        ),
        params![reason, run_identity.as_bytes(), i64::MAX],
    )?;
    let immediate = conn.execute(
        &format!(
            "UPDATE {} SET storage_finality = 'recovery_required',
                 storage_recovery_reason = ?, revision = revision + 1,
                 claim_kind = NULL, attempt_token = NULL, lease_clock_session = NULL,
                 lease_acquired_at_ms = NULL, lease_expires_at_ms = NULL
             WHERE run_identity = ? AND storage_finality != 'recovery_required'
               AND revision < ?",
            t.immediate_delivery
        ),
        params![reason, run_identity.as_bytes(), i64::MAX],
    )?;
    if current + retained + immediate != 1 {
        return Err(Error::Corrupt("duplicate delivery run storage"));
    }
    conn.execute(
        &format!(
            "UPDATE {} SET claim_kind = NULL, attempt_token = NULL,
                 lease_clock_session = NULL, lease_acquired_at_ms = NULL,
                 lease_expires_at_ms = NULL
             WHERE migration_id = (
                 SELECT migration_id FROM {} WHERE run_identity = ?
             )",
            t.delivery_claims, t.delivery_control
        ),
        params![run_identity.as_bytes()],
    )?;
    if current + immediate == 1 {
        let changed = conn.execute(
            &format!(
                "UPDATE {} SET status = 'recovery_required' WHERE run_identity = ?",
                t.delivery_runs
            ),
            params![run_identity.as_bytes()],
        )?;
        if changed != 1 {
            return Err(Error::Corrupt("delivery recovery run transition"));
        }
    } else {
        // A retained predecessor no longer owns the account's current lane. Its archive and
        // reservation rows carry recovery authority; keeping the parent run terminal avoids
        // falsely occupying the account-wide live-lane uniqueness slot.
        let terminal: bool = conn.query_row(
            &format!(
                "SELECT status IN ('finalized', 'abandoned') FROM {}
                  WHERE run_identity = ? AND canonical_migration_id IS NULL",
                t.delivery_runs
            ),
            params![run_identity.as_bytes()],
            |row| row.get(0),
        )?;
        if !terminal {
            return Err(Error::Corrupt("retained recovery run authority"));
        }
    }
    conn.execute(
        &format!(
            "UPDATE {} SET status = 'recovery_required'
              WHERE run_identity = ? AND status IN ('active', 'finality_released')",
            t.delivery_reservations
        ),
        params![run_identity.as_bytes()],
    )?;
    Ok(())
}

/// Audits every current and retained finality record from one caller-owned atomic database view.
/// A failed audit is durably converted to recovery authority before the result is returned, so a
/// later ordinary spend/runtime read cannot ignore evidence invalidated by a deep rewind.
#[cfg(feature = "migration-delivery")]
pub(super) fn audit_account_finality_archives(
    conn: &Connection,
    t: &Tables,
    account: AccountUuid,
    submission_context: SubmissionContext,
) -> Result<Vec<RunFinalityAudit>, Error> {
    let Some(runtime) = load_account_migration_runtime(conn, t, account, submission_context)?
    else {
        return Ok(Vec::new());
    };
    let account_id = account_ref(conn, &account)?.ok_or(Error::AccountUnknown)?;
    let mut audits = Vec::new();
    if let Some(current) = runtime.runtime().delivery() {
        if let Some(result) = audit_delivery_snapshot_finality(conn, current)? {
            if let FinalityAuditResult::RecoveryRequired(reason) = result {
                mark_delivery_run_recovery_required(conn, t, current.run_identity(), reason)?;
            }
            audits.push(RunFinalityAudit::new(current.run_identity(), result));
        }
    }
    for retained in runtime.runtime().retained_predecessors() {
        let snapshot = retained.delivery();
        let result = if matches!(
            snapshot.storage_finality(),
            StorageFinality::CompletePendingFinality(_)
        ) {
            // This helper performs both the successful CAS/release and its fail-closed recovery
            // transition, so its recovery result must not be applied a second time below.
            audit_retained_pending_finality(conn, t, account_id, retained)?
        } else {
            let result = audit_delivery_snapshot_finality(conn, snapshot)?;
            if let Some(FinalityAuditResult::RecoveryRequired(reason)) = result {
                mark_delivery_run_recovery_required(conn, t, snapshot.run_identity(), reason)?;
            }
            result
        };
        if let Some(result) = result {
            audits.push(RunFinalityAudit::new(snapshot.run_identity(), result));
        }
    }
    Ok(audits)
}

// ---------------------------------------------------------------------------
// The store
// ---------------------------------------------------------------------------

/// The generic pool-migration store: it carries the [`PoolMigrationRead`] / [`PoolMigrationWrite`]
/// logic over a `rusqlite::Connection`, parameterized by the [`Tables`] names for a given pool and
/// scoped to a single account's migration. Construct it with a connection borrow (`&Connection` for
/// read-only access, `&mut Connection` to also write) plus the pool's table names and the account;
/// a concrete facade wraps it so the generic type never appears in the public API.
///
/// [`PoolMigrationRead`]: zcash_pool_migration::engine::PoolMigrationRead
/// [`PoolMigrationWrite`]: zcash_pool_migration::engine::PoolMigrationWrite
pub(crate) struct Store<C> {
    conn: C,
    tables: &'static Tables,
    account_id: AccountRef,
    #[cfg(feature = "migration-delivery")]
    submission_context: Option<SubmissionContext>,
}

impl<C> Store<C> {
    pub(crate) fn new(conn: C, tables: &'static Tables, account_id: AccountRef) -> Self {
        Self {
            conn,
            tables,
            account_id,
            #[cfg(feature = "migration-delivery")]
            submission_context: None,
        }
    }

    #[cfg(feature = "migration-delivery")]
    pub(crate) fn new_with_submission_context(
        conn: C,
        tables: &'static Tables,
        account_id: AccountRef,
        submission_context: SubmissionContext,
    ) -> Self {
        Self {
            conn,
            tables,
            account_id,
            submission_context: Some(submission_context),
        }
    }

    pub(crate) fn into_inner(self) -> C {
        self.conn
    }

    #[cfg(feature = "migration-delivery")]
    fn submission_context(&self) -> Result<SubmissionContext, Error> {
        self.submission_context
            .ok_or(Error::DeliveryContextUnavailable)
    }
}

impl<C: Borrow<Connection>> Store<C> {
    pub(crate) fn get_migration(&self) -> Result<Option<MigrationState>, Error> {
        read_migration(self.conn.borrow(), self.tables, self.account_id)
    }

    /// Returns the set of [`LockOwner`]s under which this account's in-progress migration has
    /// locked notes (empty if the account has no migration, or none of its transactions hold a
    /// lock).
    pub(crate) fn migration_lock_owners(&self) -> Result<BTreeSet<LockOwner>, Error> {
        read_lock_owners(self.conn.borrow(), self.tables, self.account_id)
    }

    #[cfg(feature = "migration-delivery")]
    pub(crate) fn delivery_schema_provenance(&self) -> Result<DeliverySchemaProvenance, Error> {
        delivery_schema_provenance(self.conn.borrow(), self.tables)
    }

    #[cfg(feature = "migration-delivery")]
    pub(crate) fn legacy_cutover_status(&self) -> Result<LegacyCutoverStatus, Error> {
        legacy_cutover_status(self.conn.borrow(), self.tables)
    }

    /// Classifies an exact Ironwood output using only canonical wallet rows and the same
    /// confirmation, anchor, witness, economic, spentness, and lock rules as ordinary note
    /// selection.
    #[cfg(feature = "migration-delivery")]
    pub(crate) fn received_output_availability(
        &self,
        output: ExactReceivedOutput,
        target_height: TargetHeight,
        confirmations_policy: ConfirmationsPolicy,
        lock_filter: LockFilter<'_>,
    ) -> Result<ReceivedOutputAvailability, Error> {
        received_output_availability(
            self.conn.borrow(),
            self.account_id,
            output,
            target_height,
            confirmations_policy,
            lock_filter,
        )
    }
}

impl<C: BorrowMut<Connection>> Store<C> {
    pub(crate) fn replace_migration(&mut self, state: &MigrationState) -> Result<(), Error> {
        let tables = self.tables;
        let account_id = self.account_id;
        let tx = self
            .conn
            .borrow_mut()
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        #[cfg(feature = "migration-delivery")]
        if sqlite_object_exists(&tx, tables.delivery_meta)?
            && !state.is_terminal()
            && !state.transactions().is_empty()
        {
            // A real live migration must enter SQLite through
            // `PoolMigrationLockStore::lock_outputs_and_replace_migration`. That seam writes the
            // canonical state, exact physical locks, run/control authority, and typed source
            // reservations in one IMMEDIATE transaction. Letting the generic pool-agnostic seam
            // persist the same state first would create an unlocked/unowned crash window.
            return Err(Error::DeliveryPhaseMismatch);
        }
        replace_migration(
            &tx,
            tables,
            account_id,
            state,
            CanonicalMutationAuthority::Ordinary,
        )?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn update_transaction(
        &mut self,
        id: MigrationTxId,
        state: MigrationTxState,
    ) -> Result<(), Error> {
        let tables = self.tables;
        let account_id = self.account_id;
        let tx = self
            .conn
            .borrow_mut()
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let migration_id = resolve_migration_id(&tx, tables, account_id)?
            .ok_or(Error::Corrupt("update_transaction: no such transaction"))?;
        #[cfg(feature = "migration-delivery")]
        if sqlite_object_exists(&tx, tables.delivery_control)?
            && delivery_control_exists(&tx, tables, migration_id)?
        {
            // Once delivery authority exists, transaction lifecycle changes must be committed by
            // a delivery CAS operation that also advances exact-artifact evidence. The generic
            // engine seam cannot make those writes independently.
            return Err(Error::DeliveryPhaseMismatch);
        }
        let updated = tx.execute(
            &format!(
                "UPDATE {}
                    SET state = :state, txid = :txid, mined_height = :mined_height
                  WHERE migration_id = :migration_id AND tx_id = :tx_id",
                tables.transactions
            ),
            named_params! {
                ":state": state.as_ref(),
                ":txid": state.broadcast_txid().map(hex::encode),
                ":mined_height": state.mined_height().map(u32::from),
                ":migration_id": migration_id,
                ":tx_id": u32::from(id),
            },
        )?;
        if updated == 0 {
            return Err(Error::Corrupt("update_transaction: no such transaction"));
        }
        tx.commit()?;
        Ok(())
    }

    /// Acquire the exact migration input locks and replace the canonical migration state in the
    /// same SQLite transaction. Any lock conflict or store error rolls both halves back.
    #[cfg(feature = "migration-delivery")]
    pub(crate) fn lock_outputs_and_replace_migration(
        &mut self,
        expected: Option<&MigrationState>,
        state: &MigrationState,
        outputs: &[OutputRef],
        owner: LockOwner,
        lock_expiry_height: BlockHeight,
    ) -> Result<(), Error> {
        let tables = self.tables;
        let account_id = self.account_id;
        let submission_context = self.submission_context;
        let tx = self
            .conn
            .borrow_mut()
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        require_canonical_state(&tx, tables, account_id, expected)?;
        let existing_run = if let Some(migration_id) =
            resolve_migration_id(&tx, tables, account_id)?
            && sqlite_object_exists(&tx, tables.delivery_control)?
            && delivery_control_exists(&tx, tables, migration_id)?
        {
            if expected != Some(state) {
                // This generic lock-store seam may refresh exact physical locks for an unchanged
                // delivery-owned snapshot, but it cannot authorize any PCZT, schedule, lifecycle,
                // owner, or phase mutation. Those changes require their dedicated typed delivery
                // CAS.
                return Err(Error::DeliveryPhaseMismatch);
            }
            Some(tx.query_row(
                &format!(
                    "SELECT run_identity FROM {} WHERE migration_id = ?",
                    tables.delivery_control
                ),
                params![migration_id],
                |row| row.get::<_, [u8; 32]>(0),
            )?)
        } else {
            None
        };
        require_canonical_owner(&tx, tables, account_id, &BTreeSet::from([owner]))?;
        lock_outputs(&tx, account_id, outputs, owner, lock_expiry_height)?;
        if let Some(run_identity) = existing_run {
            let run_identity = MigrationRunIdentity::read(run_identity.as_slice())
                .map_err(|_| Error::Corrupt("delivery run identity"))?;
            // A refresh receives the complete currently-resolvable source set. Newly scanned
            // dependent outputs join the same run in this transaction; stale or substituted rows
            // are rejected by the exact provenance comparison below and roll every write back.
            upsert_source_reservations(&tx, tables, outputs, run_identity)?;
        }
        replace_migration(
            &tx,
            tables,
            account_id,
            state,
            CanonicalMutationAuthority::DeliveryCas,
        )?;
        reconcile_delivery(
            &tx,
            tables,
            account_id,
            submission_context,
            delivery_clock_now(),
            Some(outputs),
        )?
        .ok_or(Error::Corrupt("delivery canonical migration"))?;
        if !scheduled_reservations_are_complete(&tx, tables)? {
            return Err(Error::DeliveryArtifactMismatch);
        }
        tx.commit()?;
        Ok(())
    }

    /// Release only locks owned by this migration and replace its terminal state in one SQLite
    /// transaction. Locks belonging to another in-flight flow are never touched.
    #[cfg(feature = "migration-delivery")]
    pub(crate) fn release_locks_and_replace_migration(
        &mut self,
        expected: &MigrationState,
        state: &MigrationState,
        owners: &BTreeSet<LockOwner>,
    ) -> Result<(), Error> {
        let tables = self.tables;
        let account_id = self.account_id;
        let tx = self.conn.borrow_mut().transaction()?;
        require_canonical_state(&tx, tables, account_id, Some(expected))?;
        if let Some(migration_id) = resolve_migration_id(&tx, tables, account_id)?
            && sqlite_object_exists(&tx, tables.delivery_control)?
            && delivery_control_exists(&tx, tables, migration_id)?
        {
            // Delivery-enabled migrations must use the atomic abandonment protocol. This generic
            // lock-store seam may not bypass claim reconciliation or phase CAS.
            return Err(Error::DeliveryPhaseMismatch);
        }
        require_canonical_owner(&tx, tables, account_id, owners)?;
        release_locks(&tx, account_id, owners)?;
        replace_migration(
            &tx,
            tables,
            account_id,
            state,
            CanonicalMutationAuthority::Ordinary,
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Acquire an immediate SQLite write transaction before reading exact-output evidence. Normal
    /// wallet-policy spendability is returned independently from the fixed storage-finality
    /// horizon; source owners/locks are released only after every exact transfer is on the fully
    /// scanned active chain with `PRUNING_DEPTH + 1` confirmations.
    #[cfg(feature = "migration-delivery")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn finalize_migration_if_outputs_available(
        &mut self,
        expected: &MigrationState,
        finalized: &MigrationState,
        owners: &BTreeSet<LockOwner>,
        outputs: &[(MigrationTxId, ExactReceivedOutput)],
        target_height: TargetHeight,
        confirmations_policy: ConfirmationsPolicy,
        lock_filter: LockFilter<'_>,
    ) -> Result<MigrationFinalizationAudit, Error> {
        let tables = self.tables;
        let account_id = self.account_id;
        let submission_context = self.submission_context()?;
        let tx = self
            .conn
            .borrow_mut()
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        require_canonical_state(&tx, tables, account_id, Some(expected))?;
        require_canonical_owner(&tx, tables, account_id, owners)?;
        let snapshot = reconcile_delivery(
            &tx,
            tables,
            account_id,
            Some(submission_context),
            delivery_clock_now(),
            None,
        )?
        .ok_or(Error::Corrupt("delivery canonical migration"))?;

        require_exact_finalized_successor(expected, finalized, owners)?;
        let expected_transfer_ids = expected
            .transactions()
            .iter()
            .filter(|transaction| matches!(transaction.kind(), MigrationTxKind::Transfer { .. }))
            .map(|transaction| u32::from(transaction.id()))
            .collect::<BTreeSet<_>>();
        let provided_transfer_ids = outputs
            .iter()
            .map(|(transaction_id, _)| u32::from(*transaction_id))
            .collect::<BTreeSet<_>>();
        let provided_output_refs = outputs
            .iter()
            .map(|(_, output)| output.output_ref())
            .collect::<BTreeSet<_>>();
        if expected_transfer_ids.is_empty()
            || outputs.len() != expected_transfer_ids.len()
            || provided_transfer_ids != expected_transfer_ids
            || provided_output_refs.len() != outputs.len()
        {
            return Err(Error::DeliveryArtifactMismatch);
        }
        for (transaction_id, output) in outputs {
            let canonical = expected
                .transactions()
                .iter()
                .find(|transaction| transaction.id() == *transaction_id)
                .ok_or(Error::DeliveryArtifactMismatch)?;
            let claim = snapshot
                .claims()
                .iter()
                .find(|claim| claim.transaction_id() == *transaction_id)
                .ok_or(Error::DeliveryArtifactMismatch)?;
            let exact = claim
                .exact_transaction()
                .ok_or(Error::DeliveryArtifactMismatch)?;
            if claim.status() != ClaimStatus::Confirmed
                || exact.txid() != *output.output_ref().txid()
                || output.output_ref().pool() != PoolType::Shielded(ShieldedPool::Ironwood)
                || output.output_ref().output_index() != 0
                || expected.transfer_amount(canonical) != Some(output.value())
            {
                return Err(Error::DeliveryArtifactMismatch);
            }
        }

        let evidence = outputs
            .iter()
            .map(|(transaction_id, output)| {
                received_output_availability(
                    &tx,
                    account_id,
                    *output,
                    target_height,
                    confirmations_policy,
                    lock_filter,
                )
                .map(|availability| {
                    MigrationOutputAvailability::new(*transaction_id, *output, availability)
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        if let StorageFinality::RecoveryRequired(reason) = snapshot.storage_finality() {
            tx.commit()?;
            return Ok(MigrationFinalizationAudit::new(
                evidence,
                StorageFinality::RecoveryRequired(reason),
            ));
        }
        if let StorageFinality::Finalized(release) = snapshot.storage_finality() {
            tx.commit()?;
            return Ok(MigrationFinalizationAudit::new(
                evidence,
                StorageFinality::Finalized(release),
            ));
        }

        let fixed_target = TargetHeight::from(canonical_wallet_target_height(&tx)?);
        let fixed_policy = ConfirmationsPolicy::new_symmetrical(
            NonZeroU32::new(MIGRATION_STORAGE_FINALITY_CONFIRMATIONS)
                .expect("PRUNING_DEPTH + 1 is nonzero"),
            #[cfg(feature = "transparent-inputs")]
            false,
        );
        let fixed_lock_policy = LockedInputPolicy::Exclude;
        let fixed_evidence = outputs
            .iter()
            .map(|(transaction_id, output)| {
                received_output_availability(
                    &tx,
                    account_id,
                    *output,
                    fixed_target,
                    fixed_policy,
                    LockFilter::Policy(&fixed_lock_policy),
                )
                .map(|availability| {
                    MigrationOutputAvailability::new(*transaction_id, *output, availability)
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let fixed_outputs_available = fixed_evidence.iter().all(|entry| {
            matches!(
                entry.availability(),
                ReceivedOutputAvailability::Spendable | ReceivedOutputAvailability::Spent { .. }
            )
        });

        let fully_scanned = fully_scanned_height(&tx)?;
        let mut transfers_stable = true;
        for (transaction_id, output) in outputs {
            let canonical_height = expected
                .transactions()
                .iter()
                .find(|transaction| transaction.id() == *transaction_id)
                .and_then(|transaction| transaction.state().mined_height());
            let Some(mined_height) = canonical_height else {
                transfers_stable = false;
                break;
            };
            let wallet_height = current_wallet_mined_height(&tx, *output.output_ref().txid())?;
            let sufficiently_scanned = fully_scanned.is_some_and(|scanned| {
                u32::from(scanned)
                    >= u32::from(mined_height)
                        .saturating_add(MIGRATION_STORAGE_FINALITY_CONFIRMATIONS - 1)
            });
            if wallet_height != Some(mined_height) || !sufficiently_scanned {
                transfers_stable = false;
                break;
            }
        }
        let claims_confirmed = outputs.iter().all(|(transaction_id, _)| {
            snapshot.claims().iter().any(|claim| {
                claim.transaction_id() == *transaction_id
                    && claim.status() == ClaimStatus::Confirmed
            })
        });
        let storage_finalized = fixed_outputs_available && transfers_stable && claims_confirmed;
        if storage_finalized {
            let tip = BlockHeight::from(fixed_target).saturating_sub(1);
            let migration_id = resolve_migration_id(&tx, tables, account_id)?
                .ok_or(Error::Corrupt("delivery canonical migration"))?;
            let release_at_height =
                read_delivery_control(&tx, tables, migration_id, Some(submission_context))?
                    .and_then(|control| control.release_at_height)
                    .ok_or(Error::Corrupt("delivery finality release height"))?;
            if tip < release_at_height {
                return Err(Error::Corrupt("premature delivery finality"));
            }
            tx.execute(
                &format!(
                    "UPDATE {} SET storage_finality = 'finalized', finalized_tip_height = ?
                     WHERE migration_id = ?",
                    tables.delivery_control
                ),
                params![u32::from(tip), migration_id],
            )?;
            tx.execute(
                &format!(
                    "UPDATE {} SET status = 'finalized' WHERE run_identity = ?",
                    tables.delivery_runs
                ),
                params![snapshot.run_identity().as_bytes()],
            )?;
            archive_delivery_evidence(
                &tx,
                tables,
                migration_id,
                snapshot.run_identity(),
                Some((outputs, release_at_height)),
            )?;
            transition_source_reservations(
                &tx,
                tables,
                snapshot.run_identity(),
                snapshot.source_reservation_owner(),
                "finality_released",
                Some(release_at_height),
                Some(tip),
            )?;
            release_locks(&tx, account_id, owners)?;
            replace_migration(
                &tx,
                tables,
                account_id,
                finalized,
                CanonicalMutationAuthority::DeliveryCas,
            )?;
            tx.execute(
                &format!(
                    "UPDATE {} SET state_fingerprint = ? WHERE migration_id = ?",
                    tables.delivery_control
                ),
                params![
                    migration_state_fingerprint(finalized).as_bytes(),
                    migration_id
                ],
            )?;
            bump_delivery_revision(&tx, tables, migration_id)?;
        }
        tx.commit()?;
        Ok(MigrationFinalizationAudit::new(
            evidence,
            if storage_finalized {
                StorageFinality::Finalized(ReservationRelease::at(
                    canonical_transfer_release_height(finalized)?
                        .ok_or(Error::Corrupt("delivery finality release height"))?,
                ))
            } else {
                snapshot.storage_finality()
            },
        ))
    }

    #[cfg(feature = "migration-delivery")]
    pub(crate) fn delivery_snapshot(&mut self) -> Result<Option<DeliverySnapshot>, Error> {
        let tables = self.tables;
        let account_id = self.account_id;
        let submission_context = self.submission_context()?;
        let tx = self
            .conn
            .borrow_mut()
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let snapshot = reconcile_delivery(
            &tx,
            tables,
            account_id,
            Some(submission_context),
            delivery_clock_now(),
            None,
        )?;
        tx.commit()?;
        Ok(snapshot)
    }

    #[cfg(feature = "migration-delivery")]
    pub(crate) fn bind_submission_policy(
        &mut self,
        expected_state: &MigrationState,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        policy: &SubmissionPolicy,
    ) -> Result<DeliverySnapshot, Error> {
        if policy.canonical_bytes().len() > MAX_SUBMISSION_POLICY_BYTES {
            return Err(Error::DeliveryValueTooLarge);
        }
        let tables = self.tables;
        let account_id = self.account_id;
        let submission_context = self.submission_context()?;
        let tx = self
            .conn
            .borrow_mut()
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let (migration_id, snapshot) = require_delivery_context(
            &tx,
            tables,
            account_id,
            expected_state,
            expected_revision,
            run_identity,
            submission_context,
            delivery_clock_now(),
        )?;
        require_active(&snapshot)?;
        match snapshot.submission_policy() {
            Some(bound) if bound == policy => {}
            Some(_) => return Err(Error::DeliveryPolicyAlreadyBound),
            None => {
                tx.execute(
                    &format!(
                        "UPDATE {} SET policy = ?, policy_fingerprint = ?,
                             policy_validation_failure = NULL
                         WHERE migration_id = ?",
                        tables.delivery_control
                    ),
                    params![
                        policy.canonical_bytes(),
                        policy.fingerprint().as_bytes(),
                        migration_id
                    ],
                )?;
                bump_delivery_revision(&tx, tables, migration_id)?;
            }
        }
        let result =
            delivery_snapshot_after_mutation(&tx, tables, migration_id, submission_context)?;
        tx.commit()?;
        Ok(result)
    }

    #[cfg(feature = "migration-delivery")]
    pub(crate) fn record_policy_validation_failure(
        &mut self,
        expected_state: &MigrationState,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        failure: PolicyValidationFailure,
    ) -> Result<DeliverySnapshot, Error> {
        let tables = self.tables;
        let account_id = self.account_id;
        let submission_context = self.submission_context()?;
        let tx = self
            .conn
            .borrow_mut()
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let (migration_id, snapshot) = require_delivery_context(
            &tx,
            tables,
            account_id,
            expected_state,
            expected_revision,
            run_identity,
            submission_context,
            delivery_clock_now(),
        )?;
        require_active(&snapshot)?;
        tx.execute(
            &format!(
                "UPDATE {} SET policy_validation_failure = ? WHERE migration_id = ?",
                tables.delivery_control
            ),
            params![failure.as_str(), migration_id],
        )?;
        bump_delivery_revision(&tx, tables, migration_id)?;
        let result =
            delivery_snapshot_after_mutation(&tx, tables, migration_id, submission_context)?;
        tx.commit()?;
        Ok(result)
    }

    #[cfg(feature = "migration-delivery")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn claim_materialization(
        &mut self,
        expected_state: &MigrationState,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        evidence: &DeliveryArtifactEvidence,
        signer_ownership: SignerOwnership,
        lease_duration: LeaseDuration,
        expected_policy_fingerprint: PolicyFingerprint,
    ) -> Result<Option<DeliverySnapshot>, Error> {
        let transaction_id = evidence
            .scheduled_transaction_id()
            .ok_or(Error::DeliveryArtifactMismatch)?;
        let canonical_evidence = scheduled_artifact_evidence(expected_state, transaction_id)
            .map(DeliveryArtifactEvidence::Scheduled)
            .ok_or(Error::DeliveryArtifactMismatch)?;
        if &canonical_evidence != evidence {
            return Err(Error::DeliveryArtifactMismatch);
        }
        let canonical = expected_state
            .transactions()
            .iter()
            .find(|transaction| transaction.id() == transaction_id)
            .ok_or(Error::DeliveryArtifactMismatch)?;
        let state_is_materializable = match signer_ownership {
            // The SDK owns both signing and proving. It must acquire the materialization
            // capability while the canonical artifact is Signed, use that same live token for
            // the sealed Signed -> Proved CAS, and then stage the exact extracted transaction.
            // Proved is also accepted so an interrupted worker can resume exact extraction.
            SignerOwnership::Sdk => matches!(
                canonical.state(),
                MigrationTxState::Signed | MigrationTxState::Proved
            ),
            SignerOwnership::External => matches!(
                canonical.state(),
                MigrationTxState::AwaitingSignature | MigrationTxState::Signed
            ),
        };
        if !state_is_materializable {
            return Err(Error::DeliveryClaimUnavailable);
        }
        let lease = checked_delivery_lease(ClaimKind::Materialization, lease_duration)?;
        let tables = self.tables;
        let account_id = self.account_id;
        let submission_context = self.submission_context()?;
        let tx = self
            .conn
            .borrow_mut()
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let (migration_id, snapshot) = require_delivery_context(
            &tx,
            tables,
            account_id,
            expected_state,
            expected_revision,
            run_identity,
            submission_context,
            delivery_clock_now(),
        )?;
        require_active(&snapshot)?;
        require_bound_policy(&snapshot, expected_policy_fingerprint)?;
        if let Some(claim) = snapshot
            .claims()
            .iter()
            .find(|claim| claim.artifact_identity() == evidence.identity())
        {
            match claim.status() {
                ClaimStatus::AwaitingExternalSignature => {
                    if signer_ownership != SignerOwnership::External
                        || claim.signer_ownership() != SignerOwnership::External
                    {
                        return Err(Error::DeliveryClaimUnavailable);
                    }
                    if claim.lease().is_some_and(|existing| {
                        existing.validity_at(lease.acquired_at()) == LeaseValidity::Live
                    }) {
                        tx.commit()?;
                        return Ok(None);
                    }
                    // Reacquire only the Rust-owned capability fields. Staged unsigned and signed
                    // PCZT evidence has crossed an external trust boundary and must remain byte
                    // exact across process/session changes and lease expiry.
                    tx.execute(
                        &format!(
                            "UPDATE {} SET claim_kind = 'materialization', attempt_token = ?,
                             lease_clock_session = ?, lease_acquired_at_ms = ?,
                             lease_expires_at_ms = ?
                             WHERE migration_id = ? AND tx_id = ?",
                            tables.delivery_claims
                        ),
                        params![
                            lease.token().as_bytes(),
                            lease.acquired_at().session().as_bytes(),
                            lease.acquired_at().tick_millis(),
                            lease.expires_at().tick_millis(),
                            migration_id,
                            u32::from(transaction_id),
                        ],
                    )?;
                    bump_delivery_revision(&tx, tables, migration_id)?;
                    let result = delivery_snapshot_after_mutation(
                        &tx,
                        tables,
                        migration_id,
                        submission_context,
                    )?;
                    tx.commit()?;
                    return Ok(Some(result));
                }
                ClaimStatus::MaterializationFailed => {}
                ClaimStatus::Materializing
                | ClaimStatus::Staged
                | ClaimStatus::Submitting
                | ClaimStatus::OutcomeUnknown
                | ClaimStatus::Broadcasted
                | ClaimStatus::Confirmed
                | ClaimStatus::ExpiredUnmined
                | ClaimStatus::ExternalSigningExpiredUnmined => {
                    tx.commit()?;
                    return Ok(None);
                }
            }
        }
        tx.execute(
            &format!(
                "INSERT INTO {} (
                     migration_id, tx_id, pczt_digest, transaction_fingerprint, status,
                     signer_ownership, claim_kind, attempt_token, lease_clock_session,
                     lease_acquired_at_ms, lease_expires_at_ms, policy_fingerprint
                 ) VALUES (?, ?, ?, ?, 'materializing', ?, 'materialization', ?, ?, ?, ?, ?)
                 ON CONFLICT(migration_id, tx_id) DO UPDATE SET
                     pczt_digest = excluded.pczt_digest,
                     transaction_fingerprint = excluded.transaction_fingerprint,
                     status = 'materializing',
                     signer_ownership = excluded.signer_ownership,
                     claim_kind = 'materialization',
                     attempt_token = excluded.attempt_token,
                     lease_clock_session = excluded.lease_clock_session,
                     lease_acquired_at_ms = excluded.lease_acquired_at_ms,
                     lease_expires_at_ms = excluded.lease_expires_at_ms,
                     txid = NULL,
                     exact_tx = NULL,
                     external_signing_pczt_digest = NULL,
                     canonical_external_signing_pczt = NULL,
                     signed_pczt_digest = NULL,
                     canonical_signed_pczt = NULL,
                     signed_pczt_binding = NULL,
                     policy_fingerprint = excluded.policy_fingerprint,
                     last_error = NULL",
                tables.delivery_claims
            ),
            params![
                migration_id,
                u32::from(transaction_id),
                evidence
                    .pczt_digest()
                    .ok_or(Error::DeliveryArtifactMismatch)?
                    .as_bytes(),
                evidence
                    .transaction_fingerprint()
                    .ok_or(Error::DeliveryArtifactMismatch)?
                    .as_bytes(),
                match signer_ownership {
                    SignerOwnership::Sdk => "sdk",
                    SignerOwnership::External => "external",
                },
                lease.token().as_bytes(),
                lease.acquired_at().session().as_bytes(),
                lease.acquired_at().tick_millis(),
                lease.expires_at().tick_millis(),
                expected_policy_fingerprint.as_bytes(),
            ],
        )?;
        bump_delivery_revision(&tx, tables, migration_id)?;
        let result =
            delivery_snapshot_after_mutation(&tx, tables, migration_id, submission_context)?;
        tx.commit()?;
        Ok(Some(result))
    }

    #[cfg(feature = "migration-delivery")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn stage_external_signing_pczt(
        &mut self,
        expected_state: &MigrationState,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        artifact_identity: DeliveryArtifactIdentity,
        token: ClaimToken,
        pczt: &ExternalSigningPczt,
        expected_policy_fingerprint: PolicyFingerprint,
    ) -> Result<DeliverySnapshot, Error> {
        let transaction_id =
            require_scheduled_artifact_identity(expected_state, artifact_identity)?;
        let evidence = scheduled_artifact_evidence(expected_state, transaction_id)
            .ok_or(Error::DeliveryArtifactMismatch)?;
        if evidence.canonical_pczt() != pczt.bytes() || evidence.pczt_digest() != pczt.digest() {
            return Err(Error::DeliveryArtifactMismatch);
        }
        let tables = self.tables;
        let account_id = self.account_id;
        let submission_context = self.submission_context()?;
        let now = delivery_clock_now();
        let tx = self
            .conn
            .borrow_mut()
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let (migration_id, snapshot) = require_delivery_context(
            &tx,
            tables,
            account_id,
            expected_state,
            expected_revision,
            run_identity,
            submission_context,
            now,
        )?;
        require_active(&snapshot)?;
        require_bound_policy(&snapshot, expected_policy_fingerprint)?;
        let claim = snapshot
            .claims()
            .iter()
            .find(|claim| claim.artifact_identity() == artifact_identity)
            .ok_or(Error::DeliveryClaimUnavailable)?;
        if claim.signer_ownership() != SignerOwnership::External
            || claim.status() != ClaimStatus::Materializing
            || claim.token() != Some(token)
            || claim
                .lease()
                .is_none_or(|lease| lease.validity_at(now) != LeaseValidity::Live)
        {
            return Err(Error::DeliveryClaimUnavailable);
        }
        tx.execute(
            &format!(
                "UPDATE {} SET status = 'awaiting_external_signature',
                     external_signing_pczt_digest = ?, canonical_external_signing_pczt = ?
                 WHERE migration_id = ? AND tx_id = ?",
                tables.delivery_claims
            ),
            params![
                pczt.digest().as_bytes(),
                pczt.bytes(),
                migration_id,
                u32::from(transaction_id)
            ],
        )?;
        bump_delivery_revision(&tx, tables, migration_id)?;
        let result =
            delivery_snapshot_after_mutation(&tx, tables, migration_id, submission_context)?;
        tx.commit()?;
        Ok(result)
    }

    #[cfg(feature = "migration-delivery")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn stage_signed_pczt(
        &mut self,
        expected_state: &MigrationState,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        artifact_identity: DeliveryArtifactIdentity,
        token: ClaimToken,
        signed_pczt: &SignedPcztEvidence,
        expected_policy_fingerprint: PolicyFingerprint,
    ) -> Result<DeliverySnapshot, Error> {
        let transaction_id =
            require_scheduled_artifact_identity(expected_state, artifact_identity)?;
        let tables = self.tables;
        let account_id = self.account_id;
        let submission_context = self.submission_context()?;
        let now = delivery_clock_now();
        let tx = self
            .conn
            .borrow_mut()
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let (migration_id, snapshot) = require_delivery_context(
            &tx,
            tables,
            account_id,
            expected_state,
            expected_revision,
            run_identity,
            submission_context,
            now,
        )?;
        require_active(&snapshot)?;
        require_bound_policy(&snapshot, expected_policy_fingerprint)?;
        let claim = snapshot
            .claims()
            .iter()
            .find(|claim| claim.artifact_identity() == artifact_identity)
            .ok_or(Error::DeliveryClaimUnavailable)?;
        if claim.signer_ownership() != SignerOwnership::External
            || claim.status() != ClaimStatus::AwaitingExternalSignature
            || claim.token() != Some(token)
            || claim
                .lease()
                .is_none_or(|lease| lease.validity_at(now) != LeaseValidity::Live)
            || claim
                .external_signing_pczt()
                .is_none_or(|staged| signed_pczt.staged_digest() != staged.digest())
        {
            return Err(Error::DeliveryClaimUnavailable);
        }
        tx.execute(
            &format!(
                "UPDATE {} SET signed_pczt_digest = ?, canonical_signed_pczt = ?,
                     signed_pczt_binding = ?
                 WHERE migration_id = ? AND tx_id = ?",
                tables.delivery_claims
            ),
            params![
                signed_pczt.signed_digest().as_bytes(),
                signed_pczt.bytes(),
                signed_pczt.staged_digest().as_bytes(),
                migration_id,
                u32::from(transaction_id)
            ],
        )?;
        bump_delivery_revision(&tx, tables, migration_id)?;
        let result =
            delivery_snapshot_after_mutation(&tx, tables, migration_id, submission_context)?;
        tx.commit()?;
        Ok(result)
    }

    /// Applies the sealed signing/proving delta while the matching Rust-owned materialization
    /// capability is live. Canonical rows, claim evidence, run fingerprint, and revision share one
    /// SQLite transaction; no generic migration write path can perform this transition.
    #[cfg(feature = "migration-delivery")]
    pub(crate) fn advance_canonical_materialization(
        &mut self,
        request: CanonicalMaterializationTransition,
    ) -> Result<CanonicalMaterializationReceipt, Error> {
        let tables = self.tables;
        let account_id = self.account_id;
        let submission_context = self.submission_context()?;
        let now = delivery_clock_now();
        let tx = self
            .conn
            .borrow_mut()
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let expected_state =
            read_migration(&tx, tables, account_id)?.ok_or(Error::CanonicalStateMismatch)?;
        if migration_state_fingerprint(&expected_state) != request.expected_state_fingerprint() {
            return Err(Error::CanonicalStateMismatch);
        }
        let migration_id =
            resolve_migration_id(&tx, tables, account_id)?.ok_or(Error::CanonicalStateMismatch)?;
        let snapshot =
            reconcile_delivery(&tx, tables, account_id, Some(submission_context), now, None)?
                .ok_or(Error::CanonicalStateMismatch)?;
        if snapshot.revision() != request.expected_revision() {
            return Err(Error::DeliveryRevisionMismatch);
        }
        if snapshot.run_identity() != request.run_identity() {
            return Err(Error::DeliveryRunMismatch);
        }
        require_active(&snapshot)?;
        require_bound_policy(&snapshot, request.expected_policy_fingerprint())?;
        let claim = snapshot
            .claims()
            .iter()
            .find(|claim| claim.artifact_identity() == request.artifact_identity())
            .ok_or(Error::DeliveryClaimUnavailable)?;
        if claim.claim_kind() != Some(request.claim_kind())
            || claim.token() != Some(request.token())
            || claim
                .lease()
                .is_none_or(|lease| lease.validity_at(now) != LeaseValidity::Live)
        {
            return Err(Error::DeliveryClaimUnavailable);
        }

        // Re-seal against the state loaded under the write transaction. This independently rejects
        // a request constructed from a stale sibling state or a broader canonical mutation even if
        // its echoed identifiers happen to match.
        let validated = CanonicalMaterializationTransition::new(
            request.expected_revision(),
            request.run_identity(),
            &expected_state,
            request.artifact_identity(),
            request.token(),
            request.expected_policy_fingerprint(),
            request.successor_state().clone(),
        )
        .map_err(|_| Error::DeliveryArtifactMismatch)?;
        if validated != request {
            return Err(Error::DeliveryArtifactMismatch);
        }
        let DeliveryArtifactIdentity::Scheduled(scheduled_identity) = request.artifact_identity()
        else {
            return Err(Error::DeliveryArtifactMismatch);
        };
        let transaction_id = scheduled_identity.transaction_id();
        let successor_evidence =
            scheduled_artifact_evidence(request.successor_state(), transaction_id)
                .ok_or(Error::DeliveryArtifactMismatch)?;
        let proved_exact = match request.purpose() {
            CanonicalMaterializationPurpose::ExternalSignature => {
                if claim.signer_ownership() != SignerOwnership::External
                    || claim
                        .signed_pczt()
                        .is_none_or(|signed| signed.bytes() != successor_evidence.canonical_pczt())
                {
                    return Err(Error::DeliveryArtifactMismatch);
                }
                None
            }
            CanonicalMaterializationPurpose::Proof => {
                let predecessor = expected_state
                    .transactions()
                    .iter()
                    .find(|transaction| transaction.id() == transaction_id)
                    .ok_or(Error::DeliveryArtifactMismatch)?;
                // Attempt identity deliberately ignores mutable PCZT bytes, so independently
                // prove that the successor is a conflict-free canonical extension of the exact
                // Signed PCZT loaded under this write transaction. This rejects redirected
                // inputs/outputs, values, recipients, and global transaction-field substitution.
                require_canonical_pczt_extension(
                    predecessor.pczt(),
                    successor_evidence.canonical_pczt(),
                )?;
                let exact = exact_transaction(request.successor_state(), transaction_id)
                    .map_err(|_| Error::DeliveryArtifactMismatch)?;
                if exact.artifact_identity()
                    != DeliveryArtifactIdentity::Scheduled(successor_evidence.identity())
                    || exact.consensus_expiry_height() != successor_evidence.expiry_height()
                {
                    return Err(Error::DeliveryArtifactMismatch);
                }
                Some(exact)
            }
        };

        replace_migration(
            &tx,
            tables,
            account_id,
            request.successor_state(),
            CanonicalMutationAuthority::DeliveryCas,
        )?;
        if let Some(exact) = proved_exact {
            // Proof already yields the consensus transaction. Stage those exact bytes in the same
            // CAS that commits canonical Proved, and retire the materialization capability, so a
            // crash can never leave a Proved canonical artifact without durable exact evidence.
            tx.execute(
                &format!(
                    "UPDATE {} SET pczt_digest = ?, transaction_fingerprint = ?,
                         status = 'staged', claim_kind = NULL, attempt_token = NULL,
                         lease_clock_session = NULL, lease_acquired_at_ms = NULL,
                         lease_expires_at_ms = NULL, txid = ?, exact_tx = ?, last_error = NULL
                      WHERE migration_id = ? AND tx_id = ?",
                    tables.delivery_claims
                ),
                params![
                    successor_evidence.pczt_digest().as_bytes(),
                    successor_evidence.transaction_fingerprint().as_bytes(),
                    exact.txid().as_ref(),
                    exact.bytes(),
                    migration_id,
                    u32::from(transaction_id),
                ],
            )?;
        } else {
            tx.execute(
                &format!(
                    "UPDATE {} SET pczt_digest = ?, transaction_fingerprint = ?
                      WHERE migration_id = ? AND tx_id = ?",
                    tables.delivery_claims
                ),
                params![
                    successor_evidence.pczt_digest().as_bytes(),
                    successor_evidence.transaction_fingerprint().as_bytes(),
                    migration_id,
                    u32::from(transaction_id),
                ],
            )?;
        }
        tx.execute(
            &format!(
                "UPDATE {} SET state_fingerprint = ? WHERE migration_id = ?",
                tables.delivery_control
            ),
            params![
                migration_state_fingerprint(request.successor_state()).as_bytes(),
                migration_id,
            ],
        )?;
        bump_delivery_revision(&tx, tables, migration_id)?;
        let delivery =
            delivery_snapshot_after_mutation(&tx, tables, migration_id, submission_context)?;
        let receipt = CanonicalMaterializationReceipt::from_committed_parts(request, delivery)
            .ok_or(Error::Corrupt("canonical materialization receipt"))?;
        tx.commit()?;
        Ok(receipt)
    }

    #[cfg(feature = "migration-delivery")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn claim_submission(
        &mut self,
        expected_state: &MigrationState,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        artifact_identity: DeliveryArtifactIdentity,
        lease_duration: LeaseDuration,
        expected_policy_fingerprint: PolicyFingerprint,
    ) -> Result<Option<DeliverySnapshot>, Error> {
        let transaction_id =
            require_scheduled_artifact_identity(expected_state, artifact_identity)?;
        let lease = checked_delivery_lease(ClaimKind::Submission, lease_duration)?;
        let tables = self.tables;
        let account_id = self.account_id;
        let submission_context = self.submission_context()?;
        let tx = self
            .conn
            .borrow_mut()
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let (migration_id, snapshot) = require_delivery_context(
            &tx,
            tables,
            account_id,
            expected_state,
            expected_revision,
            run_identity,
            submission_context,
            delivery_clock_now(),
        )?;
        require_active(&snapshot)?;
        require_bound_policy(&snapshot, expected_policy_fingerprint)?;
        let target_height = canonical_wallet_target_height(&tx)?;
        if expected_state.next_broadcastable(target_height) != Some(transaction_id) {
            return Err(Error::DeliveryClaimUnavailable);
        }
        let Some(claim) = snapshot
            .claims()
            .iter()
            .find(|claim| claim.artifact_identity() == artifact_identity)
        else {
            tx.commit()?;
            return Ok(None);
        };
        if claim.status() != ClaimStatus::Staged {
            tx.commit()?;
            return Ok(None);
        }
        tx.execute(
            &format!(
                "UPDATE {} SET status = 'submitting', claim_kind = 'submission',
                     attempt_token = ?, lease_clock_session = ?, lease_acquired_at_ms = ?,
                     lease_expires_at_ms = ?, last_error = NULL
                 WHERE migration_id = ? AND tx_id = ?",
                tables.delivery_claims
            ),
            params![
                lease.token().as_bytes(),
                lease.acquired_at().session().as_bytes(),
                lease.acquired_at().tick_millis(),
                lease.expires_at().tick_millis(),
                migration_id,
                u32::from(transaction_id)
            ],
        )?;
        bump_delivery_revision(&tx, tables, migration_id)?;
        let result =
            delivery_snapshot_after_mutation(&tx, tables, migration_id, submission_context)?;
        tx.commit()?;
        Ok(Some(result))
    }

    #[cfg(feature = "migration-delivery")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn claim_outcome_resolution(
        &mut self,
        expected_state: &MigrationState,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        artifact_identity: DeliveryArtifactIdentity,
        lease_duration: LeaseDuration,
        expected_policy_fingerprint: PolicyFingerprint,
    ) -> Result<Option<DeliverySnapshot>, Error> {
        let transaction_id =
            require_scheduled_artifact_identity(expected_state, artifact_identity)?;
        let lease = checked_delivery_lease(ClaimKind::OutcomeResolution, lease_duration)?;
        let tables = self.tables;
        let account_id = self.account_id;
        let submission_context = self.submission_context()?;
        let tx = self
            .conn
            .borrow_mut()
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let (migration_id, snapshot) = require_delivery_context(
            &tx,
            tables,
            account_id,
            expected_state,
            expected_revision,
            run_identity,
            submission_context,
            delivery_clock_now(),
        )?;
        require_bound_policy(&snapshot, expected_policy_fingerprint)?;
        let Some(claim) = snapshot
            .claims()
            .iter()
            .find(|claim| claim.artifact_identity() == artifact_identity)
        else {
            tx.commit()?;
            return Ok(None);
        };
        if !matches!(
            claim.status(),
            ClaimStatus::OutcomeUnknown | ClaimStatus::Broadcasted
        ) || claim.kind().is_some()
        {
            tx.commit()?;
            return Ok(None);
        }
        tx.execute(
            &format!(
                "UPDATE {} SET claim_kind = 'outcome_resolution', attempt_token = ?,
                     lease_clock_session = ?, lease_acquired_at_ms = ?,
                     lease_expires_at_ms = ? WHERE migration_id = ? AND tx_id = ?",
                tables.delivery_claims
            ),
            params![
                lease.token().as_bytes(),
                lease.acquired_at().session().as_bytes(),
                lease.acquired_at().tick_millis(),
                lease.expires_at().tick_millis(),
                migration_id,
                u32::from(transaction_id)
            ],
        )?;
        bump_delivery_revision(&tx, tables, migration_id)?;
        let result =
            delivery_snapshot_after_mutation(&tx, tables, migration_id, submission_context)?;
        tx.commit()?;
        Ok(Some(result))
    }

    #[cfg(feature = "migration-delivery")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn resume_claim(
        &mut self,
        expected_state: &MigrationState,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        artifact_identity: DeliveryArtifactIdentity,
        token: ClaimToken,
        expected_policy_fingerprint: PolicyFingerprint,
    ) -> Result<Option<DeliverySnapshot>, Error> {
        require_scheduled_artifact_identity(expected_state, artifact_identity)?;
        let tables = self.tables;
        let account_id = self.account_id;
        let submission_context = self.submission_context()?;
        let now = delivery_clock_now();
        let tx = self
            .conn
            .borrow_mut()
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let (_, snapshot) = require_delivery_context(
            &tx,
            tables,
            account_id,
            expected_state,
            expected_revision,
            run_identity,
            submission_context,
            now,
        )?;
        require_bound_policy(&snapshot, expected_policy_fingerprint)?;
        let Some(claim) = snapshot
            .claims()
            .iter()
            .find(|claim| claim.artifact_identity() == artifact_identity)
        else {
            tx.commit()?;
            return Ok(None);
        };
        if claim.token() != Some(token) {
            return Err(Error::DeliveryClaimTokenMismatch);
        }
        if claim
            .lease()
            .is_none_or(|lease| lease.validity_at(now) != LeaseValidity::Live)
        {
            return Err(Error::DeliveryClaimLeaseExpired);
        }
        tx.commit()?;
        Ok(Some(snapshot))
    }

    #[cfg(feature = "migration-delivery")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn renew_claim(
        &mut self,
        expected_state: &MigrationState,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        artifact_identity: DeliveryArtifactIdentity,
        token: ClaimToken,
        lease_duration: LeaseDuration,
        expected_policy_fingerprint: PolicyFingerprint,
    ) -> Result<Option<DeliverySnapshot>, Error> {
        let transaction_id =
            require_scheduled_artifact_identity(expected_state, artifact_identity)?;
        let tables = self.tables;
        let account_id = self.account_id;
        let submission_context = self.submission_context()?;
        let now = delivery_clock_now();
        let tx = self
            .conn
            .borrow_mut()
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let (migration_id, snapshot) = require_delivery_context(
            &tx,
            tables,
            account_id,
            expected_state,
            expected_revision,
            run_identity,
            submission_context,
            now,
        )?;
        require_bound_policy(&snapshot, expected_policy_fingerprint)?;
        let Some(claim) = snapshot
            .claims()
            .iter()
            .find(|claim| claim.artifact_identity() == artifact_identity)
        else {
            tx.commit()?;
            return Ok(None);
        };
        if claim.token() != Some(token) {
            return Err(Error::DeliveryClaimTokenMismatch);
        }
        if claim
            .lease()
            .is_none_or(|lease| lease.validity_at(now) != LeaseValidity::Live)
        {
            return Err(Error::DeliveryClaimLeaseExpired);
        }
        let renewed = DeliveryLease::new(
            claim.kind().ok_or(Error::DeliveryClaimUnavailable)?,
            token,
            now,
            lease_duration,
        )
        .ok_or(Error::DeliveryValueTooLarge)?;
        tx.execute(
            &format!(
                "UPDATE {} SET lease_clock_session = ?, lease_acquired_at_ms = ?,
                     lease_expires_at_ms = ? WHERE migration_id = ? AND tx_id = ?",
                tables.delivery_claims
            ),
            params![
                renewed.acquired_at().session().as_bytes(),
                renewed.acquired_at().tick_millis(),
                renewed.expires_at().tick_millis(),
                migration_id,
                u32::from(transaction_id)
            ],
        )?;
        bump_delivery_revision(&tx, tables, migration_id)?;
        let result =
            delivery_snapshot_after_mutation(&tx, tables, migration_id, submission_context)?;
        tx.commit()?;
        Ok(Some(result))
    }

    #[cfg(feature = "migration-delivery")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn record_submission_outcome(
        &mut self,
        expected_state: &MigrationState,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        artifact_identity: DeliveryArtifactIdentity,
        token: ClaimToken,
        outcome: SubmissionOutcome,
        expected_policy_fingerprint: PolicyFingerprint,
    ) -> Result<zcash_pool_migration::delivery::CanonicalDeliveryReceipt, Error> {
        let transaction_id =
            require_scheduled_artifact_identity(expected_state, artifact_identity)?;
        let tables = self.tables;
        let account_id = self.account_id;
        let submission_context = self.submission_context()?;
        let now = delivery_clock_now();
        let tx = self
            .conn
            .borrow_mut()
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let (migration_id, snapshot) = require_delivery_context(
            &tx,
            tables,
            account_id,
            expected_state,
            expected_revision,
            run_identity,
            submission_context,
            now,
        )?;
        require_active(&snapshot)?;
        require_bound_policy(&snapshot, expected_policy_fingerprint)?;
        let claim = snapshot
            .claims()
            .iter()
            .find(|claim| claim.artifact_identity() == artifact_identity)
            .ok_or(Error::DeliveryClaimUnavailable)?;
        if claim.status() != ClaimStatus::Submitting || claim.kind() != Some(ClaimKind::Submission)
        {
            return Err(Error::DeliveryClaimUnavailable);
        }
        if claim.token() != Some(token) {
            return Err(Error::DeliveryClaimTokenMismatch);
        }
        if claim
            .lease()
            .is_none_or(|lease| lease.validity_at(now) != LeaseValidity::Live)
        {
            return Err(Error::DeliveryClaimLeaseExpired);
        }
        let exact = exact_transaction(expected_state, transaction_id)
            .map_err(|_| Error::DeliveryArtifactMismatch)?;
        if exact.artifact_identity() != artifact_identity
            || claim.txid() != Some(exact.txid())
            || claim.exact_tx() != Some(exact.bytes())
        {
            return Err(Error::DeliveryArtifactMismatch);
        }
        let committed_state = match outcome {
            SubmissionOutcome::Accepted => {
                let canonical = expected_state
                    .transactions()
                    .iter()
                    .find(|transaction| transaction.id() == transaction_id)
                    .ok_or(Error::DeliveryArtifactMismatch)?;
                if canonical.state() != MigrationTxState::Proved {
                    return Err(Error::DeliveryClaimUnavailable);
                }
                with_canonical_transaction_state(
                    expected_state,
                    transaction_id,
                    MigrationTxState::Broadcast { txid: exact.txid() },
                )?
            }
            SubmissionOutcome::KnownUnsent | SubmissionOutcome::Unknown => expected_state.clone(),
        };
        let (status, last_error) = match outcome {
            SubmissionOutcome::Accepted => ("broadcasted", None),
            SubmissionOutcome::KnownUnsent => {
                ("staged", Some(DeliveryFailureReason::TransportDidNotBegin))
            }
            SubmissionOutcome::Unknown => (
                "outcome_unknown",
                Some(DeliveryFailureReason::TransportOutcomeUnknown),
            ),
        };
        tx.execute(
            &format!(
                "UPDATE {} SET status = ?, claim_kind = NULL, attempt_token = NULL,
                     lease_clock_session = NULL, lease_acquired_at_ms = NULL,
                     lease_expires_at_ms = NULL, last_error = ?
                 WHERE migration_id = ? AND tx_id = ?",
                tables.delivery_claims
            ),
            params![
                status,
                last_error.map(DeliveryFailureReason::as_str),
                migration_id,
                u32::from(transaction_id)
            ],
        )?;
        if outcome == SubmissionOutcome::Accepted {
            replace_migration(
                &tx,
                tables,
                account_id,
                &committed_state,
                CanonicalMutationAuthority::DeliveryCas,
            )?;
            let successor_evidence = scheduled_artifact_evidence(&committed_state, transaction_id)
                .ok_or(Error::DeliveryArtifactMismatch)?;
            tx.execute(
                &format!(
                    "UPDATE {} SET pczt_digest = ?, transaction_fingerprint = ?
                     WHERE migration_id = ? AND tx_id = ?",
                    tables.delivery_claims
                ),
                params![
                    successor_evidence.pczt_digest().as_bytes(),
                    successor_evidence.transaction_fingerprint().as_bytes(),
                    migration_id,
                    u32::from(transaction_id),
                ],
            )?;
            tx.execute(
                &format!(
                    "UPDATE {} SET state_fingerprint = ? WHERE migration_id = ?",
                    tables.delivery_control
                ),
                params![
                    migration_state_fingerprint(&committed_state).as_bytes(),
                    migration_id,
                ],
            )?;
        }
        bump_delivery_revision(&tx, tables, migration_id)?;
        let delivery =
            delivery_snapshot_after_mutation(&tx, tables, migration_id, submission_context)?;
        let receipt =
            zcash_pool_migration::delivery::CanonicalDeliveryReceipt::from_committed_parts(
                expected_revision,
                run_identity,
                committed_state,
                delivery,
            )
            .ok_or(Error::Corrupt("canonical delivery receipt"))?;
        tx.commit()?;
        Ok(receipt)
    }

    #[cfg(feature = "migration-delivery")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn release_claim_known_unsent(
        &mut self,
        expected_state: &MigrationState,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        artifact_identity: DeliveryArtifactIdentity,
        token: ClaimToken,
        reason: DeliveryFailureReason,
        expected_policy_fingerprint: PolicyFingerprint,
    ) -> Result<DeliverySnapshot, Error> {
        let transaction_id =
            require_scheduled_artifact_identity(expected_state, artifact_identity)?;
        let tables = self.tables;
        let account_id = self.account_id;
        let submission_context = self.submission_context()?;
        let now = delivery_clock_now();
        let tx = self
            .conn
            .borrow_mut()
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let (migration_id, snapshot) = require_delivery_context(
            &tx,
            tables,
            account_id,
            expected_state,
            expected_revision,
            run_identity,
            submission_context,
            now,
        )?;
        require_bound_policy(&snapshot, expected_policy_fingerprint)?;
        let claim = snapshot
            .claims()
            .iter()
            .find(|claim| claim.artifact_identity() == artifact_identity)
            .ok_or(Error::DeliveryClaimUnavailable)?;
        if claim.token() != Some(token) {
            return Err(Error::DeliveryClaimTokenMismatch);
        }
        if claim
            .lease()
            .is_none_or(|lease| lease.validity_at(now) != LeaseValidity::Live)
        {
            return Err(Error::DeliveryClaimLeaseExpired);
        }
        let next_status = match (claim.status(), claim.kind()) {
            (ClaimStatus::Materializing, Some(ClaimKind::Materialization)) => {
                "materialization_failed"
            }
            (ClaimStatus::Submitting, Some(ClaimKind::Submission)) => "staged",
            _ => return Err(Error::DeliveryClaimUnavailable),
        };
        tx.execute(
            &format!(
                "UPDATE {} SET status = ?, claim_kind = NULL, attempt_token = NULL,
                     lease_clock_session = NULL, lease_acquired_at_ms = NULL,
                     lease_expires_at_ms = NULL, last_error = ?
                 WHERE migration_id = ? AND tx_id = ?",
                tables.delivery_claims
            ),
            params![
                next_status,
                reason.as_str(),
                migration_id,
                u32::from(transaction_id)
            ],
        )?;
        bump_delivery_revision(&tx, tables, migration_id)?;
        let result =
            delivery_snapshot_after_mutation(&tx, tables, migration_id, submission_context)?;
        tx.commit()?;
        Ok(result)
    }

    #[cfg(feature = "migration-delivery")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn reconcile_submission(
        &mut self,
        expected_state: &MigrationState,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        artifact_identity: DeliveryArtifactIdentity,
        token: ClaimToken,
    ) -> Result<zcash_pool_migration::delivery::CanonicalDeliveryReceipt, Error> {
        let transaction_id =
            require_scheduled_artifact_identity(expected_state, artifact_identity)?;
        let canonical = expected_state
            .transactions()
            .iter()
            .find(|transaction| transaction.id() == transaction_id)
            .ok_or(Error::DeliveryArtifactMismatch)?;
        let tables = self.tables;
        let account_id = self.account_id;
        let submission_context = self.submission_context()?;
        let now = delivery_clock_now();
        let tx = self
            .conn
            .borrow_mut()
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let (migration_id, snapshot) = require_delivery_context(
            &tx,
            tables,
            account_id,
            expected_state,
            expected_revision,
            run_identity,
            submission_context,
            now,
        )?;
        let claim = snapshot
            .claims()
            .iter()
            .find(|claim| claim.artifact_identity() == artifact_identity)
            .ok_or(Error::DeliveryClaimUnavailable)?;
        let target_height = canonical_wallet_target_height(&tx)?;
        if !matches!(
            claim.status(),
            ClaimStatus::OutcomeUnknown | ClaimStatus::Broadcasted
        ) || claim.kind() != Some(ClaimKind::OutcomeResolution)
        {
            return Err(Error::DeliveryClaimUnavailable);
        }
        if claim.token() != Some(token) {
            return Err(Error::DeliveryClaimTokenMismatch);
        }
        if claim
            .lease()
            .is_none_or(|lease| lease.validity_at(now) != LeaseValidity::Live)
        {
            return Err(Error::DeliveryClaimLeaseExpired);
        }
        let txid = claim.txid().ok_or(Error::Corrupt("delivery exact txid"))?;
        let exact = exact_transaction(expected_state, transaction_id)
            .map_err(|_| Error::DeliveryArtifactMismatch)?;
        if exact.artifact_identity() != artifact_identity
            || exact.txid() != txid
            || claim.exact_tx() != Some(exact.bytes())
        {
            return Err(Error::DeliveryArtifactMismatch);
        }
        let mined_height = current_wallet_mined_height(&tx, txid)?;
        let committed_state = if let Some(height) = mined_height {
            with_canonical_transaction_state(
                expected_state,
                transaction_id,
                MigrationTxState::Mined { height },
            )?
        } else if matches!(canonical.state(), MigrationTxState::Mined { .. }) {
            with_canonical_transaction_state(
                expected_state,
                transaction_id,
                MigrationTxState::Broadcast { txid },
            )?
        } else {
            expected_state.clone()
        };
        let status = if mined_height.is_some() {
            "confirmed"
        } else if u32::from(canonical.expiry_height()) != 0
            && target_height > canonical.expiry_height()
        {
            "expired_unmined"
        } else if matches!(canonical.state(), MigrationTxState::Mined { .. }) {
            "broadcasted"
        } else {
            claim.status().as_str()
        };
        tx.execute(
            &format!(
                "UPDATE {} SET status = ?, claim_kind = NULL, attempt_token = NULL,
                     lease_clock_session = NULL, lease_acquired_at_ms = NULL,
                     lease_expires_at_ms = NULL
                 WHERE migration_id = ? AND tx_id = ?",
                tables.delivery_claims
            ),
            params![status, migration_id, u32::from(transaction_id)],
        )?;
        if committed_state != *expected_state {
            replace_migration(
                &tx,
                tables,
                account_id,
                &committed_state,
                CanonicalMutationAuthority::DeliveryCas,
            )?;
            let successor_evidence = scheduled_artifact_evidence(&committed_state, transaction_id)
                .ok_or(Error::DeliveryArtifactMismatch)?;
            tx.execute(
                &format!(
                    "UPDATE {} SET pczt_digest = ?, transaction_fingerprint = ?
                     WHERE migration_id = ? AND tx_id = ?",
                    tables.delivery_claims
                ),
                params![
                    successor_evidence.pczt_digest().as_bytes(),
                    successor_evidence.transaction_fingerprint().as_bytes(),
                    migration_id,
                    u32::from(transaction_id),
                ],
            )?;
            tx.execute(
                &format!(
                    "UPDATE {} SET state_fingerprint = ? WHERE migration_id = ?",
                    tables.delivery_control
                ),
                params![
                    migration_state_fingerprint(&committed_state).as_bytes(),
                    migration_id,
                ],
            )?;
        }
        bump_delivery_revision(&tx, tables, migration_id)?;
        let delivery =
            delivery_snapshot_after_mutation(&tx, tables, migration_id, submission_context)?;
        let receipt =
            zcash_pool_migration::delivery::CanonicalDeliveryReceipt::from_committed_parts(
                expected_revision,
                run_identity,
                committed_state,
                delivery,
            )
            .ok_or(Error::Corrupt("canonical delivery receipt"))?;
        tx.commit()?;
        Ok(receipt)
    }

    /// Reconciles exact scheduled artifacts and canonical lifecycle in one SQLite CAS.
    #[cfg(feature = "migration-delivery")]
    pub(crate) fn reconcile_canonical_chain(
        &mut self,
        expected_state: &MigrationState,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
    ) -> Result<Option<zcash_pool_migration::delivery::CanonicalDeliveryReceipt>, Error> {
        let tables = self.tables;
        let account_id = self.account_id;
        let submission_context = self.submission_context()?;
        let tx = self
            .conn
            .borrow_mut()
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        require_canonical_state(&tx, tables, account_id, Some(expected_state))?;
        let migration_id =
            resolve_migration_id(&tx, tables, account_id)?.ok_or(Error::CanonicalStateMismatch)?;
        let control = read_delivery_control(&tx, tables, migration_id, Some(submission_context))?
            .ok_or(Error::Corrupt("delivery control"))?;
        let snapshot = build_delivery_snapshot(&tx, tables, control)?;
        if snapshot.revision() != expected_revision {
            return Err(Error::DeliveryRevisionMismatch);
        }
        if snapshot.run_identity() != run_identity {
            return Err(Error::DeliveryRunMismatch);
        }

        let fully_scanned = fully_scanned_height(&tx)?;
        let mut committed_state = expected_state.clone();
        let mut changed = false;
        let mut shallow_reorg = false;
        let mut deep_reorg = false;
        let mut external_signing_unresolved = false;

        for claim in snapshot.claims() {
            let DeliveryArtifactIdentity::Scheduled(identity) = claim.artifact_identity() else {
                return Err(Error::DeliveryArtifactMismatch);
            };
            let transaction_id = identity.transaction_id();
            let canonical = committed_state
                .transactions()
                .iter()
                .find(|transaction| transaction.id() == transaction_id)
                .ok_or(Error::DeliveryArtifactMismatch)?;
            let canonical_state = canonical.state();
            let expiry_height = canonical.expiry_height();
            let Some(exact) = claim.exact_transaction() else {
                if !claim.has_external_signing_exposure()
                    || claim.status() == ClaimStatus::ExternalSigningExpiredUnmined
                {
                    continue;
                }

                // A signer-returned PCZT may already contain every authorization required to
                // derive exact network bytes even if the process crashed before the normal Proof
                // CAS. Mining is authoritative evidence that those exact bytes were valid and
                // exposed, so recover the canonical PCZT/lifecycle and delivery evidence in this
                // same transaction. The backend helper rejects noncanonical or conflicting PCZT
                // extensions and binds the transaction to this exact scheduled attempt.
                let derived = claim.signed_pczt().and_then(|signed| {
                    exact_scheduled_transaction_from_pczt(
                        &committed_state,
                        identity,
                        signed.bytes(),
                    )
                    .ok()
                    .map(|exact| (signed.bytes().to_vec(), exact))
                });
                if let Some((canonical_pczt, exact)) = derived
                    && let Some(height) = current_wallet_mined_height(&tx, exact.txid())?
                {
                    committed_state = with_canonical_transaction_pczt_and_state(
                        &committed_state,
                        transaction_id,
                        &canonical_pczt,
                        MigrationTxState::Mined { height },
                    )?;
                    let successor_evidence =
                        scheduled_artifact_evidence(&committed_state, transaction_id)
                            .ok_or(Error::DeliveryArtifactMismatch)?;
                    tx.execute(
                        &format!(
                            "UPDATE {} SET pczt_digest = ?, transaction_fingerprint = ?,
                                 status = 'confirmed', claim_kind = NULL, attempt_token = NULL,
                                 lease_clock_session = NULL, lease_acquired_at_ms = NULL,
                                 lease_expires_at_ms = NULL, txid = ?, exact_tx = ?,
                                 last_error = NULL WHERE migration_id = ? AND tx_id = ?",
                            tables.delivery_claims
                        ),
                        params![
                            successor_evidence.pczt_digest().as_bytes(),
                            successor_evidence.transaction_fingerprint().as_bytes(),
                            exact.txid().as_ref(),
                            exact.bytes(),
                            migration_id,
                            u32::from(transaction_id),
                        ],
                    )?;
                    changed = true;
                    continue;
                }

                // Merely reaching expiry is not sufficient after signer exposure. The wallet's
                // fully scanned active-chain view must be strictly beyond expiry and every exact
                // reserved source must still be positively present and unspent in this same SQL
                // transaction. Ambiguous or spent evidence enters recovery without deleting PCZT
                // bytes or releasing reservations.
                let expired = fully_scanned
                    .is_some_and(|height| u32::from(expiry_height) != 0 && height > expiry_height);
                if expired {
                    let fully_scanned =
                        fully_scanned.ok_or(Error::Corrupt("fully scanned height changed"))?;
                    let target_height = canonical_wallet_target_height(&tx)?;
                    if reserved_sources_proven_unspent(
                        &tx,
                        tables,
                        account_id,
                        run_identity,
                        fully_scanned,
                        target_height,
                    )? {
                        tx.execute(
                            &format!(
                                "UPDATE {} SET status = 'external_signing_expired_unmined',
                                     claim_kind = NULL, attempt_token = NULL,
                                     lease_clock_session = NULL, lease_acquired_at_ms = NULL,
                                     lease_expires_at_ms = NULL, last_error = NULL
                                 WHERE migration_id = ? AND tx_id = ?",
                                tables.delivery_claims
                            ),
                            params![migration_id, u32::from(transaction_id)],
                        )?;
                    } else {
                        external_signing_unresolved = true;
                    }
                    changed = true;
                }
                continue;
            };
            let canonical_exact = exact_transaction(&committed_state, transaction_id)
                .map_err(|_| Error::DeliveryArtifactMismatch)?;
            if canonical_exact.artifact_identity() != claim.artifact_identity()
                || canonical_exact.txid() != exact.txid()
                || canonical_exact.bytes() != exact.bytes()
            {
                return Err(Error::DeliveryArtifactMismatch);
            }

            match current_wallet_mined_height(&tx, exact.txid())? {
                Some(height) => {
                    if !matches!(canonical_state, MigrationTxState::Mined { height: h } if h == height)
                    {
                        committed_state = with_canonical_transaction_state(
                            &committed_state,
                            transaction_id,
                            MigrationTxState::Mined { height },
                        )?;
                        changed = true;
                    }
                    if claim.status() != ClaimStatus::Confirmed || claim.kind().is_some() {
                        tx.execute(
                            &format!(
                                "UPDATE {} SET status = 'confirmed', claim_kind = NULL,
                                 attempt_token = NULL, lease_clock_session = NULL,
                                 lease_acquired_at_ms = NULL, lease_expires_at_ms = NULL,
                                 last_error = NULL WHERE migration_id = ? AND tx_id = ?",
                                tables.delivery_claims
                            ),
                            params![migration_id, u32::from(transaction_id)],
                        )?;
                        changed = true;
                    }
                }
                None if matches!(canonical_state, MigrationTxState::Mined { .. }) => {
                    if matches!(snapshot.storage_finality(), StorageFinality::Finalized(_)) {
                        deep_reorg = true;
                        continue;
                    }
                    committed_state = with_canonical_transaction_state(
                        &committed_state,
                        transaction_id,
                        MigrationTxState::Broadcast { txid: exact.txid() },
                    )?;
                    let expired = fully_scanned.is_some_and(|height| {
                        u32::from(expiry_height) != 0 && height > expiry_height
                    });
                    tx.execute(
                        &format!(
                            "UPDATE {} SET status = ?, claim_kind = NULL, attempt_token = NULL,
                             lease_clock_session = NULL, lease_acquired_at_ms = NULL,
                             lease_expires_at_ms = NULL, last_error = NULL
                             WHERE migration_id = ? AND tx_id = ?",
                            tables.delivery_claims
                        ),
                        params![
                            if expired {
                                "expired_unmined"
                            } else {
                                "broadcasted"
                            },
                            migration_id,
                            u32::from(transaction_id),
                        ],
                    )?;
                    shallow_reorg = true;
                    changed = true;
                }
                None => {
                    let expired = fully_scanned.is_some_and(|height| {
                        u32::from(expiry_height) != 0 && height > expiry_height
                    });
                    if expired
                        && matches!(
                            claim.status(),
                            ClaimStatus::OutcomeUnknown
                                | ClaimStatus::Broadcasted
                                | ClaimStatus::Confirmed
                        )
                    {
                        tx.execute(
                            &format!(
                                "UPDATE {} SET status = 'expired_unmined', claim_kind = NULL,
                                 attempt_token = NULL, lease_clock_session = NULL,
                                 lease_acquired_at_ms = NULL, lease_expires_at_ms = NULL,
                                 last_error = NULL WHERE migration_id = ? AND tx_id = ?",
                                tables.delivery_claims
                            ),
                            params![migration_id, u32::from(transaction_id)],
                        )?;
                        changed = true;
                    }
                }
            }
        }

        if deep_reorg {
            tx.execute(
                &format!(
                    "UPDATE {} SET storage_finality = 'recovery_required',
                     storage_recovery_reason = 'rewound_beyond_finality_horizon'
                     WHERE migration_id = ?",
                    tables.delivery_control
                ),
                params![migration_id],
            )?;
            tx.execute(
                &format!(
                    "UPDATE {} SET status = 'recovery_required'
                     WHERE run_identity = ? AND status IN ('active', 'finality_released')",
                    tables.delivery_reservations
                ),
                params![run_identity.as_bytes()],
            )?;
            tx.execute(
                &format!(
                    "UPDATE {} SET status = 'recovery_required' WHERE run_identity = ?",
                    tables.delivery_runs
                ),
                params![run_identity.as_bytes()],
            )?;
            changed = true;
        } else if external_signing_unresolved {
            tx.execute(
                &format!(
                    "UPDATE {} SET storage_finality = 'recovery_required',
                     storage_recovery_reason = 'external_signing_exposure_unresolved'
                     WHERE migration_id = ?",
                    tables.delivery_control
                ),
                params![migration_id],
            )?;
            tx.execute(
                &format!(
                    "UPDATE {} SET status = 'recovery_required'
                     WHERE run_identity = ? AND status IN ('active', 'finality_released')",
                    tables.delivery_reservations
                ),
                params![run_identity.as_bytes()],
            )?;
            tx.execute(
                &format!(
                    "UPDATE {} SET status = 'recovery_required' WHERE run_identity = ?",
                    tables.delivery_runs
                ),
                params![run_identity.as_bytes()],
            )?;
        } else if shallow_reorg {
            tx.execute(
                &format!(
                    "UPDATE {} SET storage_finality = 'active', storage_recovery_reason = NULL,
                     release_at_height = NULL, finalized_tip_height = NULL
                     WHERE migration_id = ?",
                    tables.delivery_control
                ),
                params![migration_id],
            )?;
            tx.execute(
                &format!(
                    "UPDATE {} SET status = 'active', release_at_height = NULL,
                     released_tip_height = NULL
                     WHERE run_identity = ? AND status = 'finality_released'",
                    tables.delivery_reservations
                ),
                params![run_identity.as_bytes()],
            )?;
            tx.execute(
                &format!(
                    "UPDATE {} SET status = 'active' WHERE run_identity = ?",
                    tables.delivery_runs
                ),
                params![run_identity.as_bytes()],
            )?;
        }

        if committed_state != *expected_state {
            replace_migration(
                &tx,
                tables,
                account_id,
                &committed_state,
                CanonicalMutationAuthority::DeliveryCas,
            )?;
        }
        if changed {
            tx.execute(
                &format!(
                    "UPDATE {} SET state_fingerprint = ? WHERE migration_id = ?",
                    tables.delivery_control
                ),
                params![
                    migration_state_fingerprint(&committed_state).as_bytes(),
                    migration_id,
                ],
            )?;
            bump_delivery_revision(&tx, tables, migration_id)?;
            let delivery =
                delivery_snapshot_after_mutation(&tx, tables, migration_id, submission_context)?;
            let receipt =
                zcash_pool_migration::delivery::CanonicalDeliveryReceipt::from_committed_parts(
                    expected_revision,
                    run_identity,
                    committed_state,
                    delivery,
                )
                .ok_or(Error::Corrupt("canonical chain receipt"))?;
            tx.commit()?;
            Ok(Some(receipt))
        } else {
            tx.commit()?;
            Ok(None)
        }
    }

    #[cfg(feature = "migration-delivery")]
    pub(crate) fn pause_delivery(
        &mut self,
        expected_state: &MigrationState,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
    ) -> Result<DeliverySnapshot, Error> {
        let tables = self.tables;
        let account_id = self.account_id;
        let submission_context = self.submission_context()?;
        let tx = self
            .conn
            .borrow_mut()
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let (migration_id, snapshot) = require_delivery_context(
            &tx,
            tables,
            account_id,
            expected_state,
            expected_revision,
            run_identity,
            submission_context,
            delivery_clock_now(),
        )?;
        if snapshot.phase() != DeliveryPhase::Active {
            return Err(Error::DeliveryPhaseMismatch);
        }
        tx.execute(
            &format!(
                "UPDATE {} SET phase = 'paused' WHERE migration_id = ?",
                tables.delivery_control
            ),
            params![migration_id],
        )?;
        bump_delivery_revision(&tx, tables, migration_id)?;
        let result =
            delivery_snapshot_after_mutation(&tx, tables, migration_id, submission_context)?;
        tx.commit()?;
        Ok(result)
    }

    #[cfg(feature = "migration-delivery")]
    pub(crate) fn resume_delivery(
        &mut self,
        expected_state: &MigrationState,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
    ) -> Result<DeliverySnapshot, Error> {
        let tables = self.tables;
        let account_id = self.account_id;
        let submission_context = self.submission_context()?;
        let tx = self
            .conn
            .borrow_mut()
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let (migration_id, snapshot) = require_delivery_context(
            &tx,
            tables,
            account_id,
            expected_state,
            expected_revision,
            run_identity,
            submission_context,
            delivery_clock_now(),
        )?;
        if snapshot.phase() != DeliveryPhase::Paused {
            return Err(Error::DeliveryPhaseMismatch);
        }
        tx.execute(
            &format!(
                "UPDATE {} SET phase = 'active' WHERE migration_id = ?",
                tables.delivery_control
            ),
            params![migration_id],
        )?;
        bump_delivery_revision(&tx, tables, migration_id)?;
        let result =
            delivery_snapshot_after_mutation(&tx, tables, migration_id, submission_context)?;
        tx.commit()?;
        Ok(result)
    }

    #[cfg(feature = "migration-delivery")]
    pub(crate) fn begin_abandonment(
        &mut self,
        expected_state: &MigrationState,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
    ) -> Result<DeliverySnapshot, Error> {
        let tables = self.tables;
        let account_id = self.account_id;
        let submission_context = self.submission_context()?;
        let tx = self
            .conn
            .borrow_mut()
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let (migration_id, snapshot) = require_delivery_context(
            &tx,
            tables,
            account_id,
            expected_state,
            expected_revision,
            run_identity,
            submission_context,
            delivery_clock_now(),
        )?;
        if !matches!(
            snapshot.phase(),
            DeliveryPhase::Active | DeliveryPhase::Paused
        ) {
            return Err(Error::DeliveryPhaseMismatch);
        }
        // Invalidating unexposed rows atomically invalidates their late local callbacks. Status
        // alone is not enough: an externally owned Staged claim retains exact PCZT evidence that
        // crossed the signer boundary and therefore remains authoritative even though transport
        // has not begun. Preserve every claim with either signer or network exposure byte-for-byte
        // until explicit mined/expiry resolution reaches its release horizon.
        let removable = snapshot
            .claims()
            .iter()
            .filter(|claim| !claim.has_exposure_history())
            .map(DeliveryClaim::transaction_id)
            .collect::<Vec<_>>();
        for transaction_id in removable {
            delete_delivery_claim(&tx, tables, migration_id, transaction_id)?;
        }
        tx.execute(
            &format!(
                "UPDATE {} SET phase = 'abandoning' WHERE migration_id = ?",
                tables.delivery_control
            ),
            params![migration_id],
        )?;
        bump_delivery_revision(&tx, tables, migration_id)?;
        let result =
            delivery_snapshot_after_mutation(&tx, tables, migration_id, submission_context)?;
        tx.commit()?;
        Ok(result)
    }

    #[cfg(feature = "migration-delivery")]
    pub(crate) fn finish_abandonment(
        &mut self,
        expected_state: &MigrationState,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
    ) -> Result<DeliverySnapshot, Error> {
        let tables = self.tables;
        let account_id = self.account_id;
        let submission_context = self.submission_context()?;
        let tx = self
            .conn
            .borrow_mut()
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let (migration_id, snapshot) = require_delivery_context(
            &tx,
            tables,
            account_id,
            expected_state,
            expected_revision,
            run_identity,
            submission_context,
            delivery_clock_now(),
        )?;
        if snapshot.phase() != DeliveryPhase::Abandoning {
            return Err(Error::DeliveryPhaseMismatch);
        }
        if !snapshot.safe_to_cancel() {
            return Err(Error::DeliveryNotSafeToAbandon);
        }
        if expected_state.status() == MigrationStatus::Complete {
            return Err(Error::DeliveryNotSafeToAbandon);
        }
        let exposed_claims = snapshot
            .claims()
            .iter()
            .filter(|claim| claim.has_exposure_history())
            .collect::<Vec<_>>();
        let (release, finalized_tip, reservation_status) = if exposed_claims.is_empty() {
            // A never-exposed cancellation has no chain dependency. Height zero is the explicit
            // tombstone sentinel, so every possible wallet rewind remains at or above it.
            (
                ReservationRelease::at(BlockHeight::from_u32(0)),
                BlockHeight::from_u32(0),
                "abandoned",
            )
        } else {
            if exposed_claims.iter().any(|claim| {
                !matches!(
                    claim.status(),
                    ClaimStatus::ExpiredUnmined | ClaimStatus::ExternalSigningExpiredUnmined
                ) || claim.lease().is_some()
            }) {
                return Err(Error::DeliveryNotSafeToAbandon);
            }
            let max_expiry = exposed_claims
                .iter()
                .map(|claim| claim.expiry_height())
                .max()
                .ok_or(Error::DeliveryNotSafeToAbandon)?;
            let release = ReservationRelease::after_resolved_unmined_expiry(max_expiry)
                .ok_or(Error::DeliveryRecoveryRequired)?;
            let fully_scanned = fully_scanned_height(&tx)?
                .filter(|height| *height >= release.release_at())
                .ok_or(Error::DeliveryNotSafeToAbandon)?;
            if !reserved_sources_proven_unspent(
                &tx,
                tables,
                account_id,
                snapshot.run_identity(),
                fully_scanned,
                canonical_wallet_target_height(&tx)?,
            )? {
                return Err(Error::DeliveryRecoveryRequired);
            }
            (release, fully_scanned, "finality_released")
        };
        // The run identity is deliberately independent from the canonical lock owner; source the
        // release authority from the control row that was compared by `require_delivery_context`.
        let control = read_delivery_control(&tx, tables, migration_id, Some(submission_context))?
            .ok_or(Error::Corrupt("delivery control"))?;
        let owner = control.canonical_lock_owner;
        let owners = BTreeSet::from([owner]);
        require_canonical_owner(&tx, tables, account_id, &owners)?;

        let failed = MigrationState::from_parts(
            MigrationStatus::Failed,
            expected_state.note_split().clone(),
            expected_state.preparation().clone(),
            expected_state
                .transactions()
                .iter()
                .map(|canonical| {
                    MigrationTransaction::from_parts(
                        canonical.id(),
                        canonical.kind(),
                        canonical.pczt().clone(),
                        canonical.depends_on().to_vec(),
                        canonical.scheduled_height(),
                        canonical.expiry_height(),
                        canonical.anchor_boundary(),
                        canonical.state(),
                        None,
                    )
                })
                .collect(),
        );
        tx.execute(
            &format!(
                "UPDATE {} SET phase = 'abandoned', storage_finality = 'finalized',
                     storage_recovery_reason = NULL, release_at_height = ?,
                     finalized_tip_height = ? WHERE migration_id = ?",
                tables.delivery_control
            ),
            params![
                u32::from(release.release_at()),
                u32::from(finalized_tip),
                migration_id
            ],
        )?;
        tx.execute(
            &format!(
                "UPDATE {} SET status = 'abandoned' WHERE run_identity = ?",
                tables.delivery_runs
            ),
            params![control.run_identity.as_bytes()],
        )?;
        // Phase, exact release horizon, canonical Failed state, and owner-scoped source-lock
        // release share this transaction. Claims remain in place as the authoritative exposure
        // history until a future rollover archives the whole predecessor run.
        transition_source_reservations(
            &tx,
            tables,
            control.run_identity,
            control.source_reservation_owner,
            reservation_status,
            (reservation_status == "finality_released").then_some(release.release_at()),
            Some(finalized_tip),
        )?;
        release_locks(&tx, account_id, &owners)?;
        replace_migration(
            &tx,
            tables,
            account_id,
            &failed,
            CanonicalMutationAuthority::DeliveryCas,
        )?;
        tx.execute(
            &format!(
                "UPDATE {} SET state_fingerprint = ? WHERE migration_id = ?",
                tables.delivery_control
            ),
            params![
                migration_state_fingerprint(&failed).as_bytes(),
                migration_id
            ],
        )?;
        bump_delivery_revision(&tx, tables, migration_id)?;
        let result =
            delivery_snapshot_after_mutation(&tx, tables, migration_id, submission_context)?;
        tx.commit()?;
        Ok(result)
    }
}

#[cfg(feature = "migration-delivery")]
struct StoredImmediateDelivery {
    run_identity: [u8; 32],
    source_owner: [u8; 32],
    canonical_lock_owner: Option<[u8; 32]>,
    run_status: String,
    revision: u64,
    phase: String,
    artifact_identity: [u8; 32],
    proposal_fingerprint: [u8; 32],
    canonical_proposal: Vec<u8>,
    signer_ownership: String,
    status: String,
    claim_kind: Option<String>,
    attempt_token: Option<[u8; 32]>,
    lease_clock_session: Option<[u8; 32]>,
    lease_acquired_at_ms: Option<u64>,
    lease_expires_at_ms: Option<u64>,
    txid: Option<[u8; 32]>,
    exact_tx: Option<Vec<u8>>,
    exact_tx_digest: Option<[u8; 32]>,
    unsigned_pczt_digest: Option<[u8; 32]>,
    canonical_unsigned_pczt: Option<Vec<u8>>,
    signed_pczt_digest: Option<[u8; 32]>,
    canonical_signed_pczt: Option<Vec<u8>>,
    signed_pczt_binding: Option<[u8; 32]>,
    last_error: Option<String>,
    expiry_height: u32,
    storage_finality: String,
    storage_recovery_reason: Option<String>,
    observed_mined_height: Option<u32>,
    destination_output_index: Option<u32>,
    expected_ironwood_amount: Option<u64>,
    release_at_height: Option<u32>,
    finalized_tip_height: Option<u32>,
    policy: Option<Vec<u8>>,
    policy_fingerprint: Option<[u8; 32]>,
    policy_validation_failure: Option<String>,
    authorization_version: Option<i64>,
    maximum_gross_amount: Option<i64>,
}

#[cfg(feature = "migration-delivery")]
fn read_stored_immediate_delivery(
    conn: &Connection,
    tables: &Tables,
    account_id: AccountRef,
    run_identity: MigrationRunIdentity,
) -> Result<Option<StoredImmediateDelivery>, Error> {
    conn.query_row(
        &format!(
            "SELECT runs.run_identity, runs.source_owner, runs.canonical_lock_owner,
                    runs.status, immediate.revision, immediate.phase,
                    immediate.artifact_identity, immediate.proposal_fingerprint,
                    immediate.canonical_proposal, immediate.signer_ownership,
                    immediate.status, immediate.claim_kind, immediate.attempt_token,
                    immediate.lease_clock_session, immediate.lease_acquired_at_ms,
                    immediate.lease_expires_at_ms, immediate.txid, immediate.exact_tx,
                    immediate.exact_tx_digest, immediate.unsigned_pczt_digest,
                    immediate.canonical_unsigned_pczt, immediate.signed_pczt_digest,
                    immediate.canonical_signed_pczt, immediate.signed_pczt_binding,
                    immediate.last_error, immediate.expiry_height, immediate.storage_finality,
                    immediate.storage_recovery_reason, immediate.observed_mined_height,
                    immediate.destination_output_index, immediate.expected_ironwood_amount,
                    immediate.release_at_height, immediate.finalized_tip_height,
                    immediate.policy, immediate.policy_fingerprint,
                    immediate.policy_validation_failure, authorization.authorization_version,
                    authorization.maximum_gross_amount
               FROM {} runs
               JOIN {} immediate ON immediate.run_identity = runs.run_identity
               LEFT JOIN {} authorization ON authorization.run_identity = runs.run_identity
              WHERE runs.run_identity = ? AND runs.account_id = ? AND runs.lane = 'immediate'",
            tables.delivery_runs, tables.immediate_delivery, tables.immediate_gross_authorization
        ),
        params![run_identity.as_bytes(), account_id.0],
        |row| {
            Ok(StoredImmediateDelivery {
                run_identity: row.get(0)?,
                source_owner: row.get(1)?,
                canonical_lock_owner: row.get(2)?,
                run_status: row.get(3)?,
                revision: row.get(4)?,
                phase: row.get(5)?,
                artifact_identity: row.get(6)?,
                proposal_fingerprint: row.get(7)?,
                canonical_proposal: row.get(8)?,
                signer_ownership: row.get(9)?,
                status: row.get(10)?,
                claim_kind: row.get(11)?,
                attempt_token: row.get(12)?,
                lease_clock_session: row.get(13)?,
                lease_acquired_at_ms: row.get(14)?,
                lease_expires_at_ms: row.get(15)?,
                txid: row.get(16)?,
                exact_tx: row.get(17)?,
                exact_tx_digest: row.get(18)?,
                unsigned_pczt_digest: row.get(19)?,
                canonical_unsigned_pczt: row.get(20)?,
                signed_pczt_digest: row.get(21)?,
                canonical_signed_pczt: row.get(22)?,
                signed_pczt_binding: row.get(23)?,
                last_error: row.get(24)?,
                expiry_height: row.get(25)?,
                storage_finality: row.get(26)?,
                storage_recovery_reason: row.get(27)?,
                observed_mined_height: row.get(28)?,
                destination_output_index: row.get(29)?,
                expected_ironwood_amount: row.get(30)?,
                release_at_height: row.get(31)?,
                finalized_tip_height: row.get(32)?,
                policy: row.get(33)?,
                policy_fingerprint: row.get(34)?,
                policy_validation_failure: row.get(35)?,
                authorization_version: row.get(36)?,
                maximum_gross_amount: row.get(37)?,
            })
        },
    )
    .optional()
    .map_err(Error::Db)
}

#[cfg(feature = "migration-delivery")]
fn decode_immediate_storage_finality(
    value: &str,
    recovery: Option<&str>,
    release_at_height: Option<u32>,
    finalized_tip_height: Option<u32>,
) -> Result<StorageFinality, Error> {
    let release = release_at_height.map(BlockHeight::from_u32);
    let finalized_tip = finalized_tip_height.map(BlockHeight::from_u32);
    let recovery = match recovery {
        None => None,
        Some("transfer_evidence_lost") => Some(StorageRecoveryReason::TransferEvidenceLost),
        Some("rewound_beyond_finality_horizon") => {
            Some(StorageRecoveryReason::RewoundBeyondFinalityHorizon)
        }
        Some("corrupt_finality_evidence") => Some(StorageRecoveryReason::CorruptFinalityEvidence),
        Some("external_signing_exposure_unresolved") => {
            Some(StorageRecoveryReason::ExternalSigningExposureUnresolved)
        }
        Some(_) => return Err(Error::Corrupt("immediate storage recovery reason")),
    };
    match value {
        "active" if release.is_none() && finalized_tip.is_none() => Ok(StorageFinality::Active),
        "complete_pending_finality" if finalized_tip.is_none() => {
            Ok(StorageFinality::CompletePendingFinality(
                ReservationRelease::at(release.ok_or(Error::Corrupt("immediate release height"))?),
            ))
        }
        "finalized" if finalized_tip.is_some() => Ok(StorageFinality::Finalized(
            ReservationRelease::at(release.ok_or(Error::Corrupt("immediate release height"))?),
        )),
        "recovery_required" => Ok(StorageFinality::RecoveryRequired(
            recovery.ok_or(Error::Corrupt("immediate storage recovery reason"))?,
        )),
        _ => Err(Error::Corrupt("immediate storage finality")),
    }
}

#[cfg(feature = "migration-delivery")]
fn read_immediate_delivery_snapshot(
    conn: &Connection,
    tables: &Tables,
    account_id: AccountRef,
    run_identity: MigrationRunIdentity,
    submission_context: SubmissionContext,
) -> Result<(DeliverySnapshot, DestinationSpendability), Error> {
    let row = read_stored_immediate_delivery(conn, tables, account_id, run_identity)?
        .ok_or(Error::Corrupt("immediate delivery row"))?;
    if !matches!(
        row.run_status.as_str(),
        "active" | "recovery_required" | "finalized" | "abandoned"
    ) {
        return Err(Error::Corrupt("immediate run status"));
    }
    let decoded_run = MigrationRunIdentity::read(row.run_identity.as_slice())
        .map_err(|_| Error::Corrupt("immediate run identity"))?;
    if decoded_run != run_identity || row.canonical_lock_owner.is_none() {
        return Err(Error::Corrupt("immediate run authority"));
    }
    let source_owner = SourceReservationOwner::read(row.source_owner.as_slice())
        .map_err(|_| Error::Corrupt("immediate source owner"))?;
    if row.canonical_lock_owner == Some(*source_owner.as_bytes()) {
        return Err(Error::Corrupt("aliased immediate owners"));
    }
    let revision = DeliveryRevision::read(row.revision.to_le_bytes().as_slice())
        .map_err(|_| Error::Corrupt("immediate delivery revision"))?;
    let phase =
        DeliveryPhase::from_stored(&row.phase).ok_or(Error::Corrupt("immediate delivery phase"))?;
    let artifact_identity = ImmediateArtifactIdentity::read(row.artifact_identity.as_slice())
        .map_err(|_| Error::Corrupt("immediate artifact identity"))?;
    let proposal = ImmediateProposal::decode(&row.canonical_proposal)
        .map_err(|_| Error::Corrupt("immediate proposal envelope"))?;
    if proposal.expiry_height() != BlockHeight::from_u32(row.expiry_height)
        || proposal.digest().as_bytes() != &row.proposal_fingerprint
    {
        return Err(Error::DeliveryArtifactMismatch);
    }
    let evidence = ImmediateArtifactEvidence::from_proposal(artifact_identity, &proposal);
    if evidence.canonical_proposal() != row.canonical_proposal {
        return Err(Error::DeliveryArtifactMismatch);
    }
    let (_, proposal_gross_amount) = immediate_proposal_authority(evidence.canonical_proposal())?;
    let immediate_maximum_gross_amount = match (row.authorization_version, row.maximum_gross_amount)
    {
        (None, None) => None,
        (Some(version), Some(maximum))
            if version == i64::from(IMMEDIATE_GROSS_AUTHORIZATION_VERSION) =>
        {
            let maximum = u64::try_from(maximum)
                .map_err(|_| Error::Corrupt("immediate gross authorization"))?;
            let maximum = Zatoshis::from_u64(maximum)?;
            if proposal_gross_amount > maximum {
                return Err(Error::DeliveryArtifactMismatch);
            }
            Some(maximum)
        }
        _ => return Err(Error::Corrupt("immediate gross authorization tuple")),
    };
    let policy_fingerprint = row
        .policy_fingerprint
        .map(|bytes| {
            PolicyFingerprint::read(bytes.as_slice())
                .map_err(|_| Error::Corrupt("immediate policy fingerprint"))
        })
        .transpose()?;
    let policy = match (row.policy, policy_fingerprint) {
        (Some(bytes), Some(fingerprint)) => Some(
            SubmissionPolicy::decode(bytes, fingerprint, submission_context)
                .map_err(|_| Error::Corrupt("immediate policy binding"))?,
        ),
        (None, None) => None,
        _ => return Err(Error::Corrupt("immediate policy tuple")),
    };
    let policy_failure = row
        .policy_validation_failure
        .as_deref()
        .map(|value| {
            PolicyValidationFailure::from_stored(value)
                .ok_or(Error::Corrupt("immediate policy validation failure"))
        })
        .transpose()?;
    let storage_finality = decode_immediate_storage_finality(
        &row.storage_finality,
        row.storage_recovery_reason.as_deref(),
        row.release_at_height,
        row.finalized_tip_height,
    )?;

    let signer_ownership = match row.signer_ownership.as_str() {
        "sdk" => SignerOwnership::Sdk,
        "external" => SignerOwnership::External,
        _ => return Err(Error::Corrupt("immediate signer ownership")),
    };
    let lease = match (
        row.claim_kind.as_deref(),
        row.attempt_token,
        row.lease_clock_session,
        row.lease_acquired_at_ms,
        row.lease_expires_at_ms,
    ) {
        (None, None, None, None, None) => None,
        (Some(kind), Some(token), Some(session), Some(acquired), Some(expires)) => {
            let kind =
                ClaimKind::from_stored(kind).ok_or(Error::Corrupt("immediate claim kind"))?;
            let token = ClaimToken::read(token.as_slice())
                .map_err(|_| Error::Corrupt("immediate claim token"))?;
            let session = LeaseClockSession::read(session.as_slice())
                .map_err(|_| Error::Corrupt("immediate lease session"))?;
            Some(
                DeliveryLease::from_parts(
                    kind,
                    token,
                    MonotonicLeaseInstant::new(session, acquired),
                    MonotonicLeaseInstant::new(session, expires),
                )
                .map_err(|_| Error::Corrupt("immediate lease tuple"))?,
            )
        }
        _ => return Err(Error::Corrupt("immediate lease tuple")),
    };
    let external_pczt = match (row.unsigned_pczt_digest, row.canonical_unsigned_pczt) {
        (None, None) => None,
        (Some(stored_digest), Some(bytes)) => {
            let staged = ExternalSigningPczt::parse(bytes)
                .map_err(|_| Error::Corrupt("immediate unsigned PCZT"))?;
            if staged.digest().as_bytes() != &stored_digest {
                return Err(Error::DeliveryArtifactMismatch);
            }
            Some(staged)
        }
        _ => return Err(Error::Corrupt("immediate unsigned PCZT tuple")),
    };
    let signed_pczt = match (
        row.signed_pczt_digest,
        row.canonical_signed_pczt,
        row.signed_pczt_binding,
    ) {
        (None, None, None) => None,
        (Some(stored_digest), Some(bytes), Some(stored_binding)) => {
            let staged = external_pczt
                .as_ref()
                .ok_or(Error::Corrupt("immediate signed PCZT without unsigned"))?;
            let signed = SignedPcztEvidence::decode(staged, bytes)
                .map_err(|_| Error::Corrupt("immediate signed PCZT"))?;
            if signed.signed_digest().as_bytes() != &stored_digest
                || signed.staged_digest().as_bytes() != &stored_binding
            {
                return Err(Error::DeliveryArtifactMismatch);
            }
            Some(signed)
        }
        _ => return Err(Error::Corrupt("immediate signed PCZT tuple")),
    };
    let last_error = row
        .last_error
        .as_deref()
        .map(|value| {
            DeliveryFailureReason::from_stored(value)
                .ok_or(Error::Corrupt("immediate failure reason"))
        })
        .transpose()?;
    let exact_transaction = match (row.txid, row.exact_tx, row.exact_tx_digest) {
        (None, None, None) => None,
        (Some(stored_txid), Some(bytes), Some(stored_digest)) => {
            let exact = decode_exact_immediate_transaction(&evidence, &bytes, proposal.branch_id())
                .map_err(|_| Error::DeliveryArtifactMismatch)?;
            if exact.txid().as_ref() != stored_txid.as_slice()
                || exact.digest().as_bytes() != &stored_digest
                || exact.bytes() != bytes
            {
                return Err(Error::DeliveryArtifactMismatch);
            }
            Some(exact)
        }
        _ => return Err(Error::Corrupt("immediate exact transaction tuple")),
    };

    let claims = if row.status == "abandoned" {
        // An unexposed immediate artifact becomes a zero-claim tombstone at the beginning of the
        // two-step abandonment protocol. It remains in `Abandoning` while its wallet locks and
        // source reservations are still live, and becomes `Abandoned` only when those resources
        // are released atomically by `finish_immediate_abandonment`.
        if !matches!(phase, DeliveryPhase::Abandoning | DeliveryPhase::Abandoned)
            || lease.is_some()
            || external_pczt.is_some()
            || signed_pczt.is_some()
            || exact_transaction.is_some()
            || last_error.is_some()
        {
            return Err(Error::Corrupt("immediate abandoned tombstone"));
        }
        vec![]
    } else {
        let status = ClaimStatus::from_stored(&row.status)
            .ok_or(Error::Corrupt("immediate claim status"))?;
        let policy_fingerprint =
            policy_fingerprint.ok_or(Error::Corrupt("immediate claim without policy"))?;
        vec![
            DeliveryClaim::from_parts(
                DeliveryArtifactEvidence::Immediate(evidence.clone()),
                signer_ownership,
                status,
                lease,
                external_pczt,
                signed_pczt,
                exact_transaction.clone(),
                policy_fingerprint,
                last_error,
            )
            .map_err(|_| Error::Corrupt("immediate claim semantic invariants"))?,
        ]
    };
    let active_source_reservation_count = conn.query_row(
        &format!(
            "SELECT COUNT(*) FROM {} WHERE run_identity = ?
             AND status IN ('active', 'recovery_required')",
            tables.delivery_reservations
        ),
        params![run_identity.as_bytes()],
        |row| row.get::<_, u64>(0),
    )?;
    let finality_archive = match (storage_finality, claims.first(), row.observed_mined_height) {
        (StorageFinality::Finalized(release), Some(claim), Some(mined_height))
            if claim.status() == ClaimStatus::Confirmed =>
        {
            let exact = claim
                .exact_transaction()
                .ok_or(Error::Corrupt("immediate finalized exact transaction"))?;
            Some(
                FinalityArchive::new(
                    release,
                    vec![FinalizedTransferEvidence::new(
                        claim.artifact_identity(),
                        exact.txid(),
                        exact.digest(),
                        BlockHeight::from_u32(mined_height),
                    )],
                )
                .map_err(|_| Error::Corrupt("immediate finality archive"))?,
            )
        }
        _ => None,
    };
    let snapshot = DeliverySnapshot::from_parts_with_immediate_gross_authorization(
        revision,
        run_identity,
        DeliveryRunFingerprint::Immediate(proposal.digest()),
        source_owner,
        phase,
        storage_finality,
        active_source_reservation_count,
        finality_archive,
        policy,
        policy_failure,
        immediate_maximum_gross_amount,
        claims,
    )
    .map_err(|_| Error::Corrupt("immediate delivery snapshot"))?;
    let destination = if snapshot.released_without_exposure() {
        DestinationSpendability::NotApplicable
    } else if let (Some(claim), Some(output_index), Some(amount)) = (
        snapshot.claims().first(),
        row.destination_output_index,
        row.expected_ironwood_amount,
    ) {
        if claim.status() != ClaimStatus::Confirmed {
            DestinationSpendability::NotSpendable
        } else {
            let exact = claim
                .exact_transaction()
                .ok_or(Error::Corrupt("immediate destination exact transaction"))?;
            let output = ExactReceivedOutput::new(
                OutputRef::new(exact.txid(), PoolType::IRONWOOD, output_index),
                Zatoshis::from_u64(amount)?,
            );
            match received_output_availability(
                conn,
                account_id,
                output,
                TargetHeight::from(canonical_wallet_target_height(conn)?),
                ConfirmationsPolicy::default(),
                LockFilter::Policy(&LockedInputPolicy::Exclude),
            )? {
                ReceivedOutputAvailability::Spendable => DestinationSpendability::Spendable,
                ReceivedOutputAvailability::Spent { .. } => DestinationSpendability::AlreadySpent,
                ReceivedOutputAvailability::Unknown
                | ReceivedOutputAvailability::Unavailable(_) => {
                    DestinationSpendability::NotSpendable
                }
            }
        }
    } else {
        DestinationSpendability::NotSpendable
    };
    Ok((snapshot, destination))
}

/// Reconciles one immediate row against Rust-owned monotonic time and one fully-scanned active
/// chain view. The caller owns the surrounding IMMEDIATE transaction.
#[cfg(feature = "migration-delivery")]
fn reconcile_immediate_delivery(
    conn: &Connection,
    tables: &Tables,
    account_id: AccountRef,
    run_identity: MigrationRunIdentity,
    submission_context: SubmissionContext,
) -> Result<(), Error> {
    let (snapshot, _) = read_immediate_delivery_snapshot(
        conn,
        tables,
        account_id,
        run_identity,
        submission_context,
    )?;
    let Some(claim) = snapshot.claims().first() else {
        return Ok(());
    };
    let status = claim.status();
    let exact = claim.exact_transaction().cloned();
    let expiry = claim.expiry_height();
    let lease = claim.lease();
    let signer = claim.signer_ownership();
    let has_spend_authorization = snapshot.immediate_maximum_gross_amount().is_some();
    let storage_finality = snapshot.storage_finality();
    let source_owner = snapshot.source_reservation_owner();
    let now = delivery_clock_now();
    let fully_scanned = fully_scanned_height(conn)?;
    let mut changed = false;

    let destination_evidence: (Option<u32>, Option<u64>) = conn.query_row(
        &format!(
            "SELECT destination_output_index, expected_ironwood_amount
               FROM {} WHERE run_identity = ?",
            tables.immediate_delivery
        ),
        params![run_identity.as_bytes()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let destination_evidence_complete = matches!(destination_evidence, (Some(_), Some(_)));
    let destination_evidence_partial =
        matches!(destination_evidence, (Some(_), None) | (None, Some(_)));
    if !matches!(storage_finality, StorageFinality::RecoveryRequired(_))
        && (destination_evidence_partial || exact.is_some() != destination_evidence_complete)
    {
        conn.execute(
            &format!(
                "UPDATE {} SET storage_finality = 'recovery_required',
                 storage_recovery_reason = 'corrupt_finality_evidence'
                 WHERE run_identity = ?",
                tables.immediate_delivery
            ),
            params![run_identity.as_bytes()],
        )?;
        conn.execute(
            &format!(
                "UPDATE {} SET status = 'recovery_required' WHERE run_identity = ?",
                tables.delivery_runs
            ),
            params![run_identity.as_bytes()],
        )?;
        conn.execute(
            &format!(
                "UPDATE {} SET status = 'recovery_required' WHERE run_identity = ?",
                tables.delivery_reservations
            ),
            params![run_identity.as_bytes()],
        )?;
        bump_immediate_revision(conn, tables, run_identity)?;
        return Ok(());
    }

    // Recovery authority is absorbing. Once either this reconciliation pass or an earlier one
    // has quarantined the row, no lease, chain-observation, expiry, or finality transition may
    // reinterpret it. In particular, a legacy exact transaction with no destination tuple is
    // admitted structurally by v2 so it can be quarantined; a later load must not then attempt a
    // `complete_pending_finality` write that v2 correctly rejects for the missing destination.
    if matches!(storage_finality, StorageFinality::RecoveryRequired(_)) {
        return Ok(());
    }

    if let StorageFinality::Finalized(release) = storage_finality {
        let observed_height = exact
            .as_ref()
            .map(|exact| current_wallet_mined_height(conn, exact.txid()))
            .transpose()?
            .flatten();
        let archived_height = snapshot
            .finality_archive()
            .and_then(|archive| archive.transfers().first())
            .map(|transfer| transfer.mined_height());
        let terminal_evidence_is_consistent = match status {
            ClaimStatus::Confirmed => {
                exact.is_some() && archived_height.is_some() && observed_height == archived_height
            }
            ClaimStatus::ExpiredUnmined => {
                exact.is_some() && observed_height.is_none() && archived_height.is_none()
            }
            ClaimStatus::ExternalSigningExpiredUnmined => {
                exact.is_none() && observed_height.is_none() && archived_height.is_none()
            }
            _ => false,
        };
        let active_chain_is_consistent = fully_scanned.is_some_and(|height| {
            height >= release.release_at() && terminal_evidence_is_consistent
        });
        if !active_chain_is_consistent {
            conn.execute(
                &format!(
                    "UPDATE {} SET storage_finality = 'recovery_required',
                     storage_recovery_reason = 'rewound_beyond_finality_horizon'
                     WHERE run_identity = ?",
                    tables.immediate_delivery
                ),
                params![run_identity.as_bytes()],
            )?;
            conn.execute(
                &format!(
                    "UPDATE {} SET status = 'recovery_required' WHERE run_identity = ?",
                    tables.delivery_runs
                ),
                params![run_identity.as_bytes()],
            )?;
            conn.execute(
                &format!(
                    "UPDATE {} SET status = 'recovery_required' WHERE run_identity = ?",
                    tables.delivery_reservations
                ),
                params![run_identity.as_bytes()],
            )?;
            bump_immediate_revision(conn, tables, run_identity)?;
        }
        return Ok(());
    }

    if let Some(lease) = lease
        && lease.validity_at(now) != LeaseValidity::Live
    {
        match status {
            ClaimStatus::Materializing => {
                if has_spend_authorization {
                    let duration_ms = lease
                        .expires_at()
                        .tick_millis()
                        .checked_sub(lease.acquired_at().tick_millis())
                        .and_then(LeaseDuration::from_millis)
                        .ok_or(Error::Corrupt("immediate materialization lease duration"))?;
                    let replacement =
                        checked_delivery_lease(ClaimKind::Materialization, duration_ms)?;
                    conn.execute(
                        &format!(
                            "UPDATE {} SET attempt_token = ?, lease_clock_session = ?,
                             lease_acquired_at_ms = ?, lease_expires_at_ms = ?
                             WHERE run_identity = ?",
                            tables.immediate_delivery
                        ),
                        params![
                            replacement.token().as_bytes(),
                            replacement.acquired_at().session().as_bytes(),
                            replacement.acquired_at().tick_millis(),
                            replacement.expires_at().tick_millis(),
                            run_identity.as_bytes(),
                        ],
                    )?;
                } else {
                    conn.execute(
                        &format!(
                            "UPDATE {} SET status = 'materialization_failed', claim_kind = NULL,
                             attempt_token = NULL, lease_clock_session = NULL,
                             lease_acquired_at_ms = NULL, lease_expires_at_ms = NULL,
                             last_error = 'materialization_lease_expired'
                             WHERE run_identity = ?",
                            tables.immediate_delivery
                        ),
                        params![run_identity.as_bytes()],
                    )?;
                }
                changed = true;
            }
            ClaimStatus::AwaitingExternalSignature => {
                conn.execute(
                    &format!(
                        "UPDATE {} SET claim_kind = NULL, attempt_token = NULL,
                         lease_clock_session = NULL, lease_acquired_at_ms = NULL,
                         lease_expires_at_ms = NULL WHERE run_identity = ?",
                        tables.immediate_delivery
                    ),
                    params![run_identity.as_bytes()],
                )?;
                changed = true;
            }
            ClaimStatus::Submitting => {
                conn.execute(
                    &format!(
                        "UPDATE {} SET status = 'outcome_unknown', claim_kind = NULL,
                         attempt_token = NULL, lease_clock_session = NULL,
                         lease_acquired_at_ms = NULL, lease_expires_at_ms = NULL,
                         last_error = 'transport_outcome_unknown' WHERE run_identity = ?",
                        tables.immediate_delivery
                    ),
                    params![run_identity.as_bytes()],
                )?;
                changed = true;
            }
            ClaimStatus::OutcomeUnknown | ClaimStatus::Broadcasted => {
                conn.execute(
                    &format!(
                        "UPDATE {} SET claim_kind = NULL, attempt_token = NULL,
                         lease_clock_session = NULL, lease_acquired_at_ms = NULL,
                         lease_expires_at_ms = NULL WHERE run_identity = ?",
                        tables.immediate_delivery
                    ),
                    params![run_identity.as_bytes()],
                )?;
                changed = true;
            }
            ClaimStatus::MaterializationFailed
            | ClaimStatus::Staged
            | ClaimStatus::Confirmed
            | ClaimStatus::ExpiredUnmined
            | ClaimStatus::ExternalSigningExpiredUnmined => {}
        }
    }

    let mined_height = exact
        .as_ref()
        .map(|exact| current_wallet_mined_height(conn, exact.txid()))
        .transpose()?
        .flatten();
    if let (Some(exact), Some(mined_height)) = (exact.as_ref(), mined_height) {
        if status != ClaimStatus::Confirmed {
            let release_at = u32::from(mined_height)
                .checked_add(MIGRATION_STORAGE_FINALITY_CONFIRMATIONS - 1)
                .map(BlockHeight::from_u32)
                .ok_or(Error::DeliveryValueTooLarge)?;
            conn.execute(
                &format!(
                    "UPDATE {} SET status = 'confirmed', claim_kind = NULL,
                     attempt_token = NULL, lease_clock_session = NULL,
                     lease_acquired_at_ms = NULL, lease_expires_at_ms = NULL,
                     observed_mined_height = ?, storage_finality = 'complete_pending_finality',
                     release_at_height = ?, last_error = NULL WHERE run_identity = ?",
                    tables.immediate_delivery
                ),
                params![
                    u32::from(mined_height),
                    u32::from(release_at),
                    run_identity.as_bytes()
                ],
            )?;
            changed = true;
        }
        let release_at = u32::from(mined_height)
            .checked_add(MIGRATION_STORAGE_FINALITY_CONFIRMATIONS - 1)
            .map(BlockHeight::from_u32)
            .ok_or(Error::DeliveryValueTooLarge)?;
        if fully_scanned.is_some_and(|height| height >= release_at) {
            let finalized_tip = fully_scanned.expect("checked above");
            conn.execute(
                &format!(
                    "UPDATE {} SET status = 'confirmed', storage_finality = 'finalized',
                     storage_recovery_reason = NULL, observed_mined_height = ?,
                     release_at_height = ?, finalized_tip_height = ? WHERE run_identity = ?",
                    tables.immediate_delivery
                ),
                params![
                    u32::from(mined_height),
                    u32::from(release_at),
                    u32::from(finalized_tip),
                    run_identity.as_bytes(),
                ],
            )?;
            conn.execute(
                &format!(
                    "UPDATE {} SET status = 'finalized' WHERE run_identity = ?",
                    tables.delivery_runs
                ),
                params![run_identity.as_bytes()],
            )?;
            transition_source_reservations(
                conn,
                tables,
                run_identity,
                source_owner,
                "finality_released",
                Some(release_at),
                Some(finalized_tip),
            )?;
            let row = read_stored_immediate_delivery(conn, tables, account_id, run_identity)?
                .ok_or(Error::Corrupt("immediate delivery row"))?;
            let lock_owner = row
                .canonical_lock_owner
                .map(LockOwner::new)
                .ok_or(Error::Corrupt("immediate lock owner"))?;
            release_locks(conn, account_id, &BTreeSet::from([lock_owner]))?;
            let _ = exact;
            changed = true;
        }
    } else if status == ClaimStatus::Confirmed {
        conn.execute(
            &format!(
                "UPDATE {} SET status = 'broadcasted', storage_finality = 'active',
                 storage_recovery_reason = NULL, observed_mined_height = NULL,
                 release_at_height = NULL, finalized_tip_height = NULL WHERE run_identity = ?",
                tables.immediate_delivery
            ),
            params![run_identity.as_bytes()],
        )?;
        changed = true;
    } else if fully_scanned.is_some_and(|height| height > expiry) {
        if signer == SignerOwnership::External && status == ClaimStatus::AwaitingExternalSignature {
            let fully_scanned = fully_scanned.expect("checked above");
            if reserved_sources_proven_unspent(
                conn,
                tables,
                account_id,
                run_identity,
                fully_scanned,
                canonical_wallet_target_height(conn)?,
            )? {
                conn.execute(
                    &format!(
                        "UPDATE {} SET status = 'external_signing_expired_unmined',
                         claim_kind = NULL, attempt_token = NULL, lease_clock_session = NULL,
                         lease_acquired_at_ms = NULL, lease_expires_at_ms = NULL,
                         last_error = NULL WHERE run_identity = ?",
                        tables.immediate_delivery
                    ),
                    params![run_identity.as_bytes()],
                )?;
            } else {
                conn.execute(
                    &format!(
                        "UPDATE {} SET storage_finality = 'recovery_required',
                         storage_recovery_reason = 'external_signing_exposure_unresolved'
                         WHERE run_identity = ?",
                        tables.immediate_delivery
                    ),
                    params![run_identity.as_bytes()],
                )?;
                conn.execute(
                    &format!(
                        "UPDATE {} SET status = 'recovery_required' WHERE run_identity = ?",
                        tables.delivery_runs
                    ),
                    params![run_identity.as_bytes()],
                )?;
                conn.execute(
                    &format!(
                        "UPDATE {} SET status = 'recovery_required' WHERE run_identity = ?",
                        tables.delivery_reservations
                    ),
                    params![run_identity.as_bytes()],
                )?;
            }
            changed = true;
        } else if exact.is_some()
            && (matches!(
                status,
                ClaimStatus::Submitting | ClaimStatus::OutcomeUnknown | ClaimStatus::Broadcasted
            ) || (signer == SignerOwnership::External && status == ClaimStatus::Staged))
        {
            conn.execute(
                &format!(
                    "UPDATE {} SET status = 'expired_unmined', claim_kind = NULL,
                     attempt_token = NULL, lease_clock_session = NULL,
                     lease_acquired_at_ms = NULL, lease_expires_at_ms = NULL,
                     last_error = NULL WHERE run_identity = ?",
                    tables.immediate_delivery
                ),
                params![run_identity.as_bytes()],
            )?;
            changed = true;
        }
    }
    if changed {
        bump_immediate_revision(conn, tables, run_identity)?;
    }
    Ok(())
}

/// Loads the sole live immediate run plus every terminal predecessor from one caller-owned atomic
/// view. Multiple live rows are corrupt even if a damaged index allowed them to persist.
#[cfg(feature = "migration-delivery")]
pub(super) type ImmediateDeliveryRuntimeParts = (
    Option<(DeliverySnapshot, DestinationSpendability)>,
    Vec<RetainedMigrationRun>,
);

/// Loads the sole live immediate run plus every terminal predecessor from one caller-owned atomic
/// view. Multiple live rows are corrupt even if a damaged index allowed them to persist.
#[cfg(feature = "migration-delivery")]
pub(super) fn load_immediate_delivery_runtime_parts(
    conn: &Connection,
    tables: &Tables,
    account_id: AccountRef,
    submission_context: SubmissionContext,
) -> Result<ImmediateDeliveryRuntimeParts, Error> {
    let rows = {
        let mut stmt = conn.prepare(&format!(
            "SELECT run_identity, status FROM {} WHERE account_id = ? AND lane = 'immediate'
             ORDER BY rowid",
            tables.delivery_runs
        ))?;
        stmt.query_map(params![account_id.0], |row| {
            Ok((row.get::<_, [u8; 32]>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?
    };
    let mut current = None;
    let mut retained = Vec::new();
    for (run_bytes, _) in rows {
        let run_identity = MigrationRunIdentity::read(run_bytes.as_slice())
            .map_err(|_| Error::Corrupt("immediate run identity"))?;
        reconcile_immediate_delivery(conn, tables, account_id, run_identity, submission_context)?;
        let run_status = conn.query_row(
            &format!(
                "SELECT status FROM {} WHERE run_identity = ?",
                tables.delivery_runs
            ),
            params![run_identity.as_bytes()],
            |row| row.get::<_, String>(0),
        )?;
        let (snapshot, destination) = read_immediate_delivery_snapshot(
            conn,
            tables,
            account_id,
            run_identity,
            submission_context,
        )?;
        match run_status.as_str() {
            "active" | "recovery_required" => {
                if current.replace((snapshot, destination)).is_some() {
                    return Err(Error::Corrupt("multiple live immediate runs"));
                }
            }
            "finalized" | "abandoned" => retained.push(
                RetainedMigrationRun::from_observed(None, snapshot, destination)
                    .map_err(|_| Error::Corrupt("retained immediate run"))?,
            ),
            _ => return Err(Error::Corrupt("immediate run status")),
        }
    }
    Ok((current, retained))
}

/// Commits one wallet-derived immediate proposal and every item of authority that makes it safe to
/// expose. The caller owns the surrounding wallet transaction so proposal selection and these
/// writes share the same revision-consistent view.
#[cfg(feature = "migration-delivery")]
#[allow(clippy::too_many_arguments)]
pub(super) fn reserve_immediate_delivery(
    transaction: &super::ImmediateDeliveryWriteTransaction<'_>,
    tables: &Tables,
    account_id: AccountRef,
    proposal: &ImmediateProposal,
    evidence: &ImmediateArtifactEvidence,
    sources: &[OutputRef],
    run_identity: MigrationRunIdentity,
    source_owner: SourceReservationOwner,
    lock_owner: LockOwner,
    signer_ownership: SignerOwnership,
    lease: DeliveryLease,
    policy: &SubmissionPolicy,
    submission_context: SubmissionContext,
    maximum_gross_amount: Zatoshis,
) -> Result<DeliverySnapshot, Error> {
    let conn = transaction.connection();
    if !matches!(
        delivery_schema_provenance(conn, tables)?,
        DeliverySchemaProvenance::Compatible(_)
    ) {
        return Err(Error::DeliverySchemaIncompatible);
    }
    if !matches!(
        legacy_cutover_status(conn, tables)?,
        LegacyCutoverStatus::Fresh
    ) {
        return Err(Error::LegacyRecoveryRequired);
    }
    if policy.request().context() != submission_context {
        return Err(Error::DeliveryPolicyMismatch);
    }
    if policy.canonical_bytes().len() > MAX_SUBMISSION_POLICY_BYTES {
        return Err(Error::DeliveryValueTooLarge);
    }
    if evidence.identity()
        == ImmediateArtifactIdentity::read(run_identity.as_bytes().as_slice())
            .map_err(|_| Error::Corrupt("immediate identity alias check"))?
        || source_owner.as_bytes() == lock_owner.as_bytes()
    {
        return Err(Error::Corrupt("aliased immediate authority"));
    }
    if evidence.expiry_height() != proposal.expiry_height()
        || evidence.proposal_digest() != proposal.digest()
        || evidence.canonical_proposal() != {
            let mut bytes = Vec::new();
            proposal
                .write(&mut bytes)
                .map_err(|_| Error::Corrupt("immediate proposal encoding"))?;
            bytes
        }
    {
        return Err(Error::DeliveryArtifactMismatch);
    }
    let supplied_sources = sources.iter().copied().collect::<BTreeSet<_>>();
    let (proposal_sources, proposal_gross_amount) =
        immediate_proposal_authority(evidence.canonical_proposal())?;
    if supplied_sources.len() != sources.len() || supplied_sources != proposal_sources {
        return Err(Error::DeliveryArtifactMismatch);
    }
    require_immediate_gross_authorization(proposal_gross_amount, maximum_gross_amount)?;
    let stored_maximum_gross_amount = i64::try_from(maximum_gross_amount.into_u64())
        .map_err(|_| Error::Corrupt("immediate gross authorization"))?;
    let live_run_exists = conn.query_row(
        &format!(
            "SELECT EXISTS(SELECT 1 FROM {} WHERE account_id = ?
             AND status IN ('active', 'recovery_required'))",
            tables.delivery_runs
        ),
        params![account_id.0],
        |row| row.get::<_, bool>(0),
    )?;
    if live_run_exists {
        return Err(Error::DeliveryLaneConflict);
    }
    let authority_fingerprint = delivery_run_authority_fingerprint(
        run_identity.as_bytes(),
        account_id.0,
        "immediate",
        None,
        source_owner.as_bytes(),
        Some(lock_owner.as_bytes()),
    )?;
    conn.execute(
        &format!(
            "INSERT INTO {} (
                 run_identity, account_id, lane, canonical_migration_id, source_owner,
                 canonical_lock_owner, authority_fingerprint, status
             ) VALUES (?, ?, 'immediate', NULL, ?, ?, ?, 'active')",
            tables.delivery_runs
        ),
        params![
            run_identity.as_bytes(),
            account_id.0,
            source_owner.as_bytes(),
            lock_owner.as_bytes(),
            authority_fingerprint,
        ],
    )
    .map_err(|error| match error {
        rusqlite::Error::SqliteFailure(ref failure, _)
            if failure.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            Error::DeliveryLaneConflict
        }
        other => Error::Db(other),
    })?;
    conn.execute(
        &format!(
            "INSERT INTO {} (
                 run_identity, revision, phase, artifact_identity, proposal_fingerprint,
                 canonical_proposal, signer_ownership, status, claim_kind, attempt_token,
                 lease_clock_session, lease_acquired_at_ms, lease_expires_at_ms, expiry_height,
                 storage_finality, policy, policy_fingerprint
             ) VALUES (?, ?, 'active', ?, ?, ?, ?, 'materializing', 'materialization',
                       ?, ?, ?, ?, ?, 'active', ?, ?)",
            tables.immediate_delivery
        ),
        params![
            run_identity.as_bytes(),
            DeliveryRevision::INITIAL.as_u64(),
            evidence.identity().as_bytes(),
            evidence.proposal_digest().as_bytes(),
            evidence.canonical_proposal(),
            match signer_ownership {
                SignerOwnership::Sdk => "sdk",
                SignerOwnership::External => "external",
            },
            lease.token().as_bytes(),
            lease.acquired_at().session().as_bytes(),
            lease.acquired_at().tick_millis(),
            lease.expires_at().tick_millis(),
            u32::from(evidence.expiry_height()),
            policy.canonical_bytes(),
            policy.fingerprint().as_bytes(),
        ],
    )?;
    conn.execute(
        &format!(
            "INSERT INTO {} (run_identity, authorization_version, maximum_gross_amount)
             VALUES (?, ?, ?)",
            tables.immediate_gross_authorization
        ),
        params![
            run_identity.as_bytes(),
            IMMEDIATE_GROSS_AUTHORIZATION_VERSION,
            stored_maximum_gross_amount,
        ],
    )?;
    upsert_source_reservations(conn, tables, sources, run_identity)?;
    lock_outputs(
        conn,
        account_id,
        sources,
        lock_owner,
        evidence.expiry_height(),
    )?;
    if !immediate_reservations_are_complete(conn, tables, run_identity)? {
        return Err(Error::DeliveryArtifactMismatch);
    }
    let (snapshot, _) = read_immediate_delivery_snapshot(
        conn,
        tables,
        account_id,
        run_identity,
        submission_context,
    )?;
    Ok(snapshot)
}

#[cfg(feature = "migration-delivery")]
fn bump_immediate_revision(
    conn: &Connection,
    tables: &Tables,
    run_identity: MigrationRunIdentity,
) -> Result<(), Error> {
    let changed = conn.execute(
        &format!(
            "UPDATE {} SET revision = revision + 1 WHERE run_identity = ?
             AND revision < 9223372036854775807",
            tables.immediate_delivery
        ),
        params![run_identity.as_bytes()],
    )?;
    if changed != 1 {
        return Err(Error::DeliveryRevisionMismatch);
    }
    Ok(())
}

#[cfg(feature = "migration-delivery")]
fn require_immediate_cas_update(changed: usize) -> Result<(), Error> {
    if changed == 1 {
        Ok(())
    } else {
        Err(Error::DeliveryRevisionMismatch)
    }
}

#[cfg(feature = "migration-delivery")]
// These values are the independent identity and policy checks for one immediate-lane CAS read.
#[allow(clippy::too_many_arguments)]
fn require_immediate_context(
    conn: &Connection,
    tables: &Tables,
    account_id: AccountRef,
    submission_context: SubmissionContext,
    expected_revision: DeliveryRevision,
    run_identity: MigrationRunIdentity,
    artifact_identity: Option<ImmediateArtifactIdentity>,
    expected_policy_fingerprint: Option<PolicyFingerprint>,
) -> Result<DeliverySnapshot, Error> {
    let (snapshot, _) = read_immediate_delivery_snapshot(
        conn,
        tables,
        account_id,
        run_identity,
        submission_context,
    )?;
    if snapshot.revision() != expected_revision {
        return Err(Error::DeliveryRevisionMismatch);
    }
    if snapshot.run_identity() != run_identity {
        return Err(Error::DeliveryRunMismatch);
    }
    if let Some(artifact_identity) = artifact_identity
        && snapshot.claims().first().is_none_or(|claim| {
            claim.artifact_identity() != DeliveryArtifactIdentity::Immediate(artifact_identity)
        })
    {
        return Err(Error::DeliveryArtifactMismatch);
    }
    if let Some(expected) = expected_policy_fingerprint
        && snapshot
            .submission_policy()
            .is_none_or(|policy| policy.fingerprint() != expected)
    {
        return Err(Error::DeliveryPolicyMismatch);
    }
    Ok(snapshot)
}

/// Requires active finality and exact active run/reservation authority before an immediate run may
/// advance toward new external exposure.
#[cfg(feature = "migration-delivery")]
fn require_immediate_forward_exposure_context(
    conn: &Connection,
    tables: &Tables,
    snapshot: &DeliverySnapshot,
) -> Result<(), Error> {
    if snapshot.lane() != DeliveryLane::Immediate
        || snapshot.storage_finality() != StorageFinality::Active
        || snapshot.active_source_reservation_count() == 0
    {
        return Err(Error::DeliveryRecoveryRequired);
    }
    let authority = conn
        .query_row(
            &format!(
                "SELECT runs.status,
                        (SELECT COUNT(*) FROM {} reservations
                          WHERE reservations.run_identity = runs.run_identity),
                        (SELECT COUNT(*) FROM {} reservations
                          WHERE reservations.run_identity = runs.run_identity
                            AND reservations.status = 'active')
                   FROM {} runs WHERE runs.run_identity = ? AND runs.lane = 'immediate'",
                tables.delivery_reservations, tables.delivery_reservations, tables.delivery_runs,
            ),
            params![snapshot.run_identity().as_bytes()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, u64>(1)?,
                    row.get::<_, u64>(2)?,
                ))
            },
        )
        .optional()?;
    let Some((run_status, reservation_count, active_reservation_count)) = authority else {
        return Err(Error::DeliveryRecoveryRequired);
    };
    if run_status != "active"
        || reservation_count == 0
        || reservation_count != active_reservation_count
        || active_reservation_count != snapshot.active_source_reservation_count()
        || !immediate_reservations_are_complete(conn, tables, snapshot.run_identity())?
    {
        return Err(Error::DeliveryRecoveryRequired);
    }
    Ok(())
}

/// Additionally requires the durable, versioned gross-spend authorization. Legacy rows remain
/// readable and may reconcile or unwind, but cannot use proposal bytes as a substitute for user
/// consent. The exact unexposed materialization-failure path may persist fresh authorization only
/// after independently satisfying the forward-exposure context and its stricter retry predicates.
#[cfg(feature = "migration-delivery")]
fn require_immediate_spend_authorization(
    conn: &Connection,
    tables: &Tables,
    snapshot: &DeliverySnapshot,
) -> Result<(), Error> {
    require_immediate_forward_exposure_context(conn, tables, snapshot)?;
    snapshot
        .immediate_maximum_gross_amount()
        .map(|_| ())
        .ok_or(Error::DeliveryRecoveryRequired)
}

#[cfg(feature = "migration-delivery")]
fn immediate_snapshot_after_mutation(
    conn: &Connection,
    tables: &Tables,
    account_id: AccountRef,
    run_identity: MigrationRunIdentity,
    submission_context: SubmissionContext,
) -> Result<DeliverySnapshot, Error> {
    read_immediate_delivery_snapshot(conn, tables, account_id, run_identity, submission_context)
        .map(|(snapshot, _)| snapshot)
}

/// Reissues only the bounded materialization capability for one exact, unexposed, known-unsent
/// immediate failure. The enclosing wallet transaction makes the authorization predicate and
/// revision bump one compare-and-swap; proposal evidence, reservations, and identities are never
/// rewritten.
#[cfg(feature = "migration-delivery")]
#[allow(clippy::too_many_arguments)]
pub(super) fn reacquire_failed_immediate_materialization(
    transaction: &super::ImmediateDeliveryWriteTransaction<'_>,
    tables: &Tables,
    account_id: AccountRef,
    submission_context: SubmissionContext,
    expected_revision: DeliveryRevision,
    run_identity: MigrationRunIdentity,
    artifact_identity: ImmediateArtifactIdentity,
    signer_ownership: SignerOwnership,
    maximum_gross_amount: Zatoshis,
    lease_duration: LeaseDuration,
    expected_policy_fingerprint: PolicyFingerprint,
) -> Result<DeliverySnapshot, Error> {
    let conn = transaction.connection();
    let snapshot = require_immediate_context(
        conn,
        tables,
        account_id,
        submission_context,
        expected_revision,
        run_identity,
        Some(artifact_identity),
        Some(expected_policy_fingerprint),
    )?;
    require_immediate_forward_exposure_context(conn, tables, &snapshot)?;
    if snapshot.phase() != DeliveryPhase::Active {
        return Err(Error::DeliveryPhaseMismatch);
    }
    let claim = snapshot
        .claims()
        .first()
        .ok_or(Error::DeliveryClaimUnavailable)?;
    if claim.signer_ownership() != signer_ownership
        || claim.status() != ClaimStatus::MaterializationFailed
        || claim.lease().is_some()
        || claim.has_exposure_history()
        || claim.external_signing_pczt().is_some()
        || claim.signed_pczt().is_some()
        || claim.exact_transaction().is_some()
        || claim.txid().is_some()
        || !matches!(
            claim.last_error(),
            Some(
                DeliveryFailureReason::MaterializationFailed
                    | DeliveryFailureReason::MaterializationLeaseExpired
                    | DeliveryFailureReason::SigningCancelled
            )
        )
    {
        return Err(Error::DeliveryClaimUnavailable);
    }
    let DeliveryArtifactEvidence::Immediate(evidence) = claim.evidence() else {
        return Err(Error::DeliveryArtifactMismatch);
    };
    let (_, proposal_gross_amount) = immediate_proposal_authority(evidence.canonical_proposal())?;
    require_immediate_gross_authorization(proposal_gross_amount, maximum_gross_amount)?;
    let legacy_authorization = snapshot.immediate_maximum_gross_amount().is_none();
    let stored_maximum_gross_amount = i64::try_from(maximum_gross_amount.into_u64())
        .map_err(|_| Error::Corrupt("immediate gross authorization"))?;

    let lease = checked_delivery_lease(ClaimKind::Materialization, lease_duration)?;
    let signer = match signer_ownership {
        SignerOwnership::Sdk => "sdk",
        SignerOwnership::External => "external",
    };
    if legacy_authorization {
        conn.execute(
            &format!(
                "INSERT INTO {} (run_identity, authorization_version, maximum_gross_amount)
                 VALUES (?, ?, ?)",
                tables.immediate_gross_authorization
            ),
            params![
                run_identity.as_bytes(),
                IMMEDIATE_GROSS_AUTHORIZATION_VERSION,
                stored_maximum_gross_amount,
            ],
        )?;
    }
    let changed = conn.execute(
        &format!(
            "UPDATE {} SET status = 'materializing', claim_kind = 'materialization',
             attempt_token = ?, lease_clock_session = ?, lease_acquired_at_ms = ?,
             lease_expires_at_ms = ?, last_error = NULL
             WHERE run_identity = ? AND revision = ? AND phase = 'active'
               AND status = 'materialization_failed' AND signer_ownership = ?
               AND claim_kind IS NULL AND attempt_token IS NULL
               AND lease_clock_session IS NULL AND lease_acquired_at_ms IS NULL
               AND lease_expires_at_ms IS NULL AND unsigned_pczt_digest IS NULL
               AND canonical_unsigned_pczt IS NULL AND signed_pczt_digest IS NULL
               AND canonical_signed_pczt IS NULL AND signed_pczt_binding IS NULL
               AND txid IS NULL AND exact_tx IS NULL AND exact_tx_digest IS NULL",
            tables.immediate_delivery
        ),
        params![
            lease.token().as_bytes(),
            lease.acquired_at().session().as_bytes(),
            lease.acquired_at().tick_millis(),
            lease.expires_at().tick_millis(),
            run_identity.as_bytes(),
            expected_revision.as_u64(),
            signer,
        ],
    )?;
    require_immediate_cas_update(changed)?;
    bump_immediate_revision(conn, tables, run_identity)?;
    immediate_snapshot_after_mutation(conn, tables, account_id, run_identity, submission_context)
}

#[cfg(feature = "migration-delivery")]
#[allow(clippy::too_many_arguments)]
pub(super) fn reacquire_immediate_external_signing(
    conn: &Connection,
    tables: &Tables,
    account_id: AccountRef,
    submission_context: SubmissionContext,
    expected_revision: DeliveryRevision,
    run_identity: MigrationRunIdentity,
    artifact_identity: ImmediateArtifactIdentity,
    lease_duration: LeaseDuration,
    expected_policy_fingerprint: PolicyFingerprint,
) -> Result<Option<DeliverySnapshot>, Error> {
    let now = delivery_clock_now();
    let snapshot = require_immediate_context(
        conn,
        tables,
        account_id,
        submission_context,
        expected_revision,
        run_identity,
        Some(artifact_identity),
        Some(expected_policy_fingerprint),
    )?;
    require_immediate_spend_authorization(conn, tables, &snapshot)?;
    if snapshot.phase() != DeliveryPhase::Active {
        return Err(Error::DeliveryPhaseMismatch);
    }
    let claim = snapshot
        .claims()
        .first()
        .ok_or(Error::DeliveryClaimUnavailable)?;
    if claim.signer_ownership() != SignerOwnership::External
        || claim.status() != ClaimStatus::AwaitingExternalSignature
        || claim.external_signing_pczt().is_none()
    {
        return Err(Error::DeliveryClaimUnavailable);
    }
    if claim
        .lease()
        .is_some_and(|lease| lease.validity_at(now) == LeaseValidity::Live)
    {
        return Ok(None);
    }
    let lease = checked_delivery_lease(ClaimKind::Materialization, lease_duration)?;
    let changed = conn.execute(
        &format!(
            "UPDATE {} SET claim_kind = 'materialization', attempt_token = ?,
             lease_clock_session = ?, lease_acquired_at_ms = ?, lease_expires_at_ms = ?
             WHERE run_identity = ? AND revision = ?",
            tables.immediate_delivery
        ),
        params![
            lease.token().as_bytes(),
            lease.acquired_at().session().as_bytes(),
            lease.acquired_at().tick_millis(),
            lease.expires_at().tick_millis(),
            run_identity.as_bytes(),
            expected_revision.as_u64(),
        ],
    )?;
    require_immediate_cas_update(changed)?;
    bump_immediate_revision(conn, tables, run_identity)?;
    immediate_snapshot_after_mutation(conn, tables, account_id, run_identity, submission_context)
        .map(Some)
}

#[cfg(feature = "migration-delivery")]
#[allow(clippy::too_many_arguments)]
pub(super) fn stage_immediate_external_signing_pczt(
    conn: &Connection,
    tables: &Tables,
    account_id: AccountRef,
    submission_context: SubmissionContext,
    expected_revision: DeliveryRevision,
    run_identity: MigrationRunIdentity,
    artifact_identity: ImmediateArtifactIdentity,
    token: ClaimToken,
    pczt: &ExternalSigningPczt,
    expected_policy_fingerprint: PolicyFingerprint,
    seal: &super::ValidatedImmediatePczt,
) -> Result<DeliverySnapshot, Error> {
    let now = delivery_clock_now();
    let snapshot = require_immediate_context(
        conn,
        tables,
        account_id,
        submission_context,
        expected_revision,
        run_identity,
        Some(artifact_identity),
        Some(expected_policy_fingerprint),
    )?;
    require_immediate_spend_authorization(conn, tables, &snapshot)?;
    let claim = snapshot
        .claims()
        .first()
        .ok_or(Error::DeliveryClaimUnavailable)?;
    if snapshot.phase() != DeliveryPhase::Active
        || seal.artifact_identity != artifact_identity
        || seal.pczt_digest != pczt.digest()
        || snapshot.run_fingerprint() != DeliveryRunFingerprint::Immediate(seal.proposal_digest)
        || claim.signer_ownership() != SignerOwnership::External
        || claim.status() != ClaimStatus::Materializing
        || claim.token() != Some(token)
        || claim
            .lease()
            .is_none_or(|lease| lease.validity_at(now) != LeaseValidity::Live)
    {
        return Err(Error::DeliveryClaimUnavailable);
    }
    let changed = conn.execute(
        &format!(
            "UPDATE {} SET status = 'awaiting_external_signature',
             unsigned_pczt_digest = ?, canonical_unsigned_pczt = ?, last_error = NULL
             WHERE run_identity = ? AND revision = ?",
            tables.immediate_delivery
        ),
        params![
            pczt.digest().as_bytes(),
            pczt.bytes(),
            run_identity.as_bytes(),
            expected_revision.as_u64(),
        ],
    )?;
    require_immediate_cas_update(changed)?;
    bump_immediate_revision(conn, tables, run_identity)?;
    immediate_snapshot_after_mutation(conn, tables, account_id, run_identity, submission_context)
}

#[cfg(feature = "migration-delivery")]
#[allow(clippy::too_many_arguments)]
pub(super) fn stage_immediate_signed_pczt(
    conn: &Connection,
    tables: &Tables,
    account_id: AccountRef,
    submission_context: SubmissionContext,
    expected_revision: DeliveryRevision,
    run_identity: MigrationRunIdentity,
    artifact_identity: ImmediateArtifactIdentity,
    token: ClaimToken,
    signed_pczt: &SignedPcztEvidence,
    expected_policy_fingerprint: PolicyFingerprint,
) -> Result<DeliverySnapshot, Error> {
    let now = delivery_clock_now();
    let snapshot = require_immediate_context(
        conn,
        tables,
        account_id,
        submission_context,
        expected_revision,
        run_identity,
        Some(artifact_identity),
        Some(expected_policy_fingerprint),
    )?;
    require_immediate_spend_authorization(conn, tables, &snapshot)?;
    let claim = snapshot
        .claims()
        .first()
        .ok_or(Error::DeliveryClaimUnavailable)?;
    if snapshot.phase() != DeliveryPhase::Active
        || claim.signer_ownership() != SignerOwnership::External
        || claim.status() != ClaimStatus::AwaitingExternalSignature
        || claim.token() != Some(token)
        || claim
            .lease()
            .is_none_or(|lease| lease.validity_at(now) != LeaseValidity::Live)
        || claim
            .external_signing_pczt()
            .is_none_or(|staged| signed_pczt.staged_digest() != staged.digest())
    {
        return Err(Error::DeliveryClaimUnavailable);
    }
    let changed = conn.execute(
        &format!(
            "UPDATE {} SET signed_pczt_digest = ?, canonical_signed_pczt = ?,
             signed_pczt_binding = ?, last_error = NULL
             WHERE run_identity = ? AND revision = ?",
            tables.immediate_delivery
        ),
        params![
            signed_pczt.signed_digest().as_bytes(),
            signed_pczt.bytes(),
            signed_pczt.staged_digest().as_bytes(),
            run_identity.as_bytes(),
            expected_revision.as_u64(),
        ],
    )?;
    require_immediate_cas_update(changed)?;
    bump_immediate_revision(conn, tables, run_identity)?;
    immediate_snapshot_after_mutation(conn, tables, account_id, run_identity, submission_context)
}

#[cfg(feature = "migration-delivery")]
#[allow(clippy::too_many_arguments)]
pub(super) fn stage_immediate_transaction(
    conn: &Connection,
    tables: &Tables,
    account_id: AccountRef,
    submission_context: SubmissionContext,
    expected_revision: DeliveryRevision,
    run_identity: MigrationRunIdentity,
    token: ClaimToken,
    artifact: &ExactTransaction,
    expected_policy_fingerprint: PolicyFingerprint,
    seal: &super::ValidatedImmediateTransaction,
) -> Result<DeliverySnapshot, Error> {
    let artifact_identity = match artifact.artifact_identity() {
        DeliveryArtifactIdentity::Immediate(identity) => identity,
        DeliveryArtifactIdentity::Scheduled(_) => return Err(Error::DeliveryArtifactMismatch),
    };
    let now = delivery_clock_now();
    let snapshot = require_immediate_context(
        conn,
        tables,
        account_id,
        submission_context,
        expected_revision,
        run_identity,
        Some(artifact_identity),
        Some(expected_policy_fingerprint),
    )?;
    require_immediate_spend_authorization(conn, tables, &snapshot)?;
    let claim = snapshot
        .claims()
        .first()
        .ok_or(Error::DeliveryClaimUnavailable)?;
    if snapshot.phase() != DeliveryPhase::Active
        || seal.artifact_identity != artifact_identity
        || seal.exact_digest != artifact.digest()
        || snapshot.run_fingerprint() != DeliveryRunFingerprint::Immediate(seal.proposal_digest)
        || !matches!(
            claim.status(),
            ClaimStatus::Materializing | ClaimStatus::AwaitingExternalSignature
        )
        || claim.token() != Some(token)
        || claim
            .lease()
            .is_none_or(|lease| lease.validity_at(now) != LeaseValidity::Live)
        || artifact.consensus_expiry_height() != claim.expiry_height()
        || (claim.signer_ownership() == SignerOwnership::External && claim.signed_pczt().is_none())
        || !immediate_reservations_are_complete(conn, tables, run_identity)?
    {
        return Err(Error::DeliveryArtifactMismatch);
    }
    let changed = conn.execute(
        &format!(
            "UPDATE {} SET status = 'staged', claim_kind = NULL, attempt_token = NULL,
             lease_clock_session = NULL, lease_acquired_at_ms = NULL,
             lease_expires_at_ms = NULL, txid = ?, exact_tx = ?, exact_tx_digest = ?,
             destination_output_index = ?, expected_ironwood_amount = ?, last_error = NULL
             WHERE run_identity = ? AND revision = ?",
            tables.immediate_delivery
        ),
        params![
            artifact.txid().as_ref(),
            artifact.bytes(),
            artifact.digest().as_bytes(),
            seal.destination_output_index,
            u64::from(seal.ironwood_amount),
            run_identity.as_bytes(),
            expected_revision.as_u64(),
        ],
    )?;
    require_immediate_cas_update(changed)?;
    bump_immediate_revision(conn, tables, run_identity)?;
    immediate_snapshot_after_mutation(conn, tables, account_id, run_identity, submission_context)
}

#[cfg(feature = "migration-delivery")]
#[allow(clippy::too_many_arguments)]
pub(super) fn claim_immediate(
    conn: &Connection,
    tables: &Tables,
    account_id: AccountRef,
    submission_context: SubmissionContext,
    expected_revision: DeliveryRevision,
    run_identity: MigrationRunIdentity,
    artifact_identity: ImmediateArtifactIdentity,
    lease_duration: LeaseDuration,
    expected_policy_fingerprint: PolicyFingerprint,
    kind: ClaimKind,
) -> Result<Option<DeliverySnapshot>, Error> {
    let now = delivery_clock_now();
    let snapshot = require_immediate_context(
        conn,
        tables,
        account_id,
        submission_context,
        expected_revision,
        run_identity,
        Some(artifact_identity),
        Some(expected_policy_fingerprint),
    )?;
    if kind == ClaimKind::Submission {
        require_immediate_spend_authorization(conn, tables, &snapshot)?;
    }
    if snapshot.phase() != DeliveryPhase::Active {
        return Err(Error::DeliveryPhaseMismatch);
    }
    let claim = snapshot
        .claims()
        .first()
        .ok_or(Error::DeliveryClaimUnavailable)?;
    let eligible = match kind {
        ClaimKind::Submission => claim.status() == ClaimStatus::Staged,
        ClaimKind::OutcomeResolution => matches!(
            claim.status(),
            ClaimStatus::OutcomeUnknown | ClaimStatus::Broadcasted
        ),
        ClaimKind::Materialization => false,
    };
    if !eligible {
        return Ok(None);
    }
    if claim
        .lease()
        .is_some_and(|lease| lease.validity_at(now) == LeaseValidity::Live)
    {
        return Ok(None);
    }
    let lease = checked_delivery_lease(kind, lease_duration)?;
    let status = match kind {
        ClaimKind::Submission => "submitting",
        ClaimKind::OutcomeResolution => claim.status().as_str(),
        ClaimKind::Materialization => unreachable!("handled above"),
    };
    let changed = conn.execute(
        &format!(
            "UPDATE {} SET status = ?, claim_kind = ?, attempt_token = ?,
             lease_clock_session = ?, lease_acquired_at_ms = ?, lease_expires_at_ms = ?,
             last_error = CASE WHEN ? = 'outcome_resolution' THEN last_error ELSE NULL END
             WHERE run_identity = ? AND revision = ?",
            tables.immediate_delivery
        ),
        params![
            status,
            kind.as_str(),
            lease.token().as_bytes(),
            lease.acquired_at().session().as_bytes(),
            lease.acquired_at().tick_millis(),
            lease.expires_at().tick_millis(),
            kind.as_str(),
            run_identity.as_bytes(),
            expected_revision.as_u64(),
        ],
    )?;
    require_immediate_cas_update(changed)?;
    bump_immediate_revision(conn, tables, run_identity)?;
    immediate_snapshot_after_mutation(conn, tables, account_id, run_identity, submission_context)
        .map(Some)
}

#[cfg(feature = "migration-delivery")]
#[allow(clippy::too_many_arguments)]
pub(super) fn resume_immediate_claim(
    conn: &Connection,
    tables: &Tables,
    account_id: AccountRef,
    submission_context: SubmissionContext,
    expected_revision: DeliveryRevision,
    run_identity: MigrationRunIdentity,
    artifact_identity: ImmediateArtifactIdentity,
    token: ClaimToken,
    expected_policy_fingerprint: PolicyFingerprint,
) -> Result<Option<DeliverySnapshot>, Error> {
    let snapshot = require_immediate_context(
        conn,
        tables,
        account_id,
        submission_context,
        expected_revision,
        run_identity,
        Some(artifact_identity),
        Some(expected_policy_fingerprint),
    )?;
    let claim = snapshot
        .claims()
        .first()
        .ok_or(Error::DeliveryClaimUnavailable)?;
    if matches!(
        claim.claim_kind(),
        Some(ClaimKind::Materialization | ClaimKind::Submission)
    ) {
        require_immediate_spend_authorization(conn, tables, &snapshot)?;
    }
    if snapshot.phase() != DeliveryPhase::Active || claim.token() != Some(token) {
        return Ok(None);
    }
    if claim
        .lease()
        .is_none_or(|lease| lease.validity_at(delivery_clock_now()) != LeaseValidity::Live)
    {
        return Ok(None);
    }
    Ok(Some(snapshot))
}

#[cfg(feature = "migration-delivery")]
#[allow(clippy::too_many_arguments)]
pub(super) fn renew_immediate_claim(
    conn: &Connection,
    tables: &Tables,
    account_id: AccountRef,
    submission_context: SubmissionContext,
    expected_revision: DeliveryRevision,
    run_identity: MigrationRunIdentity,
    artifact_identity: ImmediateArtifactIdentity,
    token: ClaimToken,
    lease_duration: LeaseDuration,
    expected_policy_fingerprint: PolicyFingerprint,
) -> Result<Option<DeliverySnapshot>, Error> {
    let now = delivery_clock_now();
    let snapshot = require_immediate_context(
        conn,
        tables,
        account_id,
        submission_context,
        expected_revision,
        run_identity,
        Some(artifact_identity),
        Some(expected_policy_fingerprint),
    )?;
    let claim = snapshot
        .claims()
        .first()
        .ok_or(Error::DeliveryClaimUnavailable)?;
    if matches!(
        claim.claim_kind(),
        Some(ClaimKind::Materialization | ClaimKind::Submission)
    ) {
        require_immediate_spend_authorization(conn, tables, &snapshot)?;
    }
    let Some(existing) = claim.lease() else {
        return Ok(None);
    };
    if snapshot.phase() != DeliveryPhase::Active
        || existing.token() != token
        || existing.validity_at(now) != LeaseValidity::Live
    {
        return Ok(None);
    }
    let renewed = DeliveryLease::new(existing.kind(), token, now, lease_duration)
        .ok_or(Error::DeliveryValueTooLarge)?;
    let changed = conn.execute(
        &format!(
            "UPDATE {} SET lease_clock_session = ?, lease_acquired_at_ms = ?,
             lease_expires_at_ms = ? WHERE run_identity = ? AND revision = ?",
            tables.immediate_delivery
        ),
        params![
            renewed.acquired_at().session().as_bytes(),
            renewed.acquired_at().tick_millis(),
            renewed.expires_at().tick_millis(),
            run_identity.as_bytes(),
            expected_revision.as_u64(),
        ],
    )?;
    require_immediate_cas_update(changed)?;
    bump_immediate_revision(conn, tables, run_identity)?;
    immediate_snapshot_after_mutation(conn, tables, account_id, run_identity, submission_context)
        .map(Some)
}

#[cfg(feature = "migration-delivery")]
#[allow(clippy::too_many_arguments)]
pub(super) fn record_immediate_submission_outcome(
    conn: &Connection,
    tables: &Tables,
    account_id: AccountRef,
    submission_context: SubmissionContext,
    expected_revision: DeliveryRevision,
    run_identity: MigrationRunIdentity,
    artifact_identity: ImmediateArtifactIdentity,
    token: ClaimToken,
    outcome: SubmissionOutcome,
    expected_policy_fingerprint: PolicyFingerprint,
) -> Result<DeliverySnapshot, Error> {
    let snapshot = require_immediate_context(
        conn,
        tables,
        account_id,
        submission_context,
        expected_revision,
        run_identity,
        Some(artifact_identity),
        Some(expected_policy_fingerprint),
    )?;
    let claim = snapshot
        .claims()
        .first()
        .ok_or(Error::DeliveryClaimUnavailable)?;
    if claim.status() != ClaimStatus::Submitting
        || claim.claim_kind() != Some(ClaimKind::Submission)
        || claim.token() != Some(token)
    {
        return Err(Error::DeliveryClaimTokenMismatch);
    }
    let (status, last_error) = match outcome {
        SubmissionOutcome::Accepted => ("broadcasted", None),
        SubmissionOutcome::KnownUnsent => (
            "staged",
            Some(DeliveryFailureReason::TransportDidNotBegin.as_str()),
        ),
        SubmissionOutcome::Unknown => (
            "outcome_unknown",
            Some(DeliveryFailureReason::TransportOutcomeUnknown.as_str()),
        ),
    };
    let changed = conn.execute(
        &format!(
            "UPDATE {} SET status = ?, claim_kind = NULL, attempt_token = NULL,
             lease_clock_session = NULL, lease_acquired_at_ms = NULL,
             lease_expires_at_ms = NULL, last_error = ?
             WHERE run_identity = ? AND revision = ?",
            tables.immediate_delivery
        ),
        params![
            status,
            last_error,
            run_identity.as_bytes(),
            expected_revision.as_u64(),
        ],
    )?;
    require_immediate_cas_update(changed)?;
    bump_immediate_revision(conn, tables, run_identity)?;
    immediate_snapshot_after_mutation(conn, tables, account_id, run_identity, submission_context)
}

#[cfg(feature = "migration-delivery")]
#[allow(clippy::too_many_arguments)]
pub(super) fn release_immediate_claim_known_unsent(
    conn: &Connection,
    tables: &Tables,
    account_id: AccountRef,
    submission_context: SubmissionContext,
    expected_revision: DeliveryRevision,
    run_identity: MigrationRunIdentity,
    artifact_identity: ImmediateArtifactIdentity,
    token: ClaimToken,
    reason: DeliveryFailureReason,
    expected_policy_fingerprint: PolicyFingerprint,
) -> Result<DeliverySnapshot, Error> {
    let snapshot = require_immediate_context(
        conn,
        tables,
        account_id,
        submission_context,
        expected_revision,
        run_identity,
        Some(artifact_identity),
        Some(expected_policy_fingerprint),
    )?;
    let claim = snapshot
        .claims()
        .first()
        .ok_or(Error::DeliveryClaimUnavailable)?;
    if claim.token() != Some(token) {
        return Err(Error::DeliveryClaimTokenMismatch);
    }
    let status = match claim.claim_kind() {
        Some(ClaimKind::Materialization)
            if matches!(
                reason,
                DeliveryFailureReason::MaterializationFailed
                    | DeliveryFailureReason::MaterializationLeaseExpired
                    | DeliveryFailureReason::SigningCancelled
            ) && !claim.has_exposure_history() =>
        {
            "materialization_failed"
        }
        Some(ClaimKind::Submission)
            if matches!(
                reason,
                DeliveryFailureReason::TransportSetupFailed
                    | DeliveryFailureReason::TransportDidNotBegin
                    | DeliveryFailureReason::SubmissionLeaseExpired
            ) =>
        {
            "staged"
        }
        _ => return Err(Error::DeliveryClaimUnavailable),
    };
    let changed = conn.execute(
        &format!(
            "UPDATE {} SET status = ?, claim_kind = NULL, attempt_token = NULL,
             lease_clock_session = NULL, lease_acquired_at_ms = NULL,
             lease_expires_at_ms = NULL, last_error = ?
             WHERE run_identity = ? AND revision = ?",
            tables.immediate_delivery
        ),
        params![
            status,
            reason.as_str(),
            run_identity.as_bytes(),
            expected_revision.as_u64(),
        ],
    )?;
    require_immediate_cas_update(changed)?;
    bump_immediate_revision(conn, tables, run_identity)?;
    immediate_snapshot_after_mutation(conn, tables, account_id, run_identity, submission_context)
}

#[cfg(feature = "migration-delivery")]
#[allow(clippy::too_many_arguments)]
pub(super) fn reconcile_immediate_submission(
    conn: &Connection,
    tables: &Tables,
    account_id: AccountRef,
    submission_context: SubmissionContext,
    expected_revision: DeliveryRevision,
    run_identity: MigrationRunIdentity,
    artifact_identity: ImmediateArtifactIdentity,
    token: ClaimToken,
) -> Result<DeliverySnapshot, Error> {
    let snapshot = require_immediate_context(
        conn,
        tables,
        account_id,
        submission_context,
        expected_revision,
        run_identity,
        Some(artifact_identity),
        None,
    )?;
    let claim = snapshot
        .claims()
        .first()
        .ok_or(Error::DeliveryClaimUnavailable)?;
    if !matches!(
        claim.status(),
        ClaimStatus::OutcomeUnknown | ClaimStatus::Broadcasted
    ) || claim.claim_kind() != Some(ClaimKind::OutcomeResolution)
        || claim.token() != Some(token)
    {
        return Err(Error::DeliveryClaimTokenMismatch);
    }
    reconcile_immediate_delivery(conn, tables, account_id, run_identity, submission_context)?;
    immediate_snapshot_after_mutation(conn, tables, account_id, run_identity, submission_context)
}

#[cfg(feature = "migration-delivery")]
/// Advances the immediate run phase through a revision-checked compare-and-swap. The separate
/// expected and successor phases are intentional proof of the permitted lifecycle edge.
#[allow(clippy::too_many_arguments)]
pub(super) fn set_immediate_phase(
    conn: &Connection,
    tables: &Tables,
    account_id: AccountRef,
    submission_context: SubmissionContext,
    expected_revision: DeliveryRevision,
    run_identity: MigrationRunIdentity,
    expected_phase: DeliveryPhase,
    successor_phase: DeliveryPhase,
) -> Result<DeliverySnapshot, Error> {
    let snapshot = require_immediate_context(
        conn,
        tables,
        account_id,
        submission_context,
        expected_revision,
        run_identity,
        None,
        None,
    )?;
    if snapshot.phase() != expected_phase {
        return Err(Error::DeliveryPhaseMismatch);
    }
    let changed = conn.execute(
        &format!(
            "UPDATE {} SET phase = ? WHERE run_identity = ? AND revision = ?",
            tables.immediate_delivery
        ),
        params![
            successor_phase.as_str(),
            run_identity.as_bytes(),
            expected_revision.as_u64(),
        ],
    )?;
    require_immediate_cas_update(changed)?;
    bump_immediate_revision(conn, tables, run_identity)?;
    immediate_snapshot_after_mutation(conn, tables, account_id, run_identity, submission_context)
}

#[cfg(feature = "migration-delivery")]
pub(super) fn begin_immediate_abandonment(
    conn: &Connection,
    tables: &Tables,
    account_id: AccountRef,
    submission_context: SubmissionContext,
    expected_revision: DeliveryRevision,
    run_identity: MigrationRunIdentity,
) -> Result<DeliverySnapshot, Error> {
    let snapshot = require_immediate_context(
        conn,
        tables,
        account_id,
        submission_context,
        expected_revision,
        run_identity,
        None,
        None,
    )?;
    if !matches!(
        snapshot.phase(),
        DeliveryPhase::Active | DeliveryPhase::Paused
    ) {
        return Err(Error::DeliveryPhaseMismatch);
    }
    let claim = snapshot.claims().first();
    let changed = if claim.is_some_and(|claim| claim.has_exposure_history()) {
        conn.execute(
            &format!(
                "UPDATE {} SET phase = 'abandoning'
                 WHERE run_identity = ? AND revision = ?",
                tables.immediate_delivery
            ),
            params![run_identity.as_bytes(), expected_revision.as_u64()],
        )?
    } else {
        conn.execute(
            &format!(
                "UPDATE {} SET phase = 'abandoning', status = 'abandoned',
                 claim_kind = NULL, attempt_token = NULL, lease_clock_session = NULL,
                 lease_acquired_at_ms = NULL, lease_expires_at_ms = NULL,
                 txid = NULL, exact_tx = NULL, exact_tx_digest = NULL,
                 unsigned_pczt_digest = NULL, canonical_unsigned_pczt = NULL,
                 signed_pczt_digest = NULL, canonical_signed_pczt = NULL,
                 signed_pczt_binding = NULL, last_error = NULL
                 WHERE run_identity = ? AND revision = ?",
                tables.immediate_delivery
            ),
            params![run_identity.as_bytes(), expected_revision.as_u64()],
        )?
    };
    require_immediate_cas_update(changed)?;
    bump_immediate_revision(conn, tables, run_identity)?;
    immediate_snapshot_after_mutation(conn, tables, account_id, run_identity, submission_context)
}

#[cfg(feature = "migration-delivery")]
pub(super) fn finish_immediate_abandonment(
    conn: &Connection,
    tables: &Tables,
    account_id: AccountRef,
    submission_context: SubmissionContext,
    expected_revision: DeliveryRevision,
    run_identity: MigrationRunIdentity,
) -> Result<DeliverySnapshot, Error> {
    let snapshot = require_immediate_context(
        conn,
        tables,
        account_id,
        submission_context,
        expected_revision,
        run_identity,
        None,
        None,
    )?;
    if snapshot.phase() != DeliveryPhase::Abandoning || !snapshot.safe_to_cancel() {
        return Err(Error::DeliveryNotSafeToAbandon);
    }
    let exposed = snapshot
        .claims()
        .first()
        .filter(|claim| claim.has_exposure_history());
    let (release, finalized_tip, reservation_status) = if let Some(claim) = exposed {
        if !matches!(
            claim.status(),
            ClaimStatus::ExpiredUnmined | ClaimStatus::ExternalSigningExpiredUnmined
        ) || claim.lease().is_some()
        {
            return Err(Error::DeliveryNotSafeToAbandon);
        }
        let release = ReservationRelease::after_resolved_unmined_expiry(claim.expiry_height())
            .ok_or(Error::DeliveryRecoveryRequired)?;
        let fully_scanned = fully_scanned_height(conn)?
            .filter(|height| *height >= release.release_at())
            .ok_or(Error::DeliveryNotSafeToAbandon)?;
        if !reserved_sources_proven_unspent(
            conn,
            tables,
            account_id,
            run_identity,
            fully_scanned,
            canonical_wallet_target_height(conn)?,
        )? {
            return Err(Error::DeliveryRecoveryRequired);
        }
        (release, fully_scanned, "finality_released")
    } else {
        (
            ReservationRelease::at(BlockHeight::from_u32(0)),
            BlockHeight::from_u32(0),
            "abandoned",
        )
    };
    let row = read_stored_immediate_delivery(conn, tables, account_id, run_identity)?
        .ok_or(Error::Corrupt("immediate delivery row"))?;
    let lock_owner = row
        .canonical_lock_owner
        .map(LockOwner::new)
        .ok_or(Error::Corrupt("immediate lock owner"))?;
    let changed = conn.execute(
        &format!(
            "UPDATE {} SET phase = 'abandoned', storage_finality = 'finalized',
             storage_recovery_reason = NULL, release_at_height = ?, finalized_tip_height = ?
             WHERE run_identity = ? AND revision = ?",
            tables.immediate_delivery
        ),
        params![
            u32::from(release.release_at()),
            u32::from(finalized_tip),
            run_identity.as_bytes(),
            expected_revision.as_u64(),
        ],
    )?;
    require_immediate_cas_update(changed)?;
    let changed = conn.execute(
        &format!(
            "UPDATE {} SET status = 'abandoned' WHERE run_identity = ?",
            tables.delivery_runs
        ),
        params![run_identity.as_bytes()],
    )?;
    if changed != 1 {
        return Err(Error::DeliveryRunMismatch);
    }
    transition_source_reservations(
        conn,
        tables,
        run_identity,
        snapshot.source_reservation_owner(),
        reservation_status,
        (reservation_status == "finality_released").then_some(release.release_at()),
        Some(finalized_tip),
    )?;
    release_locks(conn, account_id, &BTreeSet::from([lock_owner]))?;
    bump_immediate_revision(conn, tables, run_identity)?;
    immediate_snapshot_after_mutation(conn, tables, account_id, run_identity, submission_context)
}

/// Extracts the exact Orchard source set from the Rust-owned immediate proposal envelope without
/// consulting mutable wallet note state. This is used by schema-provenance checks, where a missing
/// or already-spent note must not make malformed durable authority look coherent.
#[cfg(feature = "migration-delivery")]
fn immediate_proposal_authority(
    canonical_proposal: &[u8],
) -> Result<(BTreeSet<OutputRef>, Zatoshis), Error> {
    use zcash_client_backend::proto::proposal::{self, proposed_input};

    let envelope = ImmediateProposal::decode(canonical_proposal)
        .map_err(|_| Error::Corrupt("immediate proposal envelope"))?;
    let proposal = proposal::Proposal::decode(envelope.payload().as_bytes())
        .map_err(|_| Error::Corrupt("immediate proposal payload"))?;
    if proposal.steps.len() != 1 {
        return Err(Error::Corrupt("immediate proposal step count"));
    }
    let mut sources = BTreeSet::new();
    let mut gross_amount = Zatoshis::ZERO;
    for input in &proposal.steps[0].inputs {
        let proposed_input::Value::ReceivedOutput(output) = input
            .value
            .as_ref()
            .ok_or(Error::Corrupt("immediate proposal input"))?
        else {
            return Err(Error::Corrupt("immediate proposal dependency"));
        };
        if proposal::ValuePool::try_from(output.value_pool).ok()
            != Some(proposal::ValuePool::Orchard)
        {
            return Err(Error::Corrupt("immediate proposal source pool"));
        }
        let value = Zatoshis::from_u64(output.value)
            .map_err(|_| Error::Corrupt("immediate proposal source value"))?;
        if !value.is_positive() {
            return Err(Error::Corrupt("immediate proposal source value"));
        }
        gross_amount = (gross_amount + value)
            .ok_or(Error::Corrupt("immediate proposal gross input amount"))?;
        let txid = <[u8; 32]>::try_from(output.txid.as_slice())
            .map(TxId::from_bytes)
            .map_err(|_| Error::Corrupt("immediate proposal source txid"))?;
        let source = OutputRef::new(
            txid,
            PoolType::Shielded(ShieldedPool::Orchard),
            output.index,
        );
        if !sources.insert(source) {
            return Err(Error::Corrupt("duplicate immediate proposal source"));
        }
    }
    if sources.is_empty() {
        return Err(Error::Corrupt("empty immediate proposal source set"));
    }
    Ok((sources, gross_amount))
}

#[cfg(feature = "migration-delivery")]
fn require_immediate_gross_authorization(
    proposal_gross_amount: Zatoshis,
    maximum_gross_amount: Zatoshis,
) -> Result<(), Error> {
    if proposal_gross_amount <= maximum_gross_amount {
        Ok(())
    } else {
        Err(Error::ImmediateAmountLimitExceeded)
    }
}

/// Proves that one immediate run's canonical proposal, source reservations, account ownership,
/// and wallet locks still describe the same exact source set.
#[cfg(feature = "migration-delivery")]
pub(super) fn immediate_reservations_are_complete(
    conn: &Connection,
    tables: &Tables,
    run_identity: MigrationRunIdentity,
) -> Result<bool, Error> {
    let row = conn
        .query_row(
            &format!(
                "SELECT runs.account_id, runs.lane, runs.status, runs.canonical_lock_owner,
                        immediate.canonical_proposal, immediate.txid
                   FROM {} runs
                   JOIN {} immediate ON immediate.run_identity = runs.run_identity
                  WHERE runs.run_identity = ?",
                tables.delivery_runs, tables.immediate_delivery
            ),
            params![run_identity.as_bytes()],
            |row| {
                Ok((
                    AccountRef(row.get::<_, i64>(0)?),
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<[u8; 32]>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Option<[u8; 32]>>(5)?,
                ))
            },
        )
        .optional()?;
    let Some((account_id, lane, run_status, lock_owner, canonical_proposal, exact_txid)) = row
    else {
        return Ok(false);
    };
    if lane != "immediate" {
        return Ok(false);
    }
    let lock_owner = lock_owner
        .map(LockOwner::new)
        .ok_or(Error::Corrupt("immediate canonical wallet lock owner"))?;
    let (proposal_sources, _) = immediate_proposal_authority(&canonical_proposal)?;

    let reserved_sources = {
        let mut stmt = conn.prepare(&format!(
            "SELECT source_txid, source_index
               FROM {}
              WHERE run_identity = ? AND status IN ('active', 'recovery_required')",
            tables.delivery_reservations
        ))?;
        stmt.query_map(params![run_identity.as_bytes()], |row| {
            Ok(OutputRef::new(
                TxId::from_bytes(row.get::<_, [u8; 32]>(0)?),
                PoolType::Shielded(ShieldedPool::Orchard),
                row.get::<_, u32>(1)?,
            ))
        })?
        .collect::<Result<BTreeSet<_>, _>>()?
    };
    let locked_sources = {
        let mut stmt = conn.prepare(
            "SELECT transactions.txid, orchard_received_notes.action_index
               FROM orchard_received_notes
               JOIN transactions
                 ON transactions.id_tx = orchard_received_notes.transaction_id
              WHERE orchard_received_notes.account_id = ?
                AND orchard_received_notes.lock_owner = ?",
        )?;
        stmt.query_map(params![account_id.0, lock_owner.as_bytes()], |row| {
            Ok(OutputRef::new(
                TxId::from_bytes(row.get::<_, [u8; 32]>(0)?),
                PoolType::Shielded(ShieldedPool::Orchard),
                row.get::<_, u32>(1)?,
            ))
        })?
        .collect::<Result<BTreeSet<_>, _>>()?
    };

    let (spent_by_exact, has_foreign_spender) = {
        let mut stmt = conn.prepare(&format!(
            "SELECT reservations.source_txid, reservations.source_index, spender.txid
               FROM {} reservations
               JOIN transactions source ON source.txid = reservations.source_txid
               JOIN orchard_received_notes rn
                 ON rn.transaction_id = source.id_tx
                AND rn.action_index = reservations.source_index
                AND rn.account_id = ?
               JOIN orchard_received_note_spends spends
                 ON spends.orchard_received_note_id = rn.id
               JOIN transactions spender ON spender.id_tx = spends.transaction_id
              WHERE reservations.run_identity = ?",
            tables.delivery_reservations
        ))?;
        let spenders = stmt
            .query_map(params![account_id.0, run_identity.as_bytes()], |row| {
                Ok((
                    OutputRef::new(
                        TxId::from_bytes(row.get::<_, [u8; 32]>(0)?),
                        PoolType::Shielded(ShieldedPool::Orchard),
                        row.get::<_, u32>(1)?,
                    ),
                    row.get::<_, [u8; 32]>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let mut exact = BTreeSet::new();
        let mut foreign = false;
        for (source, spender) in spenders {
            if Some(spender) == exact_txid {
                exact.insert(source);
            } else {
                foreign = true;
            }
        }
        (exact, foreign)
    };
    let continuously_authorized = locked_sources
        .union(&spent_by_exact)
        .copied()
        .collect::<BTreeSet<_>>();

    Ok(match run_status.as_str() {
        "active" | "recovery_required" => {
            reserved_sources == proposal_sources
                && continuously_authorized == proposal_sources
                && locked_sources.is_subset(&proposal_sources)
                && !has_foreign_spender
        }
        "finalized" | "abandoned" => reserved_sources.is_empty() && locked_sources.is_empty(),
        _ => false,
    })
}

/// Call the SQLite implementation behind `WalletWrite::lock_outputs`, preserving its owner-scoped,
/// all-or-nothing semantics inside the migration store's enclosing transaction.
#[cfg(feature = "migration-delivery")]
fn lock_outputs(
    tx: &Connection,
    account_id: AccountRef,
    outputs: &[OutputRef],
    owner: LockOwner,
    lock_expiry_height: BlockHeight,
) -> Result<(), Error> {
    // `wallet::lock_outputs` is intentionally output-reference scoped for the general wallet API;
    // this migration facade is account scoped, so prove ownership for the full batch inside this
    // same SQL transaction before mutating any row. This closes the cross-account confused-deputy
    // hole while preserving the underlying all-or-nothing conflict handling.
    for output in outputs {
        if output.pool() != PoolType::Shielded(ShieldedPool::Orchard) {
            return Err(Error::OutputNotOwned(*output));
        }
        let owned = tx.query_row(
            "SELECT EXISTS(
                 SELECT 1
                   FROM orchard_received_notes rn
                   JOIN transactions t ON t.id_tx = rn.transaction_id
                  WHERE rn.account_id = :account_id
                    AND t.txid = :txid
                    AND rn.action_index = :action_index
             )",
            named_params! {
                ":account_id": account_id.0,
                ":txid": output.txid().as_ref(),
                ":action_index": output.output_index(),
            },
            |row| row.get::<_, bool>(0),
        )?;
        if !owned {
            return Err(Error::OutputNotOwned(*output));
        }
    }

    match crate::wallet::lock_outputs(tx, outputs, owner, lock_expiry_height) {
        Ok(_) => Ok(()),
        Err(crate::error::LockError::LockFailure(output)) => Err(Error::LockConflict(output)),
        Err(crate::error::LockError::Storage(e)) => Err(Error::Db(e)),
    }
}

/// Ensures a refresh/release caller is using exactly the durable owner set already recorded by the
/// canonical migration. The check runs in the same SQLite transaction as the subsequent lock and
/// state mutations. An absent migration (the initial persist) and a canonical state with no owner
/// (a finalized migration being reactivated after reorg) deliberately permit owner bootstrap.
#[cfg(feature = "migration-delivery")]
fn require_canonical_owner(
    conn: &Connection,
    tables: &Tables,
    account_id: AccountRef,
    requested: &BTreeSet<LockOwner>,
) -> Result<(), Error> {
    let canonical = read_lock_owners(conn, tables, account_id)?;
    if !canonical.is_empty() && canonical != *requested {
        return Err(Error::CanonicalOwnerMismatch);
    }
    Ok(())
}

/// Compare-and-swap guard for every atomic lock/state mutation. Equality covers the complete
/// normalized engine state, including transaction PCZT bytes, lifecycle payloads, schedule, and
/// owner tokens, so a stale clone cannot overwrite any newer canonical transition even when it
/// happens to carry the correct owner.
#[cfg(feature = "migration-delivery")]
fn require_canonical_state(
    conn: &Connection,
    tables: &Tables,
    account_id: AccountRef,
    expected: Option<&MigrationState>,
) -> Result<(), Error> {
    let canonical = read_migration(conn, tables, account_id)?;
    if canonical.as_ref() != expected {
        return Err(Error::CanonicalStateMismatch);
    }
    Ok(())
}

/// Release every Orchard output lock held by `owners` for `account_id`. The exact output reference
/// and owner are read first, then each unlock goes through the storage implementation behind
/// `WalletWrite::unlock_output`, which re-checks the owner in its `UPDATE` predicate.
#[cfg(feature = "migration-delivery")]
fn release_locks(
    tx: &Connection,
    account_id: AccountRef,
    owners: &BTreeSet<LockOwner>,
) -> Result<(), Error> {
    if owners.is_empty() {
        return Ok(());
    }

    let locked = {
        let mut stmt = tx.prepare(
            "SELECT transactions.txid, orchard_received_notes.action_index,
                    orchard_received_notes.lock_owner
               FROM orchard_received_notes
               JOIN transactions
                 ON transactions.id_tx = orchard_received_notes.transaction_id
              WHERE orchard_received_notes.account_id = ?
                AND orchard_received_notes.lock_owner IS NOT NULL",
        )?;
        let rows = stmt.query_map(params![account_id.0], |row| {
            let txid = TxId::from_bytes(row.get::<_, [u8; 32]>(0)?);
            let output_index = row.get::<_, u32>(1)?;
            let owner = LockOwner::new(row.get::<_, [u8; 32]>(2)?);
            Ok((
                OutputRef::new(
                    txid,
                    PoolType::Shielded(ShieldedPool::Orchard),
                    output_index,
                ),
                owner,
            ))
        })?;
        rows.collect::<Result<Vec<_>, _>>()?
    };

    for (output, owner) in locked {
        if owners.contains(&owner) {
            crate::wallet::unlock_output(tx, &output, owner).map_err(Error::Wallet)?;
        }
    }
    Ok(())
}

#[cfg(feature = "migration-delivery")]
fn upsert_source_reservations(
    tx: &Connection,
    tables: &Tables,
    outputs: &[OutputRef],
    run_identity: MigrationRunIdentity,
) -> Result<(), Error> {
    for output in outputs {
        if output.pool() != PoolType::Shielded(ShieldedPool::Orchard) {
            return Err(Error::OutputNotOwned(*output));
        }
        tx.execute(
            &format!(
                "INSERT INTO {} (
                 run_identity, source_txid, source_index, status
                 ) VALUES (?, ?, ?, 'active')
                 ON CONFLICT(run_identity, source_txid, source_index) DO NOTHING",
                tables.delivery_reservations
            ),
            params![
                run_identity.as_bytes(),
                output.txid().as_ref(),
                output.output_index(),
            ],
        )?;
        let reservation = tx.query_row(
            &format!(
                "SELECT status, release_at_height, released_tip_height FROM {}
                 WHERE run_identity = ? AND source_txid = ? AND source_index = ?",
                tables.delivery_reservations
            ),
            params![
                run_identity.as_bytes(),
                output.txid().as_ref(),
                output.output_index(),
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<u32>>(1)?,
                    row.get::<_, Option<u32>>(2)?,
                ))
            },
        )?;
        if reservation != ("active".to_owned(), None, None) {
            return Err(Error::DeliveryRecoveryRequired);
        }
    }
    Ok(())
}

#[cfg(feature = "migration-delivery")]
fn transition_source_reservations(
    tx: &Connection,
    tables: &Tables,
    run_identity: MigrationRunIdentity,
    owner: SourceReservationOwner,
    status: &'static str,
    release_at_height: Option<BlockHeight>,
    released_tip_height: Option<BlockHeight>,
) -> Result<(), Error> {
    let stored_owner = tx
        .query_row(
            &format!(
                "SELECT source_owner FROM {} WHERE run_identity = ?",
                tables.delivery_runs
            ),
            params![run_identity.as_bytes()],
            |row| row.get::<_, Option<[u8; 32]>>(0),
        )
        .optional()?
        .flatten()
        .ok_or(Error::Corrupt("migration reservation run owner"))?;
    if stored_owner != *owner.as_bytes() {
        return Err(Error::CanonicalOwnerMismatch);
    }
    let changed = tx.execute(
        &format!(
            "UPDATE {} SET status = ?, release_at_height = ?, released_tip_height = ?
             WHERE run_identity = ? AND status IN (
                 'active', 'recovery_required'
             )",
            tables.delivery_reservations
        ),
        params![
            status,
            release_at_height.map(u32::from),
            released_tip_height.map(u32::from),
            run_identity.as_bytes(),
        ],
    )?;
    let total: usize = tx.query_row(
        &format!(
            "SELECT COUNT(*) FROM {} WHERE run_identity = ?",
            tables.delivery_reservations
        ),
        params![run_identity.as_bytes()],
        |row| row.get(0),
    )?;
    if total > 0 && changed == 0 {
        return Err(Error::Corrupt("migration source reservation transition"));
    }
    Ok(())
}

#[cfg(feature = "migration-delivery")]
fn archive_delivery_evidence(
    tx: &Connection,
    tables: &Tables,
    migration_id: i64,
    run_identity: MigrationRunIdentity,
    finalized_outputs: Option<(&[(MigrationTxId, ExactReceivedOutput)], BlockHeight)>,
) -> Result<(), Error> {
    #[derive(PartialEq)]
    struct ArchivedEvidence {
        id: u32,
        pczt_digest: [u8; 32],
        transaction_fingerprint: [u8; 32],
        canonical_pczt: Vec<u8>,
        transaction_kind: String,
        terminal_status: String,
        signer_ownership: String,
        txid: Option<[u8; 32]>,
        exact_tx: Option<Vec<u8>>,
        expiry_height: u32,
        external_pczt_digest: Option<[u8; 32]>,
        external_pczt: Option<Vec<u8>>,
        signed_pczt_digest: Option<[u8; 32]>,
        signed_pczt: Option<Vec<u8>>,
        signed_pczt_binding: Option<[u8; 32]>,
        policy_fingerprint: [u8; 32],
        last_error: Option<String>,
        destination_txid: Option<[u8; 32]>,
        destination_index: Option<u32>,
        amount: Option<u64>,
        observed_mined_height: Option<u32>,
        release_at_height: Option<u32>,
    }

    let rows = {
        let mut stmt = tx.prepare(&format!(
            "SELECT claims.tx_id, claims.pczt_digest, claims.transaction_fingerprint,
                    canonical.pczt, canonical.kind, claims.status, claims.signer_ownership,
                    claims.txid, claims.exact_tx, canonical.expiry_height,
                    claims.external_signing_pczt_digest,
                    claims.canonical_external_signing_pczt,
                    claims.signed_pczt_digest, claims.canonical_signed_pczt,
                    claims.signed_pczt_binding, claims.policy_fingerprint, claims.last_error
               FROM {} claims
               JOIN {} canonical
                 ON canonical.migration_id = claims.migration_id
                AND canonical.tx_id = claims.tx_id
              WHERE claims.migration_id = ? AND claims.status IN (
                    'materialization_failed', 'confirmed', 'expired_unmined',
                    'external_signing_expired_unmined'
              )
              ORDER BY claims.tx_id",
            tables.delivery_claims, tables.transactions
        ))?;
        stmt.query_map(params![migration_id], |row| {
            Ok(ArchivedEvidence {
                id: row.get(0)?,
                pczt_digest: row.get(1)?,
                transaction_fingerprint: row.get(2)?,
                canonical_pczt: row.get(3)?,
                transaction_kind: row.get(4)?,
                terminal_status: row.get(5)?,
                signer_ownership: row.get(6)?,
                txid: row.get(7)?,
                exact_tx: row.get(8)?,
                expiry_height: row.get(9)?,
                external_pczt_digest: row.get(10)?,
                external_pczt: row.get(11)?,
                signed_pczt_digest: row.get(12)?,
                signed_pczt: row.get(13)?,
                signed_pczt_binding: row.get(14)?,
                policy_fingerprint: row.get(15)?,
                last_error: row.get(16)?,
                destination_txid: None,
                destination_index: None,
                amount: None,
                observed_mined_height: None,
                release_at_height: None,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?
    };
    for mut evidence in rows {
        let destination =
            if evidence.terminal_status == "confirmed" && evidence.transaction_kind == "transfer" {
                let (outputs, release_at_height) = finalized_outputs
                    .ok_or(Error::Corrupt("missing finalized migration outputs"))?;
                let output = outputs
                    .iter()
                    .find_map(|(transaction_id, output)| {
                        (u32::from(*transaction_id) == evidence.id).then_some(*output)
                    })
                    .ok_or(Error::Corrupt("missing finalized transfer output"))?;
                let mined_height = current_wallet_mined_height(tx, *output.output_ref().txid())?
                    .ok_or(Error::Corrupt("missing finalized migration destination"))?;
                Some((output, mined_height, release_at_height))
            } else {
                None
            };
        (
            evidence.destination_txid,
            evidence.destination_index,
            evidence.amount,
            evidence.observed_mined_height,
            evidence.release_at_height,
        ) = destination.map_or(
            (None, None, None, None, None),
            |(output, mined, release)| {
                (
                    Some(*output.output_ref().txid().as_ref()),
                    Some(output.output_ref().output_index()),
                    Some(u64::from(output.value())),
                    Some(u32::from(mined)),
                    Some(u32::from(release)),
                )
            },
        );
        tx.execute(
            &format!(
                "INSERT INTO {} (
                     run_identity, tx_id, pczt_digest, transaction_fingerprint,
                     canonical_pczt, transaction_kind, terminal_status, signer_ownership,
                     txid, exact_tx, expiry_height,
                     external_signing_pczt_digest, canonical_external_signing_pczt,
                     signed_pczt_digest, canonical_signed_pczt, signed_pczt_binding,
                     policy_fingerprint, last_error,
                     destination_txid, destination_output_index,
                     expected_ironwood_amount, observed_mined_height, release_at_height
                 ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                 ON CONFLICT(run_identity, tx_id) DO NOTHING",
                tables.delivery_evidence
            ),
            params![
                run_identity.as_bytes(),
                evidence.id,
                evidence.pczt_digest,
                evidence.transaction_fingerprint,
                evidence.canonical_pczt,
                evidence.transaction_kind,
                evidence.terminal_status,
                evidence.signer_ownership,
                evidence.txid,
                evidence.exact_tx,
                evidence.expiry_height,
                evidence.external_pczt_digest,
                evidence.external_pczt,
                evidence.signed_pczt_digest,
                evidence.signed_pczt,
                evidence.signed_pczt_binding,
                evidence.policy_fingerprint,
                evidence.last_error,
                evidence.destination_txid,
                evidence.destination_index,
                evidence.amount,
                evidence.observed_mined_height,
                evidence.release_at_height,
            ],
        )?;
        let stored = tx.query_row(
            &format!(
                "SELECT tx_id, pczt_digest, transaction_fingerprint, canonical_pczt,
                        transaction_kind, terminal_status, signer_ownership, txid, exact_tx,
                        expiry_height, external_signing_pczt_digest,
                        canonical_external_signing_pczt, signed_pczt_digest,
                        canonical_signed_pczt, signed_pczt_binding,
                        policy_fingerprint, last_error,
                        destination_txid, destination_output_index, expected_ironwood_amount,
                        observed_mined_height, release_at_height
                   FROM {} WHERE run_identity = ? AND tx_id = ?",
                tables.delivery_evidence
            ),
            params![run_identity.as_bytes(), evidence.id],
            |row| {
                Ok(ArchivedEvidence {
                    id: row.get(0)?,
                    pczt_digest: row.get(1)?,
                    transaction_fingerprint: row.get(2)?,
                    canonical_pczt: row.get(3)?,
                    transaction_kind: row.get(4)?,
                    terminal_status: row.get(5)?,
                    signer_ownership: row.get(6)?,
                    txid: row.get(7)?,
                    exact_tx: row.get(8)?,
                    expiry_height: row.get(9)?,
                    external_pczt_digest: row.get(10)?,
                    external_pczt: row.get(11)?,
                    signed_pczt_digest: row.get(12)?,
                    signed_pczt: row.get(13)?,
                    signed_pczt_binding: row.get(14)?,
                    policy_fingerprint: row.get(15)?,
                    last_error: row.get(16)?,
                    destination_txid: row.get(17)?,
                    destination_index: row.get(18)?,
                    amount: row.get(19)?,
                    observed_mined_height: row.get(20)?,
                    release_at_height: row.get(21)?,
                })
            },
        )?;
        if stored != evidence {
            return Err(Error::Corrupt("conflicting immutable delivery evidence"));
        }
    }
    Ok(())
}

/// Reads every active Orchard lock across every account at the wallet's canonical next target
/// height. No value, witness, account, or spendability filter is applied: this is the narrow
/// storage primitive used by finalization-time nullifier validation, not coin selection.
#[cfg(feature = "migration-delivery")]
pub(crate) fn active_orchard_locks(
    conn: &Connection,
) -> Result<Vec<ActiveOrchardLock>, crate::error::SqliteClientError> {
    let tip = crate::wallet::chain_tip_height(conn)?
        .ok_or(crate::error::SqliteClientError::ChainHeightUnknown)?;
    let target_height = u32::from(tip) + 1;
    let sql = "SELECT t.txid, rn.action_index, rn.nf, rn.lock_owner
           FROM orchard_received_notes rn
           JOIN transactions t ON t.id_tx = rn.transaction_id
          WHERE rn.lock_expiry_height >= :target_height
            AND rn.lock_owner IS NOT NULL";
    let mut stmt = conn.prepare(sql)?;
    let rows = stmt
        .query_map(named_params![":target_height": target_height], |row| {
            Ok((
                row.get::<_, [u8; 32]>(0)?,
                row.get::<_, u32>(1)?,
                row.get::<_, Option<[u8; 32]>>(2)?,
                row.get::<_, [u8; 32]>(3)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(|(txid, action_index, nullifier, owner)| {
            let nullifier = decode_orchard_nullifier(nullifier)?;
            Ok(ActiveOrchardLock::new(
                OutputRef::new(
                    TxId::from_bytes(txid),
                    PoolType::Shielded(ShieldedPool::Orchard),
                    action_index,
                ),
                nullifier,
                LockOwner::new(owner),
            ))
        })
        .collect()
}

/// Reads delivery reservations as a distinct typed authority. The delivery schema must be the
/// exact supported shape; missing, future, or corrupt provenance fails closed instead of silently
/// degrading a reservation to an ordinary lock (or omitting it from validation).
#[cfg(feature = "migration-delivery")]
pub(crate) fn active_orchard_reservations(
    conn: &Connection,
    tables: &Tables,
) -> Result<Vec<ActiveOrchardReservation>, crate::error::SqliteClientError> {
    match delivery_schema_provenance(conn, tables)
        .map_err(|e| crate::error::SqliteClientError::CorruptedData(e.to_string()))?
    {
        DeliverySchemaProvenance::Compatible(_) => {}
        other => {
            return Err(crate::error::SqliteClientError::CorruptedData(format!(
                "pool-migration delivery schema is not authoritative: {other:?}"
            )));
        }
    }

    let mut stmt = conn.prepare(&format!(
        "SELECT reservation.source_txid, reservation.source_index, rn.nf,
                runs.source_owner, runs.canonical_lock_owner
           FROM {} reservation
           JOIN {} runs ON runs.run_identity = reservation.run_identity
           LEFT JOIN transactions source ON source.txid = reservation.source_txid
           LEFT JOIN orchard_received_notes rn
             ON rn.transaction_id = source.id_tx
            AND rn.action_index = reservation.source_index
          WHERE reservation.status IN ('active', 'recovery_required')
          ORDER BY reservation.run_identity, reservation.source_txid,
                   reservation.source_index",
        tables.delivery_reservations, tables.delivery_runs,
    ))?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, [u8; 32]>(0)?,
                row.get::<_, u32>(1)?,
                row.get::<_, Option<[u8; 32]>>(2)?,
                row.get::<_, [u8; 32]>(3)?,
                row.get::<_, Option<[u8; 32]>>(4)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(
            |(txid, action_index, nullifier, reservation_owner, canonical_lock_owner)| {
                let reservation_owner = SourceReservationOwner::decode(&reservation_owner)
                    .map_err(|_| {
                        crate::error::SqliteClientError::CorruptedData(
                            "invalid pool-migration source reservation owner".to_string(),
                        )
                    })?;
                Ok(ActiveOrchardReservation::new(
                    OutputRef::new(
                        TxId::from_bytes(txid),
                        PoolType::Shielded(ShieldedPool::Orchard),
                        action_index,
                    ),
                    decode_orchard_nullifier(nullifier)?,
                    reservation_owner,
                    canonical_lock_owner.map(LockOwner::new),
                ))
            },
        )
        .collect()
}

/// Reads every current-main-chain or unexpired pending wallet spend of an Orchard output across
/// all accounts. This remains effective after transaction ingestion clears the advisory output
/// lock: a stale, different PCZT can no longer pass the finalization guard merely because the
/// winning transaction's spend row replaced its lock.
#[cfg(feature = "migration-delivery")]
pub(crate) fn active_orchard_spends(
    conn: &Connection,
) -> Result<Vec<ActiveOrchardSpend>, crate::error::SqliteClientError> {
    let tip = crate::wallet::chain_tip_height(conn)?
        .ok_or(crate::error::SqliteClientError::ChainHeightUnknown)?;
    let target_height = u32::from(tip) + 1;
    let mut stmt = conn.prepare(&format!(
        "SELECT source.txid, rn.action_index, rn.nf, spender.txid
           FROM orchard_received_notes rn
           JOIN transactions source ON source.id_tx = rn.transaction_id
           JOIN orchard_received_note_spends spends
             ON spends.orchard_received_note_id = rn.id
           JOIN transactions spender ON spender.id_tx = spends.transaction_id
          WHERE spender.block IS NOT NULL
             OR ({})",
        crate::wallet::common::tx_unexpired_condition("spender")
    ))?;
    let rows = stmt
        .query_map(named_params![":target_height": target_height], |row| {
            Ok((
                row.get::<_, [u8; 32]>(0)?,
                row.get::<_, u32>(1)?,
                row.get::<_, Option<[u8; 32]>>(2)?,
                row.get::<_, [u8; 32]>(3)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(|(source_txid, action_index, nullifier, spender_txid)| {
            let nullifier = decode_orchard_nullifier(nullifier)?;
            Ok(ActiveOrchardSpend::new(
                OutputRef::new(
                    TxId::from_bytes(source_txid),
                    PoolType::Shielded(ShieldedPool::Orchard),
                    action_index,
                ),
                nullifier,
                TxId::from_bytes(spender_txid),
            ))
        })
        .collect()
}

/// Marks every released source reservation whose stability horizon would be crossed by a wallet
/// rewind before any chain evidence is destroyed. This runs inside the caller's wallet
/// transaction; if any later truncation step fails, neither the rewind nor this recovery
/// transition commits.
#[cfg(feature = "migration-delivery")]
pub(crate) fn prepare_for_wallet_rewind(
    conn: &Connection,
    tables: &Tables,
    truncation_height: BlockHeight,
) -> Result<(), Error> {
    match delivery_schema_provenance(conn, tables)? {
        DeliverySchemaProvenance::Unavailable => return Ok(()),
        DeliverySchemaProvenance::Compatible(version)
            if version.as_u32() == DELIVERY_SCHEMA_VERSION => {}
        DeliverySchemaProvenance::Compatible(_)
        | DeliverySchemaProvenance::Future(_)
        | DeliverySchemaProvenance::Corrupt => return Err(Error::DeliverySchemaIncompatible),
    }

    // Height-zero is the explicit unexposed tombstone sentinel. Because block heights are
    // nonnegative, the strict comparison below can never convert it to recovery.
    let affected_runs = {
        let mut stmt = conn.prepare(&format!(
            "SELECT run_identity FROM {} WHERE storage_finality = 'finalized'
                    AND release_at_height > :truncation
             UNION ALL
             SELECT run_identity FROM {} WHERE storage_finality = 'finalized'
                    AND release_at_height > :truncation
             UNION ALL
             SELECT run_identity FROM {} WHERE storage_finality = 'finalized'
                    AND release_at_height > :truncation
             ORDER BY run_identity",
            tables.delivery_control, tables.immediate_delivery, tables.delivery_run_archive,
        ))?;
        stmt.query_map(
            named_params![":truncation": u32::from(truncation_height)],
            |row| row.get::<_, [u8; 32]>(0),
        )?
        .collect::<Result<Vec<_>, _>>()?
    };
    for run_identity in affected_runs {
        let run_identity = MigrationRunIdentity::read(run_identity.as_slice())
            .map_err(|_| Error::Corrupt("rewind run identity"))?;
        mark_delivery_run_recovery_required(
            conn,
            tables,
            run_identity,
            StorageRecoveryReason::RewoundBeyondFinalityHorizon,
        )?;
    }
    Ok(())
}

#[cfg(feature = "migration-delivery")]
fn decode_orchard_nullifier(
    bytes: Option<[u8; 32]>,
) -> Result<Option<Nullifier>, crate::error::SqliteClientError> {
    bytes
        .map(|bytes| {
            Option::<Nullifier>::from(Nullifier::from_bytes(&bytes)).ok_or_else(|| {
                crate::error::SqliteClientError::CorruptedData(
                    "invalid Orchard nullifier in canonical wallet storage".to_owned(),
                )
            })
        })
        .transpose()
}

/// Returns whether `lock_filter` admits the exact row under the same logical predicate emitted by
/// `wallet::common::output_eligible_condition`: no lock, expiry strictly below target, or an owner
/// explicitly admitted by the policy. Keeping the target comparison here identical to that SQL
/// predicate is important: a lock remains active *at* its expiry height.
#[cfg(feature = "migration-delivery")]
fn lock_filter_admits(
    lock_filter: LockFilter<'_>,
    target_height: TargetHeight,
    lock_expiry_height: Option<BlockHeight>,
    lock_owner: Option<LockOwner>,
) -> bool {
    match lock_filter {
        LockFilter::Unfiltered => true,
        LockFilter::Policy(policy) => {
            lock_expiry_height.is_none_or(|expiry| expiry < BlockHeight::from(target_height))
                || lock_owner.is_some_and(|owner| policy.overridable_owners().contains(&owner))
        }
    }
}

/// Classifies a single account-scoped Ironwood output. This deliberately does not read the
/// pool-migration tables: migration completion must be derived from canonical wallet/chain state,
/// and a reorg of the receiving transaction must fail closed even if stale spend rows remain.
#[cfg(feature = "migration-delivery")]
fn received_output_availability(
    conn: &Connection,
    account_id: AccountRef,
    output: ExactReceivedOutput,
    target_height: TargetHeight,
    confirmations_policy: ConfirmationsPolicy,
    lock_filter: LockFilter<'_>,
) -> Result<ReceivedOutputAvailability, Error> {
    if output.output_ref().pool() != PoolType::Shielded(ShieldedPool::Ironwood) {
        return Ok(ReceivedOutputAvailability::Unknown);
    }

    let evidence = conn
        .query_row(
            "SELECT rn.id,
                    rn.value,
                    source.block,
                    rn.recipient_key_scope,
                    accounts.ufvk IS NOT NULL,
                    rn.nf IS NOT NULL,
                    rn.commitment_tree_position,
                    rn.witness_stabilized,
                    scan_state.max_priority,
                    IFNULL(source.trust_status, 0),
                    rn.lock_expiry_height,
                    rn.lock_owner,
                    MAX(shielding_source.mined_height),
                    MIN(IFNULL(shielding_source.trust_status, 0))
               FROM ironwood_received_notes rn
               JOIN transactions source ON source.id_tx = rn.transaction_id
               JOIN accounts ON accounts.id = rn.account_id
               LEFT JOIN v_ironwood_shards_scan_state scan_state
                 ON rn.commitment_tree_position >= scan_state.start_position
                AND rn.commitment_tree_position < scan_state.end_position_exclusive
               LEFT JOIN transparent_received_output_spends shielding_spends
                 ON shielding_spends.transaction_id = source.id_tx
               LEFT JOIN transparent_received_outputs shielding_outputs
                 ON shielding_outputs.id = shielding_spends.transparent_received_output_id
                AND shielding_outputs.account_id = accounts.id
               LEFT JOIN transactions shielding_source
                 ON shielding_source.id_tx = shielding_outputs.transaction_id
              WHERE rn.account_id = :account_id
                AND source.txid = :txid
                AND rn.action_index = :action_index
              GROUP BY rn.id",
            named_params! {
                ":account_id": account_id.0,
                ":txid": output.output_ref().txid().as_ref(),
                ":action_index": output.output_ref().output_index(),
            },
            |row| {
                let value = Zatoshis::from_nonnegative_i64(row.get::<_, i64>(1)?)
                    .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(1, 0))?;
                let mined_height = row.get::<_, Option<u32>>(2)?.map(BlockHeight::from);
                let key_scope_code = row.get::<_, Option<i64>>(3)?;
                let ufvk_present = row.get::<_, bool>(4)?;
                let nullifier_present = row.get::<_, bool>(5)?;
                let commitment_tree_position = row.get::<_, Option<u64>>(6)?;
                let witness_stabilized = row.get::<_, bool>(7)?;
                let max_priority_raw = row.get::<_, Option<i64>>(8)?;
                let tx_trusted = row.get::<_, bool>(9)?;
                let lock_expiry_height = row.get::<_, Option<u32>>(10)?.map(BlockHeight::from);
                let lock_owner = row.get::<_, Option<[u8; 32]>>(11)?.map(LockOwner::new);
                let max_shielding_input_height =
                    row.get::<_, Option<u32>>(12)?.map(BlockHeight::from);
                let shielding_inputs_trusted = row.get::<_, bool>(13)?;

                Ok((
                    row.get::<_, i64>(0)?,
                    value,
                    mined_height,
                    key_scope_code,
                    ufvk_present,
                    nullifier_present,
                    commitment_tree_position,
                    witness_stabilized,
                    max_priority_raw,
                    tx_trusted,
                    lock_expiry_height,
                    lock_owner,
                    max_shielding_input_height,
                    shielding_inputs_trusted,
                ))
            },
        )
        .optional()?;

    let Some((
        note_id,
        value,
        Some(mined_height),
        key_scope_code,
        ufvk_present,
        nullifier_present,
        commitment_tree_position,
        witness_stabilized,
        max_priority_raw,
        tx_trusted,
        lock_expiry_height,
        lock_owner,
        max_shielding_input_height,
        shielding_inputs_trusted,
    )) = evidence
    else {
        // `source.block`, rather than the weaker `source.mined_height`, is the wallet's proof that
        // the receiving transaction belongs to its fully-scanned current main chain.
        return Ok(ReceivedOutputAvailability::Unknown);
    };

    if value != output.value() {
        return Ok(ReceivedOutputAvailability::Unknown);
    }

    let key_scope = key_scope_code
        .map(crate::wallet::encoding::KeyScope::decode)
        .transpose()
        .map_err(Error::Wallet)?
        .and_then(|scope| zip32::Scope::try_from(scope).ok());
    let max_shard_priority = max_priority_raw
        .map(|code| {
            crate::wallet::scanning::parse_priority_code(code).ok_or_else(|| {
                crate::error::SqliteClientError::CorruptedData(format!(
                    "Priority code {code} not recognized."
                ))
            })
        })
        .transpose()
        .map_err(Error::Wallet)?;

    let remaining = confirmations_policy.confirmations_until_spendable(
        target_height,
        PoolType::Shielded(ShieldedPool::Ironwood),
        key_scope,
        Some(mined_height),
        tx_trusted,
        max_shielding_input_height,
        shielding_inputs_trusted,
    );
    if remaining != 0 {
        return Ok(ReceivedOutputAvailability::Unavailable(
            ReceivedOutputUnavailable::PendingConfirmations { remaining },
        ));
    }

    // Historical spendability is accepted only from a spender whose `block` row is on the current
    // fully-scanned main chain. A merely observed/mined-height-only or mempool spender is never
    // current-main-chain historical spendability evidence.
    let spent_height = conn.query_row(
        "SELECT MAX(spender.block)
               FROM ironwood_received_note_spends spends
               JOIN transactions spender ON spender.id_tx = spends.transaction_id
              WHERE spends.ironwood_received_note_id = ?
                AND spender.block IS NOT NULL",
        params![note_id],
        |row| {
            row.get::<_, Option<u32>>(0)
                .map(|height| height.map(BlockHeight::from))
        },
    )?;
    if let Some(mined_height) = spent_height {
        return Ok(ReceivedOutputAvailability::Spent { mined_height });
    }

    let pending_spend = conn.query_row(
        &format!(
            "SELECT EXISTS(
                 SELECT 1
                   FROM ironwood_received_note_spends spends
                   JOIN transactions spender ON spender.id_tx = spends.transaction_id
                  WHERE spends.ironwood_received_note_id = :note_id
                    AND spender.block IS NULL
                    AND ({})
             )",
            crate::wallet::common::tx_unexpired_condition("spender")
        ),
        named_params! {
            ":note_id": note_id,
            ":target_height": u32::from(target_height),
        },
        |row| row.get::<_, bool>(0),
    )?;
    if pending_spend {
        return Ok(ReceivedOutputAvailability::Unavailable(
            ReceivedOutputUnavailable::PendingSpend,
        ));
    }

    // This intentionally uses the shared wallet anchor rather than the latest Ironwood-only
    // checkpoint: normal multi-pool note selection anchors at the oldest available Sapling /
    // Orchard checkpoint so every selected shielded input shares one canonical anchor policy.
    let anchor_height =
        crate::wallet::get_anchor_height(conn, target_height, confirmations_policy.trusted())
            .map_err(Error::Wallet)?;
    let reconstruction_complete = ufvk_present
        && key_scope_code.is_some()
        && nullifier_present
        && commitment_tree_position.is_some();
    let tip_unscanned = anchor_height
        .map(|anchor| crate::wallet::common::unscanned_tip_exists(conn, anchor, "ironwood"))
        .transpose()?;
    let shard_witness_available = witness_stabilized
        || (tip_unscanned == Some(false)
            && max_shard_priority.is_some_and(|priority| priority <= ScanPriority::Scanned));
    let mined_at_anchor = anchor_height.is_some_and(|anchor| mined_height <= anchor);
    if !reconstruction_complete || !shard_witness_available || !mined_at_anchor {
        return Ok(ReceivedOutputAvailability::Unavailable(
            ReceivedOutputUnavailable::WitnessUnavailable,
        ));
    }

    if !lock_filter_admits(lock_filter, target_height, lock_expiry_height, lock_owner) {
        return Ok(ReceivedOutputAvailability::Unavailable(
            ReceivedOutputUnavailable::Locked,
        ));
    }

    if value <= zip317::MARGINAL_FEE {
        return Ok(ReceivedOutputAvailability::Unavailable(
            ReceivedOutputUnavailable::Uneconomic,
        ));
    }

    Ok(ReceivedOutputAvailability::Spendable)
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

/// Resolve the primary key of `account_id`'s row in `t.migrations`, if one exists. Every child table
/// is addressed by this key rather than by `account_id` directly, so a write operation resolves
/// it once and reuses it for every subsequent query.
fn resolve_migration_id(
    conn: &Connection,
    t: &Tables,
    account_id: AccountRef,
) -> Result<Option<i64>, Error> {
    Ok(conn
        .query_row(
            &format!("SELECT id FROM {} WHERE account_id = ?", t.migrations),
            params![account_id.0],
            |row| row.get(0),
        )
        .optional()?)
}

fn read_migration(
    conn: &Connection,
    t: &Tables,
    account_id: AccountRef,
) -> Result<Option<MigrationState>, Error> {
    let row = conn
        .query_row(
            &format!(
                "SELECT id, status, note_split_fee_buffer, note_split_change, note_split_prep_fees,
                        note_split_total_input, note_split_total_migratable
                   FROM {} WHERE account_id = ?",
                t.migrations
            ),
            params![account_id.0],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, u64>(2)?,
                    row.get::<_, Option<u64>>(3)?,
                    row.get::<_, u64>(4)?,
                    row.get::<_, u64>(5)?,
                    row.get::<_, u64>(6)?,
                ))
            },
        )
        .optional()?;

    let Some((migration_id, status, fee_buffer, change, prep_fees, total_input, total_migratable)) =
        row
    else {
        return Ok(None);
    };

    let crossing_values = read_zatoshi_list(conn, t.crossing_values, migration_id)?;
    let note_split = NoteSplitPlan::from_stored_parts(
        crossing_values,
        Zatoshis::from_u64(fee_buffer)?,
        change.map(Zatoshis::from_u64).transpose()?,
        Zatoshis::from_u64(prep_fees)?,
        Zatoshis::from_u64(total_input)?,
        Zatoshis::from_u64(total_migratable)?,
    )
    .map_err(|_| Error::Corrupt("note_split"))?;

    let preparation = read_preparation(conn, t, migration_id)?;
    let transactions = read_transactions(conn, t, migration_id)?;

    let status =
        MigrationStatus::try_from(status.as_str()).map_err(|_| Error::Corrupt("status"))?;
    Ok(Some(MigrationState::from_parts(
        status,
        note_split,
        preparation,
        transactions,
    )))
}

/// Read an ordered list of zatoshi amounts (`ordinal`, `value`) from a child table.
fn read_zatoshi_list(
    conn: &Connection,
    table: &str,
    migration_id: i64,
) -> Result<Vec<Zatoshis>, Error> {
    let mut stmt = conn.prepare(&format!(
        "SELECT value FROM {table} WHERE migration_id = ? ORDER BY ordinal"
    ))?;
    let rows = stmt.query_map(params![migration_id], |row| row.get::<_, u64>(0))?;
    let mut out = Vec::new();
    for v in rows {
        out.push(Zatoshis::from_u64(v?)?);
    }
    Ok(out)
}

fn read_preparation(
    conn: &Connection,
    t: &Tables,
    migration_id: i64,
) -> Result<PreparationPlan, Error> {
    // The layers/transactions grid, reconstructed from the input and output rows: every transaction
    // has at least one such row (the write side rejects a state where one does not), so the distinct
    // `(layer, tx_index)` coordinates enumerate the full grid in order.
    let coords: Vec<(usize, usize)> = {
        let mut stmt = conn.prepare(&format!(
            "SELECT layer, tx_index FROM {} WHERE migration_id = :id
             UNION
             SELECT layer, tx_index FROM {} WHERE migration_id = :id
             ORDER BY layer, tx_index",
            t.prep_inputs, t.prep_outputs
        ))?;
        let rows = stmt.query_map(named_params! { ":id": migration_id }, |row| {
            Ok((
                row.get::<_, u64>(0)? as usize,
                row.get::<_, u64>(1)? as usize,
            ))
        })?;
        rows.collect::<Result<_, _>>()?
    };
    let mut layers: Vec<Vec<PrepTransaction>> = Vec::new();
    for (layer, tx_index) in coords {
        // Both indices must be contiguous from zero: a gap means a layer or transaction left no
        // rows, and silently renumbering would misdirect later layers' prior-output references.
        if layer == layers.len() && tx_index == 0 {
            layers.push(Vec::new());
        } else if !(layer + 1 == layers.len() && tx_index == layers[layer].len()) {
            return Err(Error::Corrupt(
                "preparation grid: non-contiguous coordinates",
            ));
        }
        let inputs = read_prep_inputs(conn, t, migration_id, layer, tx_index)?;
        let outputs = read_prep_outputs(conn, t, migration_id, layer, tx_index)?;
        layers[layer].push(PrepTransaction::from_parts(inputs, outputs));
    }

    let direct_funding = {
        let mut stmt = conn.prepare(&format!(
            "SELECT wallet_index, value FROM {} WHERE migration_id = ? ORDER BY ordinal",
            t.prep_direct_funding
        ))?;
        let rows = stmt.query_map(params![migration_id], |row| {
            Ok((row.get::<_, u64>(0)? as usize, row.get::<_, u64>(1)?))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (idx, value) = r?;
            out.push((idx, Zatoshis::from_u64(value)?));
        }
        out
    };

    Ok(PreparationPlan::from_parts(layers, direct_funding))
}

fn read_prep_inputs(
    conn: &Connection,
    t: &Tables,
    migration_id: i64,
    layer: usize,
    tx_index: usize,
) -> Result<Vec<PrepInput>, Error> {
    let mut stmt = conn.prepare(&format!(
        "SELECT source, wallet_index, prior_layer, prior_transaction, prior_output, value
           FROM {}
          WHERE migration_id = ? AND layer = ? AND tx_index = ?
          ORDER BY ordinal",
        t.prep_inputs
    ))?;
    let rows = stmt.query_map(
        params![migration_id, layer as u64, tx_index as u64],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<u64>>(1)?,
                row.get::<_, Option<u64>>(2)?,
                row.get::<_, Option<u64>>(3)?,
                row.get::<_, Option<u64>>(4)?,
                row.get::<_, u64>(5)?,
            ))
        },
    )?;
    let mut out = Vec::new();
    for r in rows {
        let (source, wallet_index, prior_layer, prior_transaction, prior_output, value) = r?;
        let value = Zatoshis::from_u64(value)?;
        let input = match source.as_str() {
            "wallet" => PrepInput::Wallet {
                index: wallet_index.ok_or(Error::Corrupt("prep_input.wallet_index"))? as usize,
                value,
            },
            "prior" => PrepInput::Prior {
                layer: prior_layer.ok_or(Error::Corrupt("prep_input.prior_layer"))? as usize,
                transaction: prior_transaction
                    .ok_or(Error::Corrupt("prep_input.prior_transaction"))?
                    as usize,
                output: prior_output.ok_or(Error::Corrupt("prep_input.prior_output"))? as usize,
                value,
            },
            _ => return Err(Error::Corrupt("prep_input.source")),
        };
        out.push(input);
    }
    Ok(out)
}

fn read_prep_outputs(
    conn: &Connection,
    t: &Tables,
    migration_id: i64,
    layer: usize,
    tx_index: usize,
) -> Result<Vec<PrepOutput>, Error> {
    let mut stmt = conn.prepare(&format!(
        "SELECT role, value FROM {}
          WHERE migration_id = ? AND layer = ? AND tx_index = ?
          ORDER BY ordinal",
        t.prep_outputs
    ))?;
    let rows = stmt.query_map(
        params![migration_id, layer as u64, tx_index as u64],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?)),
    )?;
    let mut out = Vec::new();
    for r in rows {
        let (role, value) = r?;
        let value = Zatoshis::from_u64(value)?;
        let output =
            PrepOutput::from_role(&role, value).map_err(|_| Error::Corrupt("prep_output.role"))?;
        out.push(output);
    }
    Ok(out)
}

fn read_transactions(
    conn: &Connection,
    t: &Tables,
    migration_id: i64,
) -> Result<Vec<MigrationTransaction>, Error> {
    let rows: Vec<TxRow> = {
        let mut stmt = conn.prepare(&format!(
            "SELECT tx_id, kind, kind_layer, kind_index, kind_crossing, pczt,
                    scheduled_height, expiry_height, anchor_boundary, state, txid, mined_height,
                    lock_owner
               FROM {}
              WHERE migration_id = ?
              ORDER BY tx_id",
            t.transactions
        ))?;
        let mapped = stmt.query_map(params![migration_id], |row| {
            Ok(TxRow {
                tx_id: row.get(0)?,
                kind: row.get(1)?,
                kind_layer: row.get(2)?,
                kind_index: row.get(3)?,
                kind_crossing: row.get(4)?,
                pczt: row.get(5)?,
                scheduled_height: row.get(6)?,
                expiry_height: row.get(7)?,
                anchor_boundary: row.get(8)?,
                state: row.get(9)?,
                txid: row.get(10)?,
                mined_height: row.get(11)?,
                lock_owner: row.get(12)?,
            })
        })?;
        mapped.collect::<Result<_, _>>()?
    };

    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let id = MigrationTxId::new(r.tx_id);
        let kind = MigrationTxKind::from_stored(
            &r.kind,
            r.kind_layer.map(|x| x as usize),
            r.kind_index.map(|x| x as usize),
            r.kind_crossing.map(|x| x as usize),
        )
        .map_err(|_| Error::Corrupt("kind"))?;
        let txid = r
            .txid
            .map(|s| {
                hex::decode(&s)
                    .ok()
                    .and_then(|v| <[u8; 32]>::try_from(v).ok())
                    .ok_or(Error::Corrupt("state.txid"))
            })
            .transpose()?;
        let state = MigrationTxState::from_stored(
            &r.state,
            txid,
            r.mined_height.map(BlockHeight::from_u32),
        )
        .map_err(|_| Error::Corrupt("state"))?;
        let depends_on = read_deps(conn, t, migration_id, r.tx_id)?;

        out.push(MigrationTransaction::from_parts(
            id,
            kind,
            r.pczt,
            depends_on,
            BlockHeight::from_u32(r.scheduled_height),
            BlockHeight::from_u32(r.expiry_height),
            r.anchor_boundary.map(BlockHeight::from_u32),
            state,
            r.lock_owner,
        ));
    }
    Ok(out)
}

/// Returns the distinct [`LockOwner`]s recorded on `account`'s migration transactions (empty if
/// the account has no migration, or none of its transactions hold a lock). A direct `DISTINCT`
/// query over the transactions table, scoped by the account's resolved migration id, so this
/// avoids reconstructing the whole migration (with its preparation plan and every transaction)
/// just to inspect which locks it holds.
fn read_lock_owners(
    conn: &Connection,
    t: &Tables,
    account: AccountRef,
) -> Result<BTreeSet<LockOwner>, Error> {
    let Some(migration_id) = resolve_migration_id(conn, t, account)? else {
        return Ok(BTreeSet::new());
    };
    let (total, owned): (u64, u64) = conn.query_row(
        &format!(
            "SELECT COUNT(*), COUNT(lock_owner) FROM {} WHERE migration_id = ?",
            t.transactions
        ),
        params![migration_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if owned != 0 && owned != total {
        return Err(Error::CanonicalOwnerMismatch);
    }
    let mut stmt = conn.prepare(&format!(
        "SELECT DISTINCT lock_owner FROM {} WHERE migration_id = ? AND lock_owner IS NOT NULL",
        t.transactions
    ))?;
    let rows = stmt.query_map(params![migration_id], |row| row.get::<_, [u8; 32]>(0))?;
    let mut out = BTreeSet::new();
    for r in rows {
        out.insert(LockOwner::new(r?));
    }
    if out.len() > 1 {
        return Err(Error::CanonicalOwnerMismatch);
    }
    Ok(out)
}

/// One row of the transactions table, before it is decoded into a [`MigrationTransaction`].
struct TxRow {
    tx_id: u32,
    kind: String,
    kind_layer: Option<u64>,
    kind_index: Option<u64>,
    kind_crossing: Option<u64>,
    pczt: Vec<u8>,
    scheduled_height: u32,
    expiry_height: u32,
    anchor_boundary: Option<u32>,
    state: String,
    txid: Option<String>,
    mined_height: Option<u32>,
    /// The stored lock-owner token, read directly as a fixed-size blob: `rusqlite`'s `[u8; 32]`
    /// `FromSql` impl errors cleanly (`InvalidBlobSize`) if a non-NULL blob is not exactly 32
    /// bytes, so a corrupt row is rejected rather than silently truncated or panicking.
    lock_owner: Option<[u8; 32]>,
}

fn read_deps(
    conn: &Connection,
    t: &Tables,
    migration_id: i64,
    tx_id: u32,
) -> Result<Vec<MigrationTxId>, Error> {
    let mut stmt = conn.prepare(&format!(
        "SELECT depends_on_tx_id FROM {}
          WHERE migration_id = ? AND tx_id = ?
          ORDER BY ordinal",
        t.transaction_deps
    ))?;
    let rows = stmt.query_map(params![migration_id, tx_id], |row| row.get::<_, u32>(0))?;
    let mut out = Vec::new();
    for r in rows {
        out.push(MigrationTxId::new(r?));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Write
// ---------------------------------------------------------------------------

/// Sealed authority for mutating canonical migration rows.
///
/// Delivery-enabled rows may only be changed by one of this module's atomic delivery-CAS paths;
/// callers through the generic [`zcash_pool_migration::engine::PoolMigrationWrite`] seam can only
/// request `Ordinary` authority.
#[cfg_attr(not(feature = "migration-delivery"), allow(dead_code))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CanonicalMutationAuthority {
    Ordinary,
    DeliveryCas,
}

/// Replace `account_id`'s migration in the tables named by `t` with `state` (deletes that account's
/// existing migration and its children first, if any). Runs inside the caller's transaction so the
/// replacement is atomic.
fn replace_migration(
    tx: &Connection,
    t: &Tables,
    account_id: AccountRef,
    state: &MigrationState,
    #[cfg_attr(not(feature = "migration-delivery"), allow(unused_variables))]
    authority: CanonicalMutationAuthority,
) -> Result<(), Error> {
    let retained_ids = state
        .transactions()
        .iter()
        .map(|transaction| u32::from(transaction.id()))
        .collect::<BTreeSet<_>>();
    // The layers/transactions grid is stored only through the input and output rows, so a layer
    // with no transactions, or a transaction with neither inputs nor outputs, would leave no trace
    // and read back with later coordinates silently renumbered — misdirecting prior-output
    // references. A plan the engine produced never contains these; reject rather than corrupt.
    for transactions in state.preparation().layers() {
        if transactions.is_empty() {
            return Err(Error::Unrepresentable("empty preparation layer"));
        }
        for prep_tx in transactions {
            if prep_tx.inputs().is_empty() && prep_tx.outputs().is_empty() {
                return Err(Error::Unrepresentable(
                    "preparation transaction with no inputs or outputs",
                ));
            }
        }
    }

    // Replace the canonical child rows while preserving the parent migration id. Zend's additive
    // delivery-control row is keyed to that parent and must survive ordinary lifecycle/PCZT state
    // replacement; its next snapshot reconciles the complete canonical-state fingerprint and
    // invalidates only unexposed stale claims. A genuinely new migration is distinguished by its
    // new canonical owner/run identity at that boundary.
    let existing_migration_id = resolve_migration_id(tx, t, account_id)?;
    if let Some(migration_id) = existing_migration_id {
        #[cfg(feature = "migration-delivery")]
        if sqlite_object_exists(tx, t.delivery_control)?
            && delivery_control_exists(tx, t, migration_id)?
        {
            if authority != CanonicalMutationAuthority::DeliveryCas {
                // A generic replacement cannot advance canonical lifecycle state without the
                // matching revision, claim, exact-artifact, and finality transition.
                return Err(Error::DeliveryPhaseMismatch);
            }
            let (stored_owner, phase, storage_finality) = tx.query_row(
                &format!(
                    "SELECT runs.canonical_lock_owner, control.phase,
                                control.storage_finality
                           FROM {} control
                           JOIN {} runs ON runs.run_identity = control.run_identity
                          WHERE control.migration_id = ?",
                    t.delivery_control, t.delivery_runs
                ),
                params![migration_id],
                |row| {
                    Ok((
                        row.get::<_, [u8; 32]>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )?;
            let incoming_owner = canonical_lock_owner(state)?;
            match incoming_owner {
                Some(owner) if owner.as_bytes() != &stored_owner => {
                    // Run creation/reorg recovery is an explicit delivery CAS operation. A
                    // generic canonical replacement may never silently pair a new owner with
                    // the old run's policy or exact network evidence.
                    return Err(Error::DeliveryRunMismatch);
                }
                None => {
                    let claims = read_delivery_claims(tx, t, migration_id)?;
                    let safe = !claims
                        .iter()
                        .any(|claim| claim_status_is_unresolved(claim.status()));
                    let atomic_abandonment = state.status() == MigrationStatus::Failed
                        && phase == DeliveryPhase::Abandoned.as_str();
                    let storage_finalization = state.status() == MigrationStatus::Complete
                        && storage_finality == "finalized";
                    if (!atomic_abandonment && !storage_finalization) || !safe {
                        return Err(Error::DeliveryPhaseMismatch);
                    }
                }
                Some(_) => {}
            }
        }

        #[cfg(feature = "migration-delivery")]
        if sqlite_object_exists(tx, t.delivery_claims)? {
            let mut stmt = tx.prepare(&format!(
                "SELECT tx_id FROM {} WHERE migration_id = ? ORDER BY tx_id",
                t.delivery_claims
            ))?;
            let claimed_ids = stmt
                .query_map(params![migration_id], |row| row.get::<_, u32>(0))?
                .collect::<Result<Vec<_>, _>>()?;
            if let Some(removed) = claimed_ids
                .into_iter()
                .find(|id| !retained_ids.contains(id))
            {
                return Err(Error::DeliveryClaimedTransactionRemoved(
                    MigrationTxId::new(removed),
                ));
            }
        }
        for table in [
            t.transaction_deps,
            t.prep_inputs,
            t.prep_outputs,
            t.prep_direct_funding,
            t.crossing_values,
        ] {
            tx.execute(
                &format!("DELETE FROM {table} WHERE migration_id = ?"),
                params![migration_id],
            )?;
        }
    }

    let ns = state.note_split();
    let migration_id = if let Some(migration_id) = existing_migration_id {
        tx.execute(
            &format!(
                "UPDATE {} SET status = :status,
                     note_split_fee_buffer = :fee_buffer, note_split_change = :change,
                     note_split_prep_fees = :prep_fees, note_split_total_input = :total_input,
                     note_split_total_migratable = :total_migratable
                 WHERE id = :migration_id",
                t.migrations
            ),
            named_params! {
                ":status": state.status().as_ref(),
                ":fee_buffer": ns.note_fee_buffer().into_u64(),
                ":change": ns.change().map(Zatoshis::into_u64),
                ":prep_fees": ns.prep_fees().into_u64(),
                ":total_input": ns.total_input().into_u64(),
                ":total_migratable": ns.total_migratable().into_u64(),
                ":migration_id": migration_id,
            },
        )?;
        migration_id
    } else {
        tx.execute(
            &format!(
                "INSERT INTO {} (account_id, status, note_split_fee_buffer, note_split_change,
                                 note_split_prep_fees, note_split_total_input, note_split_total_migratable)
                 VALUES (:account_id, :status, :fee_buffer, :change, :prep_fees, :total_input, :total_migratable)",
                t.migrations
            ),
            named_params! {
                ":account_id": account_id.0,
                ":status": state.status().as_ref(),
                ":fee_buffer": ns.note_fee_buffer().into_u64(),
                ":change": ns.change().map(Zatoshis::into_u64),
                ":prep_fees": ns.prep_fees().into_u64(),
                ":total_input": ns.total_input().into_u64(),
                ":total_migratable": ns.total_migratable().into_u64(),
            },
        )?;
        tx.last_insert_rowid()
    };

    insert_zatoshi_list(tx, t.crossing_values, migration_id, ns.crossing_values())?;

    let prep = state.preparation();
    for (layer, transactions) in prep.layers().iter().enumerate() {
        for (tx_index, prep_tx) in transactions.iter().enumerate() {
            for (ordinal, input) in prep_tx.inputs().iter().enumerate() {
                let (source, wallet_index, prior_layer, prior_transaction, prior_output) =
                    match input {
                        PrepInput::Wallet { index, .. } => {
                            ("wallet", Some(*index as u64), None, None, None)
                        }
                        PrepInput::Prior {
                            layer,
                            transaction,
                            output,
                            ..
                        } => (
                            "prior",
                            None,
                            Some(*layer as u64),
                            Some(*transaction as u64),
                            Some(*output as u64),
                        ),
                    };
                tx.execute(
                    &format!(
                        "INSERT INTO {} (migration_id, layer, tx_index, ordinal, source,
                                         wallet_index, prior_layer, prior_transaction, prior_output, value)
                         VALUES (:migration_id, :layer, :tx_index, :ordinal, :source,
                                 :wallet_index, :prior_layer, :prior_transaction, :prior_output, :value)",
                        t.prep_inputs
                    ),
                    named_params! {
                        ":migration_id": migration_id,
                        ":layer": layer as u64,
                        ":tx_index": tx_index as u64,
                        ":ordinal": ordinal as u64,
                        ":source": source,
                        ":wallet_index": wallet_index,
                        ":prior_layer": prior_layer,
                        ":prior_transaction": prior_transaction,
                        ":prior_output": prior_output,
                        ":value": input.value().into_u64(),
                    },
                )?;
            }
            for (ordinal, output) in prep_tx.outputs().iter().enumerate() {
                tx.execute(
                    &format!(
                        "INSERT INTO {} (migration_id, layer, tx_index, ordinal, role, value)
                         VALUES (:migration_id, :layer, :tx_index, :ordinal, :role, :value)",
                        t.prep_outputs
                    ),
                    named_params! {
                        ":migration_id": migration_id,
                        ":layer": layer as u64,
                        ":tx_index": tx_index as u64,
                        ":ordinal": ordinal as u64,
                        ":role": output.as_ref(),
                        ":value": output.value().into_u64(),
                    },
                )?;
            }
        }
    }
    for (ordinal, (wallet_index, value)) in prep.direct_funding_notes().iter().enumerate() {
        tx.execute(
            &format!(
                "INSERT INTO {} (migration_id, ordinal, wallet_index, value)
                 VALUES (:migration_id, :ordinal, :wallet_index, :value)",
                t.prep_direct_funding
            ),
            named_params! {
                ":migration_id": migration_id,
                ":ordinal": ordinal as u64,
                ":wallet_index": *wallet_index as u64,
                ":value": (*value).into_u64(),
            },
        )?;
    }

    for mtx in state.transactions() {
        let kind = mtx.kind();
        let (kind_layer, kind_index) = kind
            .preparation_indices()
            .map_or((None, None), |(l, i)| (Some(l as u64), Some(i as u64)));
        let kind_crossing = kind.transfer_crossing().map(|c| c as u64);
        let tx_state = mtx.state();
        tx.execute(
            &format!(
                "INSERT INTO {} (migration_id, tx_id, kind, kind_layer, kind_index, kind_crossing,
                                 pczt, scheduled_height, expiry_height, anchor_boundary, state, txid,
                                 mined_height, lock_owner)
                 VALUES (:migration_id, :tx_id, :kind, :kind_layer, :kind_index, :kind_crossing,
                         :pczt, :scheduled_height, :expiry_height, :anchor_boundary, :state, :txid,
                         :mined_height, :lock_owner)
                 ON CONFLICT(migration_id, tx_id) DO UPDATE SET
                     kind = excluded.kind,
                     kind_layer = excluded.kind_layer,
                     kind_index = excluded.kind_index,
                     kind_crossing = excluded.kind_crossing,
                     pczt = excluded.pczt,
                     scheduled_height = excluded.scheduled_height,
                     expiry_height = excluded.expiry_height,
                     anchor_boundary = excluded.anchor_boundary,
                     state = excluded.state,
                     txid = excluded.txid,
                     mined_height = excluded.mined_height,
                     lock_owner = excluded.lock_owner",
                t.transactions
            ),
            named_params! {
                ":migration_id": migration_id,
                ":tx_id": u32::from(mtx.id()),
                ":kind": kind.as_ref(),
                ":kind_layer": kind_layer,
                ":kind_index": kind_index,
                ":kind_crossing": kind_crossing,
                ":pczt": mtx.pczt().as_slice(),
                ":scheduled_height": u32::from(mtx.scheduled_height()),
                ":expiry_height": u32::from(mtx.expiry_height()),
                ":anchor_boundary": mtx.anchor_boundary().map(u32::from),
                ":state": tx_state.as_ref(),
                ":txid": tx_state.broadcast_txid().map(hex::encode),
                ":mined_height": tx_state.mined_height().map(u32::from),
                ":lock_owner": mtx.lock_owner(),
            },
        )?;
        for (ordinal, dep) in mtx.depends_on().iter().enumerate() {
            tx.execute(
                &format!(
                    "INSERT INTO {} (migration_id, tx_id, ordinal, depends_on_tx_id)
                     VALUES (:migration_id, :tx_id, :ordinal, :depends_on_tx_id)",
                    t.transaction_deps
                ),
                named_params! {
                    ":migration_id": migration_id,
                    ":tx_id": u32::from(mtx.id()),
                    ":ordinal": ordinal as u64,
                    ":depends_on_tx_id": u32::from(*dep),
                },
            )?;
        }
    }

    // Remove canonical transaction rows no longer present in the replacement. The explicit
    // claimed-transaction check above makes this fail closed before the canonical replacement can
    // cascade-delete exact-artifact evidence for a transaction it would remove. Ordinary
    // lifecycle updates retain transaction ids and therefore preserve their claims across the
    // upserts above.
    let retained_ids = retained_ids.iter().map(u32::to_string).collect::<Vec<_>>();
    let predicate = if retained_ids.is_empty() {
        String::new()
    } else {
        format!(" AND tx_id NOT IN ({})", retained_ids.join(","))
    };
    tx.execute(
        &format!(
            "DELETE FROM {} WHERE migration_id = ?{}",
            t.transactions, predicate
        ),
        params![migration_id],
    )?;
    Ok(())
}

/// Insert an ordered list of zatoshi amounts as `(ordinal, value)` rows into a child table.
fn insert_zatoshi_list(
    tx: &Connection,
    table: &str,
    migration_id: i64,
    values: &[Zatoshis],
) -> Result<(), Error> {
    for (ordinal, value) in values.iter().enumerate() {
        tx.execute(
            &format!(
                "INSERT INTO {table} (migration_id, ordinal, value)
                 VALUES (:migration_id, :ordinal, :value)"
            ),
            named_params! {
                ":migration_id": migration_id,
                ":ordinal": ordinal as u64,
                ":value": (*value).into_u64(),
            },
        )?;
    }
    Ok(())
}

#[cfg(all(test, feature = "migration-delivery"))]
mod tests {
    use super::*;
    use zcash_client_backend::proto::proposal::{self, proposed_input};
    use zcash_pool_migration::delivery::{ImmediateProposalPayload, SignerOwnership};
    use zcash_primitives::transaction::builder::DEFAULT_TX_EXPIRY_DELTA;
    use zcash_protocol::consensus::BranchId;

    /// Stable target at which the test proposal uses the NU6.3 branch.
    const TEST_TARGET_HEIGHT: u32 = 2_000;
    /// Byte width of a canonical transaction identifier.
    const TEST_TXID_LENGTH: usize = 32;
    /// First nonzero byte used to distinguish synthetic proposal sources.
    const TEST_TXID_BASE_BYTE: u8 = 1;
    /// Opaque account identifier used to prove intent preservation.
    const TEST_ACCOUNT_ID: u32 = 7;
    /// User-confirmed ceiling used to prove the intent accessor is lossless.
    const TEST_INTENT_CEILING: u64 = 12_345;
    /// First exact Orchard input value in the multi-input proposal.
    const TEST_FIRST_INPUT_VALUE: u64 = 7;
    /// Second exact Orchard input value in the multi-input proposal.
    const TEST_SECOND_INPUT_VALUE: u64 = 11;
    /// Sum of the two exact Orchard input values above.
    const TEST_EXPECTED_GROSS_AMOUNT: u64 = TEST_FIRST_INPUT_VALUE + TEST_SECOND_INPUT_VALUE;
    /// Smallest positive value used to force a bounded-value overflow.
    const TEST_ONE_ZATOSHI: u64 = 1;

    fn immediate_proposal_with_inputs(values: &[u64]) -> Vec<u8> {
        let inputs = values
            .iter()
            .enumerate()
            .map(|(index, value)| proposal::ProposedInput {
                value: Some(proposed_input::Value::ReceivedOutput(
                    proposal::ReceivedOutput {
                        txid: vec![
                            u8::try_from(index)
                                .unwrap()
                                .checked_add(TEST_TXID_BASE_BYTE)
                                .unwrap();
                            TEST_TXID_LENGTH
                        ],
                        value_pool: proposal::ValuePool::Orchard.into(),
                        index: u32::try_from(index).unwrap(),
                        value: *value,
                    },
                )),
            })
            .collect();
        let payload = proposal::Proposal {
            steps: vec![proposal::ProposalStep {
                inputs,
                ..Default::default()
            }],
            ..Default::default()
        }
        .encode_to_vec();
        let target = BlockHeight::from_u32(TEST_TARGET_HEIGHT);
        let envelope = ImmediateProposal::new(
            target,
            BlockHeight::from_u32(TEST_TARGET_HEIGHT + DEFAULT_TX_EXPIRY_DELTA),
            BranchId::Nu6_3,
            ImmediateProposalPayload::try_from(payload).unwrap(),
        )
        .unwrap();
        let mut canonical = Vec::new();
        envelope.write(&mut canonical).unwrap();
        canonical
    }

    #[test]
    fn historical_delivery_v1_schema_fingerprint_is_frozen() {
        let normalized = normalized_schema_sql(&delivery_control_schema_v1_sql(
            &crate::pool_migration::orchard_ironwood::TABLES,
        ));
        let fingerprint = LegacySchemaFingerprint::from_schema_sql(normalized.as_bytes());
        assert_eq!(
            hex::encode(fingerprint.as_bytes()),
            "b34a91a47c83acb9a3eb9d588cbc50ac8d6373a0fd77c1f5f051c7e6a2f61220",
            "migration d14c3f72 must continue to emit the exact normalized schema published by 98b51b18",
        );
    }

    #[test]
    fn delivery_v2_schema_limits_match_current_domain_limits() {
        assert_eq!(
            DELIVERY_SCHEMA_V2_GROSS_AUTHORIZATION_VERSION,
            IMMEDIATE_GROSS_AUTHORIZATION_VERSION,
        );
        assert_eq!(
            DELIVERY_SCHEMA_V2_MAX_MONEY,
            zcash_protocol::value::MAX_MONEY
        );
        assert_eq!(
            DELIVERY_SCHEMA_V2_MAX_IMMEDIATE_PROPOSAL_ENVELOPE,
            zcash_pool_migration::delivery::MAX_IMMEDIATE_PROPOSAL_ENVELOPE_BYTES,
        );
        assert_eq!(
            DELIVERY_SCHEMA_V2_MAX_EXACT_TRANSACTION,
            zcash_pool_migration::delivery::MAX_EXACT_TRANSACTION_BYTES,
        );
        assert_eq!(
            DELIVERY_SCHEMA_V2_MAX_FINALITY_ARCHIVE,
            zcash_pool_migration::delivery::MAX_FINALITY_ARCHIVE_BYTES,
        );
    }

    #[test]
    fn immediate_intent_preserves_the_user_confirmed_gross_ceiling() {
        let maximum = Zatoshis::from_u64(TEST_INTENT_CEILING).unwrap();
        let intent = zcash_pool_migration::delivery::ImmediateMigrationIntent::new(
            TEST_ACCOUNT_ID,
            SignerOwnership::External,
            maximum,
        );
        assert_eq!(intent.account_id(), &TEST_ACCOUNT_ID);
        assert_eq!(intent.signer_ownership(), SignerOwnership::External);
        assert_eq!(intent.maximum_gross_amount(), maximum);
    }

    #[test]
    fn immediate_proposal_authority_derives_exact_gross_input_value() {
        let input_values = [TEST_FIRST_INPUT_VALUE, TEST_SECOND_INPUT_VALUE];
        let canonical = immediate_proposal_with_inputs(&input_values);
        let (sources, gross) = immediate_proposal_authority(&canonical).unwrap();
        assert_eq!(sources.len(), input_values.len());
        assert_eq!(
            gross,
            Zatoshis::from_u64(TEST_EXPECTED_GROSS_AMOUNT).unwrap()
        );
    }

    #[test]
    fn immediate_gross_authorization_accepts_at_or_below_and_rejects_above() {
        let maximum = Zatoshis::from_u64(TEST_EXPECTED_GROSS_AMOUNT).unwrap();
        assert!(
            require_immediate_gross_authorization(
                Zatoshis::from_u64(TEST_EXPECTED_GROSS_AMOUNT - TEST_ONE_ZATOSHI).unwrap(),
                maximum
            )
            .is_ok()
        );
        assert!(require_immediate_gross_authorization(maximum, maximum).is_ok());
        assert!(matches!(
            require_immediate_gross_authorization(
                Zatoshis::from_u64(TEST_EXPECTED_GROSS_AMOUNT + TEST_ONE_ZATOSHI).unwrap(),
                maximum
            ),
            Err(Error::ImmediateAmountLimitExceeded)
        ));
    }

    #[test]
    fn immediate_proposal_authority_rejects_zero_and_overflowing_inputs() {
        assert!(matches!(
            immediate_proposal_authority(&immediate_proposal_with_inputs(&[0])),
            Err(Error::Corrupt("immediate proposal source value"))
        ));
        assert!(matches!(
            immediate_proposal_authority(&immediate_proposal_with_inputs(&[
                zcash_protocol::value::MAX_MONEY,
                TEST_ONE_ZATOSHI,
            ])),
            Err(Error::Corrupt("immediate proposal gross input amount"))
        ));
    }
}
