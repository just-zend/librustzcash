//! The SQLite pool-migration store instantiated for the Orchard -> Ironwood migration (ZIP 318);
//! tables prefixed `orchard_ironwood_migration[s]_`.
//!
//! This is the only public surface of the pool-migration store: it wraps the generic (private)
//! store with this pool's table names, exposing a concrete [`PoolMigrations`] that implements
//! [`PoolMigrationRead`] / [`PoolMigrationWrite`], and the `init_migration_tables` DDL its schema
//! migration runs. The generic store type never leaks into this API.

use std::borrow::{Borrow, BorrowMut};
use std::collections::BTreeSet;

use rusqlite::{Connection, OptionalExtension};

use zcash_client_backend::wallet::LockOwner;
#[cfg(feature = "migration-delivery")]
use zcash_pool_migration::delivery::{
    CanonicalDeliveryReceipt, CanonicalMaterializationReceipt, CanonicalMaterializationTransition,
    ClaimToken, DeliveryArtifactEvidence, DeliveryArtifactIdentity, DeliveryFailureReason,
    DeliveryRevision, DeliverySchemaProvenance, DeliverySnapshot, ExternalSigningPczt,
    LeaseDuration, LegacyCutoverStatus, MigrationDeliveryStore, MigrationRunIdentity,
    PolicyFingerprint, PolicyValidationFailure, SignedPcztEvidence, SignerOwnership,
    SubmissionContext, SubmissionOutcome, SubmissionPolicy,
};
use zcash_pool_migration::engine::{
    MigrationState, MigrationTxId, MigrationTxState, PoolMigrationRead, PoolMigrationWrite,
};
#[cfg(feature = "migration-delivery")]
use zcash_pool_migration::wallet::PoolMigrationLockStore;
#[cfg(feature = "migration-delivery")]
use zcash_protocol::consensus::{BlockHeight, Parameters};
#[cfg(feature = "migration-delivery")]
use {
    zcash_client_backend::{
        data_api::wallet::{ConfirmationsPolicy, TargetHeight, input_selection::LockFilter},
        wallet::OutputRef,
    },
    zcash_pool_migration::wallet::{
        ExactReceivedOutput, MigrationFinalizationAudit, ReceivedOutputAvailability,
        ReceivedOutputAvailabilitySource,
    },
};

use crate::{AccountRef, AccountUuid};

use super::store::{self, Store, Tables};

/// A failure reading or writing the pool-migration store.
pub use super::error::Error;

/// The Orchard -> Ironwood table and index names this store operates over.
pub(super) static TABLES: Tables = Tables {
    migrations: "orchard_ironwood_migrations",
    crossing_values: "orchard_ironwood_migration_crossing_values",
    prep_inputs: "orchard_ironwood_migration_prep_inputs",
    prep_outputs: "orchard_ironwood_migration_prep_outputs",
    prep_direct_funding: "orchard_ironwood_migration_prep_direct_funding",
    transactions: "orchard_ironwood_migration_transactions",
    transaction_deps: "orchard_ironwood_migration_transaction_deps",
    tx_due_index: "idx_orchard_ironwood_migration_tx_due",
    account_index: "idx_orchard_ironwood_migrations_account",
    delivery_meta: "zend_orchard_ironwood_delivery_meta",
    delivery_runs: "zend_orchard_ironwood_delivery_runs",
    delivery_active_lane_index: "idx_zend_orchard_ironwood_delivery_active_lane",
    delivery_active_source_index: "idx_zend_orchard_ironwood_delivery_active_source",
    delivery_run_delete_guard: "zend_orchard_ironwood_delivery_run_delete_guard",
    delivery_account_delete_guard: "zend_orchard_ironwood_delivery_account_delete_guard",
    delivery_control: "zend_orchard_ironwood_delivery_control",
    delivery_claims: "zend_orchard_ironwood_delivery_claims",
    delivery_claim_lease_index: "idx_zend_orchard_ironwood_delivery_claim_lease",
    delivery_reservations: "zend_orchard_ironwood_delivery_reservations",
    delivery_reservation_status_index: "idx_zend_orchard_ironwood_reservation_status",
    delivery_evidence: "zend_orchard_ironwood_delivery_evidence",
    delivery_attempt_archive: "zend_orchard_ironwood_delivery_attempt_archive",
    delivery_run_archive: "zend_orchard_ironwood_delivery_run_archive",
    immediate_delivery: "zend_orchard_ironwood_immediate_delivery",
    immediate_gross_authorization: "zend_orchard_ironwood_immediate_gross_authorization",
    immediate_lease_index: "idx_zend_orchard_ironwood_immediate_lease",
    legacy_quarantine: "zend_ironwood_legacy_quarantine",
};

/// Create the Orchard -> Ironwood pool-migration tables (and the due-transaction and account
/// indexes) on `conn`. This is the body the `orchard_ironwood_migration_tables` schema migration's
/// `up()` calls; it is idempotent (`IF NOT EXISTS`).
pub(crate) fn init_migration_tables(conn: &Connection) -> rusqlite::Result<()> {
    store::init(conn, &TABLES)
}

/// Create the additive Zend delivery-control and legacy-cutover quarantine tables. Registered by a
/// separate wallet-schema migration so databases that already ran the canonical table migration
/// receive this schema too.
#[cfg(feature = "migration-delivery")]
pub(crate) fn init_delivery_control_tables(conn: &Connection) -> rusqlite::Result<()> {
    store::init_delivery_control(conn, &TABLES)?;
    store::quarantine_legacy_engine_state(conn, &TABLES)?;
    Ok(())
}

/// Creates the current delivery-control schema directly for focused runtime tests. Production
/// wallets reach this shape only by replaying the immutable v1 node and its v2 successor.
#[cfg(all(feature = "migration-delivery", test))]
pub(crate) fn init_current_delivery_control_tables(conn: &Connection) -> rusqlite::Result<()> {
    store::init_current_delivery_control(conn, &TABLES)?;
    store::quarantine_legacy_engine_state(conn, &TABLES)?;
    Ok(())
}

/// Upgrades the delivery schema from the exact v1 implementation to v2 by adding the durable
/// immediate gross-authorization boundary. Existing immediate rows intentionally receive no
/// authorization record: only new user-confirmed reservations may create one.
#[cfg(feature = "migration-delivery")]
pub(crate) fn upgrade_immediate_gross_authorization(
    transaction: &rusqlite::Transaction<'_>,
) -> Result<(), Error> {
    store::upgrade_immediate_gross_authorization(transaction, &TABLES)
}

/// Validates the installed delivery schema using the same runtime provenance checks as wallet
/// operations. Kept crate-private for migration integration tests and startup diagnostics.
#[cfg(all(feature = "migration-delivery", test))]
pub(crate) fn delivery_schema_provenance(
    conn: &Connection,
) -> Result<zcash_pool_migration::delivery::DeliverySchemaProvenance, Error> {
    store::delivery_schema_provenance(conn, &TABLES)
}

/// Returns whether the exact current Zend delivery schema and all of its authority relations are
/// present. Ordinary Orchard selection uses this as a fail-closed provenance gate before it ever
/// interpolates the reservation tables into SQL; object-name presence alone is not authority.
#[cfg(feature = "migration-delivery")]
pub(crate) fn delivery_schema_is_compatible(conn: &Connection) -> rusqlite::Result<bool> {
    match store::delivery_schema_provenance(conn, &TABLES) {
        Ok(DeliverySchemaProvenance::Compatible(_)) => Ok(true),
        Ok(
            DeliverySchemaProvenance::Unavailable
            | DeliverySchemaProvenance::Future(_)
            | DeliverySchemaProvenance::Corrupt,
        ) => Ok(false),
        Err(Error::Db(error)) => Err(error),
        Err(_) => Ok(false),
    }
}

/// Reacquires released migration-source reservations before a wallet rewind crosses their fixed
/// stability horizon. Called by the shared wallet truncation primitive so every public rewind path
/// receives the same fail-closed behavior.
#[cfg(feature = "migration-delivery")]
pub(crate) fn prepare_for_wallet_rewind(
    conn: &Connection,
    truncation_height: BlockHeight,
) -> Result<(), Error> {
    store::prepare_for_wallet_rewind(conn, &TABLES, truncation_height)
}

/// The Orchard -> Ironwood pool-migration store: a [`PoolMigrationRead`] / [`PoolMigrationWrite`]
/// over a `rusqlite::Connection`, scoped to one account's migration. Construct it with a connection
/// borrow (`&Connection` for read-only access, `&mut Connection` to also write) over the same
/// connection a [`WalletDb`](crate::WalletDb) uses, so the pool-migration tables share the wallet
/// database.
///
/// An account's migration is owned by its row in the wallet's `accounts` table through the
/// `account_id` foreign key, so deleting the account removes its migration automatically (via
/// `ON DELETE CASCADE`); no explicit cleanup is required.
pub struct PoolMigrations<C>(Store<C>);

impl<C: Borrow<Connection>> PoolMigrations<C> {
    /// Wrap a connection borrow as the store, scoped to `account`'s migration.
    ///
    /// The account is resolved to its `accounts` row up front, so the store keys its migration by
    /// that row (the foreign key the schema uses) rather than by the external UUID. Returns
    /// [`Error::AccountUnknown`] if no account with this UUID exists in the wallet.
    pub fn for_account(conn: C, account: AccountUuid) -> Result<Self, Error> {
        let account_id = conn
            .borrow()
            .query_row(
                "SELECT id FROM accounts WHERE uuid = ?",
                rusqlite::params![account.expose_uuid()],
                |row| row.get(0).map(AccountRef),
            )
            .optional()?
            .ok_or(Error::AccountUnknown)?;
        Ok(Self(Store::new(conn, &TABLES, account_id)))
    }

    /// Constructs the delivery-capable account store with Rust-derived network and consensus
    /// context. The context-free [`for_account`](Self::for_account) remains available for the
    /// canonical upstream migration traits, but every delivery operation fails closed without
    /// this parameter-derived context.
    #[cfg(feature = "migration-delivery")]
    pub fn for_account_with_parameters<P: Parameters>(
        conn: C,
        account: AccountUuid,
        params: &P,
    ) -> Result<Self, Error> {
        let account_id = conn
            .borrow()
            .query_row(
                "SELECT id FROM accounts WHERE uuid = ?",
                rusqlite::params![account.expose_uuid()],
                |row| row.get(0).map(AccountRef),
            )
            .optional()?
            .ok_or(Error::AccountUnknown)?;
        Ok(Self(Store::new_with_submission_context(
            conn,
            &TABLES,
            account_id,
            SubmissionContext::from_parameters(params),
        )))
    }
}

impl<C> PoolMigrations<C> {
    /// Recover the wrapped connection borrow.
    pub fn into_inner(self) -> C {
        self.0.into_inner()
    }
}

impl<C: Borrow<Connection>> PoolMigrations<C> {
    /// Returns the set of [`LockOwner`]s under which this account's in-progress pool migration
    /// has locked notes (empty if there is no migration, or it holds no locks).
    ///
    /// This is the set a caller passes to a `LockedInputPolicy::PreferUnlocked` /
    /// `PreferLocked` override so a proposal may draw on the migration's own locked notes
    /// without disturbing any other flow's locks. It is not part of [`PoolMigrationRead`]: that
    /// trait is shared with the pool-agnostic migration engine, which has no notion of
    /// [`LockOwner`] (a wallet-level concept).
    pub fn migration_lock_owners(&self) -> Result<BTreeSet<LockOwner>, Error> {
        self.0.migration_lock_owners()
    }
}

impl<C: Borrow<Connection>> PoolMigrationRead for PoolMigrations<C> {
    type Error = Error;

    fn get_migration(&self) -> Result<Option<MigrationState>, Self::Error> {
        self.0.get_migration()
    }
}

#[cfg(feature = "migration-delivery")]
impl<C: BorrowMut<Connection>> MigrationDeliveryStore for PoolMigrations<C> {
    fn delivery_schema_provenance(&self) -> Result<DeliverySchemaProvenance, Self::Error> {
        self.0.delivery_schema_provenance()
    }

    fn legacy_cutover_status(&self) -> Result<LegacyCutoverStatus, Self::Error> {
        self.0.legacy_cutover_status()
    }

    fn delivery_snapshot(&mut self) -> Result<Option<DeliverySnapshot>, Self::Error> {
        self.0.delivery_snapshot()
    }

    fn bind_submission_policy(
        &mut self,
        expected_state: &MigrationState,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        policy: &SubmissionPolicy,
    ) -> Result<DeliverySnapshot, Self::Error> {
        self.0
            .bind_submission_policy(expected_state, expected_revision, run_identity, policy)
    }

    fn record_policy_validation_failure(
        &mut self,
        expected_state: &MigrationState,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        failure: PolicyValidationFailure,
    ) -> Result<DeliverySnapshot, Self::Error> {
        self.0.record_policy_validation_failure(
            expected_state,
            expected_revision,
            run_identity,
            failure,
        )
    }

    fn claim_materialization(
        &mut self,
        expected_state: &MigrationState,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        evidence: &DeliveryArtifactEvidence,
        signer_ownership: SignerOwnership,
        lease_duration: LeaseDuration,
        expected_policy_fingerprint: PolicyFingerprint,
    ) -> Result<Option<DeliverySnapshot>, Self::Error> {
        self.0.claim_materialization(
            expected_state,
            expected_revision,
            run_identity,
            evidence,
            signer_ownership,
            lease_duration,
            expected_policy_fingerprint,
        )
    }

    fn stage_external_signing_pczt(
        &mut self,
        expected_state: &MigrationState,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        artifact_identity: DeliveryArtifactIdentity,
        token: ClaimToken,
        pczt: &ExternalSigningPczt,
        expected_policy_fingerprint: PolicyFingerprint,
    ) -> Result<DeliverySnapshot, Self::Error> {
        self.0.stage_external_signing_pczt(
            expected_state,
            expected_revision,
            run_identity,
            artifact_identity,
            token,
            pczt,
            expected_policy_fingerprint,
        )
    }

    fn stage_signed_pczt(
        &mut self,
        expected_state: &MigrationState,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        artifact_identity: DeliveryArtifactIdentity,
        token: ClaimToken,
        signed_pczt: &SignedPcztEvidence,
        expected_policy_fingerprint: PolicyFingerprint,
    ) -> Result<DeliverySnapshot, Self::Error> {
        self.0.stage_signed_pczt(
            expected_state,
            expected_revision,
            run_identity,
            artifact_identity,
            token,
            signed_pczt,
            expected_policy_fingerprint,
        )
    }

    fn advance_canonical_materialization(
        &mut self,
        request: CanonicalMaterializationTransition,
    ) -> Result<CanonicalMaterializationReceipt, Self::Error> {
        self.0.advance_canonical_materialization(request)
    }

    fn claim_submission(
        &mut self,
        expected_state: &MigrationState,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        artifact_identity: DeliveryArtifactIdentity,
        lease_duration: LeaseDuration,
        expected_policy_fingerprint: PolicyFingerprint,
    ) -> Result<Option<DeliverySnapshot>, Self::Error> {
        self.0.claim_submission(
            expected_state,
            expected_revision,
            run_identity,
            artifact_identity,
            lease_duration,
            expected_policy_fingerprint,
        )
    }

    fn claim_outcome_resolution(
        &mut self,
        expected_state: &MigrationState,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        artifact_identity: DeliveryArtifactIdentity,
        lease_duration: LeaseDuration,
        expected_policy_fingerprint: PolicyFingerprint,
    ) -> Result<Option<DeliverySnapshot>, Self::Error> {
        self.0.claim_outcome_resolution(
            expected_state,
            expected_revision,
            run_identity,
            artifact_identity,
            lease_duration,
            expected_policy_fingerprint,
        )
    }

    fn resume_claim(
        &mut self,
        expected_state: &MigrationState,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        artifact_identity: DeliveryArtifactIdentity,
        token: ClaimToken,
        expected_policy_fingerprint: PolicyFingerprint,
    ) -> Result<Option<DeliverySnapshot>, Self::Error> {
        self.0.resume_claim(
            expected_state,
            expected_revision,
            run_identity,
            artifact_identity,
            token,
            expected_policy_fingerprint,
        )
    }

    fn renew_claim(
        &mut self,
        expected_state: &MigrationState,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        artifact_identity: DeliveryArtifactIdentity,
        token: ClaimToken,
        lease_duration: LeaseDuration,
        expected_policy_fingerprint: PolicyFingerprint,
    ) -> Result<Option<DeliverySnapshot>, Self::Error> {
        self.0.renew_claim(
            expected_state,
            expected_revision,
            run_identity,
            artifact_identity,
            token,
            lease_duration,
            expected_policy_fingerprint,
        )
    }

    fn record_submission_outcome(
        &mut self,
        expected_state: &MigrationState,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        artifact_identity: DeliveryArtifactIdentity,
        token: ClaimToken,
        outcome: SubmissionOutcome,
        expected_policy_fingerprint: PolicyFingerprint,
    ) -> Result<CanonicalDeliveryReceipt, Self::Error> {
        self.0.record_submission_outcome(
            expected_state,
            expected_revision,
            run_identity,
            artifact_identity,
            token,
            outcome,
            expected_policy_fingerprint,
        )
    }

    fn reconcile_submission(
        &mut self,
        expected_state: &MigrationState,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        artifact_identity: DeliveryArtifactIdentity,
        token: ClaimToken,
    ) -> Result<CanonicalDeliveryReceipt, Self::Error> {
        self.0.reconcile_submission(
            expected_state,
            expected_revision,
            run_identity,
            artifact_identity,
            token,
        )
    }

    fn reconcile_canonical_chain(
        &mut self,
        expected_state: &MigrationState,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
    ) -> Result<Option<CanonicalDeliveryReceipt>, Self::Error> {
        self.0
            .reconcile_canonical_chain(expected_state, expected_revision, run_identity)
    }

    fn release_claim_known_unsent(
        &mut self,
        expected_state: &MigrationState,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        artifact_identity: DeliveryArtifactIdentity,
        token: ClaimToken,
        reason: DeliveryFailureReason,
        expected_policy_fingerprint: PolicyFingerprint,
    ) -> Result<DeliverySnapshot, Self::Error> {
        self.0.release_claim_known_unsent(
            expected_state,
            expected_revision,
            run_identity,
            artifact_identity,
            token,
            reason,
            expected_policy_fingerprint,
        )
    }

    fn pause_delivery(
        &mut self,
        expected_state: &MigrationState,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
    ) -> Result<DeliverySnapshot, Self::Error> {
        self.0
            .pause_delivery(expected_state, expected_revision, run_identity)
    }

    fn resume_delivery(
        &mut self,
        expected_state: &MigrationState,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
    ) -> Result<DeliverySnapshot, Self::Error> {
        self.0
            .resume_delivery(expected_state, expected_revision, run_identity)
    }

    fn begin_abandonment(
        &mut self,
        expected_state: &MigrationState,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
    ) -> Result<DeliverySnapshot, Self::Error> {
        self.0
            .begin_abandonment(expected_state, expected_revision, run_identity)
    }

    fn finish_abandonment(
        &mut self,
        expected_state: &MigrationState,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
    ) -> Result<DeliverySnapshot, Self::Error> {
        self.0
            .finish_abandonment(expected_state, expected_revision, run_identity)
    }
}

#[cfg(feature = "migration-delivery")]
impl<C: Borrow<Connection>> ReceivedOutputAvailabilitySource for PoolMigrations<C> {
    type Error = Error;

    fn received_output_availability(
        &self,
        output: ExactReceivedOutput,
        target_height: TargetHeight,
        confirmations_policy: ConfirmationsPolicy,
        lock_filter: LockFilter<'_>,
    ) -> Result<ReceivedOutputAvailability, Self::Error> {
        self.0.received_output_availability(
            output,
            target_height,
            confirmations_policy,
            lock_filter,
        )
    }
}

impl<C: BorrowMut<Connection>> PoolMigrationWrite for PoolMigrations<C> {
    fn replace_migration(&mut self, state: &MigrationState) -> Result<(), Self::Error> {
        self.0.replace_migration(state)
    }

    fn update_transaction(
        &mut self,
        id: MigrationTxId,
        state: MigrationTxState,
    ) -> Result<(), Self::Error> {
        self.0.update_transaction(id, state)
    }
}

#[cfg(feature = "migration-delivery")]
impl<C: BorrowMut<Connection>> PoolMigrationLockStore for PoolMigrations<C> {
    fn lock_outputs_and_replace_migration(
        &mut self,
        expected: Option<&MigrationState>,
        state: &MigrationState,
        outputs: &[OutputRef],
        owner: LockOwner,
        lock_expiry_height: BlockHeight,
    ) -> Result<(), Self::Error> {
        self.0.lock_outputs_and_replace_migration(
            expected,
            state,
            outputs,
            owner,
            lock_expiry_height,
        )
    }

    fn release_locks_and_replace_migration(
        &mut self,
        expected: &MigrationState,
        state: &MigrationState,
        owners: &BTreeSet<LockOwner>,
    ) -> Result<(), Self::Error> {
        self.0
            .release_locks_and_replace_migration(expected, state, owners)
    }

    fn finalize_migration_if_outputs_available(
        &mut self,
        expected: &MigrationState,
        finalized: &MigrationState,
        owners: &BTreeSet<LockOwner>,
        outputs: &[(MigrationTxId, ExactReceivedOutput)],
        target_height: TargetHeight,
        confirmations_policy: ConfirmationsPolicy,
        lock_filter: LockFilter<'_>,
    ) -> Result<MigrationFinalizationAudit, Self::Error> {
        self.0.finalize_migration_if_outputs_available(
            expected,
            finalized,
            owners,
            outputs,
            target_height,
            confirmations_policy,
            lock_filter,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{PoolMigrations, init_migration_tables};
    #[cfg(feature = "migration-delivery")]
    use super::{
        TABLES, init_current_delivery_control_tables as init_delivery_control_tables,
        init_delivery_control_tables as init_delivery_control_v1_tables, prepare_for_wallet_rewind,
        upgrade_immediate_gross_authorization,
    };
    #[cfg(feature = "migration-delivery")]
    use crate::pool_migration::ImmediateDeliveryWriteTransaction;
    #[cfg(feature = "migration-delivery")]
    use crate::pool_migration::store;

    use proptest::prelude::*;
    use rusqlite::Connection;
    use uuid::Uuid;

    use zcash_pool_migration::engine::{
        MigrationTxId, MigrationTxState, PoolMigrationRead, PoolMigrationWrite,
    };
    use zcash_pool_migration::testing::{
        arb_migration_state, arb_migration_tx_state, assert_empty_is_none,
        assert_put_get_roundtrip, assert_put_replaces, assert_update_transaction,
        first_transaction_id,
    };

    use crate::AccountUuid;

    use super::Error;

    /// A fresh in-memory database with a minimal `accounts` table (the `account_id` foreign-key
    /// target) and the migration tables created, but not yet wrapped as a store for any particular
    /// account. Used by tests that put more than one account's [`PoolMigrations`] over the same
    /// connection.
    fn fresh_conn() -> Connection {
        let conn = Connection::open_in_memory().expect("in-memory db");
        // A minimal stand-in for the wallet's `accounts` table: the migration tables' `account_id`
        // foreign key references `accounts(id)`, and `for_account` resolves an `AccountUuid` to its
        // row through `accounts(uuid)`.
        conn.execute_batch(
            "CREATE TABLE accounts (
                 id INTEGER PRIMARY KEY,
                 uuid BLOB NOT NULL,
                 ufvk BLOB DEFAULT X'00',
                 birthday_height INTEGER
             );
             CREATE UNIQUE INDEX accounts_uuid ON accounts (uuid);
             CREATE TABLE scan_queue (
                 block_range_start INTEGER NOT NULL DEFAULT 0,
                 block_range_end INTEGER NOT NULL,
                 priority INTEGER NOT NULL DEFAULT 10
             );
             INSERT INTO scan_queue (block_range_end) VALUES (101);
             CREATE TABLE transactions (
                 id_tx INTEGER PRIMARY KEY,
                 txid BLOB NOT NULL UNIQUE,
                 block INTEGER,
                 mined_height INTEGER,
                 expiry_height INTEGER,
                 min_observed_height INTEGER NOT NULL DEFAULT 0,
                 trust_status INTEGER
             );
             CREATE TABLE orchard_received_notes (
                 id INTEGER PRIMARY KEY,
                 transaction_id INTEGER NOT NULL,
                 action_index INTEGER NOT NULL,
                 account_id INTEGER NOT NULL,
                 nf BLOB,
                 lock_expiry_height INTEGER,
                 lock_owner BLOB,
                 UNIQUE (transaction_id, action_index)
             );
             CREATE TABLE orchard_received_note_spends (
                 orchard_received_note_id INTEGER NOT NULL,
                 transaction_id INTEGER NOT NULL,
                 UNIQUE (orchard_received_note_id, transaction_id)
             );
             CREATE TABLE sapling_received_notes (
                 id INTEGER PRIMARY KEY,
                 lock_expiry_height INTEGER,
                 lock_owner BLOB
             );
             CREATE TABLE ironwood_received_notes (
                 id INTEGER PRIMARY KEY,
                 transaction_id INTEGER NOT NULL,
                 action_index INTEGER NOT NULL,
                 account_id INTEGER NOT NULL,
                 diversifier BLOB NOT NULL,
                 value INTEGER NOT NULL,
                 rho BLOB NOT NULL,
                 rseed BLOB NOT NULL,
                 nf BLOB,
                 is_change INTEGER NOT NULL,
                 memo BLOB,
                 commitment_tree_position INTEGER,
                 recipient_key_scope INTEGER,
                 witness_stabilized INTEGER NOT NULL DEFAULT 0,
                 note_version INTEGER NOT NULL,
                 lock_expiry_height INTEGER,
                 lock_owner BLOB,
                 UNIQUE (transaction_id, action_index)
             );
             CREATE TABLE ironwood_received_note_spends (
                 ironwood_received_note_id INTEGER NOT NULL,
                 transaction_id INTEGER NOT NULL,
                 UNIQUE (ironwood_received_note_id, transaction_id)
             );
             CREATE TABLE transparent_received_outputs (
                 id INTEGER PRIMARY KEY,
                 transaction_id INTEGER NOT NULL,
                 account_id INTEGER NOT NULL,
                 lock_expiry_height INTEGER,
                 lock_owner BLOB
             );
             CREATE TABLE transparent_received_output_spends (
                 transparent_received_output_id INTEGER NOT NULL,
                 transaction_id INTEGER NOT NULL
             );
             CREATE TABLE v_ironwood_shards_scan_state (
                 start_position INTEGER NOT NULL,
                 end_position_exclusive INTEGER NOT NULL,
                 max_priority INTEGER
             );
             INSERT INTO v_ironwood_shards_scan_state
                 (start_position, end_position_exclusive, max_priority)
             VALUES (0, 1000, 10);
             CREATE TABLE v_ironwood_shard_unscanned_ranges (
                 block_range_start INTEGER,
                 subtree_start_height INTEGER,
                 subtree_end_height INTEGER
             );
             CREATE TABLE sapling_tree_checkpoints (checkpoint_id INTEGER PRIMARY KEY);
             CREATE TABLE orchard_tree_checkpoints (checkpoint_id INTEGER PRIMARY KEY);
             INSERT INTO sapling_tree_checkpoints (checkpoint_id) VALUES (108);
             INSERT INTO orchard_tree_checkpoints (checkpoint_id) VALUES (108);",
        )
        .expect("create accounts table");
        init_migration_tables(&conn).expect("create tables");
        conn
    }

    /// Insert a fresh random account into `conn`'s `accounts` table and return its UUID, so a store
    /// can be scoped to it.
    fn insert_account(conn: &Connection) -> AccountUuid {
        let account = AccountUuid::from_uuid(Uuid::new_v4());
        conn.execute(
            "INSERT INTO accounts (uuid) VALUES (?)",
            rusqlite::params![account.expose_uuid()],
        )
        .expect("insert account");
        account
    }

    /// A fresh, empty store over a new in-memory database with the migration tables created, scoped
    /// to a fresh account. Each proptest case and test gets its own database and account, so writes
    /// never bleed between cases.
    fn fresh_store() -> PoolMigrations<Connection> {
        let conn = fresh_conn();
        let account = insert_account(&conn);
        PoolMigrations::for_account(conn, account).expect("account exists")
    }

    #[cfg(feature = "migration-delivery")]
    fn immediate_delivery_write<T>(
        conn: &Connection,
        operation: impl FnOnce(&ImmediateDeliveryWriteTransaction<'_>) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let transaction = ImmediateDeliveryWriteTransaction::begin(conn)?;
        let result = operation(&transaction);
        match result {
            Ok(value) => {
                transaction.commit()?;
                Ok(value)
            }
            Err(error) => {
                transaction.rollback()?;
                Err(error)
            }
        }
    }

    #[cfg(feature = "migration-delivery")]
    fn insert_lockable_output(
        conn: &Connection,
        account: AccountUuid,
        marker: u8,
    ) -> zcash_client_backend::wallet::OutputRef {
        use zcash_protocol::{PoolType, ShieldedPool, TxId};

        let account_id: i64 = conn
            .query_row(
                "SELECT id FROM accounts WHERE uuid = ?",
                rusqlite::params![account.expose_uuid()],
                |row| row.get(0),
            )
            .expect("account row exists");
        let txid = TxId::from_bytes([marker; 32]);
        conn.execute(
            "INSERT INTO transactions (txid) VALUES (?)",
            rusqlite::params![txid.as_ref()],
        )
        .expect("insert transaction");
        let transaction_id = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO orchard_received_notes
                 (transaction_id, action_index, account_id)
             VALUES (?, 0, ?)",
            rusqlite::params![transaction_id, account_id],
        )
        .expect("insert Orchard output");

        zcash_client_backend::wallet::OutputRef::new(
            txid,
            PoolType::Shielded(ShieldedPool::Orchard),
            0,
        )
    }

    #[cfg(feature = "migration-delivery")]
    fn insert_ironwood_output(
        conn: &Connection,
        account: AccountUuid,
        marker: u8,
        value: zcash_protocol::value::Zatoshis,
        mined_height: u32,
    ) -> zcash_pool_migration::wallet::ExactReceivedOutput {
        use zcash_client_backend::wallet::OutputRef;
        use zcash_pool_migration::wallet::ExactReceivedOutput;
        use zcash_protocol::{PoolType, ShieldedPool, TxId};

        let account_id: i64 = conn
            .query_row(
                "SELECT id FROM accounts WHERE uuid = ?",
                rusqlite::params![account.expose_uuid()],
                |row| row.get(0),
            )
            .expect("account row exists");
        let txid = TxId::from_bytes([marker; 32]);
        conn.execute(
            "INSERT INTO transactions (txid, block, mined_height, expiry_height)
             VALUES (?, ?, ?, 0)",
            rusqlite::params![txid.as_ref(), mined_height, mined_height],
        )
        .expect("insert receiving transaction");
        let transaction_id = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO ironwood_received_notes
                 (transaction_id, action_index, account_id, diversifier, value, rho, rseed, nf,
                  is_change, commitment_tree_position, recipient_key_scope, witness_stabilized,
                  note_version)
             VALUES (?, 0, ?, ?, ?, ?, ?, ?, 1, ?, 1, 0, 3)",
            rusqlite::params![
                transaction_id,
                account_id,
                [0u8; 11],
                u64::from(value),
                [1u8; 32],
                [2u8; 32],
                [marker.wrapping_add(1); 32],
                u64::from(marker),
            ],
        )
        .expect("insert Ironwood output");

        ExactReceivedOutput::new(
            OutputRef::new(txid, PoolType::Shielded(ShieldedPool::Ironwood), 0),
            value,
        )
    }

    #[cfg(feature = "migration-delivery")]
    fn output_lock(
        conn: &Connection,
        output: &zcash_client_backend::wallet::OutputRef,
    ) -> (Option<u32>, Option<[u8; 32]>) {
        conn.query_row(
            "SELECT orchard_received_notes.lock_expiry_height,
                    orchard_received_notes.lock_owner
               FROM orchard_received_notes
               JOIN transactions
                 ON transactions.id_tx = orchard_received_notes.transaction_id
              WHERE transactions.txid = ?
                AND orchard_received_notes.action_index = ?",
            rusqlite::params![output.txid().as_ref(), output.output_index()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("output exists")
    }

    #[cfg(feature = "migration-delivery")]
    fn migration_state(
        status: zcash_pool_migration::engine::MigrationStatus,
        owner: Option<zcash_client_backend::wallet::LockOwner>,
    ) -> zcash_pool_migration::engine::MigrationState {
        migration_state_variant(
            status,
            owner,
            vec![1, 2, 3],
            zcash_pool_migration::engine::MigrationTxState::Signed,
            120,
        )
    }

    #[cfg(feature = "migration-delivery")]
    fn migration_state_variant(
        status: zcash_pool_migration::engine::MigrationStatus,
        owner: Option<zcash_client_backend::wallet::LockOwner>,
        pczt: Vec<u8>,
        transaction_state: zcash_pool_migration::engine::MigrationTxState,
        scheduled_height: u32,
    ) -> zcash_pool_migration::engine::MigrationState {
        use zcash_pool_migration::engine::{MigrationState, MigrationTransaction, MigrationTxKind};
        use zcash_pool_migration::note_splitting::NoteSplitPlan;
        use zcash_pool_migration::preparation::PreparationPlan;
        use zcash_protocol::{consensus::BlockHeight, value::Zatoshis};

        let one = Zatoshis::const_from_u64(1);
        let note_split = NoteSplitPlan::from_stored_parts(
            vec![one],
            Zatoshis::ZERO,
            None,
            Zatoshis::ZERO,
            one,
            one,
        )
        .expect("one-crossing plan is valid");
        let transaction = MigrationTransaction::from_parts(
            MigrationTxId::new(0),
            MigrationTxKind::Transfer { crossing: 0 },
            pczt,
            Vec::new(),
            BlockHeight::from_u32(scheduled_height),
            BlockHeight::from_u32(200),
            Some(BlockHeight::from_u32(112)),
            transaction_state,
            owner.map(|owner| *owner.as_bytes()),
        );
        MigrationState::from_parts(
            status,
            note_split,
            PreparationPlan::from_parts(Vec::new(), Vec::new()),
            vec![transaction],
        )
    }

    #[cfg(feature = "migration-delivery")]
    fn source_bound_transfer_state(
        conn: &Connection,
        account: AccountUuid,
        owner: zcash_client_backend::wallet::LockOwner,
        source_marker: u8,
        note_seed: u64,
    ) -> (
        zcash_pool_migration::engine::MigrationState,
        zcash_client_backend::wallet::OutputRef,
    ) {
        use orchard::keys::FullViewingKey;
        use rand_chacha::ChaCha8Rng;
        use rand_core::SeedableRng;
        use zcash_pool_migration::{
            build::build_transfer_pczt, note_splitting::RESIDUAL_MIGRATION_MIN,
        };
        use zcash_primitives::transaction::fees::zip317::MARGINAL_FEE;

        let fvk = FullViewingKey::from(&zcash_pool_migration_memory::spending_key(note_seed));
        let crossing = RESIDUAL_MIGRATION_MIN;
        let source_value = u64::from(crossing) + 3 * MARGINAL_FEE.into_u64();
        let (note, _, _) =
            zcash_pool_migration_memory::single_note_witness(&fvk, source_value, note_seed);
        let nullifier = note.nullifier(&fvk);
        let pczt = build_transfer_pczt(
            &zcash_pool_migration_memory::regtest_network(true),
            100,
            140,
            &fvk,
            note,
            crossing,
            ChaCha8Rng::seed_from_u64(note_seed ^ 0x5a5a),
        )
        .expect("build source-bound transfer PCZT")
        .serialize()
        .expect("serialize source-bound transfer PCZT");
        let output = insert_lockable_output(conn, account, source_marker);
        conn.execute(
            "UPDATE orchard_received_notes SET nf = ?
              WHERE transaction_id = (SELECT id_tx FROM transactions WHERE txid = ?)
                AND action_index = ?",
            rusqlite::params![
                nullifier.to_bytes(),
                output.txid().as_ref(),
                output.output_index()
            ],
        )
        .expect("bind source nullifier");
        (
            migration_state_variant(
                zcash_pool_migration::engine::MigrationStatus::Committed,
                Some(owner),
                pczt,
                zcash_pool_migration::engine::MigrationTxState::Signed,
                120,
            ),
            output,
        )
    }

    #[cfg(feature = "migration-delivery")]
    fn start_source_bound_delivery(
        conn: &mut Connection,
        account: AccountUuid,
        owner: zcash_client_backend::wallet::LockOwner,
        source_marker: u8,
        note_seed: u64,
    ) -> (
        zcash_pool_migration::engine::MigrationState,
        zcash_client_backend::wallet::OutputRef,
        zcash_pool_migration::delivery::MigrationRunIdentity,
    ) {
        use zcash_pool_migration::{
            delivery::MigrationDeliveryStore, wallet::PoolMigrationLockStore,
        };
        use zcash_protocol::consensus::BlockHeight;

        let (state, output) =
            source_bound_transfer_state(conn, account, owner, source_marker, note_seed);
        let params = zcash_pool_migration_memory::regtest_network(true);
        let run = {
            let mut store =
                PoolMigrations::for_account_with_parameters(&mut *conn, account, &params)
                    .expect("account store");
            store
                .lock_outputs_and_replace_migration(
                    None,
                    &state,
                    &[output],
                    owner,
                    BlockHeight::from_u32(u32::MAX),
                )
                .expect("atomic scheduled start");
            store
                .delivery_snapshot()
                .expect("delivery snapshot")
                .expect("delivery run")
                .run_identity()
        };
        (state, output, run)
    }

    #[cfg(feature = "migration-delivery")]
    #[test]
    fn delivery_schema_enforces_canonical_transaction_integrity_and_lifecycle_reconciliation() {
        use zcash_client_backend::wallet::LockOwner;
        use zcash_pool_migration::{
            delivery::{DeliveryLane, MigrationDeliveryStore, migration_state_fingerprint},
            engine::{MigrationStatus, MigrationTxState, PoolMigrationWrite},
        };

        let mut conn = fresh_conn();
        conn.pragma_update(None, "foreign_keys", true).unwrap();
        init_delivery_control_tables(&conn).expect("delivery schema");
        let account = insert_account(&conn);
        let owner = LockOwner::new([0xD1; 32]);
        let (initial, output, run) =
            start_source_bound_delivery(&mut conn, account, owner, 0xD2, 0xD300);
        let migration_id: i64 = conn
            .query_row("SELECT id FROM orchard_ironwood_migrations", [], |row| {
                row.get(0)
            })
            .unwrap();
        let params = zcash_pool_migration_memory::regtest_network(true);
        let snapshot = PoolMigrations::for_account_with_parameters(&mut conn, account, &params)
            .unwrap()
            .delivery_snapshot()
            .unwrap()
            .unwrap();
        assert_eq!(snapshot.run_identity(), run);
        assert_eq!(snapshot.lane(), DeliveryLane::Scheduled);
        assert_eq!(snapshot.active_source_reservation_count(), 1);
        assert!(snapshot.claims().is_empty());
        assert_ne!(run.as_bytes(), owner.as_bytes());

        let (lane, run_status, canonical_id, canonical_owner): (
            String,
            String,
            Option<i64>,
            [u8; 32],
        ) = conn
            .query_row(
                "SELECT lane, status, canonical_migration_id, canonical_lock_owner
                   FROM zend_orchard_ironwood_delivery_runs WHERE run_identity = ?",
                rusqlite::params![run.as_bytes()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(lane, "canonical");
        assert_eq!(run_status, "active");
        assert_eq!(canonical_id, Some(migration_id));
        assert_eq!(canonical_owner, *owner.as_bytes());

        let (revision, phase, stored_fingerprint): (u64, String, [u8; 32]) = conn
            .query_row(
                "SELECT revision, phase, state_fingerprint
                   FROM zend_orchard_ironwood_delivery_control WHERE migration_id = ?",
                [migration_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(revision, 1);
        assert_eq!(phase, "active");
        assert_eq!(
            stored_fingerprint,
            *migration_state_fingerprint(&initial).as_bytes()
        );

        let (source_txid, source_index, reservation_status): ([u8; 32], u32, String) = conn
            .query_row(
                "SELECT source_txid, source_index, status
                   FROM zend_orchard_ironwood_delivery_reservations
                  WHERE run_identity = ?",
                rusqlite::params![run.as_bytes()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(source_txid, *output.txid().as_ref());
        assert_eq!(source_index, output.output_index());
        assert_eq!(reservation_status, "active");

        let canonical = &initial.transactions()[0];
        assert!(
            conn.execute(
                "INSERT INTO zend_orchard_ironwood_delivery_claims (
                     migration_id, tx_id, pczt_digest, transaction_fingerprint,
                     status, signer_ownership, policy_fingerprint
                 ) VALUES (?, 1, ?, ?, 'materialization_failed', 'sdk', ?)",
                rusqlite::params![
                    migration_id,
                    zcash_pool_migration::delivery::PcztDigest::from_pczt(canonical.pczt())
                        .as_bytes(),
                    zcash_pool_migration::delivery::migration_transaction_fingerprint(
                        &initial, canonical
                    )
                    .as_bytes(),
                    [0xD4u8; 32],
                ],
            )
            .is_err(),
            "a claim must reference one exact canonical transaction row",
        );

        let changed_schedule = migration_state_variant(
            MigrationStatus::Committed,
            Some(owner),
            canonical.pczt().clone(),
            MigrationTxState::Signed,
            121,
        );
        let mut store = PoolMigrations::for_account(&mut conn, account).unwrap();
        assert!(matches!(
            store.replace_migration(&changed_schedule),
            Err(Error::DeliveryPhaseMismatch)
        ));
        assert_eq!(store.get_migration().unwrap(), Some(initial));
    }

    #[cfg(feature = "migration-delivery")]
    #[test]
    fn account_deletion_cascades_every_delivery_lane_and_evidence_row() {
        use zcash_client_backend::wallet::LockOwner;
        use zcash_pool_migration::delivery::{PcztDigest, migration_transaction_fingerprint};

        let mut conn = fresh_conn();
        conn.pragma_update(None, "foreign_keys", true).unwrap();
        init_delivery_control_tables(&conn).unwrap();
        let account = insert_account(&conn);
        let account_id: i64 = conn
            .query_row(
                "SELECT id FROM accounts WHERE uuid = ?",
                rusqlite::params![account.expose_uuid()],
                |row| row.get(0),
            )
            .unwrap();
        let owner = LockOwner::new([0xA1; 32]);
        let (state, output, run) =
            start_source_bound_delivery(&mut conn, account, owner, 0xA2, 0xA300);
        let migration_id: i64 = conn
            .query_row("SELECT id FROM orchard_ironwood_migrations", [], |row| {
                row.get(0)
            })
            .unwrap();
        let canonical = &state.transactions()[0];
        conn.execute(
            "INSERT INTO zend_orchard_ironwood_delivery_claims (
                 migration_id, tx_id, pczt_digest, transaction_fingerprint, status,
                 signer_ownership, policy_fingerprint
             ) VALUES (?, 0, ?, ?, 'materialization_failed', 'sdk', ?)",
            rusqlite::params![
                migration_id,
                PcztDigest::from_pczt(canonical.pczt()).as_bytes(),
                migration_transaction_fingerprint(&state, canonical).as_bytes(),
                [0xA4u8; 32],
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO zend_orchard_ironwood_delivery_evidence (
                 run_identity, tx_id, pczt_digest, transaction_fingerprint, canonical_pczt,
                 transaction_kind, terminal_status, signer_ownership, expiry_height,
                 policy_fingerprint
             ) VALUES (?, 0, ?, ?, ?, 'transfer', 'materialization_failed', 'sdk', ?, ?)",
            rusqlite::params![
                run.as_bytes(),
                PcztDigest::from_pczt(canonical.pczt()).as_bytes(),
                migration_transaction_fingerprint(&state, canonical).as_bytes(),
                canonical.pczt(),
                u32::from(canonical.expiry_height()),
                [0xA4u8; 32],
            ],
        )
        .unwrap();
        let immediate_run = [0xA5u8; 32];
        let immediate_source_owner = [0xA6u8; 32];
        let immediate_lock_owner = [0xA7u8; 32];
        let immediate_authority = store::delivery_run_authority_fingerprint(
            &immediate_run,
            account_id,
            "immediate",
            None,
            &immediate_source_owner,
            Some(&immediate_lock_owner),
        )
        .unwrap();
        assert!(
            conn.execute(
                "INSERT INTO zend_orchard_ironwood_delivery_runs (
                     run_identity, account_id, lane, source_owner,
                     canonical_lock_owner, authority_fingerprint, status
                 ) VALUES (?, ?, 'immediate', ?, ?, ?, 'active')",
                rusqlite::params![
                    immediate_run,
                    account_id,
                    immediate_source_owner,
                    immediate_lock_owner,
                    immediate_authority,
                ],
            )
            .is_err(),
            "one account cannot hold simultaneous live scheduled and immediate lanes",
        );

        assert!(
            conn.execute("DELETE FROM accounts WHERE id = ?", [account_id])
                .is_err(),
            "account deletion must fail while the scheduled lane is live",
        );
        conn.execute(
            "UPDATE zend_orchard_ironwood_delivery_control
                SET phase = 'abandoned', storage_finality = 'finalized',
                    release_at_height = 0, finalized_tip_height = 0
              WHERE run_identity = ?",
            rusqlite::params![run.as_bytes()],
        )
        .unwrap();
        conn.execute(
            "UPDATE zend_orchard_ironwood_delivery_reservations
                SET status = 'abandoned', release_at_height = NULL, released_tip_height = 0
              WHERE run_identity = ?",
            rusqlite::params![run.as_bytes()],
        )
        .unwrap();
        conn.execute(
            "UPDATE orchard_received_notes SET lock_owner = NULL, lock_expiry_height = NULL
              WHERE transaction_id = (SELECT id_tx FROM transactions WHERE txid = ?)
                AND action_index = ?",
            rusqlite::params![output.txid().as_ref(), output.output_index()],
        )
        .unwrap();
        let scheduled_source_owner: [u8; 32] = conn
            .query_row(
                "SELECT source_owner FROM zend_orchard_ironwood_delivery_runs
                  WHERE run_identity = ?",
                rusqlite::params![run.as_bytes()],
                |row| row.get(0),
            )
            .unwrap();
        let retired_authority = store::delivery_run_authority_fingerprint(
            run.as_bytes(),
            account_id,
            "canonical",
            None,
            &scheduled_source_owner,
            Some(owner.as_bytes()),
        )
        .unwrap();
        conn.execute(
            "UPDATE zend_orchard_ironwood_delivery_runs
                SET status = 'abandoned', canonical_migration_id = NULL,
                    authority_fingerprint = ?
              WHERE run_identity = ?",
            rusqlite::params![retired_authority, run.as_bytes()],
        )
        .unwrap();

        conn.execute(
            "INSERT INTO zend_orchard_ironwood_delivery_runs (
                 run_identity, account_id, lane, source_owner,
                 canonical_lock_owner, authority_fingerprint, status
             ) VALUES (?, ?, 'immediate', ?, ?, ?, 'active')",
            rusqlite::params![
                immediate_run,
                account_id,
                immediate_source_owner,
                immediate_lock_owner,
                immediate_authority,
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO zend_orchard_ironwood_immediate_delivery (
                 run_identity, revision, phase, artifact_identity, proposal_fingerprint,
                 canonical_proposal, signer_ownership, status, expiry_height
             ) VALUES (?, 1, 'abandoned', ?, ?, X'01', 'sdk', 'abandoned', 0)",
            rusqlite::params![immediate_run, [0xA8u8; 32], [0xA9u8; 32]],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO zend_orchard_ironwood_immediate_gross_authorization
                 (run_identity, authorization_version, maximum_gross_amount)
             VALUES (?, 1, 0)",
            rusqlite::params![immediate_run],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO zend_orchard_ironwood_delivery_reservations (
                 run_identity, source_txid, source_index, status, released_tip_height
             ) VALUES (?, ?, 1, 'abandoned', 0)",
            rusqlite::params![immediate_run, [0xAAu8; 32]],
        )
        .unwrap();

        assert!(
            conn.execute(
                "DELETE FROM zend_orchard_ironwood_delivery_runs WHERE run_identity = ?",
                rusqlite::params![run.as_bytes()],
            )
            .is_err(),
            "ordinary run deletion must not erase canonical delivery claims or evidence",
        );
        let retained_claim: bool = conn
            .query_row(
                "SELECT EXISTS(
                     SELECT 1 FROM zend_orchard_ironwood_delivery_claims
                      WHERE migration_id = ?
                 )",
                [migration_id],
                |row| row.get(0),
            )
            .unwrap();
        assert!(retained_claim);

        conn.execute(
            "UPDATE zend_orchard_ironwood_delivery_runs SET status = 'abandoned'
             WHERE run_identity = ?",
            rusqlite::params![immediate_run],
        )
        .unwrap();
        conn.execute("DELETE FROM accounts WHERE id = ?", [account_id])
            .unwrap();
        for table in [
            "orchard_ironwood_migrations",
            "zend_orchard_ironwood_delivery_runs",
            "zend_orchard_ironwood_delivery_control",
            "zend_orchard_ironwood_delivery_claims",
            "zend_orchard_ironwood_delivery_reservations",
            "zend_orchard_ironwood_delivery_evidence",
            "zend_orchard_ironwood_immediate_delivery",
            "zend_orchard_ironwood_immediate_gross_authorization",
        ] {
            let remaining: u64 = conn
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(remaining, 0, "{table} retained deleted-account state");
        }
        let fk_violation = conn
            .prepare("PRAGMA foreign_key_check")
            .unwrap()
            .query([])
            .unwrap()
            .next()
            .unwrap()
            .is_some();
        assert!(!fk_violation);
    }

    #[cfg(feature = "migration-delivery")]
    #[test]
    fn failed_immediate_materialization_reacquisition_is_exact_and_account_scoped() {
        use prost::Message;
        use rand::rngs::OsRng;
        use zcash_client_backend::{
            proto::proposal::{self, proposed_input},
            wallet::LockOwner,
        };
        use zcash_pool_migration::delivery::{
            ClaimKind, ClaimStatus, ClaimToken, DeliveryArtifactIdentity, DeliveryFailureReason,
            DeliveryRevision, ExternalSigningPczt, ImmediateArtifactEvidence,
            ImmediateArtifactIdentity, ImmediateMigrationDeliveryStore, ImmediateProposal,
            ImmediateProposalPayload, LeaseDuration, LoopbackDevelopmentEndpoint,
            MigrationRunIdentity, SignerOwnership, SourceReservationOwner, SubmissionContext,
            SubmissionOutcome, SubmissionPolicy, SubmissionPolicyRequest, SubmissionTransport,
            exact_immediate_transaction,
        };
        use zcash_primitives::transaction::{
            Authorized, TransactionData, builder::DEFAULT_TX_EXPIRY_DELTA,
        };
        use zcash_protocol::{
            consensus::{BlockHeight, BranchId},
            value::Zatoshis,
        };

        /// A stable height at which the test network has an active transaction branch.
        const TEST_TARGET_HEIGHT: u32 = 120;
        /// A bounded retry lease; only Rust interprets it as materialization authority.
        const TEST_LEASE_MILLIS: u64 = 5_000;
        /// Gross Orchard value committed by the persisted canonical proposal.
        const TEST_GROSS_AMOUNT: u64 = 100_000;
        /// Distinct test-only identifier byte for the proposal source transaction.
        const TEST_SOURCE_TXID_BYTE: u8 = 0x53;
        /// Distinct test-only identifier byte for the wallet lock owner.
        const TEST_LOCK_OWNER_BYTE: u8 = 0x52;
        /// Largest revision representable by the SQLite delivery schema.
        const MAX_PERSISTED_DELIVERY_REVISION: u64 = i64::MAX as u64;
        type StableImmediateAuthority = (Vec<u8>, Vec<u8>, Vec<u8>, String, Vec<u8>, Vec<u8>);
        type RetryMutableState = (u64, String, Option<String>, Option<Vec<u8>>);

        let mut conn = fresh_conn();
        conn.pragma_update(None, "foreign_keys", true).unwrap();
        init_delivery_control_v1_tables(&conn).expect("historical delivery schema");
        let account = insert_account(&conn);
        let foreign_account = insert_account(&conn);
        let account_id: i64 = conn
            .query_row(
                "SELECT id FROM accounts WHERE uuid = ?",
                rusqlite::params![account.expose_uuid()],
                |row| row.get(0),
            )
            .unwrap();
        let foreign_account_id: i64 = conn
            .query_row(
                "SELECT id FROM accounts WHERE uuid = ?",
                rusqlite::params![foreign_account.expose_uuid()],
                |row| row.get(0),
            )
            .unwrap();
        let source = insert_lockable_output(&conn, account, TEST_SOURCE_TXID_BYTE);

        let params = zcash_pool_migration_memory::regtest_network(true);
        let context = SubmissionContext::from_parameters(&params);
        let transport = SubmissionTransport::LoopbackDevelopment(
            LoopbackDevelopmentEndpoint::try_from("http://127.0.0.1:9067".to_owned()).unwrap(),
        );
        let policy =
            SubmissionPolicy::validate(SubmissionPolicyRequest::new(context, transport), context)
                .expect("test policy");
        let target_height = BlockHeight::from_u32(TEST_TARGET_HEIGHT);
        let payload = proposal::Proposal {
            steps: vec![proposal::ProposalStep {
                inputs: vec![proposal::ProposedInput {
                    value: Some(proposed_input::Value::ReceivedOutput(
                        proposal::ReceivedOutput {
                            txid: source.txid().as_ref().to_vec(),
                            value_pool: proposal::ValuePool::Orchard.into(),
                            index: 0,
                            value: TEST_GROSS_AMOUNT,
                        },
                    )),
                }],
                ..Default::default()
            }],
            ..Default::default()
        }
        .encode_to_vec();
        let proposal = ImmediateProposal::new(
            target_height,
            BlockHeight::from_u32(TEST_TARGET_HEIGHT + DEFAULT_TX_EXPIRY_DELTA),
            BranchId::for_height(&params, target_height),
            ImmediateProposalPayload::try_from(payload).unwrap(),
        )
        .expect("test proposal envelope");
        let artifact_identity = ImmediateArtifactIdentity::random(&mut OsRng);
        let evidence = ImmediateArtifactEvidence::from_proposal(artifact_identity, &proposal);
        let run_identity = MigrationRunIdentity::random(&mut OsRng);
        let source_owner = SourceReservationOwner::random(&mut OsRng);
        let lock_owner = LockOwner::new([TEST_LOCK_OWNER_BYTE; 32]);
        conn.execute(
            "UPDATE orchard_received_notes
                SET lock_expiry_height = ?, lock_owner = ?
              WHERE transaction_id = (SELECT id_tx FROM transactions WHERE txid = ?)
                AND action_index = ?",
            rusqlite::params![
                u32::from(evidence.expiry_height()),
                lock_owner.as_bytes(),
                source.txid().as_ref(),
                source.output_index(),
            ],
        )
        .unwrap();
        let lock_before_upgrade = output_lock(&conn, &source);
        let authority = store::delivery_run_authority_fingerprint(
            run_identity.as_bytes(),
            account_id,
            "immediate",
            None,
            source_owner.as_bytes(),
            Some(lock_owner.as_bytes()),
        )
        .unwrap();
        conn.execute(
            "INSERT INTO zend_orchard_ironwood_delivery_runs (
                 run_identity, account_id, lane, source_owner, canonical_lock_owner,
                 authority_fingerprint, status
             ) VALUES (?, ?, 'immediate', ?, ?, ?, 'active')",
            rusqlite::params![
                run_identity.as_bytes(),
                account_id,
                source_owner.as_bytes(),
                lock_owner.as_bytes(),
                authority,
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO zend_orchard_ironwood_immediate_delivery (
                 run_identity, revision, phase, artifact_identity, proposal_fingerprint,
                 canonical_proposal, signer_ownership, status, last_error, expiry_height,
                 policy, policy_fingerprint
             ) VALUES (?, 1, 'active', ?, ?, ?, 'sdk', 'materialization_failed',
                       'materialization_failed', ?, ?, ?)",
            rusqlite::params![
                run_identity.as_bytes(),
                artifact_identity.as_bytes(),
                evidence.proposal_digest().as_bytes(),
                evidence.canonical_proposal(),
                u32::from(evidence.expiry_height()),
                policy.canonical_bytes(),
                policy.fingerprint().as_bytes(),
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO zend_orchard_ironwood_delivery_reservations (
                 run_identity, source_txid, source_index, status
            ) VALUES (?, ?, 0, 'active')",
            rusqlite::params![run_identity.as_bytes(), source.txid().as_ref()],
        )
        .unwrap();
        let pre_upgrade_provenance: (u32, String) = conn
            .query_row(
                "SELECT schema_version, implementation
                   FROM zend_orchard_ironwood_delivery_meta WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            pre_upgrade_provenance,
            (1, "just-zend/librustzcash-delivery-v1".to_owned())
        );
        let pre_upgrade_authorization_table: bool = conn
            .query_row(
                "SELECT EXISTS(
                     SELECT 1 FROM sqlite_schema
                      WHERE name = 'zend_orchard_ironwood_immediate_gross_authorization'
                 )",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!pre_upgrade_authorization_table);
        {
            let transaction = conn.transaction().unwrap();
            upgrade_immediate_gross_authorization(&transaction).expect("upgrade exact v1 schema");
            transaction.commit().unwrap();
        }
        let upgraded_provenance: (u32, String) = conn
            .query_row(
                "SELECT schema_version, implementation
                   FROM zend_orchard_ironwood_delivery_meta WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            upgraded_provenance,
            (2, "just-zend/librustzcash-delivery-v2".to_owned())
        );
        let fabricated_authorizations: u64 = conn
            .query_row(
                "SELECT COUNT(*) FROM zend_orchard_ironwood_immediate_gross_authorization",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(fabricated_authorizations, 0);
        assert_eq!(output_lock(&conn, &source), lock_before_upgrade);
        let (legacy_current, legacy_retained) = store::load_immediate_delivery_runtime_parts(
            &conn,
            &TABLES,
            crate::AccountRef(account_id),
            context,
        )
        .expect("legacy immediate state remains readable after upgrade");
        assert!(legacy_retained.is_empty());
        let legacy_snapshot = legacy_current.expect("one live legacy immediate row").0;
        assert_eq!(legacy_snapshot.immediate_maximum_gross_amount(), None);
        assert_eq!(
            legacy_snapshot.storage_finality(),
            zcash_pool_migration::delivery::StorageFinality::Active,
            "missing spend authorization is orthogonal to reservation finality",
        );
        let legacy_runtime =
            zcash_pool_migration::delivery::MigrationRuntimeSnapshot::from_observed(
                None,
                Some(legacy_snapshot),
                vec![],
                zcash_pool_migration::delivery::DeliverySchemaProvenance::Compatible(
                    zcash_pool_migration::delivery::DeliverySchemaVersion::from_u32(2).unwrap(),
                ),
                zcash_pool_migration::delivery::LegacyCutoverStatus::Fresh,
                zcash_pool_migration::delivery::DestinationSpendability::NotSpendable,
            );
        assert_eq!(
            legacy_runtime.availability(),
            zcash_pool_migration::delivery::MigrationRuntimeAvailability::Unavailable(
                zcash_pool_migration::delivery::RuntimeUnavailableReason::MissingSpendAuthorization,
            )
        );
        let active_reservations: u64 = conn
            .query_row(
                "SELECT COUNT(*) FROM zend_orchard_ironwood_delivery_reservations
                  WHERE run_identity = ? AND status = 'active'",
                rusqlite::params![run_identity.as_bytes()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(active_reservations, 1);
        let stable_before: StableImmediateAuthority = conn
            .query_row(
                "SELECT artifact_identity, proposal_fingerprint, canonical_proposal,
                        signer_ownership, policy, policy_fingerprint
                   FROM zend_orchard_ironwood_immediate_delivery WHERE run_identity = ?",
                rusqlite::params![run_identity.as_bytes()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .unwrap();
        let lease_duration = LeaseDuration::from_millis(TEST_LEASE_MILLIS).unwrap();

        let wrong_signer = immediate_delivery_write(&conn, |transaction| {
            store::reacquire_failed_immediate_materialization(
                transaction,
                &TABLES,
                crate::AccountRef(account_id),
                context,
                DeliveryRevision::INITIAL,
                run_identity,
                artifact_identity,
                SignerOwnership::External,
                Zatoshis::from_u64(TEST_GROSS_AMOUNT + 1).unwrap(),
                lease_duration,
                policy.fingerprint(),
            )
        });
        assert!(
            matches!(wrong_signer, Err(Error::DeliveryClaimUnavailable)),
            "unexpected wrong-signer result: {wrong_signer:?}"
        );
        assert!(
            immediate_delivery_write(&conn, |transaction| {
                store::reacquire_failed_immediate_materialization(
                    transaction,
                    &TABLES,
                    crate::AccountRef(foreign_account_id),
                    context,
                    DeliveryRevision::INITIAL,
                    run_identity,
                    artifact_identity,
                    SignerOwnership::Sdk,
                    Zatoshis::from_u64(TEST_GROSS_AMOUNT + 1).unwrap(),
                    lease_duration,
                    policy.fingerprint(),
                )
            })
            .is_err(),
            "a different account cannot reacquire the claim",
        );
        let authorizations_after_invalid_identity: u64 = conn
            .query_row(
                "SELECT COUNT(*) FROM zend_orchard_ironwood_immediate_gross_authorization",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(authorizations_after_invalid_identity, 0);

        let mutable_before: RetryMutableState = conn
            .query_row(
                "SELECT revision, status, claim_kind, attempt_token
                   FROM zend_orchard_ironwood_immediate_delivery WHERE run_identity = ?",
                rusqlite::params![run_identity.as_bytes()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        let over_limit = immediate_delivery_write(&conn, |transaction| {
            store::reacquire_failed_immediate_materialization(
                transaction,
                &TABLES,
                crate::AccountRef(account_id),
                context,
                DeliveryRevision::INITIAL,
                run_identity,
                artifact_identity,
                SignerOwnership::Sdk,
                Zatoshis::from_u64(TEST_GROSS_AMOUNT - 1).unwrap(),
                lease_duration,
                policy.fingerprint(),
            )
        });
        assert!(matches!(
            over_limit,
            Err(Error::ImmediateAmountLimitExceeded)
        ));
        let mutable_after_rejection: RetryMutableState = conn
            .query_row(
                "SELECT revision, status, claim_kind, attempt_token
                   FROM zend_orchard_ironwood_immediate_delivery WHERE run_identity = ?",
                rusqlite::params![run_identity.as_bytes()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(mutable_after_rejection, mutable_before);
        let authorizations_after_limit_rejection: u64 = conn
            .query_row(
                "SELECT COUNT(*) FROM zend_orchard_ironwood_immediate_gross_authorization",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(authorizations_after_limit_rejection, 0);

        let read_mutable_state = |conn: &Connection| -> RetryMutableState {
            conn.query_row(
                "SELECT revision, status, claim_kind, attempt_token
                   FROM zend_orchard_ironwood_immediate_delivery WHERE run_identity = ?",
                rusqlite::params![run_identity.as_bytes()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap()
        };
        let empty_transaction = TransactionData::<Authorized>::from_parts_v6(
            proposal.branch_id(),
            133,
            evidence.expiry_height(),
            #[cfg(all(zcash_unstable = "nu7", feature = "zip-233"))]
            Zatoshis::ZERO,
            None,
            None,
            None,
            None,
        )
        .freeze()
        .unwrap();
        let exact = exact_immediate_transaction(&evidence, &empty_transaction).unwrap();
        let staging_token = ClaimToken::random(&mut OsRng);
        let staging_seal = crate::pool_migration::ValidatedImmediateTransaction {
            artifact_identity,
            proposal_digest: evidence.proposal_digest(),
            exact_digest: exact.digest(),
            destination_output_index: 0,
            ironwood_amount: Zatoshis::ZERO,
        };
        let state_before_blocked_staging = read_mutable_state(&conn);
        assert!(matches!(
            store::stage_immediate_transaction(
                &conn,
                &TABLES,
                crate::AccountRef(account_id),
                context,
                DeliveryRevision::INITIAL,
                run_identity,
                staging_token,
                &exact,
                policy.fingerprint(),
                &staging_seal,
            ),
            Err(Error::DeliveryRecoveryRequired)
        ));
        assert_eq!(read_mutable_state(&conn), state_before_blocked_staging);
        assert!(matches!(
            store::reacquire_immediate_external_signing(
                &conn,
                &TABLES,
                crate::AccountRef(account_id),
                context,
                DeliveryRevision::INITIAL,
                run_identity,
                artifact_identity,
                lease_duration,
                policy.fingerprint(),
            ),
            Err(Error::DeliveryRecoveryRequired)
        ));
        let unsigned_pczt_bytes = pczt::roles::creator::Creator::new(
            u32::from(proposal.branch_id()),
            u32::from(evidence.expiry_height()),
            133,
            None,
            None,
        )
        .unwrap()
        .build()
        .unwrap()
        .serialize()
        .unwrap();
        let unsigned_pczt = ExternalSigningPczt::parse(unsigned_pczt_bytes.clone()).unwrap();
        let signed_pczt = unsigned_pczt.merge_signed(unsigned_pczt_bytes).unwrap();
        let pczt_seal = crate::pool_migration::ValidatedImmediatePczt {
            artifact_identity,
            proposal_digest: evidence.proposal_digest(),
            pczt_digest: unsigned_pczt.digest(),
        };
        assert!(matches!(
            store::stage_immediate_external_signing_pczt(
                &conn,
                &TABLES,
                crate::AccountRef(account_id),
                context,
                DeliveryRevision::INITIAL,
                run_identity,
                artifact_identity,
                staging_token,
                &unsigned_pczt,
                policy.fingerprint(),
                &pczt_seal,
            ),
            Err(Error::DeliveryRecoveryRequired)
        ));
        assert!(matches!(
            store::stage_immediate_signed_pczt(
                &conn,
                &TABLES,
                crate::AccountRef(account_id),
                context,
                DeliveryRevision::INITIAL,
                run_identity,
                artifact_identity,
                staging_token,
                &signed_pczt,
                policy.fingerprint(),
            ),
            Err(Error::DeliveryRecoveryRequired)
        ));
        assert_eq!(read_mutable_state(&conn), state_before_blocked_staging);
        assert!(matches!(
            store::claim_immediate(
                &conn,
                &TABLES,
                crate::AccountRef(account_id),
                context,
                DeliveryRevision::INITIAL,
                run_identity,
                artifact_identity,
                lease_duration,
                policy.fingerprint(),
                ClaimKind::Submission,
            ),
            Err(Error::DeliveryRecoveryRequired)
        ));
        assert_eq!(read_mutable_state(&conn), state_before_blocked_staging);

        let materialization_lease =
            store::checked_delivery_lease(ClaimKind::Materialization, lease_duration).unwrap();
        conn.execute(
            "UPDATE zend_orchard_ironwood_immediate_delivery
                SET status = 'materializing', last_error = NULL,
                    claim_kind = 'materialization', attempt_token = ?,
                    lease_clock_session = ?, lease_acquired_at_ms = ?, lease_expires_at_ms = ?
              WHERE run_identity = ?",
            rusqlite::params![
                materialization_lease.token().as_bytes(),
                materialization_lease.acquired_at().session().as_bytes(),
                materialization_lease.acquired_at().tick_millis(),
                materialization_lease.expires_at().tick_millis(),
                run_identity.as_bytes(),
            ],
        )
        .unwrap();
        let materializing_state = read_mutable_state(&conn);
        assert!(matches!(
            store::resume_immediate_claim(
                &conn,
                &TABLES,
                crate::AccountRef(account_id),
                context,
                DeliveryRevision::INITIAL,
                run_identity,
                artifact_identity,
                materialization_lease.token(),
                policy.fingerprint(),
            ),
            Err(Error::DeliveryRecoveryRequired)
        ));
        assert!(matches!(
            store::renew_immediate_claim(
                &conn,
                &TABLES,
                crate::AccountRef(account_id),
                context,
                DeliveryRevision::INITIAL,
                run_identity,
                artifact_identity,
                materialization_lease.token(),
                lease_duration,
                policy.fingerprint(),
            ),
            Err(Error::DeliveryRecoveryRequired)
        ));
        assert_eq!(read_mutable_state(&conn), materializing_state);

        let released = store::release_immediate_claim_known_unsent(
            &conn,
            &TABLES,
            crate::AccountRef(account_id),
            context,
            DeliveryRevision::INITIAL,
            run_identity,
            artifact_identity,
            materialization_lease.token(),
            DeliveryFailureReason::MaterializationFailed,
            policy.fingerprint(),
        )
        .expect("known-unsent release remains operable without legacy spend authorization");
        assert_eq!(
            released.claims()[0].status(),
            ClaimStatus::MaterializationFailed
        );
        assert_eq!(released.immediate_maximum_gross_amount(), None);

        conn.execute_batch("SAVEPOINT blocked_submission_resume")
            .unwrap();
        let submission_lease =
            store::checked_delivery_lease(ClaimKind::Submission, lease_duration).unwrap();
        conn.execute(
            "UPDATE zend_orchard_ironwood_immediate_delivery
                SET status = 'submitting', last_error = NULL,
                    claim_kind = 'submission', attempt_token = ?, lease_clock_session = ?,
                    lease_acquired_at_ms = ?, lease_expires_at_ms = ?, txid = ?, exact_tx = ?,
                    exact_tx_digest = ?
              WHERE run_identity = ?",
            rusqlite::params![
                submission_lease.token().as_bytes(),
                submission_lease.acquired_at().session().as_bytes(),
                submission_lease.acquired_at().tick_millis(),
                submission_lease.expires_at().tick_millis(),
                exact.txid().as_ref(),
                exact.bytes(),
                exact.digest().as_bytes(),
                run_identity.as_bytes(),
            ],
        )
        .unwrap();
        let submission_state = read_mutable_state(&conn);
        let submission_revision = released.revision();
        assert!(matches!(
            store::resume_immediate_claim(
                &conn,
                &TABLES,
                crate::AccountRef(account_id),
                context,
                submission_revision,
                run_identity,
                artifact_identity,
                submission_lease.token(),
                policy.fingerprint(),
            ),
            Err(Error::DeliveryRecoveryRequired)
        ));
        assert!(matches!(
            store::renew_immediate_claim(
                &conn,
                &TABLES,
                crate::AccountRef(account_id),
                context,
                submission_revision,
                run_identity,
                artifact_identity,
                submission_lease.token(),
                lease_duration,
                policy.fingerprint(),
            ),
            Err(Error::DeliveryRecoveryRequired)
        ));
        assert_eq!(read_mutable_state(&conn), submission_state);
        conn.execute_batch(
            "ROLLBACK TO blocked_submission_resume; RELEASE blocked_submission_resume",
        )
        .unwrap();

        conn.execute_batch("SAVEPOINT allowed_known_unsent_outcome")
            .unwrap();
        conn.execute(
            "UPDATE zend_orchard_ironwood_immediate_delivery
                SET status = 'submitting', last_error = NULL,
                    claim_kind = 'submission', attempt_token = ?, lease_clock_session = ?,
                    lease_acquired_at_ms = ?, lease_expires_at_ms = ?,
                    txid = ?, exact_tx = ?, exact_tx_digest = ?
              WHERE run_identity = ?",
            rusqlite::params![
                submission_lease.token().as_bytes(),
                submission_lease.acquired_at().session().as_bytes(),
                submission_lease.acquired_at().tick_millis(),
                submission_lease.expires_at().tick_millis(),
                exact.txid().as_ref(),
                exact.bytes(),
                exact.digest().as_bytes(),
                run_identity.as_bytes(),
            ],
        )
        .unwrap();
        let known_unsent = store::record_immediate_submission_outcome(
            &conn,
            &TABLES,
            crate::AccountRef(account_id),
            context,
            submission_revision,
            run_identity,
            artifact_identity,
            submission_lease.token(),
            SubmissionOutcome::KnownUnsent,
            policy.fingerprint(),
        )
        .expect("known-unsent outcome remains operable without spend authorization");
        assert_eq!(known_unsent.claims()[0].status(), ClaimStatus::Staged);
        assert_eq!(
            known_unsent.revision(),
            submission_revision.checked_next().unwrap()
        );
        assert_eq!(
            known_unsent.claims()[0]
                .exact_transaction()
                .unwrap()
                .digest(),
            exact.digest()
        );
        conn.execute_batch(
            "ROLLBACK TO allowed_known_unsent_outcome; RELEASE allowed_known_unsent_outcome",
        )
        .unwrap();

        conn.execute_batch("SAVEPOINT allowed_outcome_resolution")
            .unwrap();
        conn.execute(
            "UPDATE zend_orchard_ironwood_immediate_delivery
                SET status = 'submitting', last_error = NULL,
                    claim_kind = 'submission', attempt_token = ?, lease_clock_session = ?,
                    lease_acquired_at_ms = ?, lease_expires_at_ms = ?,
                    txid = ?, exact_tx = ?, exact_tx_digest = ?
              WHERE run_identity = ?",
            rusqlite::params![
                submission_lease.token().as_bytes(),
                submission_lease.acquired_at().session().as_bytes(),
                submission_lease.acquired_at().tick_millis(),
                submission_lease.expires_at().tick_millis(),
                exact.txid().as_ref(),
                exact.bytes(),
                exact.digest().as_bytes(),
                run_identity.as_bytes(),
            ],
        )
        .unwrap();
        let unknown = store::record_immediate_submission_outcome(
            &conn,
            &TABLES,
            crate::AccountRef(account_id),
            context,
            submission_revision,
            run_identity,
            artifact_identity,
            submission_lease.token(),
            SubmissionOutcome::Unknown,
            policy.fingerprint(),
        )
        .expect("unknown outcome remains operable without spend authorization");
        assert_eq!(unknown.claims()[0].status(), ClaimStatus::OutcomeUnknown);
        assert_eq!(
            unknown.claims()[0].last_error(),
            Some(DeliveryFailureReason::TransportOutcomeUnknown)
        );
        assert_eq!(
            unknown.revision(),
            submission_revision.checked_next().unwrap()
        );
        let outcome = store::claim_immediate(
            &conn,
            &TABLES,
            crate::AccountRef(account_id),
            context,
            unknown.revision(),
            run_identity,
            artifact_identity,
            lease_duration,
            policy.fingerprint(),
            ClaimKind::OutcomeResolution,
        )
        .unwrap()
        .expect("outcome resolution remains operable without spend authorization");
        let outcome_claim = &outcome.claims()[0];
        let outcome_token = outcome_claim.token().unwrap();
        assert!(
            store::resume_immediate_claim(
                &conn,
                &TABLES,
                crate::AccountRef(account_id),
                context,
                outcome.revision(),
                run_identity,
                artifact_identity,
                outcome_token,
                policy.fingerprint(),
            )
            .unwrap()
            .is_some()
        );
        let renewed_outcome = store::renew_immediate_claim(
            &conn,
            &TABLES,
            crate::AccountRef(account_id),
            context,
            outcome.revision(),
            run_identity,
            artifact_identity,
            outcome_token,
            lease_duration,
            policy.fingerprint(),
        )
        .unwrap()
        .expect("outcome lease renewal remains operable");
        store::reconcile_immediate_submission(
            &conn,
            &TABLES,
            crate::AccountRef(account_id),
            context,
            renewed_outcome.revision(),
            run_identity,
            artifact_identity,
            outcome_token,
        )
        .expect("outcome reconciliation remains operable without spend authorization");
        conn.execute_batch(
            "ROLLBACK TO allowed_outcome_resolution; RELEASE allowed_outcome_resolution",
        )
        .unwrap();

        conn.execute_batch("SAVEPOINT allowed_abandonment").unwrap();
        let abandoning = store::begin_immediate_abandonment(
            &conn,
            &TABLES,
            crate::AccountRef(account_id),
            context,
            submission_revision,
            run_identity,
        )
        .expect("safe abandonment remains operable without spend authorization");
        let abandoned = store::finish_immediate_abandonment(
            &conn,
            &TABLES,
            crate::AccountRef(account_id),
            context,
            abandoning.revision(),
            run_identity,
        )
        .expect("unexposed abandonment can release reservations without spend authorization");
        assert!(abandoned.released_without_exposure());
        conn.execute_batch("ROLLBACK TO allowed_abandonment; RELEASE allowed_abandonment")
            .unwrap();

        conn.execute_batch("SAVEPOINT recovery_required_precedence")
            .unwrap();
        conn.execute(
            "UPDATE zend_orchard_ironwood_immediate_delivery
                SET storage_finality = 'recovery_required',
                    storage_recovery_reason = 'corrupt_finality_evidence'
              WHERE run_identity = ?",
            rusqlite::params![run_identity.as_bytes()],
        )
        .unwrap();
        conn.execute(
            "UPDATE zend_orchard_ironwood_delivery_runs SET status = 'recovery_required'
              WHERE run_identity = ?",
            rusqlite::params![run_identity.as_bytes()],
        )
        .unwrap();
        conn.execute(
            "UPDATE zend_orchard_ironwood_delivery_reservations
                SET status = 'recovery_required' WHERE run_identity = ?",
            rusqlite::params![run_identity.as_bytes()],
        )
        .unwrap();
        let (recovery_current, _) = store::load_immediate_delivery_runtime_parts(
            &conn,
            &TABLES,
            crate::AccountRef(account_id),
            context,
        )
        .unwrap();
        let recovery_snapshot = recovery_current.unwrap().0;
        assert_eq!(
            recovery_snapshot.storage_finality(),
            zcash_pool_migration::delivery::StorageFinality::RecoveryRequired(
                zcash_pool_migration::delivery::StorageRecoveryReason::CorruptFinalityEvidence,
            )
        );
        let recovery_runtime =
            zcash_pool_migration::delivery::MigrationRuntimeSnapshot::from_observed(
                None,
                Some(recovery_snapshot),
                vec![],
                zcash_pool_migration::delivery::DeliverySchemaProvenance::Compatible(
                    zcash_pool_migration::delivery::DeliverySchemaVersion::from_u32(2).unwrap(),
                ),
                zcash_pool_migration::delivery::LegacyCutoverStatus::Fresh,
                zcash_pool_migration::delivery::DestinationSpendability::NotSpendable,
            );
        assert_eq!(
            recovery_runtime.availability(),
            zcash_pool_migration::delivery::MigrationRuntimeAvailability::Unavailable(
                zcash_pool_migration::delivery::RuntimeUnavailableReason::FinalityRecovery(
                    zcash_pool_migration::delivery::StorageRecoveryReason::CorruptFinalityEvidence,
                )
            )
        );
        assert!(matches!(
            immediate_delivery_write(&conn, |transaction| {
                store::reacquire_failed_immediate_materialization(
                    transaction,
                    &TABLES,
                    crate::AccountRef(account_id),
                    context,
                    submission_revision,
                    run_identity,
                    artifact_identity,
                    SignerOwnership::Sdk,
                    Zatoshis::from_u64(TEST_GROSS_AMOUNT + 1).unwrap(),
                    lease_duration,
                    policy.fingerprint(),
                )
            }),
            Err(Error::DeliveryRecoveryRequired)
        ));
        conn.execute_batch(
            "ROLLBACK TO recovery_required_precedence; RELEASE recovery_required_precedence",
        )
        .unwrap();

        conn.execute(
            "UPDATE zend_orchard_ironwood_immediate_delivery SET revision = ?
             WHERE run_identity = ?",
            rusqlite::params![MAX_PERSISTED_DELIVERY_REVISION, run_identity.as_bytes()],
        )
        .unwrap();
        let exhausted_revision =
            DeliveryRevision::read(MAX_PERSISTED_DELIVERY_REVISION.to_le_bytes().as_slice())
                .unwrap();
        let before_exhausted_retry: RetryMutableState = conn
            .query_row(
                "SELECT revision, status, claim_kind, attempt_token
                   FROM zend_orchard_ironwood_immediate_delivery WHERE run_identity = ?",
                rusqlite::params![run_identity.as_bytes()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        let outer_transaction = conn.transaction().unwrap();
        let exhausted_retry = {
            let mut wallet = crate::WalletDb::from_connection(
                crate::SqlTransaction(&outer_transaction),
                params,
                crate::util::SystemClock,
                OsRng,
            );
            ImmediateMigrationDeliveryStore::reacquire_failed_immediate_materialization(
                &mut wallet,
                &account,
                exhausted_revision,
                run_identity,
                artifact_identity,
                SignerOwnership::Sdk,
                Zatoshis::from_u64(TEST_GROSS_AMOUNT).unwrap(),
                lease_duration,
                policy.fingerprint(),
            )
        };
        assert!(matches!(
            exhausted_retry,
            Err(Error::DeliveryRevisionMismatch)
        ));
        outer_transaction
            .commit()
            .expect("the caller may safely commit unrelated outer work after the inner failure");
        let after_exhausted_retry: RetryMutableState = conn
            .query_row(
                "SELECT revision, status, claim_kind, attempt_token
                   FROM zend_orchard_ironwood_immediate_delivery WHERE run_identity = ?",
                rusqlite::params![run_identity.as_bytes()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(
            after_exhausted_retry, before_exhausted_retry,
            "revision-bump failure must roll back the preceding claim update"
        );
        let authorizations_after_exhausted_retry: u64 = conn
            .query_row(
                "SELECT COUNT(*) FROM zend_orchard_ironwood_immediate_gross_authorization",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            authorizations_after_exhausted_retry, 0,
            "revision-bump failure must also roll back newly persisted spend authorization"
        );
        conn.execute(
            "UPDATE zend_orchard_ironwood_immediate_delivery SET revision = ?
             WHERE run_identity = ?",
            rusqlite::params![DeliveryRevision::INITIAL.as_u64(), run_identity.as_bytes()],
        )
        .unwrap();

        let retry_at_exact_gross_limit = ImmediateDeliveryWriteTransaction::begin(&conn).unwrap();
        let at_limit = store::reacquire_failed_immediate_materialization(
            &retry_at_exact_gross_limit,
            &TABLES,
            crate::AccountRef(account_id),
            context,
            DeliveryRevision::INITIAL,
            run_identity,
            artifact_identity,
            SignerOwnership::Sdk,
            Zatoshis::from_u64(TEST_GROSS_AMOUNT).unwrap(),
            lease_duration,
            policy.fingerprint(),
        )
        .expect("a proposal exactly at the current gross ceiling is retryable");
        assert_eq!(at_limit.claims()[0].status(), ClaimStatus::Materializing);
        drop(retry_at_exact_gross_limit);
        let authorizations_after_savepoint_rollback: u64 = conn
            .query_row(
                "SELECT COUNT(*) FROM zend_orchard_ironwood_immediate_gross_authorization",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(authorizations_after_savepoint_rollback, 0);

        let reacquired = immediate_delivery_write(&conn, |transaction| {
            store::reacquire_failed_immediate_materialization(
                transaction,
                &TABLES,
                crate::AccountRef(account_id),
                context,
                DeliveryRevision::INITIAL,
                run_identity,
                artifact_identity,
                SignerOwnership::Sdk,
                Zatoshis::from_u64(TEST_GROSS_AMOUNT + 1).unwrap(),
                lease_duration,
                policy.fingerprint(),
            )
        })
        .expect("a proposal below the current gross ceiling is retryable");
        let claim = reacquired.claims().first().expect("one immediate claim");
        assert_eq!(reacquired.run_identity(), run_identity);
        assert_eq!(
            claim.artifact_identity(),
            DeliveryArtifactIdentity::Immediate(artifact_identity)
        );
        assert_eq!(claim.signer_ownership(), SignerOwnership::Sdk);
        assert_eq!(claim.status(), ClaimStatus::Materializing);
        assert_eq!(claim.claim_kind(), Some(ClaimKind::Materialization));
        assert!(claim.token().is_some());
        assert!(!claim.has_exposure_history());
        assert!(claim.external_signing_pczt().is_none());
        assert!(claim.signed_pczt().is_none());
        assert!(claim.exact_transaction().is_none());
        assert!(claim.txid().is_none());
        assert_eq!(claim.last_error(), None);
        assert_eq!(
            reacquired.revision(),
            DeliveryRevision::INITIAL.checked_next().unwrap()
        );
        assert_eq!(
            reacquired.immediate_maximum_gross_amount(),
            Some(Zatoshis::from_u64(TEST_GROSS_AMOUNT + 1).unwrap())
        );
        conn.execute_batch("SAVEPOINT stage_after_v1_upgrade")
            .unwrap();
        let staged_after_upgrade = store::stage_immediate_transaction(
            &conn,
            &TABLES,
            crate::AccountRef(account_id),
            context,
            reacquired.revision(),
            run_identity,
            claim.token().unwrap(),
            &exact,
            policy.fingerprint(),
            &staging_seal,
        )
        .expect("v2 active exact-evidence schema accepts a staged transaction after upgrade");
        assert_eq!(
            staged_after_upgrade.claims()[0].status(),
            ClaimStatus::Staged
        );
        conn.execute(
            "UPDATE zend_orchard_ironwood_immediate_delivery
                SET destination_output_index = NULL, expected_ironwood_amount = NULL
              WHERE run_identity = ?",
            rusqlite::params![run_identity.as_bytes()],
        )
        .unwrap();
        let (quarantined_current, _) = store::load_immediate_delivery_runtime_parts(
            &conn,
            &TABLES,
            crate::AccountRef(account_id),
            context,
        )
        .expect("legacy exact evidence without its destination tuple is quarantined");
        assert!(matches!(
            quarantined_current.unwrap().0.storage_finality(),
            zcash_pool_migration::delivery::StorageFinality::RecoveryRequired(
                zcash_pool_migration::delivery::StorageRecoveryReason::CorruptFinalityEvidence
            )
        ));
        type RecoveryMutableState = (
            u64,
            String,
            Option<String>,
            String,
            String,
            String,
            Option<Vec<u8>>,
            Option<u64>,
        );
        let recovery_state_after_first_load: RecoveryMutableState = conn
            .query_row(
                "SELECT immediate.revision, immediate.storage_finality,
                        immediate.storage_recovery_reason, immediate.status, runs.status,
                        reservations.status, immediate.attempt_token,
                        immediate.observed_mined_height
                   FROM zend_orchard_ironwood_immediate_delivery immediate
                   JOIN zend_orchard_ironwood_delivery_runs runs
                     ON runs.run_identity = immediate.run_identity
                   JOIN zend_orchard_ironwood_delivery_reservations reservations
                     ON reservations.run_identity = immediate.run_identity
                  WHERE immediate.run_identity = ?",
                rusqlite::params![run_identity.as_bytes()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                    ))
                },
            )
            .unwrap();
        let (quarantined_again, _) = store::load_immediate_delivery_runtime_parts(
            &conn,
            &TABLES,
            crate::AccountRef(account_id),
            context,
        )
        .expect("recovery authority is absorbing on repeated load");
        assert!(matches!(
            quarantined_again.unwrap().0.storage_finality(),
            zcash_pool_migration::delivery::StorageFinality::RecoveryRequired(
                zcash_pool_migration::delivery::StorageRecoveryReason::CorruptFinalityEvidence
            )
        ));
        let recovery_state_after_second_load: RecoveryMutableState = conn
            .query_row(
                "SELECT immediate.revision, immediate.storage_finality,
                        immediate.storage_recovery_reason, immediate.status, runs.status,
                        reservations.status, immediate.attempt_token,
                        immediate.observed_mined_height
                   FROM zend_orchard_ironwood_immediate_delivery immediate
                   JOIN zend_orchard_ironwood_delivery_runs runs
                     ON runs.run_identity = immediate.run_identity
                   JOIN zend_orchard_ironwood_delivery_reservations reservations
                     ON reservations.run_identity = immediate.run_identity
                  WHERE immediate.run_identity = ?",
                rusqlite::params![run_identity.as_bytes()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(
            recovery_state_after_second_load, recovery_state_after_first_load,
            "recovery rows must not receive later lease, mining, expiry, or revision mutations",
        );
        conn.execute_batch("ROLLBACK TO stage_after_v1_upgrade; RELEASE stage_after_v1_upgrade")
            .unwrap();

        let resolved_unmined_release = u32::from(evidence.expiry_height()) + 100;
        conn.execute_batch("SAVEPOINT external_signing_terminal_reload")
            .unwrap();
        conn.execute(
            "UPDATE accounts SET birthday_height = 1 WHERE id = ?",
            rusqlite::params![account_id],
        )
        .unwrap();
        conn.execute(
            "UPDATE scan_queue SET block_range_start = 0, block_range_end = ?, priority = 10",
            rusqlite::params![resolved_unmined_release + 1],
        )
        .unwrap();
        conn.execute(
            "UPDATE transactions SET block = 1, mined_height = 1 WHERE txid = ?",
            rusqlite::params![source.txid().as_ref()],
        )
        .unwrap();
        conn.execute(
            "UPDATE orchard_received_notes SET nf = ?
              WHERE transaction_id = (SELECT id_tx FROM transactions WHERE txid = ?)
                AND action_index = ?",
            rusqlite::params![[0xE1u8; 32], source.txid().as_ref(), source.output_index(),],
        )
        .unwrap();
        conn.execute(
            "UPDATE zend_orchard_ironwood_immediate_delivery
                SET phase = 'active', signer_ownership = 'external',
                    status = 'awaiting_external_signature', claim_kind = NULL,
                    attempt_token = NULL, lease_clock_session = NULL,
                    lease_acquired_at_ms = NULL, lease_expires_at_ms = NULL,
                    txid = NULL, exact_tx = NULL, exact_tx_digest = NULL,
                    unsigned_pczt_digest = ?, canonical_unsigned_pczt = ?,
                    signed_pczt_digest = NULL, canonical_signed_pczt = NULL,
                    signed_pczt_binding = NULL, last_error = NULL,
                    storage_finality = 'active', storage_recovery_reason = NULL,
                    observed_mined_height = NULL, destination_output_index = NULL,
                    expected_ironwood_amount = NULL, release_at_height = NULL,
                    finalized_tip_height = NULL
              WHERE run_identity = ?",
            rusqlite::params![
                unsigned_pczt.digest().as_bytes(),
                unsigned_pczt.bytes(),
                run_identity.as_bytes(),
            ],
        )
        .unwrap();
        let (expired_current, _) = store::load_immediate_delivery_runtime_parts(
            &conn,
            &TABLES,
            crate::AccountRef(account_id),
            context,
        )
        .unwrap();
        let expired_external = expired_current.unwrap().0;
        assert_eq!(
            expired_external.claims()[0].status(),
            ClaimStatus::ExternalSigningExpiredUnmined
        );
        let abandoning_external = store::begin_immediate_abandonment(
            &conn,
            &TABLES,
            crate::AccountRef(account_id),
            context,
            expired_external.revision(),
            run_identity,
        )
        .unwrap();
        store::finish_immediate_abandonment(
            &conn,
            &TABLES,
            crate::AccountRef(account_id),
            context,
            abandoning_external.revision(),
            run_identity,
        )
        .unwrap();
        let (finalized_current, finalized_retained) = store::load_immediate_delivery_runtime_parts(
            &conn,
            &TABLES,
            crate::AccountRef(account_id),
            context,
        )
        .unwrap();
        assert!(finalized_current.is_none());
        assert_eq!(finalized_retained.len(), 1);
        assert!(matches!(
            finalized_retained[0].delivery().storage_finality(),
            zcash_pool_migration::delivery::StorageFinality::Finalized(_)
        ));
        conn.execute(
            "UPDATE scan_queue SET block_range_end = ?",
            rusqlite::params![resolved_unmined_release],
        )
        .unwrap();
        let (rewound_current, _) = store::load_immediate_delivery_runtime_parts(
            &conn,
            &TABLES,
            crate::AccountRef(account_id),
            context,
        )
        .unwrap();
        assert!(matches!(
            rewound_current.unwrap().0.storage_finality(),
            zcash_pool_migration::delivery::StorageFinality::RecoveryRequired(
                zcash_pool_migration::delivery::StorageRecoveryReason::RewoundBeyondFinalityHorizon
            )
        ));
        conn.execute_batch(
            "ROLLBACK TO external_signing_terminal_reload;
             RELEASE external_signing_terminal_reload",
        )
        .unwrap();

        conn.execute_batch("SAVEPOINT external_staged_terminal_reload")
            .unwrap();
        conn.execute(
            "UPDATE accounts SET birthday_height = 1 WHERE id = ?",
            rusqlite::params![account_id],
        )
        .unwrap();
        conn.execute(
            "UPDATE scan_queue SET block_range_start = 0, block_range_end = ?, priority = 10",
            rusqlite::params![resolved_unmined_release + 1],
        )
        .unwrap();
        conn.execute(
            "UPDATE transactions SET block = 1, mined_height = 1 WHERE txid = ?",
            rusqlite::params![source.txid().as_ref()],
        )
        .unwrap();
        conn.execute(
            "UPDATE orchard_received_notes SET nf = ?
              WHERE transaction_id = (SELECT id_tx FROM transactions WHERE txid = ?)
                AND action_index = ?",
            rusqlite::params![[0xE2u8; 32], source.txid().as_ref(), source.output_index(),],
        )
        .unwrap();
        conn.execute(
            "UPDATE zend_orchard_ironwood_immediate_delivery
                SET phase = 'active', signer_ownership = 'external', status = 'staged',
                    claim_kind = NULL, attempt_token = NULL, lease_clock_session = NULL,
                    lease_acquired_at_ms = NULL, lease_expires_at_ms = NULL,
                    txid = ?, exact_tx = ?, exact_tx_digest = ?,
                    unsigned_pczt_digest = ?, canonical_unsigned_pczt = ?,
                    signed_pczt_digest = ?, canonical_signed_pczt = ?,
                    signed_pczt_binding = ?, last_error = NULL,
                    storage_finality = 'active', storage_recovery_reason = NULL,
                    observed_mined_height = NULL, destination_output_index = 0,
                    expected_ironwood_amount = 0, release_at_height = NULL,
                    finalized_tip_height = NULL
              WHERE run_identity = ?",
            rusqlite::params![
                exact.txid().as_ref(),
                exact.bytes(),
                exact.digest().as_bytes(),
                unsigned_pczt.digest().as_bytes(),
                unsigned_pczt.bytes(),
                signed_pczt.signed_digest().as_bytes(),
                signed_pczt.bytes(),
                signed_pczt.staged_digest().as_bytes(),
                run_identity.as_bytes(),
            ],
        )
        .unwrap();
        let (staged_expired_current, _) = store::load_immediate_delivery_runtime_parts(
            &conn,
            &TABLES,
            crate::AccountRef(account_id),
            context,
        )
        .unwrap();
        let staged_expired = staged_expired_current.unwrap().0;
        assert_eq!(
            staged_expired.claims()[0].status(),
            ClaimStatus::ExpiredUnmined
        );
        let staged_abandoning = store::begin_immediate_abandonment(
            &conn,
            &TABLES,
            crate::AccountRef(account_id),
            context,
            staged_expired.revision(),
            run_identity,
        )
        .unwrap();
        store::finish_immediate_abandonment(
            &conn,
            &TABLES,
            crate::AccountRef(account_id),
            context,
            staged_abandoning.revision(),
            run_identity,
        )
        .unwrap();
        let (staged_finalized_current, staged_finalized_retained) =
            store::load_immediate_delivery_runtime_parts(
                &conn,
                &TABLES,
                crate::AccountRef(account_id),
                context,
            )
            .unwrap();
        assert!(staged_finalized_current.is_none());
        assert_eq!(staged_finalized_retained.len(), 1);
        assert!(matches!(
            staged_finalized_retained[0].delivery().storage_finality(),
            zcash_pool_migration::delivery::StorageFinality::Finalized(_)
        ));
        conn.execute_batch(
            "ROLLBACK TO external_staged_terminal_reload;
             RELEASE external_staged_terminal_reload",
        )
        .unwrap();
        let stored_authorization: (u32, u64) = conn
            .query_row(
                "SELECT authorization_version, maximum_gross_amount
                   FROM zend_orchard_ironwood_immediate_gross_authorization
                  WHERE run_identity = ?",
                rusqlite::params![run_identity.as_bytes()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(stored_authorization, (1, TEST_GROSS_AMOUNT + 1));
        assert_eq!(
            output_lock(&conn, &source),
            lock_before_upgrade,
            "v1 reauthorization must preserve the exact wallet lock"
        );
        let stable_after: StableImmediateAuthority = conn
            .query_row(
                "SELECT artifact_identity, proposal_fingerprint, canonical_proposal,
                        signer_ownership, policy, policy_fingerprint
                   FROM zend_orchard_ironwood_immediate_delivery WHERE run_identity = ?",
                rusqlite::params![run_identity.as_bytes()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(stable_after, stable_before);
        assert!(
            immediate_delivery_write(&conn, |transaction| {
                store::reacquire_failed_immediate_materialization(
                    transaction,
                    &TABLES,
                    crate::AccountRef(account_id),
                    context,
                    DeliveryRevision::INITIAL,
                    run_identity,
                    artifact_identity,
                    SignerOwnership::Sdk,
                    Zatoshis::from_u64(TEST_GROSS_AMOUNT + 1).unwrap(),
                    lease_duration,
                    policy.fingerprint(),
                )
            })
            .is_err(),
            "a stale handle cannot mint a second claim",
        );
        assert!(matches!(
            store::delivery_schema_provenance(&conn, &TABLES).unwrap(),
            zcash_pool_migration::delivery::DeliverySchemaProvenance::Compatible(_)
        ));
        conn.execute(
            "UPDATE zend_orchard_ironwood_immediate_gross_authorization
                SET maximum_gross_amount = ? WHERE run_identity = ?",
            rusqlite::params![TEST_GROSS_AMOUNT - 1, run_identity.as_bytes()],
        )
        .unwrap();
        assert_eq!(
            store::delivery_schema_provenance(&conn, &TABLES).unwrap(),
            zcash_pool_migration::delivery::DeliverySchemaProvenance::Corrupt,
            "provenance must reject a persisted ceiling below the canonical proposal gross",
        );
    }

    #[cfg(feature = "migration-delivery")]
    #[test]
    fn immediate_gross_limit_rejects_before_any_authority_or_lock_write() {
        use prost::Message;
        use rand::rngs::OsRng;
        use zcash_client_backend::{
            proto::proposal::{self, proposed_input},
            wallet::LockOwner,
        };
        use zcash_pool_migration::delivery::{
            ClaimKind, ClaimToken, DeliveryLease, ImmediateArtifactEvidence,
            ImmediateArtifactIdentity, ImmediateProposal, ImmediateProposalPayload,
            LeaseClockSession, LeaseDuration, LoopbackDevelopmentEndpoint, MigrationRunIdentity,
            MonotonicLeaseInstant, SignerOwnership, SourceReservationOwner, SubmissionContext,
            SubmissionPolicy, SubmissionPolicyRequest, SubmissionTransport,
        };
        use zcash_primitives::transaction::builder::DEFAULT_TX_EXPIRY_DELTA;
        use zcash_protocol::{
            PoolType, ShieldedPool,
            consensus::{BlockHeight, BranchId},
            value::Zatoshis,
        };

        /// Gross Orchard input represented by the canonical one-step proposal.
        const TEST_GROSS_AMOUNT: u64 = 50_000;
        /// Stable test target at which the regtest network has an active branch.
        const TEST_TARGET_HEIGHT: u32 = 120;
        /// Bounded materialization lease used only to prove no capability row is written.
        const TEST_LEASE_MILLIS: u64 = 5_000;
        /// Start of the synthetic test clock session.
        const TEST_LEASE_START_MILLIS: u64 = 0;
        /// Distinct test-only identifier byte for the lockable source transaction.
        const TEST_SOURCE_TXID_BYTE: u8 = 0x54;
        /// Distinct test-only identifier byte for the canonical migration lock owner.
        const TEST_LOCK_OWNER_BYTE: u8 = 0x55;
        /// Byte width of a canonical lock-owner identifier.
        const TEST_LOCK_OWNER_LENGTH: usize = 32;

        let conn = fresh_conn();
        conn.pragma_update(None, "foreign_keys", true).unwrap();
        init_delivery_control_tables(&conn).expect("delivery schema");
        let account = insert_account(&conn);
        let account_id: i64 = conn
            .query_row(
                "SELECT id FROM accounts WHERE uuid = ?",
                rusqlite::params![account.expose_uuid()],
                |row| row.get(0),
            )
            .unwrap();
        let source = insert_lockable_output(&conn, account, TEST_SOURCE_TXID_BYTE);
        let payload = proposal::Proposal {
            steps: vec![proposal::ProposalStep {
                inputs: vec![proposal::ProposedInput {
                    value: Some(proposed_input::Value::ReceivedOutput(
                        proposal::ReceivedOutput {
                            txid: source.txid().as_ref().to_vec(),
                            value_pool: proposal::ValuePool::Orchard.into(),
                            index: source.output_index(),
                            value: TEST_GROSS_AMOUNT,
                        },
                    )),
                }],
                ..Default::default()
            }],
            ..Default::default()
        }
        .encode_to_vec();
        let params = zcash_pool_migration_memory::regtest_network(true);
        let context = SubmissionContext::from_parameters(&params);
        let target_height = BlockHeight::from_u32(TEST_TARGET_HEIGHT);
        let proposal = ImmediateProposal::new(
            target_height,
            BlockHeight::from_u32(TEST_TARGET_HEIGHT + DEFAULT_TX_EXPIRY_DELTA),
            BranchId::for_height(&params, target_height),
            ImmediateProposalPayload::try_from(payload).unwrap(),
        )
        .expect("one-step Orchard proposal envelope");
        let artifact_identity = ImmediateArtifactIdentity::random(&mut OsRng);
        let evidence = ImmediateArtifactEvidence::from_proposal(artifact_identity, &proposal);
        let run_identity = MigrationRunIdentity::random(&mut OsRng);
        let source_owner = SourceReservationOwner::random(&mut OsRng);
        let lock_owner = LockOwner::new([TEST_LOCK_OWNER_BYTE; TEST_LOCK_OWNER_LENGTH]);
        let transport = SubmissionTransport::LoopbackDevelopment(
            LoopbackDevelopmentEndpoint::try_from("http://127.0.0.1:9067".to_owned()).unwrap(),
        );
        let policy =
            SubmissionPolicy::validate(SubmissionPolicyRequest::new(context, transport), context)
                .expect("test policy");
        let lease = DeliveryLease::new(
            ClaimKind::Materialization,
            ClaimToken::random(&mut OsRng),
            MonotonicLeaseInstant::new(
                LeaseClockSession::random(&mut OsRng),
                TEST_LEASE_START_MILLIS,
            ),
            LeaseDuration::from_millis(TEST_LEASE_MILLIS).unwrap(),
        )
        .unwrap();
        let maximum_gross_amount = Zatoshis::from_u64(TEST_GROSS_AMOUNT - 1).unwrap();

        let error = immediate_delivery_write(&conn, |transaction| {
            store::reserve_immediate_delivery(
                transaction,
                &TABLES,
                crate::AccountRef(account_id),
                &proposal,
                &evidence,
                &[source],
                run_identity,
                source_owner,
                lock_owner,
                SignerOwnership::Sdk,
                lease,
                &policy,
                context,
                maximum_gross_amount,
            )
        })
        .expect_err("proposal above the user's gross ceiling must fail");
        assert!(matches!(error, Error::ImmediateAmountLimitExceeded));
        for table in [
            "zend_orchard_ironwood_delivery_runs",
            "zend_orchard_ironwood_immediate_delivery",
            "zend_orchard_ironwood_immediate_gross_authorization",
            "zend_orchard_ironwood_delivery_reservations",
        ] {
            let rows: u64 = conn
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(rows, 0, "{table} retained rejected authority");
        }
        assert_eq!(
            output_lock(&conn, &source),
            (None, None),
            "gross-limit rejection must not lock the Orchard source"
        );
        assert_eq!(source.pool(), PoolType::Shielded(ShieldedPool::Orchard));
    }

    #[cfg(feature = "migration-delivery")]
    #[test]
    fn public_immediate_reservation_rolls_back_auth_on_late_reservation_failure() {
        use zcash_client_backend::data_api::Account as _;
        use zcash_client_backend::data_api::testing::{
            AddressType, TestBuilder, orchard::OrchardPoolTester, pool::ShieldedPoolTester,
        };
        use zcash_pool_migration::delivery::{
            ImmediateMigrationDeliveryStore, ImmediateMigrationIntent, LeaseDuration,
            LoopbackDevelopmentEndpoint, SignerOwnership, SubmissionContext, SubmissionPolicy,
            SubmissionPolicyRequest, SubmissionTransport,
        };
        use zcash_primitives::block::BlockHash;
        use zcash_protocol::{
            consensus::BlockHeight, local_consensus::LocalNetwork, value::Zatoshis,
        };

        use crate::testing::{BlockCache, db::TestDbFactory};

        let activation = BlockHeight::from_u32(100_000);
        let ironwood_active_network = LocalNetwork {
            nu6: Some(activation),
            nu6_1: Some(activation),
            nu6_2: Some(activation),
            nu6_3: Some(activation),
            ..TestBuilder::<(), ()>::DEFAULT_NETWORK
        };
        let mut state = TestBuilder::new()
            .with_network(ironwood_active_network)
            .with_block_cache(BlockCache::new())
            .with_data_store_factory(TestDbFactory::default())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();
        let fvk = OrchardPoolTester::test_account_fvk(&state);
        let value = Zatoshis::const_from_u64(1_000_000);
        let (height, _, _) = state.generate_next_block(&fvk, AddressType::DefaultExternal, value);
        state.scan_cached_blocks(height, 1);
        for _ in 0..9 {
            let (height, _) = state.generate_empty_block();
            state.scan_cached_blocks(height, 1);
        }
        let account = state.test_account().unwrap().id();
        let context = SubmissionContext::from_parameters(state.network());
        let policy = SubmissionPolicy::validate(
            SubmissionPolicyRequest::new(
                context,
                SubmissionTransport::LoopbackDevelopment(
                    LoopbackDevelopmentEndpoint::try_from("http://127.0.0.1:9067".to_owned())
                        .unwrap(),
                ),
            ),
            context,
        )
        .unwrap();
        let lock_before: (Option<u32>, Option<Vec<u8>>) = state
            .wallet()
            .conn()
            .query_row(
                "SELECT lock_expiry_height, lock_owner FROM orchard_received_notes LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        state
            .wallet()
            .conn()
            .execute_batch(
                "CREATE TEMP TRIGGER fail_immediate_reservation_insert
                 BEFORE INSERT ON zend_orchard_ironwood_delivery_reservations
                 BEGIN
                     SELECT RAISE(ABORT, 'injected late reservation failure');
                 END;",
            )
            .unwrap();

        let result = ImmediateMigrationDeliveryStore::reserve_immediate_delivery(
            state.wallet_mut().db_mut(),
            ImmediateMigrationIntent::new(account, SignerOwnership::Sdk, value),
            &policy,
            LeaseDuration::from_millis(5_000).unwrap(),
        );
        let error = match result {
            Ok(_) => panic!("the injected late reservation failure must abort the reservation"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("injected late reservation failure"),
            "the test must reach the injected post-authorization reservation failure: {error}",
        );
        for table in [
            "zend_orchard_ironwood_delivery_runs",
            "zend_orchard_ironwood_immediate_delivery",
            "zend_orchard_ironwood_immediate_gross_authorization",
            "zend_orchard_ironwood_delivery_reservations",
        ] {
            let rows: u64 = state
                .wallet()
                .conn()
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(rows, 0, "{table} leaked a partial reservation write");
        }
        let lock_after: (Option<u32>, Option<Vec<u8>>) = state
            .wallet()
            .conn()
            .query_row(
                "SELECT lock_expiry_height, lock_owner FROM orchard_received_notes LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(lock_after, lock_before);
    }

    #[cfg(feature = "migration-delivery")]
    #[test]
    fn public_immediate_reservation_commits_auth_and_reloads_available() {
        use zcash_client_backend::data_api::Account as _;
        use zcash_client_backend::data_api::testing::{
            AddressType, TestBuilder, orchard::OrchardPoolTester, pool::ShieldedPoolTester,
        };
        use zcash_pool_migration::delivery::{
            ImmediateMigrationDeliveryStore, ImmediateMigrationIntent, LeaseDuration,
            LoopbackDevelopmentEndpoint, MigrationRuntimeAvailability, ReservedImmediateArtifact,
            SignerOwnership, SubmissionContext, SubmissionPolicy, SubmissionPolicyRequest,
            SubmissionTransport,
        };
        use zcash_primitives::block::BlockHash;
        use zcash_protocol::{
            consensus::BlockHeight, local_consensus::LocalNetwork, value::Zatoshis,
        };

        use crate::testing::{BlockCache, db::TestDbFactory};

        let activation = BlockHeight::from_u32(100_000);
        let ironwood_active_network = LocalNetwork {
            nu6: Some(activation),
            nu6_1: Some(activation),
            nu6_2: Some(activation),
            nu6_3: Some(activation),
            ..TestBuilder::<(), ()>::DEFAULT_NETWORK
        };
        let mut state = TestBuilder::new()
            .with_network(ironwood_active_network)
            .with_block_cache(BlockCache::new())
            .with_data_store_factory(TestDbFactory::default())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();
        let fvk = OrchardPoolTester::test_account_fvk(&state);
        let maximum_gross_amount = Zatoshis::const_from_u64(1_000_000);
        let (height, _, _) =
            state.generate_next_block(&fvk, AddressType::DefaultExternal, maximum_gross_amount);
        state.scan_cached_blocks(height, 1);
        for _ in 0..9 {
            let (height, _) = state.generate_empty_block();
            state.scan_cached_blocks(height, 1);
        }
        let account = state.test_account().unwrap().id();
        let context = SubmissionContext::from_parameters(state.network());
        let policy = SubmissionPolicy::validate(
            SubmissionPolicyRequest::new(
                context,
                SubmissionTransport::LoopbackDevelopment(
                    LoopbackDevelopmentEndpoint::try_from("http://127.0.0.1:9067".to_owned())
                        .unwrap(),
                ),
            ),
            context,
        )
        .unwrap();

        let reserved = ImmediateMigrationDeliveryStore::reserve_immediate_delivery(
            state.wallet_mut().db_mut(),
            ImmediateMigrationIntent::new(account, SignerOwnership::Sdk, maximum_gross_amount),
            &policy,
            LeaseDuration::from_millis(5_000).unwrap(),
        )
        .expect("fresh immediate reservation commits");
        assert_eq!(
            reserved.snapshot().immediate_maximum_gross_amount(),
            Some(maximum_gross_amount)
        );
        let run_identity = reserved.snapshot().run_identity();
        drop(reserved);

        let stored_authorization: (u32, u64) = state
            .wallet()
            .conn()
            .query_row(
                "SELECT authorization_version, maximum_gross_amount
                   FROM zend_orchard_ironwood_immediate_gross_authorization
                  WHERE run_identity = ?",
                rusqlite::params![run_identity.as_bytes()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(stored_authorization, (1, maximum_gross_amount.into_u64()));
        let runtime = ImmediateMigrationDeliveryStore::immediate_runtime_snapshot(
            state.wallet_mut().db_mut(),
            &account,
        )
        .expect("committed immediate runtime reloads");
        assert_eq!(
            runtime.availability(),
            MigrationRuntimeAvailability::Available
        );
        assert_eq!(
            runtime.delivery().unwrap().immediate_maximum_gross_amount(),
            Some(maximum_gross_amount)
        );
    }

    #[cfg(feature = "migration-delivery")]
    #[test]
    fn delivery_leases_fail_closed_and_tokens_are_rust_generated() {
        use zcash_pool_migration::delivery::{
            ClaimKind, ClaimToken, DeliveryLease, LeaseClockSession, LeaseDuration,
            MonotonicLeaseInstant,
        };

        assert!(LeaseDuration::from_millis(0).is_none());
        assert!(LeaseDuration::from_millis(LeaseDuration::MAX_MILLIS + 1).is_none());
        let duration = LeaseDuration::from_millis(5).unwrap();
        let now = MonotonicLeaseInstant::new(LeaseClockSession::random(&mut rand::rngs::OsRng), 0);
        let first = DeliveryLease::new(
            ClaimKind::Submission,
            ClaimToken::random(&mut rand::rngs::OsRng),
            now,
            duration,
        )
        .unwrap();
        let second = DeliveryLease::new(
            ClaimKind::Submission,
            ClaimToken::random(&mut rand::rngs::OsRng),
            now,
            duration,
        )
        .unwrap();
        assert_ne!(first.token(), second.token());
    }

    #[cfg(feature = "migration-delivery")]
    #[test]
    fn legacy_detector_blocks_partial_schemas_but_ignores_prefix_near_misses() {
        use zcash_pool_migration::delivery::{LegacyCutoverStatus, MigrationDeliveryStore};

        let mut conn = fresh_conn();
        conn.execute("CREATE TABLE extXironwood_migration_runs (id INTEGER)", [])
            .unwrap();
        conn.execute("CREATE TABLE ironwoodXmigration_runs (id INTEGER)", [])
            .unwrap();
        conn.execute("CREATE TABLE EXT_ironwood_migration_runs (id INTEGER)", [])
            .unwrap();
        conn.execute(
            "CREATE TABLE prefix_ext_ironwood_migration_runs (id INTEGER)",
            [],
        )
        .unwrap();
        init_delivery_control_tables(&conn).unwrap();
        let account = insert_account(&conn);
        let store = PoolMigrations::for_account(&mut conn, account).unwrap();
        assert_eq!(
            store.legacy_cutover_status().unwrap(),
            LegacyCutoverStatus::Fresh
        );
        conn.execute(
            "CREATE TABLE ext_ironwood_migration_future (opaque BLOB)",
            [],
        )
        .unwrap();
        let store = PoolMigrations::for_account(&mut conn, account).unwrap();
        assert!(matches!(
            store.legacy_cutover_status().unwrap(),
            LegacyCutoverStatus::RecoveryRequired(_)
        ));

        let mut older = fresh_conn();
        init_delivery_control_tables(&older).unwrap();
        let older_account = insert_account(&older);
        older
            .execute("CREATE TABLE ironwood_migration_runs (id INTEGER)", [])
            .unwrap();
        let older_store = PoolMigrations::for_account(&mut older, older_account).unwrap();
        assert!(matches!(
            older_store.legacy_cutover_status().unwrap(),
            LegacyCutoverStatus::RecoveryRequired(_)
        ));
    }

    #[cfg(feature = "migration-delivery")]
    #[test]
    fn delivery_provenance_rejects_partial_fake_future_and_fk_corruption() {
        use zcash_pool_migration::delivery::{
            DeliverySchemaProvenance, DeliverySchemaVersion, MigrationDeliveryStore,
        };

        let provenance = |conn: &mut Connection, account| {
            PoolMigrations::for_account(conn, account)
                .unwrap()
                .delivery_schema_provenance()
                .unwrap()
        };

        let mut partial = fresh_conn();
        partial.pragma_update(None, "foreign_keys", true).unwrap();
        init_delivery_control_tables(&partial).unwrap();
        let partial_account = insert_account(&partial);
        partial
            .execute("DROP TABLE zend_orchard_ironwood_immediate_delivery", [])
            .unwrap();
        assert_eq!(
            provenance(&mut partial, partial_account),
            DeliverySchemaProvenance::Corrupt
        );

        let mut fake = fresh_conn();
        fake.pragma_update(None, "foreign_keys", true).unwrap();
        init_delivery_control_tables(&fake).unwrap();
        let fake_account = insert_account(&fake);
        fake.execute("DROP TABLE zend_orchard_ironwood_immediate_delivery", [])
            .unwrap();
        fake.execute_batch(
            "CREATE TABLE zend_orchard_ironwood_immediate_delivery (
                 run_identity BLOB PRIMARY KEY,
                 proposal_fingerprint BLOB,
                 status TEXT
             );",
        )
        .unwrap();
        assert_eq!(
            provenance(&mut fake, fake_account),
            DeliverySchemaProvenance::Corrupt
        );

        let mut future = fresh_conn();
        future.pragma_update(None, "foreign_keys", true).unwrap();
        init_delivery_control_tables(&future).unwrap();
        let future_account = insert_account(&future);
        future
            .execute(
                "UPDATE zend_orchard_ironwood_delivery_meta SET schema_version = 3",
                [],
            )
            .unwrap();
        assert_eq!(
            provenance(&mut future, future_account),
            DeliverySchemaProvenance::Future(DeliverySchemaVersion::from_u32(3).unwrap())
        );

        let mut fk = fresh_conn();
        init_delivery_control_tables(&fk).unwrap();
        let fk_account = insert_account(&fk);
        fk.pragma_update(None, "foreign_keys", false).unwrap();
        fk.execute(
            "INSERT INTO zend_orchard_ironwood_delivery_reservations (
                 run_identity, source_txid, source_index, status
             ) VALUES (?, ?, 0, 'active')",
            rusqlite::params![[0xF1u8; 32], [0xF2u8; 32]],
        )
        .unwrap();
        fk.pragma_update(None, "foreign_keys", true).unwrap();
        assert_eq!(
            provenance(&mut fk, fk_account),
            DeliverySchemaProvenance::Corrupt
        );

        let mut missing_lock_prerequisite = fresh_conn();
        missing_lock_prerequisite
            .pragma_update(None, "foreign_keys", true)
            .unwrap();
        init_delivery_control_tables(&missing_lock_prerequisite).unwrap();
        let missing_lock_account = insert_account(&missing_lock_prerequisite);
        missing_lock_prerequisite
            .execute_batch(
                "DROP TABLE transparent_received_outputs;
                 CREATE TABLE transparent_received_outputs (
                     id INTEGER PRIMARY KEY,
                     transaction_id INTEGER NOT NULL,
                     account_id INTEGER NOT NULL,
                     lock_expiry_height INTEGER
                 );",
            )
            .unwrap();
        assert_eq!(
            provenance(&mut missing_lock_prerequisite, missing_lock_account),
            DeliverySchemaProvenance::Corrupt,
            "delivery DDL without every note-locking column is not a compatible runtime schema",
        );
    }

    #[cfg(feature = "migration-delivery")]
    #[test]
    fn gross_authorization_upgrade_failure_rolls_back_table_and_provenance() {
        let mut conn = fresh_conn();
        conn.pragma_update(None, "foreign_keys", true).unwrap();
        init_delivery_control_v1_tables(&conn).unwrap();
        let canonical_objects = |conn: &Connection| {
            let mut statement = conn
                .prepare(
                    "SELECT type, name, sql FROM sqlite_schema
                      WHERE name IN (
                          'zend_orchard_ironwood_immediate_delivery',
                          'idx_zend_orchard_ironwood_immediate_lease',
                          'zend_orchard_ironwood_delivery_run_delete_guard',
                          'zend_orchard_ironwood_delivery_account_delete_guard'
                      )
                      ORDER BY type, name",
                )
                .unwrap();
            statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
        };
        let schema_before = canonical_objects(&conn);
        assert_eq!(schema_before.len(), 4);
        let immediate_rows_before: u64 = conn
            .query_row(
                "SELECT COUNT(*) FROM zend_orchard_ironwood_immediate_delivery",
                [],
                |row| row.get(0),
            )
            .unwrap();
        conn.execute_batch(
            "CREATE TEMP TRIGGER fail_gross_authorization_provenance_update
             BEFORE UPDATE OF schema_version ON zend_orchard_ironwood_delivery_meta
             BEGIN
                 SELECT RAISE(ABORT, 'injected provenance CAS failure');
             END;",
        )
        .unwrap();

        let transaction = conn.transaction().unwrap();
        let error = upgrade_immediate_gross_authorization(&transaction).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("injected provenance CAS failure"),
            "the failure must be injected after the table copy, not an earlier v1-shape rejection: {error}"
        );
        transaction.rollback().unwrap();

        let provenance: (u32, String) = conn
            .query_row(
                "SELECT schema_version, implementation
                   FROM zend_orchard_ironwood_delivery_meta WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            provenance,
            (1, "just-zend/librustzcash-delivery-v1".to_owned())
        );
        assert_eq!(canonical_objects(&conn), schema_before);
        let immediate_rows_after: u64 = conn
            .query_row(
                "SELECT COUNT(*) FROM zend_orchard_ironwood_immediate_delivery",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(immediate_rows_after, immediate_rows_before);
        let authorization_table_exists: bool = conn
            .query_row(
                "SELECT EXISTS(
                     SELECT 1 FROM sqlite_schema
                      WHERE name = 'zend_orchard_ironwood_immediate_gross_authorization'
                 )",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!authorization_table_exists);
        let backup_table_exists: bool = conn
            .query_row(
                "SELECT EXISTS(
                     SELECT 1 FROM sqlite_schema
                      WHERE name = 'zend_orchard_ironwood_immediate_delivery_v1_upgrade'
                 )",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!backup_table_exists);
    }

    #[cfg(feature = "migration-delivery")]
    #[test]
    fn gross_authorization_upgrade_rejects_malformed_exact_v1_without_repair() {
        let mut conn = fresh_conn();
        conn.pragma_update(None, "foreign_keys", true).unwrap();
        init_delivery_control_v1_tables(&conn).unwrap();
        conn.execute_batch("DROP INDEX idx_zend_orchard_ironwood_immediate_lease")
            .unwrap();

        let transaction = conn.transaction().unwrap();
        assert!(matches!(
            upgrade_immediate_gross_authorization(&transaction),
            Err(Error::Corrupt("delivery v1 schema shape"))
        ));
        transaction.rollback().unwrap();

        let provenance: (u32, String) = conn
            .query_row(
                "SELECT schema_version, implementation
                   FROM zend_orchard_ironwood_delivery_meta WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            provenance,
            (1, "just-zend/librustzcash-delivery-v1".to_owned())
        );
        let authorization_table_exists: bool = conn
            .query_row(
                "SELECT EXISTS(
                     SELECT 1 FROM sqlite_schema
                      WHERE name = 'zend_orchard_ironwood_immediate_gross_authorization'
                 )",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!authorization_table_exists);
    }

    #[cfg(feature = "migration-delivery")]
    #[test]
    fn gross_authorization_upgrade_preserves_live_scheduled_lane() {
        use zcash_client_backend::wallet::LockOwner;
        use zcash_pool_migration::delivery::{
            LoopbackDevelopmentEndpoint, MigrationRunIdentity, MigrationRuntimeAvailability,
            SourceReservationOwner, SubmissionContext, SubmissionPolicy, SubmissionPolicyRequest,
            SubmissionTransport, migration_state_fingerprint,
        };
        use zcash_protocol::consensus::BlockHeight;

        let mut conn = fresh_conn();
        conn.pragma_update(None, "foreign_keys", true).unwrap();
        let account = insert_account(&conn);
        let owner = LockOwner::new([0xD1; 32]);
        let (expected_state, source) =
            source_bound_transfer_state(&conn, account, owner, 0xD2, 0xD300);
        PoolMigrations::for_account(&mut conn, account)
            .unwrap()
            .replace_migration(&expected_state)
            .unwrap();
        conn.execute(
            "UPDATE orchard_received_notes
                SET lock_expiry_height = ?, lock_owner = ?
              WHERE transaction_id = (SELECT id_tx FROM transactions WHERE txid = ?)
                AND action_index = ?",
            rusqlite::params![
                u32::from(BlockHeight::from_u32(u32::MAX)),
                owner.as_bytes(),
                source.txid().as_ref(),
                source.output_index(),
            ],
        )
        .unwrap();
        init_delivery_control_v1_tables(&conn).unwrap();
        let account_id: i64 = conn
            .query_row(
                "SELECT id FROM accounts WHERE uuid = ?",
                rusqlite::params![account.expose_uuid()],
                |row| row.get(0),
            )
            .unwrap();
        let migration_id: i64 = conn
            .query_row(
                "SELECT id FROM orchard_ironwood_migrations WHERE account_id = ?",
                rusqlite::params![account_id],
                |row| row.get(0),
            )
            .unwrap();
        let run_identity = MigrationRunIdentity::read([0xD3; 32].as_slice()).unwrap();
        let source_owner = SourceReservationOwner::read([0xD4; 32].as_slice()).unwrap();
        let params = zcash_pool_migration_memory::regtest_network(true);
        let context = SubmissionContext::from_parameters(&params);
        let policy = SubmissionPolicy::validate(
            SubmissionPolicyRequest::new(
                context,
                SubmissionTransport::LoopbackDevelopment(
                    LoopbackDevelopmentEndpoint::try_from("http://127.0.0.1:9067".to_owned())
                        .unwrap(),
                ),
            ),
            context,
        )
        .unwrap();
        let authority = store::delivery_run_authority_fingerprint(
            run_identity.as_bytes(),
            account_id,
            "canonical",
            Some(migration_id),
            source_owner.as_bytes(),
            Some(owner.as_bytes()),
        )
        .unwrap();
        conn.execute(
            "INSERT INTO zend_orchard_ironwood_delivery_runs (
                 run_identity, account_id, lane, canonical_migration_id, source_owner,
                 canonical_lock_owner, authority_fingerprint, status
             ) VALUES (?, ?, 'canonical', ?, ?, ?, ?, 'active')",
            rusqlite::params![
                run_identity.as_bytes(),
                account_id,
                migration_id,
                source_owner.as_bytes(),
                owner.as_bytes(),
                authority,
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO zend_orchard_ironwood_delivery_control (
                 migration_id, run_identity, revision, state_fingerprint, phase,
                 policy, policy_fingerprint
             ) VALUES (?, ?, 1, ?, 'active', ?, ?)",
            rusqlite::params![
                migration_id,
                run_identity.as_bytes(),
                migration_state_fingerprint(&expected_state).as_bytes(),
                policy.canonical_bytes(),
                policy.fingerprint().as_bytes(),
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO zend_orchard_ironwood_delivery_reservations (
                 run_identity, source_txid, source_index, status
             ) VALUES (?, ?, ?, 'active')",
            rusqlite::params![
                run_identity.as_bytes(),
                source.txid().as_ref(),
                source.output_index(),
            ],
        )
        .unwrap();
        let lock_before = output_lock(&conn, &source);
        {
            let transaction = conn.transaction().unwrap();
            upgrade_immediate_gross_authorization(&transaction).unwrap();
            transaction.commit().unwrap();
        }

        let runtime = store::load_account_migration_runtime(&conn, &TABLES, account, context)
            .unwrap()
            .expect("scheduled account runtime");
        assert_eq!(
            runtime.runtime().availability(),
            MigrationRuntimeAvailability::Available
        );
        assert_eq!(
            runtime
                .runtime()
                .delivery()
                .expect("live scheduled delivery")
                .run_identity(),
            run_identity,
        );
        let scheduled_authorizations: u64 = conn
            .query_row(
                "SELECT COUNT(*)
                   FROM zend_orchard_ironwood_immediate_gross_authorization
                  WHERE run_identity = ?",
                rusqlite::params![run_identity.as_bytes()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(scheduled_authorizations, 0);
        assert_eq!(output_lock(&conn, &source), lock_before);
        let store = PoolMigrations::for_account(&conn, account).unwrap();
        assert_eq!(store.get_migration().unwrap(), Some(expected_state));
    }

    #[cfg(feature = "migration-delivery")]
    #[test]
    fn delivery_provenance_rejects_cross_account_run_authority() {
        use zcash_client_backend::wallet::LockOwner;
        use zcash_pool_migration::delivery::{DeliverySchemaProvenance, MigrationDeliveryStore};

        let mut conn = fresh_conn();
        conn.pragma_update(None, "foreign_keys", true).unwrap();
        init_delivery_control_tables(&conn).unwrap();
        let account = insert_account(&conn);
        let other = insert_account(&conn);
        let (_, _, run) = start_source_bound_delivery(
            &mut conn,
            account,
            LockOwner::new([0xF3; 32]),
            0xF5,
            0xF600,
        );
        let other_id: i64 = conn
            .query_row(
                "SELECT id FROM accounts WHERE uuid = ?",
                rusqlite::params![other.expose_uuid()],
                |row| row.get(0),
            )
            .unwrap();
        let account_id: i64 = conn
            .query_row(
                "SELECT id FROM accounts WHERE uuid = ?",
                rusqlite::params![account.expose_uuid()],
                |row| row.get(0),
            )
            .unwrap();
        let (source_owner, canonical_migration_id): ([u8; 32], i64) = conn
            .query_row(
                "SELECT source_owner, canonical_migration_id
                   FROM zend_orchard_ironwood_delivery_runs
                  WHERE run_identity = ?",
                rusqlite::params![run.as_bytes()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        conn.pragma_update(None, "foreign_keys", false).unwrap();
        conn.execute(
            "UPDATE zend_orchard_ironwood_delivery_runs
                SET account_id = ? WHERE run_identity = ?",
            rusqlite::params![other_id, run.as_bytes()],
        )
        .unwrap();
        conn.pragma_update(None, "foreign_keys", true).unwrap();
        let result = PoolMigrations::for_account(&mut conn, account)
            .unwrap()
            .delivery_schema_provenance()
            .unwrap();
        assert_eq!(result, DeliverySchemaProvenance::Corrupt);

        conn.pragma_update(None, "foreign_keys", false).unwrap();
        conn.execute(
            "UPDATE zend_orchard_ironwood_delivery_runs
                SET account_id = ?, source_owner = ? WHERE run_identity = ?",
            rusqlite::params![account_id, [0xF4u8; 32], run.as_bytes()],
        )
        .unwrap();
        conn.pragma_update(None, "foreign_keys", true).unwrap();
        let owner_result = PoolMigrations::for_account(&mut conn, account)
            .unwrap()
            .delivery_schema_provenance()
            .unwrap();
        assert_eq!(owner_result, DeliverySchemaProvenance::Corrupt);

        conn.execute(
            "UPDATE zend_orchard_ironwood_delivery_runs SET source_owner = ?
              WHERE run_identity = ?",
            rusqlite::params![source_owner, run.as_bytes()],
        )
        .unwrap();
        conn.pragma_update(None, "ignore_check_constraints", true)
            .unwrap();
        conn.execute(
            "UPDATE zend_orchard_ironwood_delivery_runs SET lane = 'immediate'
              WHERE run_identity = ?",
            rusqlite::params![run.as_bytes()],
        )
        .unwrap();
        conn.pragma_update(None, "ignore_check_constraints", false)
            .unwrap();
        assert_eq!(
            PoolMigrations::for_account(&mut conn, account)
                .unwrap()
                .delivery_schema_provenance()
                .unwrap(),
            DeliverySchemaProvenance::Corrupt,
            "a one-field lane mutation invalidates the authority fingerprint",
        );

        conn.pragma_update(None, "ignore_check_constraints", true)
            .unwrap();
        conn.execute(
            "UPDATE zend_orchard_ironwood_delivery_runs
                SET lane = 'canonical', canonical_migration_id = NULL
              WHERE run_identity = ?",
            rusqlite::params![run.as_bytes()],
        )
        .unwrap();
        conn.pragma_update(None, "ignore_check_constraints", false)
            .unwrap();
        assert_eq!(
            PoolMigrations::for_account(&mut conn, account)
                .unwrap()
                .delivery_schema_provenance()
                .unwrap(),
            DeliverySchemaProvenance::Corrupt,
            "a one-field canonical-linkage mutation invalidates the authority fingerprint",
        );
        assert!(canonical_migration_id > 0);
    }

    #[cfg(feature = "migration-delivery")]
    #[test]
    fn delivery_provenance_requires_exact_root_sources_and_reservations() {
        use zcash_client_backend::wallet::LockOwner;
        use zcash_pool_migration::delivery::{DeliverySchemaProvenance, MigrationDeliveryStore};

        let provenance = |conn: &mut Connection, account| {
            let params = zcash_pool_migration_memory::regtest_network(true);
            PoolMigrations::for_account_with_parameters(conn, account, &params)
                .unwrap()
                .delivery_schema_provenance()
                .unwrap()
        };

        let mut missing_reservation = fresh_conn();
        init_delivery_control_tables(&missing_reservation).unwrap();
        let account = insert_account(&missing_reservation);
        let (_, _, run) = start_source_bound_delivery(
            &mut missing_reservation,
            account,
            LockOwner::new([0x71; 32]),
            0x72,
            0x7300,
        );
        assert!(matches!(
            provenance(&mut missing_reservation, account),
            DeliverySchemaProvenance::Compatible(_)
        ));
        missing_reservation
            .execute(
                "DELETE FROM zend_orchard_ironwood_delivery_reservations
                  WHERE run_identity = ?",
                rusqlite::params![run.as_bytes()],
            )
            .unwrap();
        assert_eq!(
            provenance(&mut missing_reservation, account),
            DeliverySchemaProvenance::Corrupt
        );

        // Deleting both the root wallet note and its reservation must not let the two observed
        // sets shrink together into a false match: the canonical root PCZT still declares one
        // exact wallet input.
        let mut missing_root = fresh_conn();
        init_delivery_control_tables(&missing_root).unwrap();
        let account = insert_account(&missing_root);
        let (_, output, run) = start_source_bound_delivery(
            &mut missing_root,
            account,
            LockOwner::new([0x74; 32]),
            0x75,
            0x7600,
        );
        missing_root
            .execute(
                "DELETE FROM zend_orchard_ironwood_delivery_reservations
                  WHERE run_identity = ?",
                rusqlite::params![run.as_bytes()],
            )
            .unwrap();
        missing_root
            .execute(
                "DELETE FROM orchard_received_notes
                  WHERE transaction_id = (SELECT id_tx FROM transactions WHERE txid = ?)
                    AND action_index = ?",
                rusqlite::params![output.txid().as_ref(), output.output_index()],
            )
            .unwrap();
        assert_eq!(
            provenance(&mut missing_root, account),
            DeliverySchemaProvenance::Corrupt
        );
    }

    #[cfg(feature = "migration-delivery")]
    #[test]
    fn delivery_provenance_rejects_extra_and_wrong_account_sources() {
        use zcash_client_backend::wallet::LockOwner;
        use zcash_pool_migration::delivery::{DeliverySchemaProvenance, MigrationDeliveryStore};

        let provenance = |conn: &mut Connection, account| {
            let params = zcash_pool_migration_memory::regtest_network(true);
            PoolMigrations::for_account_with_parameters(conn, account, &params)
                .unwrap()
                .delivery_schema_provenance()
                .unwrap()
        };

        let mut extra = fresh_conn();
        init_delivery_control_tables(&extra).unwrap();
        let account = insert_account(&extra);
        let (_, _, run) = start_source_bound_delivery(
            &mut extra,
            account,
            LockOwner::new([0x77; 32]),
            0x78,
            0x7900,
        );
        let unrelated = insert_lockable_output(&extra, account, 0x7a);
        extra
            .execute(
                "INSERT INTO zend_orchard_ironwood_delivery_reservations
                    (run_identity, source_txid, source_index, status)
                 VALUES (?, ?, ?, 'active')",
                rusqlite::params![
                    run.as_bytes(),
                    unrelated.txid().as_ref(),
                    unrelated.output_index()
                ],
            )
            .unwrap();
        assert_eq!(
            provenance(&mut extra, account),
            DeliverySchemaProvenance::Corrupt
        );

        let mut wrong_account = fresh_conn();
        init_delivery_control_tables(&wrong_account).unwrap();
        let account = insert_account(&wrong_account);
        let other = insert_account(&wrong_account);
        let (_, output, _) = start_source_bound_delivery(
            &mut wrong_account,
            account,
            LockOwner::new([0x7b; 32]),
            0x7c,
            0x7d00,
        );
        let other_id: i64 = wrong_account
            .query_row(
                "SELECT id FROM accounts WHERE uuid = ?",
                rusqlite::params![other.expose_uuid()],
                |row| row.get(0),
            )
            .unwrap();
        wrong_account
            .execute(
                "UPDATE orchard_received_notes SET account_id = ?
                  WHERE transaction_id = (SELECT id_tx FROM transactions WHERE txid = ?)
                    AND action_index = ?",
                rusqlite::params![other_id, output.txid().as_ref(), output.output_index()],
            )
            .unwrap();
        assert_eq!(
            provenance(&mut wrong_account, account),
            DeliverySchemaProvenance::Corrupt
        );
    }

    #[cfg(feature = "migration-delivery")]
    #[test]
    fn delivery_provenance_allows_dummy_and_unmaterialized_dependent_inputs() {
        use zcash_client_backend::wallet::LockOwner;
        use zcash_pool_migration::{
            delivery::{DeliverySchemaProvenance, MigrationDeliveryStore},
            engine::{
                MigrationState, MigrationTransaction, MigrationTxId, MigrationTxKind,
                MigrationTxState,
            },
            wallet::PoolMigrationLockStore,
        };
        use zcash_protocol::consensus::BlockHeight;

        let mut conn = fresh_conn();
        init_delivery_control_tables(&conn).unwrap();
        let account = insert_account(&conn);
        let owner = LockOwner::new([0x7e; 32]);
        let (root, root_output) = source_bound_transfer_state(&conn, account, owner, 0x7f, 0x8000);
        let (unmaterialized, dependent_output) =
            source_bound_transfer_state(&conn, account, owner, 0x81, 0x8200);
        conn.execute(
            "DELETE FROM orchard_received_notes
              WHERE transaction_id = (SELECT id_tx FROM transactions WHERE txid = ?)
                AND action_index = ?",
            rusqlite::params![
                dependent_output.txid().as_ref(),
                dependent_output.output_index()
            ],
        )
        .unwrap();
        let dependent = MigrationTransaction::from_parts(
            MigrationTxId::new(1),
            MigrationTxKind::Transfer { crossing: 0 },
            unmaterialized.transactions()[0].pczt().to_vec(),
            vec![MigrationTxId::new(0)],
            BlockHeight::from_u32(121),
            BlockHeight::from_u32(141),
            Some(BlockHeight::from_u32(112)),
            MigrationTxState::Signed,
            Some(*owner.as_bytes()),
        );
        let state = MigrationState::from_parts(
            root.status(),
            root.note_split().clone(),
            root.preparation().clone(),
            vec![root.transactions()[0].clone(), dependent],
        );
        let params = zcash_pool_migration_memory::regtest_network(true);
        let mut store = PoolMigrations::for_account_with_parameters(&mut conn, account, &params)
            .expect("account store");
        store
            .lock_outputs_and_replace_migration(
                None,
                &state,
                &[root_output],
                owner,
                BlockHeight::from_u32(u32::MAX),
            )
            .expect("dummy and dependent inputs do not create reservations");
        assert!(matches!(
            store.delivery_schema_provenance().unwrap(),
            DeliverySchemaProvenance::Compatible(_)
        ));
    }

    #[cfg(feature = "migration-delivery")]
    #[test]
    fn dependent_source_refresh_adds_lock_and_reservation_atomically() {
        use zcash_client_backend::wallet::LockOwner;
        use zcash_pool_migration::{
            delivery::{DeliverySchemaProvenance, MigrationDeliveryStore},
            engine::{
                MigrationState, MigrationTransaction, MigrationTxId, MigrationTxKind,
                MigrationTxState, PoolMigrationRead,
            },
            wallet::PoolMigrationLockStore,
        };
        use zcash_protocol::consensus::BlockHeight;

        let mut conn = fresh_conn();
        init_delivery_control_tables(&conn).unwrap();
        let account = insert_account(&conn);
        let owner = LockOwner::new([0x83; 32]);
        let (root, root_output) = source_bound_transfer_state(&conn, account, owner, 0x84, 0x8500);
        let (materialized, dependent_output) =
            source_bound_transfer_state(&conn, account, owner, 0x86, 0x8700);
        let (dependent_transaction_id, dependent_account_id, dependent_nullifier): (
            i64,
            i64,
            [u8; 32],
        ) = conn
            .query_row(
                "SELECT rn.transaction_id, rn.account_id, rn.nf
                   FROM orchard_received_notes rn
                   JOIN transactions source ON source.id_tx = rn.transaction_id
                  WHERE source.txid = ? AND rn.action_index = ?",
                rusqlite::params![
                    dependent_output.txid().as_ref(),
                    dependent_output.output_index()
                ],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        conn.execute(
            "DELETE FROM orchard_received_notes WHERE transaction_id = ? AND action_index = ?",
            rusqlite::params![dependent_transaction_id, dependent_output.output_index()],
        )
        .unwrap();
        let dependent = MigrationTransaction::from_parts(
            MigrationTxId::new(1),
            MigrationTxKind::Transfer { crossing: 0 },
            materialized.transactions()[0].pczt().to_vec(),
            vec![MigrationTxId::new(0)],
            BlockHeight::from_u32(121),
            BlockHeight::from_u32(141),
            Some(BlockHeight::from_u32(112)),
            MigrationTxState::Signed,
            Some(*owner.as_bytes()),
        );
        let state = MigrationState::from_parts(
            root.status(),
            root.note_split().clone(),
            root.preparation().clone(),
            vec![root.transactions()[0].clone(), dependent],
        );
        let params = zcash_pool_migration_memory::regtest_network(true);
        {
            let mut store =
                PoolMigrations::for_account_with_parameters(&mut conn, account, &params).unwrap();
            store
                .lock_outputs_and_replace_migration(
                    None,
                    &state,
                    &[root_output],
                    owner,
                    BlockHeight::from_u32(u32::MAX),
                )
                .unwrap();
        }

        // Synchronization materializes the dependent source. A failure after its physical lock but
        // before its typed reservation must roll both mutations back.
        conn.execute(
            "INSERT INTO orchard_received_notes
                (transaction_id, action_index, account_id, nf)
             VALUES (?, ?, ?, ?)",
            rusqlite::params![
                dependent_transaction_id,
                dependent_output.output_index(),
                dependent_account_id,
                dependent_nullifier
            ],
        )
        .unwrap();
        conn.execute_batch(
            "CREATE TRIGGER fail_dependent_reservation
             BEFORE INSERT ON zend_orchard_ironwood_delivery_reservations
             WHEN NEW.source_txid = X'8686868686868686868686868686868686868686868686868686868686868686'
             BEGIN SELECT RAISE(ABORT, 'injected reservation failure'); END;",
        )
        .unwrap();
        {
            let mut store =
                PoolMigrations::for_account_with_parameters(&mut conn, account, &params).unwrap();
            assert!(
                store
                    .lock_outputs_and_replace_migration(
                        Some(&state),
                        &state,
                        &[root_output, dependent_output],
                        owner,
                        BlockHeight::from_u32(u32::MAX),
                    )
                    .is_err()
            );
            assert_eq!(store.get_migration().unwrap(), Some(state.clone()));
        }
        assert_eq!(output_lock(&conn, &dependent_output), (None, None));
        let dependent_reservation_count: u64 = conn
            .query_row(
                "SELECT COUNT(*) FROM zend_orchard_ironwood_delivery_reservations
                  WHERE source_txid = ? AND source_index = ?",
                rusqlite::params![
                    dependent_output.txid().as_ref(),
                    dependent_output.output_index()
                ],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(dependent_reservation_count, 0);

        conn.execute("DROP TRIGGER fail_dependent_reservation", [])
            .unwrap();
        let mut store =
            PoolMigrations::for_account_with_parameters(&mut conn, account, &params).unwrap();
        store
            .lock_outputs_and_replace_migration(
                Some(&state),
                &state,
                &[root_output, dependent_output],
                owner,
                BlockHeight::from_u32(u32::MAX),
            )
            .expect("dependent source refresh commits atomically");
        assert!(matches!(
            store.delivery_schema_provenance().unwrap(),
            DeliverySchemaProvenance::Compatible(_)
        ));
        assert_eq!(
            output_lock(&conn, &dependent_output),
            (Some(u32::MAX), Some(*owner.as_bytes()))
        );
    }

    #[cfg(feature = "migration-delivery")]
    #[test]
    fn generic_replace_cannot_create_an_unreserved_live_delivery_run() {
        use zcash_client_backend::wallet::LockOwner;
        use zcash_pool_migration::engine::{PoolMigrationRead, PoolMigrationWrite};

        let mut conn = fresh_conn();
        init_delivery_control_tables(&conn).unwrap();
        let account = insert_account(&conn);
        let (state, output) =
            source_bound_transfer_state(&conn, account, LockOwner::new([0x88; 32]), 0x89, 0x8a00);
        let mut store = PoolMigrations::for_account(&mut conn, account).unwrap();
        assert!(matches!(
            store.replace_migration(&state),
            Err(Error::DeliveryPhaseMismatch)
        ));
        assert_eq!(store.get_migration().unwrap(), None);
        assert_eq!(output_lock(&conn, &output), (None, None));
    }

    #[cfg(feature = "migration-delivery")]
    #[test]
    fn rewind_recovery_uses_strict_release_boundary_and_preserves_zero_tombstone() {
        use zcash_client_backend::wallet::LockOwner;
        use zcash_protocol::consensus::BlockHeight;

        let mut conn = fresh_conn();
        init_delivery_control_tables(&conn).unwrap();
        let account = insert_account(&conn);
        let owner = LockOwner::new([0x8b; 32]);
        let (_, output, run) = start_source_bound_delivery(&mut conn, account, owner, 0x8c, 0x8d00);
        conn.execute(
            "UPDATE zend_orchard_ironwood_delivery_control
                SET storage_finality = 'finalized', release_at_height = 200,
                    finalized_tip_height = 200
              WHERE run_identity = ?",
            rusqlite::params![run.as_bytes()],
        )
        .unwrap();
        conn.execute(
            "UPDATE zend_orchard_ironwood_delivery_runs SET status = 'finalized'
              WHERE run_identity = ?",
            rusqlite::params![run.as_bytes()],
        )
        .unwrap();
        conn.execute(
            "UPDATE zend_orchard_ironwood_delivery_reservations
                SET status = 'finality_released', release_at_height = 200,
                    released_tip_height = 200
              WHERE run_identity = ?",
            rusqlite::params![run.as_bytes()],
        )
        .unwrap();
        conn.execute(
            "UPDATE orchard_received_notes
                SET lock_owner = NULL, lock_expiry_height = NULL
              WHERE transaction_id = (SELECT id_tx FROM transactions WHERE txid = ?)
                AND action_index = ?",
            rusqlite::params![output.txid().as_ref(), output.output_index()],
        )
        .unwrap();

        prepare_for_wallet_rewind(&conn, BlockHeight::from_u32(200)).unwrap();
        let status_at_boundary: String = conn
            .query_row(
                "SELECT storage_finality FROM zend_orchard_ironwood_delivery_control
                  WHERE run_identity = ?",
                rusqlite::params![run.as_bytes()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(status_at_boundary, "finalized");

        prepare_for_wallet_rewind(&conn, BlockHeight::from_u32(199)).unwrap();
        let (status_below, reason): (String, Option<String>) = conn
            .query_row(
                "SELECT storage_finality, storage_recovery_reason
                   FROM zend_orchard_ironwood_delivery_control WHERE run_identity = ?",
                rusqlite::params![run.as_bytes()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(status_below, "recovery_required");
        assert_eq!(reason.as_deref(), Some("rewound_beyond_finality_horizon"));

        let tombstone_account = insert_account(&conn);
        let tombstone_owner = LockOwner::new([0x8e; 32]);
        let (_, tombstone_output, tombstone_run) = start_source_bound_delivery(
            &mut conn,
            tombstone_account,
            tombstone_owner,
            0x8f,
            0x9000,
        );
        conn.execute(
            "UPDATE zend_orchard_ironwood_delivery_control
                SET phase = 'abandoned', storage_finality = 'finalized',
                    release_at_height = 0, finalized_tip_height = 0
              WHERE run_identity = ?",
            rusqlite::params![tombstone_run.as_bytes()],
        )
        .unwrap();
        conn.execute(
            "UPDATE zend_orchard_ironwood_delivery_runs SET status = 'abandoned'
              WHERE run_identity = ?",
            rusqlite::params![tombstone_run.as_bytes()],
        )
        .unwrap();
        conn.execute(
            "UPDATE zend_orchard_ironwood_delivery_reservations
                SET status = 'abandoned', released_tip_height = 0
              WHERE run_identity = ?",
            rusqlite::params![tombstone_run.as_bytes()],
        )
        .unwrap();
        conn.execute(
            "UPDATE orchard_received_notes
                SET lock_owner = NULL, lock_expiry_height = NULL
              WHERE transaction_id = (SELECT id_tx FROM transactions WHERE txid = ?)
                AND action_index = ?",
            rusqlite::params![
                tombstone_output.txid().as_ref(),
                tombstone_output.output_index()
            ],
        )
        .unwrap();
        prepare_for_wallet_rewind(&conn, BlockHeight::from_u32(0)).unwrap();
        let tombstone_status: String = conn
            .query_row(
                "SELECT storage_finality FROM zend_orchard_ironwood_delivery_control
                  WHERE run_identity = ?",
                rusqlite::params![tombstone_run.as_bytes()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(tombstone_status, "finalized");
    }

    #[test]
    fn get_migration_empty_is_none() {
        assert_empty_is_none(&fresh_store());
    }

    /// A transaction's `lock_owner` round-trips exactly through the store's `BLOB` column: a
    /// `Some` token comes back byte-for-byte and a `None` comes back as `None`, not a zeroed or
    /// otherwise substituted token. This pins the two cases the column must distinguish; the
    /// general `put_then_get_round_trips` property (whose generator also produces `lock_owner`)
    /// covers the type more broadly.
    #[test]
    fn lock_owner_round_trips() {
        use zcash_pool_migration::engine::{
            MigrationState, MigrationStatus, MigrationTransaction, MigrationTxKind,
        };
        use zcash_pool_migration::note_splitting::NoteSplitPlan;
        use zcash_pool_migration::preparation::PreparationPlan;
        use zcash_protocol::consensus::BlockHeight;
        use zcash_protocol::value::Zatoshis;

        let note_split = NoteSplitPlan::from_stored_parts(
            Vec::new(),
            Zatoshis::ZERO,
            None,
            Zatoshis::ZERO,
            Zatoshis::ZERO,
            Zatoshis::ZERO,
        )
        .expect("an empty stored plan reconstructs");

        let owner_bytes = [7u8; 32];
        let locked = MigrationTransaction::from_parts(
            MigrationTxId::new(0),
            MigrationTxKind::Preparation { layer: 0, index: 0 },
            vec![1, 2, 3],
            Vec::new(),
            BlockHeight::from_u32(100),
            BlockHeight::from_u32(200),
            None,
            MigrationTxState::Signed,
            Some(owner_bytes),
        );
        let unlocked = MigrationTransaction::from_parts(
            MigrationTxId::new(1),
            MigrationTxKind::Transfer { crossing: 0 },
            vec![4, 5, 6],
            Vec::new(),
            BlockHeight::from_u32(100),
            BlockHeight::from_u32(200),
            None,
            MigrationTxState::Signed,
            None,
        );
        let state = MigrationState::from_parts(
            MigrationStatus::Committed,
            note_split,
            PreparationPlan::from_parts(Vec::new(), Vec::new()),
            vec![locked, unlocked],
        );

        let mut store = fresh_store();
        store.replace_migration(&state).expect("write succeeds");
        let loaded = store
            .get_migration()
            .expect("read succeeds")
            .expect("a migration is stored");

        assert_eq!(
            loaded, state,
            "the whole migration, including lock_owner, must round-trip unchanged"
        );
        assert_eq!(
            loaded.transactions()[0].lock_owner(),
            Some(owner_bytes),
            "a `Some` lock_owner must survive exactly"
        );
        assert_eq!(
            loaded.transactions()[1].lock_owner(),
            None,
            "a `None` lock_owner must round-trip as `None`"
        );
    }

    /// A live migration has one canonical lock owner. Empty state reports no owner, repeated
    /// copies of the canonical owner collapse, and mixed/missing owners fail closed.
    #[test]
    fn migration_lock_owners_collects_distinct_non_none_owners() {
        use std::collections::BTreeSet;

        use zcash_client_backend::wallet::LockOwner;
        use zcash_pool_migration::engine::{
            MigrationState, MigrationStatus, MigrationTransaction, MigrationTxKind,
        };
        use zcash_pool_migration::note_splitting::NoteSplitPlan;
        use zcash_pool_migration::preparation::PreparationPlan;
        use zcash_protocol::consensus::BlockHeight;
        use zcash_protocol::value::Zatoshis;

        let mut store = fresh_store();
        assert_eq!(
            store.migration_lock_owners().expect("read succeeds"),
            BTreeSet::new(),
            "an account with no migration must report no lock owners"
        );

        let owner_a_bytes = [0xA1u8; 32];
        let owner_b_bytes = [0xB2u8; 32];

        let note_split = NoteSplitPlan::from_stored_parts(
            Vec::new(),
            Zatoshis::ZERO,
            None,
            Zatoshis::ZERO,
            Zatoshis::ZERO,
            Zatoshis::ZERO,
        )
        .expect("an empty stored plan reconstructs");

        let tx = |id: u32, crossing: usize, lock_owner: Option<[u8; 32]>| {
            MigrationTransaction::from_parts(
                MigrationTxId::new(id),
                MigrationTxKind::Transfer { crossing },
                vec![id as u8],
                Vec::new(),
                BlockHeight::from_u32(100),
                BlockHeight::from_u32(200),
                None,
                MigrationTxState::Signed,
                lock_owner,
            )
        };

        let inconsistent = MigrationState::from_parts(
            MigrationStatus::Committed,
            note_split.clone(),
            PreparationPlan::from_parts(Vec::new(), Vec::new()),
            vec![
                tx(0, 0, Some(owner_a_bytes)),
                tx(1, 1, Some(owner_b_bytes)),
                tx(2, 2, None),
                // A second transaction locked by A, to prove duplicates collapse.
                tx(3, 3, Some(owner_a_bytes)),
            ],
        );
        store
            .replace_migration(&inconsistent)
            .expect("write inconsistent legacy fixture");
        assert!(matches!(
            store.migration_lock_owners(),
            Err(Error::CanonicalOwnerMismatch)
        ));

        let consistent = MigrationState::from_parts(
            MigrationStatus::Committed,
            note_split,
            PreparationPlan::from_parts(Vec::new(), Vec::new()),
            vec![tx(0, 0, Some(owner_a_bytes)), tx(1, 1, Some(owner_a_bytes))],
        );
        store
            .replace_migration(&consistent)
            .expect("write consistent fixture");
        let owners = store.migration_lock_owners().expect("read canonical owner");
        assert_eq!(
            owners,
            BTreeSet::from([LockOwner::new(owner_a_bytes)]),
            "must contain exactly the repeated canonical owner, deduped"
        );
    }

    /// The exact Orchard output lock and the owner-bearing canonical migration state are committed
    /// together. This pins both halves of the durable round trip, including the expiry height used
    /// to reserve the input through the migration transaction's lifetime.
    #[cfg(feature = "migration-delivery")]
    #[test]
    fn locking_and_state_replacement_are_atomic_and_round_trip() {
        use zcash_client_backend::wallet::LockOwner;
        use zcash_pool_migration::wallet::PoolMigrationLockStore;
        use zcash_protocol::consensus::BlockHeight;

        let mut conn = fresh_conn();
        init_delivery_control_tables(&conn).expect("delivery schema");
        let account = insert_account(&conn);
        let owner = LockOwner::new([0xA1; 32]);
        let (state, output) = source_bound_transfer_state(&conn, account, owner, 1, 0x2100);

        {
            let mut store =
                PoolMigrations::for_account(&mut conn, account).expect("account exists");
            store
                .lock_outputs_and_replace_migration(
                    None,
                    &state,
                    &[output],
                    owner,
                    BlockHeight::from_u32(u32::MAX),
                )
                .expect("lock and state commit together");
            assert_eq!(
                store.get_migration().expect("read succeeds"),
                Some(state.clone()),
            );
        }

        assert_eq!(
            output_lock(&conn, &output),
            (Some(u32::MAX), Some(*owner.as_bytes())),
        );
    }

    /// If canonical-state serialization fails after an output was updated, the enclosing SQLite
    /// transaction rolls the lock back as well; no owner-only half commit is observable.
    #[cfg(feature = "migration-delivery")]
    #[test]
    fn state_write_failure_rolls_back_new_lock() {
        use zcash_client_backend::wallet::LockOwner;
        use zcash_pool_migration::{
            engine::{MigrationState, MigrationStatus},
            preparation::PreparationPlan,
            wallet::PoolMigrationLockStore,
        };
        use zcash_protocol::consensus::BlockHeight;

        let mut conn = fresh_conn();
        let account = insert_account(&conn);
        let output = insert_lockable_output(&conn, account, 2);
        let owner = LockOwner::new([0xA2; 32]);
        let base = migration_state(MigrationStatus::Committed, Some(owner));
        let unrepresentable = MigrationState::from_parts(
            MigrationStatus::Committed,
            base.note_split().clone(),
            PreparationPlan::from_parts(vec![Vec::new()], Vec::new()),
            base.transactions().to_vec(),
        );

        {
            let mut store =
                PoolMigrations::for_account(&mut conn, account).expect("account exists");
            let err = store
                .lock_outputs_and_replace_migration(
                    None,
                    &unrepresentable,
                    &[output],
                    owner,
                    BlockHeight::from_u32(200),
                )
                .expect_err("the state cannot be serialized");
            assert!(matches!(err, Error::Unrepresentable(_)));
            assert_eq!(store.get_migration().expect("read succeeds"), None);
        }

        assert_eq!(output_lock(&conn, &output), (None, None));
    }

    /// A conflict late in a lock batch rolls back locks taken earlier in that batch and leaves the
    /// foreign owner's existing reservation untouched.
    #[cfg(feature = "migration-delivery")]
    #[test]
    fn lock_conflict_rolls_back_the_whole_batch() {
        use zcash_client_backend::wallet::LockOwner;
        use zcash_pool_migration::{engine::MigrationStatus, wallet::PoolMigrationLockStore};
        use zcash_protocol::consensus::BlockHeight;

        let mut conn = fresh_conn();
        let account = insert_account(&conn);
        let first = insert_lockable_output(&conn, account, 3);
        let second = insert_lockable_output(&conn, account, 4);
        let owner = LockOwner::new([0xA3; 32]);
        let foreign = LockOwner::new([0xB3; 32]);
        conn.execute(
            "UPDATE orchard_received_notes
                SET lock_expiry_height = 200, lock_owner = ?
              WHERE transaction_id = (SELECT id_tx FROM transactions WHERE txid = ?)",
            rusqlite::params![foreign.as_bytes(), second.txid().as_ref()],
        )
        .expect("seed foreign lock");
        let state = migration_state(MigrationStatus::Committed, Some(owner));

        {
            let mut store =
                PoolMigrations::for_account(&mut conn, account).expect("account exists");
            let err = store
                .lock_outputs_and_replace_migration(
                    None,
                    &state,
                    &[first, second],
                    owner,
                    BlockHeight::from_u32(200),
                )
                .expect_err("the second output conflicts");
            assert!(matches!(err, Error::LockConflict(output) if output == second));
            assert_eq!(store.get_migration().expect("read succeeds"), None);
        }

        assert_eq!(output_lock(&conn, &first), (None, None));
        assert_eq!(
            output_lock(&conn, &second),
            (Some(200), Some(*foreign.as_bytes())),
        );
    }

    /// An account-scoped store cannot reserve another account's output. Discovering the foreign
    /// row after an owned row in the same requested batch rolls the entire SQLite transaction back.
    #[cfg(feature = "migration-delivery")]
    #[test]
    fn cross_account_output_in_lock_batch_is_rejected_and_rolls_back() {
        use zcash_client_backend::wallet::LockOwner;
        use zcash_pool_migration::{engine::MigrationStatus, wallet::PoolMigrationLockStore};
        use zcash_protocol::consensus::BlockHeight;

        let mut conn = fresh_conn();
        let account_a = insert_account(&conn);
        let account_b = insert_account(&conn);
        let owned = insert_lockable_output(&conn, account_a, 0x13);
        let foreign = insert_lockable_output(&conn, account_b, 0x14);
        let owner = LockOwner::new([0xAC; 32]);
        let state = migration_state(MigrationStatus::Committed, Some(owner));

        let err = PoolMigrations::for_account(&mut conn, account_a)
            .expect("account A exists")
            .lock_outputs_and_replace_migration(
                None,
                &state,
                &[owned, foreign],
                owner,
                BlockHeight::from_u32(200),
            )
            .expect_err("account A cannot lock account B's output");
        assert!(matches!(err, Error::OutputNotOwned(output) if output == foreign));
        assert_eq!(output_lock(&conn, &owned), (None, None));
        assert_eq!(output_lock(&conn, &foreign), (None, None));
        assert_eq!(
            PoolMigrations::for_account(&conn, account_a)
                .expect("account A exists")
                .get_migration()
                .expect("read succeeds"),
            None,
        );
    }

    /// Delivery-owned lock refreshes are compare-and-swap operations over the full normalized
    /// state. Stale snapshots, wrong owners, and the generic terminal-release seam all fail
    /// without changing canonical state or releasing its source.
    #[cfg(feature = "migration-delivery")]
    #[test]
    fn atomic_lock_state_writes_reject_stale_clones_and_owner_takeover() {
        use zcash_client_backend::wallet::LockOwner;
        use zcash_pool_migration::{engine::MigrationStatus, wallet::PoolMigrationLockStore};
        use zcash_protocol::consensus::BlockHeight;

        let mut conn = fresh_conn();
        init_delivery_control_tables(&conn).expect("delivery schema");
        let account = insert_account(&conn);
        let owner = LockOwner::new([0xAD; 32]);
        let wrong_owner = LockOwner::new([0xBD; 32]);
        let (live, output) = source_bound_transfer_state(&conn, account, owner, 0x15, 0x2350);

        {
            let mut store =
                PoolMigrations::for_account(&mut conn, account).expect("account exists");
            store
                .lock_outputs_and_replace_migration(
                    None,
                    &live,
                    &[output],
                    owner,
                    BlockHeight::from_u32(u32::MAX),
                )
                .expect("initial CAS succeeds");
            store
                .lock_outputs_and_replace_migration(
                    Some(&live),
                    &live,
                    &[output],
                    owner,
                    BlockHeight::from_u32(u32::MAX),
                )
                .expect("exact-state owner refresh succeeds");

            let stale = migration_state(MigrationStatus::Committed, Some(owner));
            assert!(matches!(
                store.lock_outputs_and_replace_migration(
                    Some(&stale),
                    &live,
                    &[output],
                    owner,
                    BlockHeight::from_u32(u32::MAX),
                ),
                Err(Error::CanonicalStateMismatch)
            ));
            assert!(matches!(
                store.lock_outputs_and_replace_migration(
                    Some(&live),
                    &live,
                    &[output],
                    wrong_owner,
                    BlockHeight::from_u32(u32::MAX),
                ),
                Err(Error::CanonicalOwnerMismatch)
            ));

            let terminal = migration_state(MigrationStatus::Failed, None);
            assert!(matches!(
                store.release_locks_and_replace_migration(
                    &live,
                    &terminal,
                    &std::collections::BTreeSet::from([owner]),
                ),
                Err(Error::DeliveryPhaseMismatch)
            ));
            assert_eq!(store.get_migration().expect("read succeeds"), Some(live));
        }
        assert_eq!(
            output_lock(&conn, &output),
            (Some(u32::MAX), Some(*owner.as_bytes()))
        );
    }

    /// The generic terminal seam cannot bypass delivery authority or release either the migration
    /// source or an unrelated flow's lock.
    #[cfg(feature = "migration-delivery")]
    #[test]
    fn generic_terminal_replacement_cannot_release_delivery_owned_locks() {
        use std::collections::BTreeSet;

        use zcash_client_backend::wallet::LockOwner;
        use zcash_pool_migration::{engine::MigrationStatus, wallet::PoolMigrationLockStore};
        use zcash_protocol::consensus::BlockHeight;

        let mut conn = fresh_conn();
        init_delivery_control_tables(&conn).expect("delivery schema");
        let account = insert_account(&conn);
        let owner = LockOwner::new([0xA4; 32]);
        let foreign = LockOwner::new([0xB4; 32]);
        let (live, owned_output) = source_bound_transfer_state(&conn, account, owner, 5, 0x2450);
        let foreign_output = insert_lockable_output(&conn, account, 6);
        conn.execute(
            "UPDATE orchard_received_notes
                SET lock_expiry_height = 250, lock_owner = ?
              WHERE transaction_id = (SELECT id_tx FROM transactions WHERE txid = ?)",
            rusqlite::params![foreign.as_bytes(), foreign_output.txid().as_ref()],
        )
        .expect("seed foreign lock");

        let terminal = migration_state(MigrationStatus::Failed, None);
        {
            let mut store =
                PoolMigrations::for_account(&mut conn, account).expect("account exists");
            store
                .lock_outputs_and_replace_migration(
                    None,
                    &live,
                    &[owned_output],
                    owner,
                    BlockHeight::from_u32(u32::MAX),
                )
                .expect("lock live input");
            assert!(matches!(
                store.release_locks_and_replace_migration(
                    &live,
                    &terminal,
                    &BTreeSet::from([owner])
                ),
                Err(Error::DeliveryPhaseMismatch)
            ));
            assert_eq!(store.get_migration().expect("read succeeds"), Some(live));
            assert_eq!(
                store.migration_lock_owners().expect("read owners"),
                BTreeSet::from([owner]),
            );
        }

        assert_eq!(
            output_lock(&conn, &owned_output),
            (Some(u32::MAX), Some(*owner.as_bytes()))
        );
        assert_eq!(
            output_lock(&conn, &foreign_output),
            (Some(250), Some(*foreign.as_bytes())),
        );
    }

    /// The owners recovered from the persisted migration can be fed directly into the wallet's
    /// owner-scoped selection policy: its own active lock is preferred, unlocked notes remain
    /// available as fallback, and a foreign flow's active lock is excluded.
    #[cfg(feature = "migration-delivery")]
    #[test]
    fn migration_owner_set_is_a_safe_prefer_locked_selection_override() {
        use zcash_client_backend::{
            data_api::wallet::input_selection::{LockFilter, LockedInputPolicy, NonEmptyBTreeSet},
            wallet::LockOwner,
        };
        use zcash_pool_migration::wallet::PoolMigrationLockStore;
        use zcash_protocol::consensus::BlockHeight;

        let mut conn = fresh_conn();
        rusqlite::vtab::array::load_module(&conn).expect("load rarray module");
        init_delivery_control_tables(&conn).expect("delivery schema");
        let account = insert_account(&conn);
        let owner = LockOwner::new([0xA5; 32]);
        let (state, owned_output) = source_bound_transfer_state(&conn, account, owner, 7, 0x2500);
        let foreign_output = insert_lockable_output(&conn, account, 8);
        let _unlocked_output = insert_lockable_output(&conn, account, 9);
        let foreign = LockOwner::new([0xB5; 32]);
        conn.execute(
            "UPDATE orchard_received_notes
                SET lock_expiry_height = 200, lock_owner = ?
              WHERE transaction_id = (SELECT id_tx FROM transactions WHERE txid = ?)",
            rusqlite::params![foreign.as_bytes(), foreign_output.txid().as_ref()],
        )
        .expect("seed foreign lock");
        {
            let mut store =
                PoolMigrations::for_account(&mut conn, account).expect("account exists");
            store
                .lock_outputs_and_replace_migration(
                    None,
                    &state,
                    &[owned_output],
                    owner,
                    BlockHeight::from_u32(u32::MAX),
                )
                .expect("lock migration input");
        }

        let owners = PoolMigrations::for_account(&conn, account)
            .expect("account exists")
            .migration_lock_owners()
            .expect("read owners");
        let policy = LockedInputPolicy::PreferLocked(
            NonEmptyBTreeSet::from_set(owners).expect("migration has one owner"),
        );
        let lock_filter = LockFilter::Policy(&policy);
        let condition =
            crate::wallet::common::output_eligible_condition(lock_filter, "orchard_received_notes");
        let tier =
            crate::wallet::common::locked_tier_order_key(lock_filter, "orchard_received_notes")
                .expect("PreferLocked has a tier order");
        let sql = format!(
            "SELECT orchard_received_notes.id
               FROM orchard_received_notes
              WHERE ({condition})
              ORDER BY {tier}, orchard_received_notes.id"
        );
        let target_height = 100u32;
        let overridable_owners = crate::wallet::common::overridable_owners_rarray(lock_filter);
        let mut sql_params: Vec<(&str, &dyn rusqlite::ToSql)> =
            vec![(":target_height", &target_height)];
        crate::wallet::common::push_lock_params(&mut sql_params, lock_filter, &overridable_owners);
        let selected = conn
            .prepare(&sql)
            .expect("prepare selection")
            .query_map(&sql_params[..], |row| row.get::<_, i64>(0))
            .expect("query selection")
            .collect::<Result<Vec<_>, _>>()
            .expect("read selection");

        assert_eq!(selected, vec![1, 3]);
    }

    #[cfg(feature = "migration-delivery")]
    #[test]
    fn exact_ironwood_availability_is_account_value_and_current_chain_scoped() {
        use zcash_client_backend::{
            data_api::wallet::{ConfirmationsPolicy, TargetHeight, input_selection::LockFilter},
            wallet::OutputRef,
        };
        use zcash_pool_migration::wallet::{
            ExactReceivedOutput, ReceivedOutputAvailability, ReceivedOutputAvailabilitySource,
        };
        use zcash_protocol::{PoolType, ShieldedPool, TxId, value::Zatoshis};

        let conn = fresh_conn();
        let account_a = insert_account(&conn);
        let account_b = insert_account(&conn);
        let output = insert_ironwood_output(
            &conn,
            account_a,
            0x31,
            Zatoshis::const_from_u64(2_000_000),
            100,
        );
        let target = TargetHeight::from(111);
        let policy = ConfirmationsPolicy::default();
        let store_a = PoolMigrations::for_account(&conn, account_a).expect("account A exists");
        let store_b = PoolMigrations::for_account(&conn, account_b).expect("account B exists");

        assert_eq!(
            store_a
                .received_output_availability(output, target, policy, LockFilter::Unfiltered)
                .expect("classification succeeds"),
            ReceivedOutputAvailability::Spendable,
        );
        assert_eq!(
            store_b
                .received_output_availability(output, target, policy, LockFilter::Unfiltered)
                .expect("classification succeeds"),
            ReceivedOutputAvailability::Unknown,
            "an unrelated account cannot supply completion evidence",
        );

        let wrong_value =
            ExactReceivedOutput::new(output.output_ref(), Zatoshis::const_from_u64(2_000_001));
        assert_eq!(
            store_a
                .received_output_availability(wrong_value, target, policy, LockFilter::Unfiltered,)
                .expect("classification succeeds"),
            ReceivedOutputAvailability::Unknown,
        );
        let unrelated = ExactReceivedOutput::new(
            OutputRef::new(
                TxId::from_bytes([0x32; 32]),
                PoolType::Shielded(ShieldedPool::Ironwood),
                0,
            ),
            output.value(),
        );
        assert_eq!(
            store_a
                .received_output_availability(unrelated, target, policy, LockFilter::Unfiltered,)
                .expect("classification succeeds"),
            ReceivedOutputAvailability::Unknown,
        );

        conn.execute(
            "UPDATE transactions SET block = NULL
             WHERE txid = ?",
            rusqlite::params![output.output_ref().txid().as_ref()],
        )
        .expect("simulate source reorg");
        assert_eq!(
            store_a
                .received_output_availability(output, target, policy, LockFilter::Unfiltered)
                .expect("classification succeeds"),
            ReceivedOutputAvailability::Unknown,
            "a source reorg fails closed even though the note row remains",
        );
    }

    /// The completion seam cannot convert a still-live delivery into a terminal state or release
    /// its source lock, even when the caller supplies an Ironwood output that exists in the wallet.
    #[cfg(feature = "migration-delivery")]
    #[test]
    fn completion_audit_rejects_nonterminal_delivery_without_releasing_owner() {
        use std::collections::BTreeSet;

        use zcash_client_backend::{
            data_api::wallet::{ConfirmationsPolicy, TargetHeight, input_selection::LockFilter},
            wallet::LockOwner,
        };
        use zcash_pool_migration::{
            engine::{MigrationStatus, MigrationTxId, PoolMigrationRead},
            wallet::PoolMigrationLockStore,
        };
        use zcash_protocol::value::Zatoshis;

        let mut conn = fresh_conn();
        init_delivery_control_tables(&conn).expect("delivery schema");
        let account = insert_account(&conn);
        let owner = LockOwner::new([0xA5; 32]);
        let (live, locked_input, _) =
            start_source_bound_delivery(&mut conn, account, owner, 0x35, 0x3500);
        let received = insert_ironwood_output(
            &conn,
            account,
            0x36,
            Zatoshis::const_from_u64(2_000_000),
            100,
        );
        let finalized = migration_state(MigrationStatus::Complete, None);
        let outputs = [(MigrationTxId::new(0), received)];
        {
            let params = zcash_pool_migration_memory::regtest_network(true);
            let mut store =
                PoolMigrations::for_account_with_parameters(&mut conn, account, &params)
                    .expect("account exists");
            let err = store
                .finalize_migration_if_outputs_available(
                    &live,
                    &finalized,
                    &BTreeSet::from([owner]),
                    &outputs,
                    TargetHeight::from(111),
                    ConfirmationsPolicy::default(),
                    LockFilter::Unfiltered,
                )
                .expect_err("a nonterminal delivery cannot be finalized");
            assert!(matches!(err, Error::DeliveryArtifactMismatch));
            assert_eq!(store.get_migration().unwrap(), Some(live));
        }
        assert_eq!(
            output_lock(&conn, &locked_input),
            (Some(u32::MAX), Some(*owner.as_bytes()))
        );
    }

    #[cfg(feature = "migration-delivery")]
    #[test]
    fn exact_ironwood_availability_distinguishes_confirmations_witness_and_economics() {
        use zcash_client_backend::data_api::wallet::{
            ConfirmationsPolicy, TargetHeight, input_selection::LockFilter,
        };
        use zcash_pool_migration::wallet::{
            ReceivedOutputAvailability, ReceivedOutputAvailabilitySource, ReceivedOutputUnavailable,
        };
        use zcash_primitives::transaction::fees::zip317;
        use zcash_protocol::value::Zatoshis;

        let conn = fresh_conn();
        let account = insert_account(&conn);
        let output = insert_ironwood_output(
            &conn,
            account,
            0x41,
            Zatoshis::const_from_u64(2_000_000),
            109,
        );
        let store = PoolMigrations::for_account(&conn, account).expect("account exists");
        let target = TargetHeight::from(111);
        let policy = ConfirmationsPolicy::default();

        assert_eq!(
            store
                .received_output_availability(output, target, policy, LockFilter::Unfiltered)
                .expect("classification succeeds"),
            ReceivedOutputAvailability::Unavailable(
                ReceivedOutputUnavailable::PendingConfirmations { remaining: 1 }
            ),
        );

        conn.execute(
            "UPDATE transactions SET block = 100, mined_height = 100 WHERE txid = ?",
            rusqlite::params![output.output_ref().txid().as_ref()],
        )
        .expect("mature source");
        conn.execute("DELETE FROM v_ironwood_shards_scan_state", [])
            .expect("make the note shard unscanned");
        assert_eq!(
            store
                .received_output_availability(output, target, policy, LockFilter::Unfiltered)
                .expect("classification succeeds"),
            ReceivedOutputAvailability::Unavailable(ReceivedOutputUnavailable::WitnessUnavailable),
        );

        conn.execute(
            "INSERT INTO v_ironwood_shards_scan_state
                 (start_position, end_position_exclusive, max_priority)
             VALUES (0, 1000, 10)",
            [],
        )
        .expect("restore scanned shard");
        assert_eq!(
            store
                .received_output_availability(output, target, policy, LockFilter::Unfiltered)
                .expect("classification succeeds"),
            ReceivedOutputAvailability::Spendable,
        );

        let dust = insert_ironwood_output(
            &conn,
            account,
            0x42,
            Zatoshis::from_u64(u64::from(zip317::MARGINAL_FEE)).expect("fee is in range"),
            100,
        );
        assert_eq!(
            store
                .received_output_availability(dust, target, policy, LockFilter::Unfiltered)
                .expect("classification succeeds"),
            ReceivedOutputAvailability::Unavailable(ReceivedOutputUnavailable::Uneconomic),
        );
    }

    #[cfg(feature = "migration-delivery")]
    #[test]
    fn exact_ironwood_availability_distinguishes_locks_pending_spends_and_main_chain_spends() {
        use zcash_client_backend::{
            data_api::wallet::{
                ConfirmationsPolicy, TargetHeight,
                input_selection::{LockFilter, LockedInputPolicy, NonEmptyBTreeSet},
            },
            wallet::LockOwner,
        };
        use zcash_pool_migration::wallet::{
            ReceivedOutputAvailability, ReceivedOutputAvailabilitySource, ReceivedOutputUnavailable,
        };
        use zcash_protocol::value::Zatoshis;

        let conn = fresh_conn();
        let account = insert_account(&conn);
        let output = insert_ironwood_output(
            &conn,
            account,
            0x51,
            Zatoshis::const_from_u64(2_000_000),
            100,
        );
        let store = PoolMigrations::for_account(&conn, account).expect("account exists");
        let target = TargetHeight::from(111);
        let confirmations = ConfirmationsPolicy::default();
        let owner = LockOwner::new([0xA1; 32]);
        let exclude = LockedInputPolicy::Exclude;

        conn.execute(
            "UPDATE ironwood_received_notes
                SET lock_expiry_height = 200, lock_owner = ?
              WHERE transaction_id = (SELECT id_tx FROM transactions WHERE txid = ?)",
            rusqlite::params![owner.as_bytes(), output.output_ref().txid().as_ref()],
        )
        .expect("lock exact output");
        assert_eq!(
            store
                .received_output_availability(
                    output,
                    target,
                    confirmations,
                    LockFilter::Policy(&exclude),
                )
                .expect("classification succeeds"),
            ReceivedOutputAvailability::Unavailable(ReceivedOutputUnavailable::Locked),
        );
        let own_policy = LockedInputPolicy::PreferLocked(NonEmptyBTreeSet::singleton(owner));
        assert_eq!(
            store
                .received_output_availability(
                    output,
                    target,
                    confirmations,
                    LockFilter::Policy(&own_policy),
                )
                .expect("classification succeeds"),
            ReceivedOutputAvailability::Spendable,
        );

        conn.execute(
            "UPDATE ironwood_received_notes
                SET lock_expiry_height = NULL, lock_owner = NULL
              WHERE transaction_id = (SELECT id_tx FROM transactions WHERE txid = ?)",
            rusqlite::params![output.output_ref().txid().as_ref()],
        )
        .expect("clear lock");
        conn.execute(
            "INSERT INTO transactions (txid, expiry_height, min_observed_height)
             VALUES (?, 200, 105)",
            rusqlite::params![[0x52u8; 32]],
        )
        .expect("insert pending spender");
        let spender_id = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO ironwood_received_note_spends
                 (ironwood_received_note_id, transaction_id)
             VALUES (
                 (SELECT id FROM ironwood_received_notes
                   WHERE transaction_id = (SELECT id_tx FROM transactions WHERE txid = ?)),
                 ?
             )",
            rusqlite::params![output.output_ref().txid().as_ref(), spender_id],
        )
        .expect("relate pending spend");
        assert_eq!(
            store
                .received_output_availability(
                    output,
                    target,
                    confirmations,
                    LockFilter::Policy(&exclude),
                )
                .expect("classification succeeds"),
            ReceivedOutputAvailability::Unavailable(ReceivedOutputUnavailable::PendingSpend),
        );

        conn.execute(
            "UPDATE transactions SET block = 105, mined_height = 105 WHERE id_tx = ?",
            rusqlite::params![spender_id],
        )
        .expect("mine spender on current chain");
        assert_eq!(
            store
                .received_output_availability(
                    output,
                    target,
                    confirmations,
                    LockFilter::Policy(&exclude),
                )
                .expect("classification succeeds"),
            ReceivedOutputAvailability::Spent {
                mined_height: zcash_protocol::consensus::BlockHeight::from_u32(105),
            },
        );

        conn.execute(
            "UPDATE transactions SET block = NULL
             WHERE txid = ?",
            rusqlite::params![output.output_ref().txid().as_ref()],
        )
        .expect("reorg receiving transaction after its spender");
        assert_eq!(
            store
                .received_output_availability(
                    output,
                    target,
                    confirmations,
                    LockFilter::Policy(&exclude),
                )
                .expect("classification succeeds"),
            ReceivedOutputAvailability::Unknown,
            "source reorg wins over stale main-chain spender evidence",
        );
    }

    /// A state with an empty preparation layer is rejected on write rather than silently
    /// renumbered: the layers/transactions grid is stored only through the input and output rows,
    /// so an empty layer would leave no trace (and the engine never produces one).
    #[test]
    fn empty_prep_layer_is_rejected() {
        use zcash_pool_migration::engine::{MigrationState, MigrationStatus};
        use zcash_pool_migration::note_splitting::NoteSplitPlan;
        use zcash_pool_migration::preparation::PreparationPlan;
        use zcash_protocol::value::Zatoshis;

        let note_split = NoteSplitPlan::from_stored_parts(
            Vec::new(),
            Zatoshis::ZERO,
            None,
            Zatoshis::ZERO,
            Zatoshis::ZERO,
            Zatoshis::ZERO,
        )
        .expect("an empty stored plan reconstructs");
        let state = MigrationState::from_parts(
            MigrationStatus::Committed,
            note_split,
            PreparationPlan::from_parts(vec![Vec::new()], Vec::new()),
            Vec::new(),
        );
        let err = fresh_store()
            .replace_migration(&state)
            .expect_err("an empty layer cannot be persisted");
        assert!(matches!(err, Error::Unrepresentable(_)));
    }

    /// Deleting an account cascades to its in-progress migration: the `account_id` foreign key
    /// carries `ON DELETE CASCADE`, so removing the account's row removes its migration, whose child
    /// rows cascade from it in turn. A different account's migration is untouched. This is the
    /// cleanup the wallet's account-deletion path now relies on entirely (no explicit delete).
    #[test]
    fn deleting_an_account_cascades_to_its_migration() {
        use zcash_pool_migration::engine::{MigrationState, MigrationStatus};
        use zcash_pool_migration::note_splitting::NoteSplitPlan;
        use zcash_pool_migration::preparation::PreparationPlan;
        use zcash_protocol::value::Zatoshis;

        let mut conn = fresh_conn();
        // Enforce foreign keys so the account -> migration -> child cascade actually fires, exactly
        // as the wallet database does at runtime.
        conn.execute_batch("PRAGMA foreign_keys = ON;")
            .expect("enable foreign keys");

        let account_a = insert_account(&conn);
        let account_b = insert_account(&conn);

        // A minimal but non-trivial migration (one crossing value) so the cascade is observed to
        // reach a child table, not only the parent row.
        let note_split = NoteSplitPlan::from_stored_parts(
            vec![Zatoshis::const_from_u64(1)],
            Zatoshis::ZERO,
            None,
            Zatoshis::ZERO,
            Zatoshis::const_from_u64(1),
            Zatoshis::const_from_u64(1),
        )
        .expect("a one-crossing stored plan reconstructs");
        let state = MigrationState::from_parts(
            MigrationStatus::Committed,
            note_split,
            PreparationPlan::from_parts(Vec::new(), Vec::new()),
            Vec::new(),
        );

        PoolMigrations::for_account(&mut conn, account_a)
            .expect("account A exists")
            .replace_migration(&state)
            .expect("write A's migration");
        PoolMigrations::for_account(&mut conn, account_b)
            .expect("account B exists")
            .replace_migration(&state)
            .expect("write B's migration");

        let count = |conn: &Connection, table: &str| -> i64 {
            conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .expect("count")
        };
        assert_eq!(count(&conn, "orchard_ironwood_migrations"), 2);
        assert_eq!(
            count(&conn, "orchard_ironwood_migration_crossing_values"),
            2
        );

        // Delete account A directly, as the wallet's `delete_account` does; the cascade removes its
        // migration and children with it, and nothing else.
        conn.execute(
            "DELETE FROM accounts WHERE uuid = ?",
            rusqlite::params![account_a.expose_uuid()],
        )
        .expect("delete account A");

        // Only A's migration row and its child rows are gone; B's migration remains intact.
        assert_eq!(
            count(&conn, "orchard_ironwood_migrations"),
            1,
            "only account A's migration row must cascade away"
        );
        assert_eq!(
            count(&conn, "orchard_ironwood_migration_crossing_values"),
            1,
            "account A's child rows must cascade away, and only those"
        );
        assert_eq!(
            PoolMigrations::for_account(&conn, account_b)
                .expect("account B exists")
                .get_migration()
                .expect("read B"),
            Some(state),
            "account B's migration must be untouched",
        );
    }

    proptest! {
        /// Any generated migration round-trips through the SQLite store unchanged: the shared
        /// put/get conformance property, proving the SQLite backend satisfies the suite.
        #[test]
        fn put_then_get_round_trips(state in arb_migration_state()) {
            assert_put_get_roundtrip(&mut fresh_store(), &state);
        }

        /// A second put replaces the first migration (the shared replace property).
        #[test]
        fn put_replaces_previous_migration(
            first in arb_migration_state(),
            second in arb_migration_state(),
        ) {
            assert_put_replaces(&mut fresh_store(), &first, &second);
        }

        /// Updating a stored transaction's lifecycle state persists (the shared update property),
        /// exercised across every state variant, including the `Mined` and `Broadcast` payloads.
        #[test]
        fn update_transaction_advances_state(
            state in arb_migration_state(),
            new in arb_migration_tx_state(),
        ) {
            // The shared assertion needs an id the migration contains; skip the (valid) empty case.
            prop_assume!(!state.transactions().is_empty());
            let id = first_transaction_id(&state).expect("non-empty by the assumption above");
            assert_update_transaction(&mut fresh_store(), &state, id, new);
        }

        /// Updating a transaction the stored migration does not contain is a store error. This is
        /// SQLite-specific (the shared conformance suite covers only the success path).
        #[test]
        fn update_unknown_transaction_errors(state in arb_migration_state()) {
            let mut s = fresh_store();
            s.replace_migration(&state).expect("write");
            // Generated ids are `0..transactions.len()` (< 6), so `u32::MAX` is always absent.
            let err = s
                .update_transaction(MigrationTxId::new(u32::MAX), MigrationTxState::Proved)
                .expect_err("no such transaction");
            prop_assert!(matches!(err, Error::Corrupt(_)));
        }

        /// Two accounts sharing one connection are isolated: writing account A's migration
        /// creates no row visible to account B (which reads back `None`, exactly as an untouched
        /// store would), while account A itself round-trips normally.
        #[test]
        fn accounts_are_isolated(state in arb_migration_state()) {
            let mut conn = fresh_conn();
            let account_a = insert_account(&conn);
            let account_b = insert_account(&conn);

            PoolMigrations::for_account(&mut conn, account_a)
                .expect("account A exists")
                .replace_migration(&state)
                .expect("write for A");

            prop_assert_eq!(
                PoolMigrations::for_account(&conn, account_b)
                    .expect("account B exists")
                    .get_migration()
                    .expect("read for B"),
                None
            );
            prop_assert_eq!(
                PoolMigrations::for_account(&conn, account_a)
                    .expect("account A exists")
                    .get_migration()
                    .expect("read for A"),
                Some(state)
            );
        }

        /// Replacing account A's migration touches only A's row and children: account B's
        /// previously written migration, on the same connection, is unaffected.
        #[test]
        fn replace_migration_is_scoped_to_its_account(
            state_a_1 in arb_migration_state(),
            state_a_2 in arb_migration_state(),
            state_b in arb_migration_state(),
        ) {
            let mut conn = fresh_conn();
            let account_a = insert_account(&conn);
            let account_b = insert_account(&conn);

            PoolMigrations::for_account(&mut conn, account_a)
                .expect("account A exists")
                .replace_migration(&state_a_1)
                .expect("write A first");
            PoolMigrations::for_account(&mut conn, account_b)
                .expect("account B exists")
                .replace_migration(&state_b)
                .expect("write B");
            PoolMigrations::for_account(&mut conn, account_a)
                .expect("account A exists")
                .replace_migration(&state_a_2)
                .expect("write A second");

            prop_assert_eq!(
                PoolMigrations::for_account(&conn, account_a)
                    .expect("account A exists")
                    .get_migration()
                    .expect("read A"),
                Some(state_a_2)
            );
            prop_assert_eq!(
                PoolMigrations::for_account(&conn, account_b)
                    .expect("account B exists")
                    .get_migration()
                    .expect("read B"),
                Some(state_b)
            );
        }

        /// A second `replace_migration` for the same account still replaces: the per-account
        /// singleton semantics hold (enforced by the unique index over `account_id`), because
        /// the account's existing row is deleted before the new one is inserted.
        #[test]
        fn replace_migration_replaces_same_account(
            first in arb_migration_state(),
            second in arb_migration_state(),
        ) {
            let conn = fresh_conn();
            let account = insert_account(&conn);
            let mut store = PoolMigrations::for_account(conn, account).expect("account exists");
            store.replace_migration(&first).expect("write first");
            store.replace_migration(&second).expect("write second");
            prop_assert_eq!(store.get_migration().expect("read"), Some(second));
        }

        /// `update_transaction` is scoped to its account: advancing a transaction's state for
        /// account A does not affect account B's migration on the same connection, even when both
        /// accounts started from the same migration state (and so share the updated `tx_id`).
        #[test]
        fn update_transaction_is_scoped_to_its_account(
            state in arb_migration_state(),
            new in arb_migration_tx_state(),
        ) {
            prop_assume!(!state.transactions().is_empty());
            let id = first_transaction_id(&state).expect("non-empty by the assumption above");

            let mut conn = fresh_conn();
            let account_a = insert_account(&conn);
            let account_b = insert_account(&conn);

            PoolMigrations::for_account(&mut conn, account_a)
                .expect("account A exists")
                .replace_migration(&state)
                .expect("write A");
            PoolMigrations::for_account(&mut conn, account_b)
                .expect("account B exists")
                .replace_migration(&state)
                .expect("write B");

            PoolMigrations::for_account(&mut conn, account_a)
                .expect("account A exists")
                .update_transaction(id, new)
                .expect("update A");

            prop_assert_eq!(
                PoolMigrations::for_account(&conn, account_b)
                    .expect("account B exists")
                    .get_migration()
                    .expect("read B"),
                Some(state),
                "account B's migration must be unaffected by account A's update_transaction",
            );
        }
    }
}
