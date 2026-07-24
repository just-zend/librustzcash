//! SQLite persistence for value-pool migrations (ZIP 318).
//!
//! This module implements [`zcash_pool_migration`]'s [`PoolMigrationRead`] /
//! [`PoolMigrationWrite`] store traits over a set of SQLite tables in the wallet database,
//! mirroring how this crate implements `zcash_client_backend`'s `WalletRead` / `WalletWrite`. A
//! committed migration is a set of pre-signed PCZTs plus their schedule and lifecycle state, so a
//! wallet resumes a migration entirely from these tables after being closed or restarted.
//!
//! The schema is fully NORMALIZED: every structured value (the note-split plan, the preparation
//! plan's transaction inputs/outputs and direct-funding notes, the transaction kind, and the
//! dependency graph) is stored in typed columns and child tables, so it can be queried directly.
//! The `BLOB` columns are the pre-signed transaction (`pczt`), which is genuinely unstructured,
//! already-versioned bytes, and the transaction's `lock_owner` (an opaque fixed-size token, not a
//! structured value); all amounts are zatoshi `INTEGER` columns and the broadcast `txid` is
//! hex `TEXT`. It is also MINIMAL: values derivable from other columns get no tables of their own
//! (the funding-note values are the crossing values plus the fee buffer, and the preparation
//! plan's layers/transactions grid is implied by the input and output rows' `(layer, tx_index)`
//! coordinates, since a real plan has no empty layer and no transaction without inputs and
//! outputs).
//!
//! # Structure: one generic store, one public submodule per pool
//!
//! The generic, pool-agnostic store machinery (the DDL builders and the SQL store logic) lives in
//! a private `store` submodule, parameterized over the per-pool table names, with the error type
//! in a private `error` submodule. Because the schema is normalized, the store maps the engine
//! types to and from typed columns and child-table rows directly (only the opaque `pczt` is stored
//! as bytes), rather than through a blob codec. Each pool migration is a public submodule that
//! instantiates the store with its own table names and exposes the concrete API; the generic store
//! type never appears in the public surface. This lets future pool migrations reuse the same
//! machinery under their own tables. Currently the only such submodule is [`orchard_ironwood`]
//! (the Orchard -> Ironwood migration), whose tables are all prefixed
//! `orchard_ironwood_migration[s]_`.
//!
//! # Schema registration
//!
//! Each pool submodule exposes its table DDL as an idempotent `init_migration_tables`; the
//! corresponding `schemerz` migration in `crate::wallet::init::migrations` (for Orchard ->
//! Ironwood, `orchard_ironwood_migration_tables`) runs that DDL inside the wallet schema, so the
//! pool-migration tables live in the same `wallet.db` and share its schema versioning.
//!
//! # Model
//!
//! There is at most one migration in progress per pool per account, stored as a row in the pool's
//! migrations table keyed by an `account_id` foreign key into `accounts` (with `ON DELETE CASCADE`,
//! so an account's migration is removed with the account), with its transactions, note split, and
//! preparation plan in the pool's child tables (addressed through that row's synthetic primary
//! key). The pool's `PoolMigrations` type is the store: construct it over a `rusqlite::Connection`
//! (the same one [`WalletDb`](crate::WalletDb) uses) and the [`AccountUuid`](crate::AccountUuid)
//! whose migration it tracks, which it resolves to that account's row up front.
//!
//! [`PoolMigrationRead`]: zcash_pool_migration::engine::PoolMigrationRead
//! [`PoolMigrationWrite`]: zcash_pool_migration::engine::PoolMigrationWrite

mod error;
mod store;

pub mod orchard_ironwood;

#[cfg(feature = "migration-delivery")]
use {
    prost::Message,
    rand_core::{CryptoRng, RngCore},
    zcash_address::ZcashAddress,
    zcash_client_backend::{
        data_api::wallet::{
            ConfirmationsPolicy, input_selection::LockedInputPolicy,
            propose_send_max_transfer_unlocked,
        },
        data_api::{Account as _, MaxSpendMode, WalletRead as _},
        fees::StandardFeeRule,
        proposal::Proposal,
        wallet::{LockOwner, OutputRef},
    },
    zcash_keys::address::UnifiedAddress,
    zcash_note_encryption::try_note_decryption,
    zcash_pool_migration::delivery::{
        ClaimKind, ClaimToken, DeliveryFailureReason, DeliveryRevision, DeliverySnapshot,
        ExactTransaction, ExternalSigningPczt, ImmediateArtifactEvidence,
        ImmediateArtifactIdentity, ImmediateMigrationDeliveryStore, ImmediateMigrationIntent,
        ImmediateProposal, ImmediateProposalPayload, LeaseDuration, MigrationRunIdentity,
        PolicyFingerprint, ReservedImmediateArtifact, SignedPcztEvidence, SignerOwnership,
        SourceReservationOwner, SubmissionContext, SubmissionOutcome, SubmissionPolicy,
    },
    zcash_primitives::transaction::{Transaction, builder::DEFAULT_TX_EXPIRY_DELTA},
    zcash_protocol::{
        PoolType, ShieldedPool,
        consensus::{BlockHeight, BranchId},
        value::{ZatBalance, Zatoshis},
    },
    zip32::Scope,
};

#[cfg(feature = "migration-delivery")]
fn immediate_internal_recipient(
    account: &crate::wallet::Account,
    network: zcash_protocol::consensus::NetworkType,
) -> Result<(ZcashAddress, orchard::Address), orchard_ironwood::Error> {
    let orchard_fvk = account
        .ufvk()
        .and_then(|ufvk| ufvk.orchard())
        .ok_or(orchard_ironwood::Error::DeliveryArtifactMismatch)?;
    let receiver = orchard_fvk.address_at(0u32, Scope::Internal);
    let address = UnifiedAddress::from_receivers(Some(receiver), None, None)
        .ok_or(orchard_ironwood::Error::DeliveryArtifactMismatch)?
        .to_zcash_address(network);
    Ok((address, receiver))
}

#[cfg(feature = "migration-delivery")]
/// Opaque, post-commit immediate proposal and delivery evidence owned by SQLite.
///
/// Values can only be created after proposal selection, reservations, wallet locks, policy, and
/// the initial materialization claim have committed atomically. Callers may inspect the trait
/// views but cannot construct or alter this authority.
pub struct SqliteReservedImmediateArtifact {
    proposal: Proposal<StandardFeeRule, crate::ReceivedNoteId>,
    snapshot: DeliverySnapshot,
    evidence: ImmediateArtifactEvidence,
}

/// Non-forgeable proof, constructed only after validating the exact persisted proposal and a
/// canonical external-signing PCZT in the same SQLite transaction that consumes it.
#[cfg(feature = "migration-delivery")]
struct ValidatedImmediatePczt {
    artifact_identity: ImmediateArtifactIdentity,
    proposal_digest: zcash_pool_migration::delivery::ImmediateProposalDigest,
    pczt_digest: zcash_pool_migration::delivery::PcztDigest,
}

/// Non-forgeable proof, constructed only after validating exact consensus effects against the
/// persisted proposal and wallet account in the same SQLite transaction that consumes it.
#[cfg(feature = "migration-delivery")]
struct ValidatedImmediateTransaction {
    artifact_identity: ImmediateArtifactIdentity,
    proposal_digest: zcash_pool_migration::delivery::ImmediateProposalDigest,
    exact_digest: zcash_pool_migration::delivery::ExactTransactionDigest,
    destination_output_index: u32,
    ironwood_amount: Zatoshis,
}

#[cfg(feature = "migration-delivery")]
mod immediate_delivery_write {
    /// A private write capability that exists only while an IMMEDIATE transaction or a nested
    /// savepoint is active. Multi-write delivery helpers accept this type instead of `Connection`,
    /// so they cannot accidentally be called in autocommit mode. Dropping it without `commit`
    /// rolls back the complete write unit, including when the SDK materializer already owns the
    /// outer wallet transaction.
    pub(in crate::pool_migration) struct Transaction<'conn> {
        boundary: Boundary<'conn>,
    }

    enum Boundary<'conn> {
        Immediate(Option<rusqlite::Transaction<'conn>>),
        Savepoint {
            conn: &'conn rusqlite::Connection,
            name: String,
            active: bool,
        },
    }

    impl<'conn> Transaction<'conn> {
        pub(in crate::pool_migration) fn begin(
            conn: &'conn rusqlite::Connection,
        ) -> rusqlite::Result<Self> {
            let boundary = if conn.is_autocommit() {
                Boundary::Immediate(Some(rusqlite::Transaction::new_unchecked(
                    conn,
                    rusqlite::TransactionBehavior::Immediate,
                )?))
            } else {
                static NEXT_SAVEPOINT: std::sync::atomic::AtomicU64 =
                    std::sync::atomic::AtomicU64::new(0);
                let sequence = NEXT_SAVEPOINT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let name = format!("zend_ironwood_immediate_delivery_write_{sequence}");
                conn.execute_batch(&format!("SAVEPOINT {name}"))?;
                Boundary::Savepoint {
                    conn,
                    name,
                    active: true,
                }
            };
            Ok(Self { boundary })
        }

        pub(in crate::pool_migration) fn connection(&self) -> &rusqlite::Connection {
            match &self.boundary {
                Boundary::Immediate(transaction) => transaction
                    .as_ref()
                    .expect("an active delivery write transaction owns its SQLite transaction"),
                Boundary::Savepoint { conn, .. } => conn,
            }
        }

        pub(in crate::pool_migration) fn commit(mut self) -> rusqlite::Result<()> {
            match &mut self.boundary {
                Boundary::Immediate(transaction) => transaction
                    .take()
                    .expect("an active delivery write transaction owns its SQLite transaction")
                    .commit(),
                Boundary::Savepoint { conn, name, active } => {
                    conn.execute_batch(&format!("RELEASE {name}"))?;
                    *active = false;
                    Ok(())
                }
            }
        }

        pub(in crate::pool_migration) fn rollback(mut self) -> rusqlite::Result<()> {
            match &mut self.boundary {
                Boundary::Immediate(transaction) => transaction
                    .take()
                    .expect("an active delivery write transaction owns its SQLite transaction")
                    .rollback(),
                Boundary::Savepoint { conn, name, active } => {
                    conn.execute_batch(&format!("ROLLBACK TO {name}; RELEASE {name}"))?;
                    *active = false;
                    Ok(())
                }
            }
        }
    }

    impl Drop for Transaction<'_> {
        fn drop(&mut self) {
            if let Boundary::Savepoint { conn, name, active } = &mut self.boundary
                && *active
            {
                let _ = conn.execute_batch(&format!("ROLLBACK TO {name}; RELEASE {name}"));
                *active = false;
            }
        }
    }
}

#[cfg(feature = "migration-delivery")]
pub(in crate::pool_migration) use immediate_delivery_write::Transaction as ImmediateDeliveryWriteTransaction;

#[cfg(feature = "migration-delivery")]
impl ReservedImmediateArtifact for SqliteReservedImmediateArtifact {
    type NoteRef = crate::ReceivedNoteId;

    fn wallet_proposal(&self) -> &Proposal<StandardFeeRule, Self::NoteRef> {
        &self.proposal
    }

    fn snapshot(&self) -> &DeliverySnapshot {
        &self.snapshot
    }

    fn evidence(&self) -> &ImmediateArtifactEvidence {
        &self.evidence
    }
}

#[cfg(feature = "migration-delivery")]
fn validate_immediate_wallet_proposal(
    proposal: &Proposal<StandardFeeRule, crate::ReceivedNoteId>,
    recipient: &ZcashAddress,
) -> Result<Vec<OutputRef>, orchard_ironwood::Error> {
    if proposal.steps().len() != 1
        || proposal.fee_rule() != &StandardFeeRule::Zip317
        || proposal.proposed_version().is_some()
    {
        return Err(orchard_ironwood::Error::DeliveryArtifactMismatch);
    }
    let step = &proposal.steps()[0];
    if !step.transparent_inputs().is_empty()
        || !step.prior_step_inputs().is_empty()
        || !step.balance().proposed_change().is_empty()
        || step.payment_pools().len() != 1
        || step.payment_pools().values().next() != Some(&PoolType::IRONWOOD)
    {
        return Err(orchard_ironwood::Error::DeliveryArtifactMismatch);
    }
    let payments = step.transaction_request().payments();
    if payments.len() != 1 {
        return Err(orchard_ironwood::Error::DeliveryArtifactMismatch);
    }
    let payment = payments
        .values()
        .next()
        .ok_or(orchard_ironwood::Error::DeliveryArtifactMismatch)?;
    if payment.recipient_address() != recipient
        || payment.amount().is_none_or(|amount| !amount.is_positive())
        || payment.memo().is_some()
    {
        return Err(orchard_ironwood::Error::DeliveryArtifactMismatch);
    }
    let sources = step
        .shielded_inputs()
        .ok_or(orchard_ironwood::Error::DeliveryArtifactMismatch)?
        .notes()
        .iter()
        .map(|note| {
            if note.note().pool() != ShieldedPool::Orchard {
                return Err(orchard_ironwood::Error::DeliveryArtifactMismatch);
            }
            Ok(OutputRef::new(
                *note.txid(),
                PoolType::ORCHARD,
                u32::from(note.output_index()),
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let distinct = sources
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    if sources.is_empty() || distinct.len() != sources.len() {
        return Err(orchard_ironwood::Error::DeliveryArtifactMismatch);
    }
    Ok(sources)
}

#[cfg(feature = "migration-delivery")]
fn parse_immediate_external_pczt(
    envelope: &ImmediateProposal,
    staged: &ExternalSigningPczt,
) -> Result<pczt::Pczt, orchard_ironwood::Error> {
    let parsed = pczt::Pczt::parse(staged.bytes())
        .map_err(|_| orchard_ironwood::Error::DeliveryArtifactMismatch)?;
    let canonical = parsed
        .clone()
        .serialize()
        .map_err(|_| orchard_ironwood::Error::DeliveryArtifactMismatch)?;
    let global = parsed.global();
    if canonical != staged.bytes()
        || *global.tx_version() != zcash_protocol::constants::V6_TX_VERSION
        || *global.version_group_id() != zcash_protocol::constants::V6_VERSION_GROUP_ID
        || *global.consensus_branch_id() != u32::from(envelope.branch_id())
        || *global.expiry_height() != u32::from(envelope.expiry_height())
        || pczt::common::determine_lock_time(global, parsed.transparent().inputs()) != Some(0)
        || !parsed.transparent().inputs().is_empty()
        || !parsed.transparent().outputs().is_empty()
        || !parsed.sapling().spends().is_empty()
        || !parsed.sapling().outputs().is_empty()
    {
        return Err(orchard_ironwood::Error::DeliveryArtifactMismatch);
    }
    Ok(parsed)
}

#[cfg(feature = "migration-delivery")]
fn validate_immediate_extracted_source_semantics<OrchardNullifiers, IronwoodNullifiers>(
    proposed_sources: &std::collections::BTreeMap<[u8; 32], u64>,
    orchard_nullifiers: OrchardNullifiers,
    orchard_outputs_enabled: bool,
    orchard_value_balance: ZatBalance,
    ironwood_nullifiers: IronwoodNullifiers,
    ironwood_spends_enabled: bool,
) -> Result<(), orchard_ironwood::Error>
where
    OrchardNullifiers: IntoIterator<Item = [u8; 32]>,
    IronwoodNullifiers: IntoIterator<Item = [u8; 32]>,
{
    let mut seen = std::collections::BTreeSet::new();
    for nullifier in orchard_nullifiers {
        if !seen.insert(nullifier) {
            return Err(orchard_ironwood::Error::DeliveryArtifactMismatch);
        }
    }
    let proposed_value = proposed_sources.values().try_fold(0u64, |sum, value| {
        sum.checked_add(*value)
            .ok_or(orchard_ironwood::Error::DeliveryArtifactMismatch)
    })?;
    let proposed_value = Zatoshis::from_u64(proposed_value)
        .map_err(|_| orchard_ironwood::Error::DeliveryArtifactMismatch)?;
    // Consensus proofs enforce the bundle flags. With Orchard outputs disabled, the exact
    // positive value balance is the sum of every spend. Because note values are nonnegative and
    // every proposed nullifier is present, equality with the checked proposal-input sum proves
    // that every additional padding spend has value zero. The Ironwood spends-disabled flag
    // likewise proves that every destination-pool spend is a dummy.
    if orchard_outputs_enabled
        || orchard_value_balance != ZatBalance::from(proposed_value)
        || !proposed_sources
            .keys()
            .all(|nullifier| seen.contains(nullifier))
        || ironwood_spends_enabled
    {
        return Err(orchard_ironwood::Error::DeliveryArtifactMismatch);
    }
    for nullifier in ironwood_nullifiers {
        if !seen.insert(nullifier) {
            return Err(orchard_ironwood::Error::DeliveryArtifactMismatch);
        }
    }
    Ok(())
}

#[cfg(feature = "migration-delivery")]
fn validate_immediate_pczt_source_semantics(
    parsed: &pczt::Pczt,
    orchard_fvk: &orchard::keys::FullViewingKey,
    proposed_sources: &std::collections::BTreeMap<[u8; 32], u64>,
) -> Result<(), orchard_ironwood::Error> {
    let mut seen_nullifiers = std::collections::BTreeSet::new();
    let mut seen_proposed = std::collections::BTreeSet::new();
    let verifier = pczt::roles::verifier::Verifier::new(parsed.clone())
        .with_orchard::<(), _>(|bundle| {
            bundle.verify_cross_address_restriction()?;
            for action in bundle.actions() {
                let nullifier = action.spend().nullifier().to_bytes();
                if !seen_nullifiers.insert(nullifier) {
                    return Err(pczt::roles::verifier::OrchardError::Custom(()));
                }
                let value = action
                    .spend()
                    .value()
                    .as_ref()
                    .map(|value| value.inner())
                    .ok_or(pczt::roles::verifier::OrchardError::Custom(()))?;
                match proposed_sources.get(&nullifier) {
                    Some(expected) if *expected == value => {
                        seen_proposed.insert(nullifier);
                    }
                    Some(_) => return Err(pczt::roles::verifier::OrchardError::Custom(())),
                    None if value == 0 => {}
                    None => return Err(pczt::roles::verifier::OrchardError::Custom(())),
                }
                action.verify_cv_net()?;
                action.spend().verify_nullifier(Some(orchard_fvk))?;
                action.spend().verify_rk(Some(orchard_fvk))?;
                action.output().verify_note_commitment(action.spend())?;
            }
            Ok(())
        })
        .map_err(|_| orchard_ironwood::Error::DeliveryArtifactMismatch)?;
    verifier
        .with_ironwood::<(), _>(|bundle| {
            bundle.verify_cross_address_restriction()?;
            for action in bundle.actions() {
                let nullifier = action.spend().nullifier().to_bytes();
                if !seen_nullifiers.insert(nullifier)
                    || !matches!(action.spend().value(), Some(value) if value.inner() == 0)
                {
                    return Err(pczt::roles::verifier::OrchardError::Custom(()));
                }
                action.verify_cv_net()?;
                action.spend().verify_nullifier(Some(orchard_fvk))?;
                action.spend().verify_rk(Some(orchard_fvk))?;
                action.output().verify_note_commitment(action.spend())?;
            }
            Ok(())
        })
        .map_err(|_| orchard_ironwood::Error::DeliveryArtifactMismatch)?;
    if seen_proposed.len() != proposed_sources.len() {
        return Err(orchard_ironwood::Error::DeliveryArtifactMismatch);
    }
    Ok(())
}

#[cfg(feature = "migration-delivery")]
fn validate_immediate_external_pczt<P: zcash_protocol::consensus::Parameters>(
    params: &P,
    account: &crate::wallet::Account,
    proposal: &Proposal<StandardFeeRule, crate::ReceivedNoteId>,
    evidence: &ImmediateArtifactEvidence,
    staged: &ExternalSigningPczt,
) -> Result<ValidatedImmediatePczt, orchard_ironwood::Error> {
    use zcash_primitives::transaction::components::orchard::bundle_version_for_branch;

    let envelope = ImmediateProposal::decode(evidence.canonical_proposal())
        .map_err(|_| orchard_ironwood::Error::DeliveryArtifactMismatch)?;
    if envelope.target_height() != BlockHeight::from(proposal.min_target_height())
        || envelope.expiry_height() != evidence.expiry_height()
        || BranchId::for_height(params, envelope.target_height()) != envelope.branch_id()
    {
        return Err(orchard_ironwood::Error::DeliveryArtifactMismatch);
    }

    let parsed = parse_immediate_external_pczt(&envelope, staged)?;

    let step = proposal.steps().first();
    let orchard_fvk = account
        .ufvk()
        .and_then(|ufvk| ufvk.orchard())
        .ok_or(orchard_ironwood::Error::DeliveryArtifactMismatch)?;
    let proposed_notes = step
        .shielded_inputs()
        .ok_or(orchard_ironwood::Error::DeliveryArtifactMismatch)?
        .notes();
    let proposed_sources = proposed_notes
        .iter()
        .map(|received| match received.note() {
            zcash_client_backend::wallet::Note::Orchard {
                note,
                pool: orchard::ValuePool::Orchard,
            } => Ok((note.nullifier(orchard_fvk).to_bytes(), note.value().inner())),
            _ => Err(orchard_ironwood::Error::DeliveryArtifactMismatch),
        })
        .collect::<Result<std::collections::BTreeMap<_, _>, _>>()?;
    if proposed_sources.len() != proposed_notes.len() {
        return Err(orchard_ironwood::Error::DeliveryArtifactMismatch);
    }

    validate_immediate_pczt_source_semantics(&parsed, orchard_fvk, &proposed_sources)?;
    let orchard_version =
        bundle_version_for_branch(envelope.branch_id(), orchard::ValuePool::Orchard)
            .ok_or(orchard_ironwood::Error::DeliveryArtifactMismatch)?;
    let expected_orchard_actions = step
        .orchard_action_count(orchard::builder::BundleType::DEFAULT, orchard_version)
        .map_err(|_| orchard_ironwood::Error::DeliveryArtifactMismatch)?;
    if proposed_sources.len() > expected_orchard_actions
        || parsed.orchard().actions().len() != expected_orchard_actions
        || parsed
            .orchard()
            .actions()
            .iter()
            .any(|action| action.output().value() != &Some(0))
    {
        return Err(orchard_ironwood::Error::DeliveryArtifactMismatch);
    }

    let amount = step
        .transaction_request()
        .payments()
        .values()
        .next()
        .and_then(|payment| payment.amount())
        .ok_or(orchard_ironwood::Error::DeliveryArtifactMismatch)?;
    let fee = step.balance().fee_required();
    let expected_orchard_value = u64::from(amount)
        .checked_add(u64::from(fee))
        .ok_or(orchard_ironwood::Error::DeliveryArtifactMismatch)?;
    if *parsed.orchard().value_sum() != (expected_orchard_value, false)
        || *parsed.ironwood().value_sum() != (u64::from(amount), true)
    {
        return Err(orchard_ironwood::Error::DeliveryArtifactMismatch);
    }

    let (_, expected_receiver) = immediate_internal_recipient(account, params.network_type())?;
    let expected_receiver = expected_receiver.to_raw_address_bytes();
    let ironwood_version =
        bundle_version_for_branch(envelope.branch_id(), orchard::ValuePool::Ironwood)
            .ok_or(orchard_ironwood::Error::DeliveryArtifactMismatch)?;
    let expected_ironwood_actions = step
        .ironwood_action_count(orchard::builder::BundleType::DEFAULT, ironwood_version)
        .map_err(|_| orchard_ironwood::Error::DeliveryArtifactMismatch)?;
    let mut destinations = 0usize;
    for action in parsed.ironwood().actions() {
        match *action.output().value() {
            Some(value) if value == u64::from(amount) => {
                if action.output().recipient().as_ref() != Some(&expected_receiver) {
                    return Err(orchard_ironwood::Error::DeliveryArtifactMismatch);
                }
                destinations += 1;
            }
            Some(0) => {}
            _ => return Err(orchard_ironwood::Error::DeliveryArtifactMismatch),
        }
    }
    if parsed.ironwood().actions().len() != expected_ironwood_actions || destinations != 1 {
        return Err(orchard_ironwood::Error::DeliveryArtifactMismatch);
    }

    Ok(ValidatedImmediatePczt {
        artifact_identity: evidence.identity(),
        proposal_digest: envelope.digest(),
        pczt_digest: staged.digest(),
    })
}

#[cfg(feature = "migration-delivery")]
fn validate_immediate_exact_transaction<P: zcash_protocol::consensus::Parameters>(
    params: &P,
    account: &crate::wallet::Account,
    proposal: &Proposal<StandardFeeRule, crate::ReceivedNoteId>,
    evidence: &ImmediateArtifactEvidence,
    exact: &ExactTransaction,
) -> Result<ValidatedImmediateTransaction, orchard_ironwood::Error> {
    use zcash_primitives::transaction::components::orchard::bundle_version_for_branch;

    let envelope = ImmediateProposal::decode(evidence.canonical_proposal())
        .map_err(|_| orchard_ironwood::Error::DeliveryArtifactMismatch)?;
    if envelope.target_height() != BlockHeight::from(proposal.min_target_height())
        || envelope.expiry_height() != exact.consensus_expiry_height()
        || BranchId::for_height(params, envelope.target_height()) != envelope.branch_id()
    {
        return Err(orchard_ironwood::Error::DeliveryArtifactMismatch);
    }
    if exact.artifact_identity()
        != zcash_pool_migration::delivery::DeliveryArtifactIdentity::Immediate(evidence.identity())
        || exact.consensus_expiry_height() != evidence.expiry_height()
    {
        return Err(orchard_ironwood::Error::DeliveryArtifactMismatch);
    }
    let branch_id = envelope.branch_id();
    let mut encoded = exact.bytes();
    let transaction = Transaction::read(&mut encoded, branch_id)
        .map_err(|_| orchard_ironwood::Error::DeliveryArtifactMismatch)?;
    if !encoded.is_empty()
        || transaction.txid() != exact.txid()
        || transaction.expiry_height() != evidence.expiry_height()
        || transaction.lock_time() != 0
        || transaction.transparent_bundle().is_some()
        || transaction.sapling_bundle().is_some()
        || transaction.sprout_bundle().is_some()
    {
        return Err(orchard_ironwood::Error::DeliveryArtifactMismatch);
    }

    let step = proposal.steps().first();
    let account_ufvk = account
        .ufvk()
        .ok_or(orchard_ironwood::Error::DeliveryArtifactMismatch)?;
    let orchard_fvk = account_ufvk
        .orchard()
        .ok_or(orchard_ironwood::Error::DeliveryArtifactMismatch)?;
    let proposed_notes = step
        .shielded_inputs()
        .ok_or(orchard_ironwood::Error::DeliveryArtifactMismatch)?
        .notes();
    let proposed_sources = proposed_notes
        .iter()
        .map(|received| match received.note() {
            zcash_client_backend::wallet::Note::Orchard {
                note,
                pool: orchard::ValuePool::Orchard,
            } => Ok((note.nullifier(orchard_fvk).to_bytes(), note.value().inner())),
            _ => Err(orchard_ironwood::Error::DeliveryArtifactMismatch),
        })
        .collect::<Result<std::collections::BTreeMap<_, _>, _>>()?;
    if proposed_sources.len() != proposed_notes.len() {
        return Err(orchard_ironwood::Error::DeliveryArtifactMismatch);
    }
    let orchard_bundle = transaction
        .orchard_bundle()
        .ok_or(orchard_ironwood::Error::DeliveryArtifactMismatch)?;
    let orchard_version = bundle_version_for_branch(branch_id, orchard::ValuePool::Orchard)
        .ok_or(orchard_ironwood::Error::DeliveryArtifactMismatch)?;
    let expected_orchard_actions = step
        .orchard_action_count(orchard::builder::BundleType::DEFAULT, orchard_version)
        .map_err(|_| orchard_ironwood::Error::DeliveryArtifactMismatch)?;
    if orchard_bundle.actions().len() != expected_orchard_actions
        || proposed_sources.len() > expected_orchard_actions
    {
        return Err(orchard_ironwood::Error::DeliveryArtifactMismatch);
    }

    let payment = step
        .transaction_request()
        .payments()
        .values()
        .next()
        .ok_or(orchard_ironwood::Error::DeliveryArtifactMismatch)?;
    let amount = payment
        .amount()
        .ok_or(orchard_ironwood::Error::DeliveryArtifactMismatch)?;
    let (_, expected_receiver) = immediate_internal_recipient(account, params.network_type())?;
    let ironwood_bundle = transaction
        .ironwood_bundle()
        .ok_or(orchard_ironwood::Error::DeliveryArtifactMismatch)?;
    let ironwood_version = bundle_version_for_branch(branch_id, orchard::ValuePool::Ironwood)
        .ok_or(orchard_ironwood::Error::DeliveryArtifactMismatch)?;
    let expected_ironwood_actions = step
        .ironwood_action_count(orchard::builder::BundleType::DEFAULT, ironwood_version)
        .map_err(|_| orchard_ironwood::Error::DeliveryArtifactMismatch)?;
    validate_immediate_extracted_source_semantics(
        &proposed_sources,
        orchard_bundle
            .actions()
            .iter()
            .map(|action| action.nullifier().to_bytes()),
        orchard_bundle.flags().outputs_enabled(),
        *orchard_bundle.value_balance(),
        ironwood_bundle
            .actions()
            .iter()
            .map(|action| action.nullifier().to_bytes()),
        ironwood_bundle.flags().spends_enabled(),
    )?;
    if ironwood_bundle.actions().len() != expected_ironwood_actions
        || *ironwood_bundle.value_balance() != -ZatBalance::from(amount)
    {
        return Err(orchard_ironwood::Error::DeliveryArtifactMismatch);
    }
    let internal_ivk =
        orchard::keys::PreparedIncomingViewingKey::new(&orchard_fvk.to_ivk(Scope::Internal));
    let mut destination = None;
    for (index, action) in ironwood_bundle.actions().iter().enumerate() {
        let domain = orchard::note_encryption::IronwoodDomain::for_action(action);
        if let Some((note, recipient, _)) = try_note_decryption(&domain, &internal_ivk, action) {
            let value = Zatoshis::from_u64(note.value().inner())
                .map_err(|_| orchard_ironwood::Error::DeliveryArtifactMismatch)?;
            if destination.is_some() || recipient != expected_receiver || value != amount {
                return Err(orchard_ironwood::Error::DeliveryArtifactMismatch);
            }
            destination = Some((
                u32::try_from(index)
                    .map_err(|_| orchard_ironwood::Error::DeliveryArtifactMismatch)?,
                value,
            ));
        }
    }
    let destination = destination.ok_or(orchard_ironwood::Error::DeliveryArtifactMismatch)?;
    let actual_fee = transaction
        .fee_paid::<zcash_protocol::value::BalanceError, _>(|_| Ok(None))
        .map_err(|_| orchard_ironwood::Error::DeliveryArtifactMismatch)?
        .ok_or(orchard_ironwood::Error::DeliveryArtifactMismatch)?;
    if actual_fee != step.balance().fee_required() {
        return Err(orchard_ironwood::Error::DeliveryArtifactMismatch);
    }
    Ok(ValidatedImmediateTransaction {
        artifact_identity: evidence.identity(),
        proposal_digest: envelope.digest(),
        exact_digest: exact.digest(),
        destination_output_index: destination.0,
        ironwood_amount: destination.1,
    })
}

#[cfg(feature = "migration-delivery")]
impl<C: std::borrow::Borrow<rusqlite::Connection>, P, CL, R> crate::WalletDb<C, P, CL, R> {
    /// Reserves SQLite's writer before deriving an immediate proposal, so wallet selection,
    /// proposal serialization, source reservation, locks, evidence, policy, and the initial claim
    /// commit as one atomic revision without a deferred read-to-write upgrade race.
    fn immediate_delivery_transactionally<F, A, E: From<rusqlite::Error>>(
        &mut self,
        f: F,
    ) -> Result<A, E>
    where
        F: FnOnce(
            &mut crate::WalletDb<&rusqlite::Connection, &P, &CL, &mut R>,
            &ImmediateDeliveryWriteTransaction<'_>,
        ) -> Result<A, E>,
    {
        let conn = self.conn.borrow();
        let transaction = ImmediateDeliveryWriteTransaction::begin(conn)?;
        let result = {
            let mut wallet_db = crate::WalletDb {
                conn: transaction.connection(),
                params: &self.params,
                clock: &self.clock,
                rng: &mut self.rng,
                #[cfg(feature = "transparent-inputs")]
                gap_limits: self.gap_limits,
            };
            f(&mut wallet_db, &transaction)
        };
        match result {
            Ok(value) => {
                transaction.commit()?;
                Ok(value)
            }
            Err(error) => match transaction.rollback() {
                Ok(()) => Err(error),
                Err(rollback_error) => Err(E::from(rollback_error)),
            },
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn claim_immediate_capability(
        &mut self,
        account_id: &crate::AccountUuid,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        artifact_identity: ImmediateArtifactIdentity,
        lease_duration: LeaseDuration,
        expected_policy_fingerprint: PolicyFingerprint,
        kind: ClaimKind,
    ) -> Result<Option<DeliverySnapshot>, orchard_ironwood::Error>
    where
        P: zcash_protocol::consensus::Parameters,
    {
        let context = SubmissionContext::from_parameters(self.params());
        self.immediate_delivery_transactionally(|wallet_db, _transaction| {
            let account_ref = store::account_ref(wallet_db.conn, account_id)?
                .ok_or(orchard_ironwood::Error::AccountUnknown)?;
            store::claim_immediate(
                wallet_db.conn,
                &orchard_ironwood::TABLES,
                account_ref,
                context,
                expected_revision,
                run_identity,
                artifact_identity,
                lease_duration,
                expected_policy_fingerprint,
                kind,
            )
        })
    }

    fn set_immediate_delivery_phase(
        &mut self,
        account_id: &crate::AccountUuid,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        expected_phase: zcash_pool_migration::delivery::DeliveryPhase,
        successor_phase: zcash_pool_migration::delivery::DeliveryPhase,
    ) -> Result<DeliverySnapshot, orchard_ironwood::Error>
    where
        P: zcash_protocol::consensus::Parameters,
    {
        let context = SubmissionContext::from_parameters(self.params());
        self.immediate_delivery_transactionally(|wallet_db, _transaction| {
            let account_ref = store::account_ref(wallet_db.conn, account_id)?
                .ok_or(orchard_ironwood::Error::AccountUnknown)?;
            store::set_immediate_phase(
                wallet_db.conn,
                &orchard_ironwood::TABLES,
                account_ref,
                context,
                expected_revision,
                run_identity,
                expected_phase,
                successor_phase,
            )
        })
    }
}

#[cfg(feature = "migration-delivery")]
impl<C, P, CL, R> ImmediateMigrationDeliveryStore for crate::WalletDb<C, P, CL, R>
where
    C: std::borrow::Borrow<rusqlite::Connection>,
    P: zcash_protocol::consensus::Parameters + Clone,
    CL: crate::util::Clock,
    R: RngCore + CryptoRng,
{
    type Error = orchard_ironwood::Error;
    type AccountId = crate::AccountUuid;
    type NoteRef = crate::ReceivedNoteId;
    type ReservedArtifact = SqliteReservedImmediateArtifact;

    fn reserve_immediate_delivery(
        &mut self,
        intent: ImmediateMigrationIntent<Self::AccountId>,
        policy: &SubmissionPolicy,
        lease_duration: LeaseDuration,
    ) -> Result<Self::ReservedArtifact, Self::Error> {
        self.immediate_delivery_transactionally(|wallet_db, transaction| {
            let context = SubmissionContext::from_parameters(wallet_db.params());
            if policy.request().context() != context {
                return Err(orchard_ironwood::Error::DeliveryPolicyMismatch);
            }
            let account = wallet_db
                .get_account(*intent.account_id())
                .map_err(orchard_ironwood::Error::Wallet)?
                .ok_or(orchard_ironwood::Error::AccountUnknown)?;
            let (recipient, _) =
                immediate_internal_recipient(&account, wallet_db.params().network_type())?;
            let params = *wallet_db.params();
            let proposal = propose_send_max_transfer_unlocked::<_, _, _, std::convert::Infallible>(
                wallet_db,
                &params,
                *intent.account_id(),
                &[ShieldedPool::Orchard],
                &StandardFeeRule::Zip317,
                recipient.clone(),
                None,
                MaxSpendMode::MaxSpendable,
                ConfirmationsPolicy::default(),
                &LockedInputPolicy::Exclude,
            )
            .map_err(|_| orchard_ironwood::Error::DeliveryClaimUnavailable)?;
            let sources = validate_immediate_wallet_proposal(&proposal, &recipient)?;
            let target_height = BlockHeight::from(proposal.min_target_height());
            let expiry_height = u32::from(target_height)
                .checked_add(DEFAULT_TX_EXPIRY_DELTA)
                .map(BlockHeight::from_u32)
                .ok_or(orchard_ironwood::Error::DeliveryArtifactMismatch)?;
            let payload =
                zcash_client_backend::proto::proposal::Proposal::from_standard_proposal(&proposal)
                    .encode_to_vec();
            let branch_id = BranchId::for_height(&params, target_height);
            let proposal_envelope = ImmediateProposal::new(
                target_height,
                expiry_height,
                branch_id,
                ImmediateProposalPayload::try_from(payload)
                    .map_err(|_| orchard_ironwood::Error::DeliveryValueTooLarge)?,
            )
            .map_err(|_| orchard_ironwood::Error::DeliveryArtifactMismatch)?;
            let run_identity = MigrationRunIdentity::random(&mut wallet_db.rng);
            let artifact_identity = ImmediateArtifactIdentity::random(&mut wallet_db.rng);
            let source_owner = SourceReservationOwner::random(&mut wallet_db.rng);
            let lock_owner = loop {
                let candidate = LockOwner::random(&mut wallet_db.rng);
                if candidate.as_bytes() != source_owner.as_bytes() {
                    break candidate;
                }
            };
            let evidence =
                ImmediateArtifactEvidence::from_proposal(artifact_identity, &proposal_envelope);
            let lease = store::checked_delivery_lease(ClaimKind::Materialization, lease_duration)?;
            let account_id = account.internal_id();
            let snapshot = store::reserve_immediate_delivery(
                transaction,
                &orchard_ironwood::TABLES,
                account_id,
                &proposal_envelope,
                &evidence,
                &sources,
                run_identity,
                source_owner,
                lock_owner,
                intent.signer_ownership(),
                lease,
                policy,
                context,
                intent.maximum_gross_amount(),
            )?;
            Ok(SqliteReservedImmediateArtifact {
                proposal,
                snapshot,
                evidence,
            })
        })
    }

    fn immediate_runtime_snapshot(
        &mut self,
        account_id: &Self::AccountId,
    ) -> Result<zcash_pool_migration::delivery::MigrationRuntimeSnapshot, Self::Error> {
        let context = SubmissionContext::from_parameters(self.params());
        with_atomic_delivery_view(self.conn.borrow(), |conn| {
            store::load_account_migration_runtime(
                conn,
                &orchard_ironwood::TABLES,
                *account_id,
                context,
            )?
            .map(|runtime| runtime.runtime().clone())
            .ok_or(orchard_ironwood::Error::AccountUnknown)
        })
    }

    fn reacquire_failed_immediate_materialization(
        &mut self,
        account_id: &Self::AccountId,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        artifact_identity: ImmediateArtifactIdentity,
        signer_ownership: SignerOwnership,
        maximum_gross_amount: Zatoshis,
        lease_duration: LeaseDuration,
        expected_policy_fingerprint: PolicyFingerprint,
    ) -> Result<DeliverySnapshot, Self::Error> {
        let context = SubmissionContext::from_parameters(self.params());
        self.immediate_delivery_transactionally(|wallet_db, transaction| {
            let account_ref = store::account_ref(wallet_db.conn, account_id)?
                .ok_or(orchard_ironwood::Error::AccountUnknown)?;
            store::reacquire_failed_immediate_materialization(
                transaction,
                &orchard_ironwood::TABLES,
                account_ref,
                context,
                expected_revision,
                run_identity,
                artifact_identity,
                signer_ownership,
                maximum_gross_amount,
                lease_duration,
                expected_policy_fingerprint,
            )
        })
    }

    fn reacquire_immediate_external_signing(
        &mut self,
        account_id: &Self::AccountId,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        artifact_identity: ImmediateArtifactIdentity,
        lease_duration: LeaseDuration,
        expected_policy_fingerprint: PolicyFingerprint,
    ) -> Result<Option<DeliverySnapshot>, Self::Error> {
        let context = SubmissionContext::from_parameters(self.params());
        self.immediate_delivery_transactionally(|wallet_db, _transaction| {
            let account_ref = store::account_ref(wallet_db.conn, account_id)?
                .ok_or(orchard_ironwood::Error::AccountUnknown)?;
            store::reacquire_immediate_external_signing(
                wallet_db.conn,
                &orchard_ironwood::TABLES,
                account_ref,
                context,
                expected_revision,
                run_identity,
                artifact_identity,
                lease_duration,
                expected_policy_fingerprint,
            )
        })
    }

    fn stage_immediate_external_signing_pczt(
        &mut self,
        account_id: &Self::AccountId,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        artifact_identity: ImmediateArtifactIdentity,
        token: ClaimToken,
        pczt: &ExternalSigningPczt,
        expected_policy_fingerprint: PolicyFingerprint,
    ) -> Result<DeliverySnapshot, Self::Error> {
        let context = SubmissionContext::from_parameters(self.params());
        self.immediate_delivery_transactionally(|wallet_db, _transaction| {
            let account = wallet_db
                .get_account(*account_id)
                .map_err(orchard_ironwood::Error::Wallet)?
                .ok_or(orchard_ironwood::Error::AccountUnknown)?;
            let account_ref = account.internal_id();
            let (current, _) = store::load_immediate_delivery_runtime_parts(
                wallet_db.conn,
                &orchard_ironwood::TABLES,
                account_ref,
                context,
            )?;
            let snapshot = current
                .map(|(snapshot, _)| snapshot)
                .ok_or(orchard_ironwood::Error::DeliveryClaimUnavailable)?;
            if snapshot.revision() != expected_revision || snapshot.run_identity() != run_identity {
                return Err(orchard_ironwood::Error::DeliveryRevisionMismatch);
            }
            let evidence = match snapshot.claims().first().map(|claim| claim.evidence()) {
                Some(zcash_pool_migration::delivery::DeliveryArtifactEvidence::Immediate(
                    evidence,
                )) if evidence.identity() == artifact_identity => evidence.clone(),
                _ => return Err(orchard_ironwood::Error::DeliveryArtifactMismatch),
            };
            let envelope = ImmediateProposal::decode(evidence.canonical_proposal())
                .map_err(|_| orchard_ironwood::Error::DeliveryArtifactMismatch)?;
            let encoded = zcash_client_backend::proto::proposal::Proposal::decode(
                envelope.payload().as_bytes(),
            )
            .map_err(|_| orchard_ironwood::Error::DeliveryArtifactMismatch)?;
            let params = *wallet_db.params();
            let proposal = encoded
                .try_into_standard_proposal(&params, wallet_db)
                .map_err(|_| orchard_ironwood::Error::DeliveryArtifactMismatch)?;
            if zcash_client_backend::proto::proposal::Proposal::from_standard_proposal(&proposal)
                .encode_to_vec()
                != envelope.payload().as_bytes()
            {
                return Err(orchard_ironwood::Error::DeliveryArtifactMismatch);
            }
            let (recipient, _) = immediate_internal_recipient(&account, params.network_type())?;
            validate_immediate_wallet_proposal(&proposal, &recipient)?;
            let seal =
                validate_immediate_external_pczt(&params, &account, &proposal, &evidence, pczt)?;
            store::stage_immediate_external_signing_pczt(
                wallet_db.conn,
                &orchard_ironwood::TABLES,
                account_ref,
                context,
                expected_revision,
                run_identity,
                artifact_identity,
                token,
                pczt,
                expected_policy_fingerprint,
                &seal,
            )
        })
    }

    fn stage_immediate_signed_pczt(
        &mut self,
        account_id: &Self::AccountId,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        artifact_identity: ImmediateArtifactIdentity,
        token: ClaimToken,
        signed_pczt: &SignedPcztEvidence,
        expected_policy_fingerprint: PolicyFingerprint,
    ) -> Result<DeliverySnapshot, Self::Error> {
        let context = SubmissionContext::from_parameters(self.params());
        self.immediate_delivery_transactionally(|wallet_db, _transaction| {
            let account_ref = store::account_ref(wallet_db.conn, account_id)?
                .ok_or(orchard_ironwood::Error::AccountUnknown)?;
            store::stage_immediate_signed_pczt(
                wallet_db.conn,
                &orchard_ironwood::TABLES,
                account_ref,
                context,
                expected_revision,
                run_identity,
                artifact_identity,
                token,
                signed_pczt,
                expected_policy_fingerprint,
            )
        })
    }

    fn stage_immediate_transaction(
        &mut self,
        account_id: &Self::AccountId,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        token: ClaimToken,
        artifact: &ExactTransaction,
        expected_policy_fingerprint: PolicyFingerprint,
    ) -> Result<DeliverySnapshot, Self::Error> {
        let context = SubmissionContext::from_parameters(self.params());
        self.immediate_delivery_transactionally(|wallet_db, _transaction| {
            let account = wallet_db
                .get_account(*account_id)
                .map_err(orchard_ironwood::Error::Wallet)?
                .ok_or(orchard_ironwood::Error::AccountUnknown)?;
            let account_ref = account.internal_id();
            let (current, _) = store::load_immediate_delivery_runtime_parts(
                wallet_db.conn,
                &orchard_ironwood::TABLES,
                account_ref,
                context,
            )?;
            let snapshot = current
                .map(|(snapshot, _)| snapshot)
                .ok_or(orchard_ironwood::Error::DeliveryClaimUnavailable)?;
            if snapshot.revision() != expected_revision || snapshot.run_identity() != run_identity {
                return Err(orchard_ironwood::Error::DeliveryRevisionMismatch);
            }
            let evidence = match snapshot.claims().first().map(|claim| claim.evidence()) {
                Some(zcash_pool_migration::delivery::DeliveryArtifactEvidence::Immediate(
                    evidence,
                )) => evidence.clone(),
                _ => return Err(orchard_ironwood::Error::DeliveryArtifactMismatch),
            };
            let envelope = ImmediateProposal::decode(evidence.canonical_proposal())
                .map_err(|_| orchard_ironwood::Error::DeliveryArtifactMismatch)?;
            let encoded = zcash_client_backend::proto::proposal::Proposal::decode(
                envelope.payload().as_bytes(),
            )
            .map_err(|_| orchard_ironwood::Error::DeliveryArtifactMismatch)?;
            let params = *wallet_db.params();
            let proposal = encoded
                .try_into_standard_proposal(&params, wallet_db)
                .map_err(|_| orchard_ironwood::Error::DeliveryArtifactMismatch)?;
            if zcash_client_backend::proto::proposal::Proposal::from_standard_proposal(&proposal)
                .encode_to_vec()
                != envelope.payload().as_bytes()
            {
                return Err(orchard_ironwood::Error::DeliveryArtifactMismatch);
            }
            let (recipient, _) = immediate_internal_recipient(&account, params.network_type())?;
            validate_immediate_wallet_proposal(&proposal, &recipient)?;
            let seal = validate_immediate_exact_transaction(
                &params, &account, &proposal, &evidence, artifact,
            )?;
            store::stage_immediate_transaction(
                wallet_db.conn,
                &orchard_ironwood::TABLES,
                account_ref,
                context,
                expected_revision,
                run_identity,
                token,
                artifact,
                expected_policy_fingerprint,
                &seal,
            )
        })
    }

    fn claim_immediate_submission(
        &mut self,
        account_id: &Self::AccountId,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        artifact_identity: ImmediateArtifactIdentity,
        lease_duration: LeaseDuration,
        expected_policy_fingerprint: PolicyFingerprint,
    ) -> Result<Option<DeliverySnapshot>, Self::Error> {
        self.claim_immediate_capability(
            account_id,
            expected_revision,
            run_identity,
            artifact_identity,
            lease_duration,
            expected_policy_fingerprint,
            ClaimKind::Submission,
        )
    }

    fn claim_immediate_outcome_resolution(
        &mut self,
        account_id: &Self::AccountId,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        artifact_identity: ImmediateArtifactIdentity,
        lease_duration: LeaseDuration,
        expected_policy_fingerprint: PolicyFingerprint,
    ) -> Result<Option<DeliverySnapshot>, Self::Error> {
        self.claim_immediate_capability(
            account_id,
            expected_revision,
            run_identity,
            artifact_identity,
            lease_duration,
            expected_policy_fingerprint,
            ClaimKind::OutcomeResolution,
        )
    }

    fn resume_immediate_claim(
        &mut self,
        account_id: &Self::AccountId,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        artifact_identity: ImmediateArtifactIdentity,
        token: ClaimToken,
        expected_policy_fingerprint: PolicyFingerprint,
    ) -> Result<Option<DeliverySnapshot>, Self::Error> {
        let context = SubmissionContext::from_parameters(self.params());
        self.immediate_delivery_transactionally(|wallet_db, _transaction| {
            let account_ref = store::account_ref(wallet_db.conn, account_id)?
                .ok_or(orchard_ironwood::Error::AccountUnknown)?;
            store::resume_immediate_claim(
                wallet_db.conn,
                &orchard_ironwood::TABLES,
                account_ref,
                context,
                expected_revision,
                run_identity,
                artifact_identity,
                token,
                expected_policy_fingerprint,
            )
        })
    }

    fn renew_immediate_claim(
        &mut self,
        account_id: &Self::AccountId,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        artifact_identity: ImmediateArtifactIdentity,
        token: ClaimToken,
        lease_duration: LeaseDuration,
        expected_policy_fingerprint: PolicyFingerprint,
    ) -> Result<Option<DeliverySnapshot>, Self::Error> {
        let context = SubmissionContext::from_parameters(self.params());
        self.immediate_delivery_transactionally(|wallet_db, _transaction| {
            let account_ref = store::account_ref(wallet_db.conn, account_id)?
                .ok_or(orchard_ironwood::Error::AccountUnknown)?;
            store::renew_immediate_claim(
                wallet_db.conn,
                &orchard_ironwood::TABLES,
                account_ref,
                context,
                expected_revision,
                run_identity,
                artifact_identity,
                token,
                lease_duration,
                expected_policy_fingerprint,
            )
        })
    }

    fn record_immediate_submission_outcome(
        &mut self,
        account_id: &Self::AccountId,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        artifact_identity: ImmediateArtifactIdentity,
        token: ClaimToken,
        outcome: SubmissionOutcome,
        expected_policy_fingerprint: PolicyFingerprint,
    ) -> Result<DeliverySnapshot, Self::Error> {
        let context = SubmissionContext::from_parameters(self.params());
        self.immediate_delivery_transactionally(|wallet_db, _transaction| {
            let account_ref = store::account_ref(wallet_db.conn, account_id)?
                .ok_or(orchard_ironwood::Error::AccountUnknown)?;
            store::record_immediate_submission_outcome(
                wallet_db.conn,
                &orchard_ironwood::TABLES,
                account_ref,
                context,
                expected_revision,
                run_identity,
                artifact_identity,
                token,
                outcome,
                expected_policy_fingerprint,
            )
        })
    }

    fn reconcile_immediate_submission(
        &mut self,
        account_id: &Self::AccountId,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        artifact_identity: ImmediateArtifactIdentity,
        token: ClaimToken,
    ) -> Result<DeliverySnapshot, Self::Error> {
        let context = SubmissionContext::from_parameters(self.params());
        self.immediate_delivery_transactionally(|wallet_db, _transaction| {
            let account_ref = store::account_ref(wallet_db.conn, account_id)?
                .ok_or(orchard_ironwood::Error::AccountUnknown)?;
            store::reconcile_immediate_submission(
                wallet_db.conn,
                &orchard_ironwood::TABLES,
                account_ref,
                context,
                expected_revision,
                run_identity,
                artifact_identity,
                token,
            )
        })
    }

    fn release_immediate_claim_known_unsent(
        &mut self,
        account_id: &Self::AccountId,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        artifact_identity: ImmediateArtifactIdentity,
        token: ClaimToken,
        reason: DeliveryFailureReason,
        expected_policy_fingerprint: PolicyFingerprint,
    ) -> Result<DeliverySnapshot, Self::Error> {
        let context = SubmissionContext::from_parameters(self.params());
        self.immediate_delivery_transactionally(|wallet_db, _transaction| {
            let account_ref = store::account_ref(wallet_db.conn, account_id)?
                .ok_or(orchard_ironwood::Error::AccountUnknown)?;
            store::release_immediate_claim_known_unsent(
                wallet_db.conn,
                &orchard_ironwood::TABLES,
                account_ref,
                context,
                expected_revision,
                run_identity,
                artifact_identity,
                token,
                reason,
                expected_policy_fingerprint,
            )
        })
    }

    fn pause_immediate_delivery(
        &mut self,
        account_id: &Self::AccountId,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
    ) -> Result<DeliverySnapshot, Self::Error> {
        self.set_immediate_delivery_phase(
            account_id,
            expected_revision,
            run_identity,
            zcash_pool_migration::delivery::DeliveryPhase::Active,
            zcash_pool_migration::delivery::DeliveryPhase::Paused,
        )
    }

    fn resume_immediate_delivery(
        &mut self,
        account_id: &Self::AccountId,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
    ) -> Result<DeliverySnapshot, Self::Error> {
        self.set_immediate_delivery_phase(
            account_id,
            expected_revision,
            run_identity,
            zcash_pool_migration::delivery::DeliveryPhase::Paused,
            zcash_pool_migration::delivery::DeliveryPhase::Active,
        )
    }

    fn begin_immediate_abandonment(
        &mut self,
        account_id: &Self::AccountId,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
    ) -> Result<DeliverySnapshot, Self::Error> {
        let context = SubmissionContext::from_parameters(self.params());
        self.immediate_delivery_transactionally(|wallet_db, _transaction| {
            let account_ref = store::account_ref(wallet_db.conn, account_id)?
                .ok_or(orchard_ironwood::Error::AccountUnknown)?;
            store::begin_immediate_abandonment(
                wallet_db.conn,
                &orchard_ironwood::TABLES,
                account_ref,
                context,
                expected_revision,
                run_identity,
            )
        })
    }

    fn finish_immediate_abandonment(
        &mut self,
        account_id: &Self::AccountId,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
    ) -> Result<DeliverySnapshot, Self::Error> {
        let context = SubmissionContext::from_parameters(self.params());
        self.immediate_delivery_transactionally(|wallet_db, _transaction| {
            let account_ref = store::account_ref(wallet_db.conn, account_id)?
                .ok_or(orchard_ironwood::Error::AccountUnknown)?;
            store::finish_immediate_abandonment(
                wallet_db.conn,
                &orchard_ironwood::TABLES,
                account_ref,
                context,
                expected_revision,
                run_identity,
            )
        })
    }
}

#[cfg(feature = "migration-delivery")]
fn with_atomic_delivery_view<T>(
    conn: &rusqlite::Connection,
    operation: impl FnOnce(&rusqlite::Connection) -> Result<T, orchard_ironwood::Error>,
) -> Result<T, orchard_ironwood::Error> {
    if conn.is_autocommit() {
        let tx =
            rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)?;
        let result = operation(&tx)?;
        tx.commit()?;
        Ok(result)
    } else {
        // WalletDb<SqlTransaction> already owns the surrounding atomic write boundary.
        operation(conn)
    }
}

#[cfg(feature = "migration-delivery")]
impl<C, P, CL, R> zcash_pool_migration::delivery::MigrationRuntimeStore
    for crate::WalletDb<C, P, CL, R>
where
    C: std::borrow::Borrow<rusqlite::Connection>,
    P: zcash_protocol::consensus::Parameters,
{
    type Error = orchard_ironwood::Error;
    type AccountId = crate::AccountUuid;

    fn load_account_migration_runtime_atomically(
        &mut self,
        account_id: &Self::AccountId,
    ) -> Result<
        Option<zcash_pool_migration::delivery::AccountMigrationRuntime<Self::AccountId>>,
        Self::Error,
    > {
        let context =
            zcash_pool_migration::delivery::SubmissionContext::from_parameters(self.params());
        with_atomic_delivery_view(self.conn.borrow(), |conn| {
            store::load_account_migration_runtime(
                conn,
                &orchard_ironwood::TABLES,
                *account_id,
                context,
            )
        })
    }

    fn load_all_account_migration_runtimes_atomically(
        &mut self,
    ) -> Result<
        Vec<zcash_pool_migration::delivery::AccountMigrationRuntime<Self::AccountId>>,
        Self::Error,
    > {
        let context =
            zcash_pool_migration::delivery::SubmissionContext::from_parameters(self.params());
        with_atomic_delivery_view(self.conn.borrow(), |conn| {
            store::load_all_account_migration_runtimes(conn, &orchard_ironwood::TABLES, context)
        })
    }

    fn audit_finality_archives(
        &mut self,
        account_id: &Self::AccountId,
    ) -> Result<Vec<zcash_pool_migration::delivery::RunFinalityAudit>, Self::Error> {
        let context =
            zcash_pool_migration::delivery::SubmissionContext::from_parameters(self.params());
        with_atomic_delivery_view(self.conn.borrow(), |conn| {
            store::audit_account_finality_archives(
                conn,
                &orchard_ironwood::TABLES,
                *account_id,
                context,
            )
        })
    }

    fn rollover_source_reservations(
        &mut self,
        account_id: &Self::AccountId,
        request: zcash_pool_migration::delivery::ReservationRollover,
        policy: &zcash_pool_migration::delivery::SubmissionPolicy,
    ) -> Result<zcash_pool_migration::delivery::ReservationRolloverReceipt, Self::Error> {
        let context =
            zcash_pool_migration::delivery::SubmissionContext::from_parameters(self.params());
        with_atomic_delivery_view(self.conn.borrow(), |conn| {
            store::rollover_account_source_reservations(
                conn,
                &orchard_ironwood::TABLES,
                *account_id,
                request,
                policy,
                context,
            )
        })
    }

    fn rebuild_expired_transfer_attempt(
        &mut self,
        account_id: &Self::AccountId,
        request: zcash_pool_migration::delivery::ExpiredTransferRebuild,
        policy: &zcash_pool_migration::delivery::SubmissionPolicy,
    ) -> Result<zcash_pool_migration::delivery::ExpiredTransferRebuildReceipt, Self::Error> {
        let context =
            zcash_pool_migration::delivery::SubmissionContext::from_parameters(self.params());
        with_atomic_delivery_view(self.conn.borrow(), |conn| {
            store::rebuild_account_expired_transfer_attempt(
                conn,
                &orchard_ironwood::TABLES,
                *account_id,
                request,
                policy,
                context,
            )
        })
    }
}

#[cfg(feature = "migration-delivery")]
impl<C, P, CL, R> zcash_pool_migration::wallet::PcztLockValidationSource
    for crate::WalletDb<C, P, CL, R>
where
    C: std::borrow::Borrow<rusqlite::Connection>,
{
    type Error = crate::error::SqliteClientError;

    fn active_orchard_locks(
        &self,
    ) -> Result<Vec<zcash_pool_migration::wallet::ActiveOrchardLock>, Self::Error> {
        store::active_orchard_locks(self.conn.borrow())
    }

    fn active_orchard_reservations(
        &self,
    ) -> Result<Vec<zcash_pool_migration::wallet::ActiveOrchardReservation>, Self::Error> {
        store::active_orchard_reservations(self.conn.borrow(), &orchard_ironwood::TABLES)
    }

    fn active_orchard_spends(
        &self,
    ) -> Result<Vec<zcash_pool_migration::wallet::ActiveOrchardSpend>, Self::Error> {
        store::active_orchard_spends(self.conn.borrow())
    }
}

#[cfg(all(test, feature = "migration-delivery"))]
mod delivery_tests {
    use super::*;
    use orchard::keys::FullViewingKey;
    use pczt::roles::creator::Creator;
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;
    use zcash_primitives::transaction::fees::zip317::MARGINAL_FEE;

    fn immediate_envelope() -> ImmediateProposal {
        let target = BlockHeight::from_u32(2_000);
        ImmediateProposal::new(
            target,
            BlockHeight::from_u32(2_000 + DEFAULT_TX_EXPIRY_DELTA),
            BranchId::Nu6_3,
            ImmediateProposalPayload::try_from(vec![1]).unwrap(),
        )
        .unwrap()
    }

    fn empty_pczt(fallback_lock_time: Option<u32>) -> ExternalSigningPczt {
        let mut creator = Creator::new(
            u32::from(BranchId::Nu6_3),
            2_000 + DEFAULT_TX_EXPIRY_DELTA,
            133,
            None,
            None,
        )
        .unwrap();
        if let Some(fallback_lock_time) = fallback_lock_time {
            creator = creator.with_fallback_lock_time(fallback_lock_time);
        }
        ExternalSigningPczt::parse(creator.build().unwrap().serialize().unwrap()).unwrap()
    }

    #[test]
    fn nonzero_external_pczt_lock_time_is_rejected_before_exposure() {
        let envelope = immediate_envelope();
        assert!(parse_immediate_external_pczt(&envelope, &empty_pczt(None)).is_ok());
        assert!(matches!(
            parse_immediate_external_pczt(&envelope, &empty_pczt(Some(1))),
            Err(orchard_ironwood::Error::DeliveryArtifactMismatch)
        ));
    }

    #[test]
    fn canonical_transfer_pczt_passes_full_source_verification_and_metadata_substitution_fails() {
        let seed = 0xD311u64;
        let fvk = FullViewingKey::from(&zcash_pool_migration_memory::spending_key(seed));
        let crossing = zcash_pool_migration::note_splitting::RESIDUAL_MIGRATION_MIN;
        let source_value = u64::from(crossing) + 3 * MARGINAL_FEE.into_u64();
        let (note, _, _) =
            zcash_pool_migration_memory::single_note_witness(&fvk, source_value, seed);
        let nullifier = note.nullifier(&fvk).to_bytes();
        let pczt = zcash_pool_migration::build::build_transfer_pczt(
            &zcash_pool_migration_memory::regtest_network(true),
            100,
            140,
            &fvk,
            note,
            crossing,
            ChaCha8Rng::seed_from_u64(seed ^ 0x5a5a),
        )
        .unwrap();
        let proposed = std::collections::BTreeMap::from([(nullifier, source_value)]);
        validate_immediate_pczt_source_semantics(&pczt, &fvk, &proposed).unwrap();

        let wrong_value = std::collections::BTreeMap::from([(nullifier, source_value + 1)]);
        assert!(matches!(
            validate_immediate_pczt_source_semantics(&pczt, &fvk, &wrong_value),
            Err(orchard_ironwood::Error::DeliveryArtifactMismatch)
        ));
        assert!(matches!(
            validate_immediate_pczt_source_semantics(
                &pczt,
                &fvk,
                &std::collections::BTreeMap::new()
            ),
            Err(orchard_ironwood::Error::DeliveryArtifactMismatch)
        ));
    }

    #[test]
    fn extracted_source_semantics_reject_every_hostile_shape() {
        let real = [1; 32];
        let orchard_dummy = [2; 32];
        let ironwood_dummy = [3; 32];
        let sources = std::collections::BTreeMap::from([(real, 7)]);
        let seven = ZatBalance::from(Zatoshis::from_u64(7).unwrap());
        let valid = || {
            validate_immediate_extracted_source_semantics(
                &sources,
                [real, orchard_dummy],
                false,
                seven,
                [ironwood_dummy],
                false,
            )
        };
        valid().unwrap();

        for mutation in [
            validate_immediate_extracted_source_semantics(
                &sources,
                [real, real],
                false,
                seven,
                [ironwood_dummy],
                false,
            ),
            validate_immediate_extracted_source_semantics(
                &sources,
                [real, orchard_dummy],
                false,
                ZatBalance::from(Zatoshis::from_u64(8).unwrap()),
                [ironwood_dummy],
                false,
            ),
            validate_immediate_extracted_source_semantics(
                &sources,
                [real, orchard_dummy],
                true,
                seven,
                [ironwood_dummy],
                false,
            ),
            validate_immediate_extracted_source_semantics(
                &sources,
                [real, orchard_dummy],
                false,
                seven,
                [ironwood_dummy],
                true,
            ),
            validate_immediate_extracted_source_semantics(
                &sources,
                [real, orchard_dummy],
                false,
                seven,
                [orchard_dummy],
                false,
            ),
        ] {
            assert!(matches!(
                mutation,
                Err(orchard_ironwood::Error::DeliveryArtifactMismatch)
            ));
        }
    }
}
