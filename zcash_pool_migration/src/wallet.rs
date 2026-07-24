//! A wallet-backed adapter that turns any `zcash_client_backend` wallet into a migration wallet.
//!
//! The engine's build and commit path needs an implementation of [`MigrationBackend`] +
//! [`MigrationCrypto`] (the account's viewing key, its spendable notes' plaintexts, and signing)
//! and a [`PoolMigrationRead`] / [`PoolMigrationWrite`] store. This module supplies the first two
//! for free over the traits a `zcash_client_backend` wallet already implements ([`WalletRead`],
//! [`InputSource`]) plus the account's [`UnifiedSpendingKey`], and delegates the store to a value
//! the caller supplies (for example `zcash_client_sqlite`'s `pool_migration` store over the same
//! wallet database). A consuming application (zallet, or any other `zcash_client_backend` wallet)
//! then
//! runs [`commit_preparation`] with no hand-wired cryptography.
//!
//! [`WalletMigration`] holds the wallet by a SHARED borrow and touches no note commitment tree:
//! every migration transaction is built and signed with its anchor and witnesses deferred to
//! proving time (ZIP 374). Proving is the separate [`WalletMigrationProver`], which borrows the
//! wallet as `&mut W` to resolve the source anchor and each spend's witness from the wallet's
//! Orchard commitment tree and installs them through the PCZT `Updater` role before proving the
//! transaction (a transfer's Orchard + Ironwood bundles, or a preparation's Orchard bundle), just
//! before broadcast.
//!
//! [`commit_preparation`]: crate::engine::commit_preparation

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use core::fmt;
use core::num::NonZeroU32;

use ::orchard::Anchor;
use ::orchard::circuit::OrchardCircuitVersion;
use ::orchard::keys::{FullViewingKey, SpendAuthorizingKey};
use ::orchard::note::{Note as OrchardNote, Nullifier};
use ::orchard::tree::MerklePath;
use incrementalmerkletree::Position;
use shardtree::error::ShardTreeError;

use ::pczt::roles::prover::Prover;
use ::pczt::roles::tx_extractor::TransactionExtractor;
use ::pczt::roles::updater::{AnchorUpdateError, SpendWitnessUpdateError, Updater};
use zcash_client_backend::data_api::{
    InputSource, WalletCommitmentTrees, WalletRead,
    wallet::{
        ConfirmationsPolicy, TargetHeight,
        input_selection::{LockFilter, LockedInputPolicy, NonEmptyBTreeSet},
    },
};
use zcash_client_backend::wallet::{LockOwner, OutputRef};
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_primitives::transaction::builder::cached_orchard_proving_key;
use zcash_protocol::{PoolType, ShieldedPool, consensus::BlockHeight, value::Zatoshis};

use crate::build::sign_pczt;
use crate::delivery::{SourceReservationOwner, StorageFinality};
use crate::engine::{
    MigrationBackend, MigrationCrypto, MigrationProver, MigrationState, MigrationTxId,
    MigrationTxState, PoolMigrationRead, PoolMigrationWrite,
};

/// A failure of the wallet-backed migration adapter. Parameterized by the error types of the two
/// wallet traits and the store, which for `zcash_client_sqlite`'s `WalletDb` are all one type but in
/// general need not be.
pub enum Error<WRE, ISE, SE> {
    /// A `WalletRead` failure (chain-tip lookup).
    WalletRead(WRE),
    /// An `InputSource` failure (spendable-note selection).
    InputSource(ISE),
    /// A store failure (`PoolMigrationRead` / `PoolMigrationWrite`).
    Store(SE),
    /// No spendable note exists at the requested index.
    NoteNotFound(usize),
    /// The wallet has no chain tip (it has never synced), so no note selection target exists.
    ChainTipUnknown,
    /// Signing the migration PCZT failed.
    Sign(crate::build::BuildError),
    /// The spendable note at this index has a value that is not a valid [`Zatoshis`] amount
    /// (it exceeds the money-supply cap).
    InvalidNoteValue(usize),
    /// A stored migration PCZT could not be decoded while resolving the exact notes it spends.
    Pczt(::pczt::ParseError),
    /// A real Orchard spend in a stored PCZT carries bytes that are not a valid nullifier.
    MalformedNullifier([u8; 32]),
    /// A root transaction (one with no migration dependency) does not resolve to every wallet note
    /// that its PCZT spends. Root inputs must already exist when the migration is committed, so
    /// persisting the migration would otherwise leave an initial input unreserved.
    RootInputNotFound(MigrationTxId),
    /// A persisted transaction names a lock owner other than the owner of this locked migration.
    /// Mixing owners would make release ambiguous, so the state is rejected instead.
    LockOwnerMismatch(MigrationTxId),
    /// A transaction update was requested when no migration is persisted for the account.
    MigrationNotFound,
    /// A transaction update named an id that is not part of the persisted migration.
    TransactionNotFound(MigrationTxId),
    /// Cancellation was requested for a completed migration. Completion must be handled by the
    /// exact-output finalizer or by an explicit reorg lifecycle update, never by re-locking it as a
    /// cancellation side effect.
    MigrationComplete,
}

impl<WRE: fmt::Debug, ISE: fmt::Debug, SE: fmt::Debug> fmt::Debug for Error<WRE, ISE, SE> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WalletRead(error) => f.debug_tuple("WalletRead").field(error).finish(),
            Self::InputSource(error) => f.debug_tuple("InputSource").field(error).finish(),
            Self::Store(error) => f.debug_tuple("Store").field(error).finish(),
            Self::NoteNotFound(index) => f.debug_tuple("NoteNotFound").field(index).finish(),
            Self::ChainTipUnknown => f.write_str("ChainTipUnknown"),
            Self::Sign(error) => f.debug_tuple("Sign").field(error).finish(),
            Self::InvalidNoteValue(index) => {
                f.debug_tuple("InvalidNoteValue").field(index).finish()
            }
            Self::Pczt(error) => f.debug_tuple("Pczt").field(error).finish(),
            Self::MalformedNullifier(_) => f.write_str("MalformedNullifier(<redacted>)"),
            Self::RootInputNotFound(id) => f.debug_tuple("RootInputNotFound").field(id).finish(),
            Self::LockOwnerMismatch(id) => f.debug_tuple("LockOwnerMismatch").field(id).finish(),
            Self::MigrationNotFound => f.write_str("MigrationNotFound"),
            Self::TransactionNotFound(id) => {
                f.debug_tuple("TransactionNotFound").field(id).finish()
            }
            Self::MigrationComplete => f.write_str("MigrationComplete"),
        }
    }
}

impl<WRE: fmt::Display, ISE: fmt::Display, SE: fmt::Display> fmt::Display for Error<WRE, ISE, SE> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::WalletRead(e) => write!(f, "wallet read error: {e}"),
            Error::InputSource(e) => write!(f, "input source error: {e}"),
            Error::Store(e) => write!(f, "migration store error: {e}"),
            Error::NoteNotFound(i) => write!(f, "no spendable note at index {i}"),
            Error::ChainTipUnknown => f.write_str("the wallet has no chain tip"),
            Error::Sign(e) => write!(f, "signing the migration failed: {e}"),
            Error::InvalidNoteValue(i) => {
                write!(f, "spendable note {i} has an invalid (out-of-range) value")
            }
            Error::Pczt(e) => write!(f, "decoding a migration PCZT failed: {e:?}"),
            Error::MalformedNullifier(_) => {
                f.write_str("a migration PCZT contains an invalid nullifier: <redacted>")
            }
            Error::RootInputNotFound(id) => write!(
                f,
                "migration transaction {} does not resolve to all of its wallet inputs",
                u32::from(*id)
            ),
            Error::LockOwnerMismatch(id) => write!(
                f,
                "migration transaction {} is assigned to a different lock owner",
                u32::from(*id)
            ),
            Error::MigrationNotFound => f.write_str("no migration is persisted for this account"),
            Error::TransactionNotFound(id) => write!(
                f,
                "migration transaction {} is not present in the persisted migration",
                u32::from(*id)
            ),
            Error::MigrationComplete => f.write_str("a completed migration cannot be cancelled"),
        }
    }
}

impl<WRE, ISE, SE> core::error::Error for Error<WRE, ISE, SE>
where
    WRE: fmt::Debug + fmt::Display,
    ISE: fmt::Debug + fmt::Display,
    SE: fmt::Debug + fmt::Display,
{
}

/// The adapter's error type for a wallet `W` and store `St`.
/// The concrete error produced by a wallet-backed migration adapter.
pub type AdapterError<W, St> =
    Error<<W as WalletRead>::Error, <W as InputSource>::Error, <St as PoolMigrationRead>::Error>;

/// Canonical storage evidence for one currently active Orchard output lock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActiveOrchardLock {
    output: OutputRef,
    nullifier: Option<Nullifier>,
    owner: LockOwner,
}

/// Canonical storage evidence for one active delivery-owned Orchard source reservation.
///
/// Reservation ownership remains distinct from the wallet's physical [`LockOwner`]. Carrying both
/// prevents storage adapters from byte-casting a delivery run owner into a wallet lock owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActiveOrchardReservation {
    output: OutputRef,
    nullifier: Option<Nullifier>,
    reservation_owner: SourceReservationOwner,
    canonical_lock_owner: Option<LockOwner>,
}

impl ActiveOrchardReservation {
    /// Constructs typed active-reservation evidence read from canonical wallet and delivery state.
    pub const fn new(
        output: OutputRef,
        nullifier: Option<Nullifier>,
        reservation_owner: SourceReservationOwner,
        canonical_lock_owner: Option<LockOwner>,
    ) -> Self {
        Self {
            output,
            nullifier,
            reservation_owner,
            canonical_lock_owner,
        }
    }

    /// Returns the reserved output's stable identity.
    pub const fn output(&self) -> OutputRef {
        self.output
    }

    /// Returns the stored nullifier, or `None` when validation must fail closed.
    pub const fn nullifier(&self) -> Option<Nullifier> {
        self.nullifier
    }

    /// Returns the distinct delivery reservation owner.
    pub const fn reservation_owner(&self) -> SourceReservationOwner {
        self.reservation_owner
    }

    /// Returns the canonical wallet lock owner bound to the exact delivery run.
    pub const fn canonical_lock_owner(&self) -> Option<LockOwner> {
        self.canonical_lock_owner
    }
}

/// Exact authority supplied at the PCZT finalization boundary.
///
/// Ordinary finalization carries [`ORDINARY`](Self::ORDINARY). A delivery path carries one exact
/// run binding between its semantically distinct reservation owner and canonical wallet lock
/// owner. Constructors do not grant authority: the validator still matches both values against
/// account-independent storage evidence for every spent nullifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OrchardReservationAuthorization {
    binding: Option<(SourceReservationOwner, LockOwner)>,
}

impl OrchardReservationAuthorization {
    /// No delivery reservation or wallet lock owner is recognized.
    pub const ORDINARY: Self = Self { binding: None };

    /// Binds one exact delivery run's reservation owner to its canonical wallet lock owner.
    pub const fn delivery(
        reservation_owner: SourceReservationOwner,
        canonical_lock_owner: LockOwner,
    ) -> Self {
        Self {
            binding: Some((reservation_owner, canonical_lock_owner)),
        }
    }

    const fn binding(self) -> Option<(SourceReservationOwner, LockOwner)> {
        self.binding
    }
}

/// Canonical storage evidence that a wallet transaction currently spends an Orchard output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActiveOrchardSpend {
    output: OutputRef,
    nullifier: Option<Nullifier>,
    spender_txid: zcash_protocol::TxId,
}

impl ActiveOrchardSpend {
    /// Constructs active-spend evidence read from canonical wallet storage.
    pub const fn new(
        output: OutputRef,
        nullifier: Option<Nullifier>,
        spender_txid: zcash_protocol::TxId,
    ) -> Self {
        Self {
            output,
            nullifier,
            spender_txid,
        }
    }

    /// Returns the spent output's stable identity.
    pub const fn output(&self) -> OutputRef {
        self.output
    }

    /// Returns the stored nullifier, or `None` when conflict validation must fail closed.
    pub const fn nullifier(&self) -> Option<Nullifier> {
        self.nullifier
    }

    /// Returns the active spending transaction's consensus txid.
    pub const fn spender_txid(&self) -> zcash_protocol::TxId {
        self.spender_txid
    }
}

impl ActiveOrchardLock {
    /// Constructs active-lock evidence read from canonical wallet storage.
    pub const fn new(output: OutputRef, nullifier: Option<Nullifier>, owner: LockOwner) -> Self {
        Self {
            output,
            nullifier,
            owner,
        }
    }

    /// Returns the locked output's stable identity.
    pub const fn output(&self) -> OutputRef {
        self.output
    }

    /// Returns the stored nullifier, or `None` when the locked row cannot be verified against a
    /// PCZT and validation must fail closed.
    pub const fn nullifier(&self) -> Option<Nullifier> {
        self.nullifier
    }

    /// Returns the owner holding the active lock.
    pub const fn owner(&self) -> LockOwner {
        self.owner
    }
}

/// Account-independent source of every currently active Orchard lock in a wallet database.
///
/// Implementations must derive activity against their own canonical chain tip and must not filter
/// by account, viewing key, note value, witness availability, or economic threshold. This lets the
/// finalization guard validate a PCZT directly by its consensus nullifiers and prevents a wrong
/// caller-supplied account/FVK from silently producing an empty match set.
pub trait PcztLockValidationSource {
    /// Backend-specific storage error.
    type Error;

    /// Returns all currently active Orchard locks across every wallet account.
    fn active_orchard_locks(&self) -> Result<Vec<ActiveOrchardLock>, Self::Error>;

    /// Returns all active delivery source reservations across every wallet account, retaining the
    /// typed reservation owner separately from the canonical wallet lock owner.
    fn active_orchard_reservations(&self) -> Result<Vec<ActiveOrchardReservation>, Self::Error>;

    /// Returns every current-main-chain or unexpired pending wallet spend of an Orchard output,
    /// across every account. Exact candidate-txid retries are filtered by the validator, not here.
    fn active_orchard_spends(&self) -> Result<Vec<ActiveOrchardSpend>, Self::Error>;
}

/// A failure while checking whether an Orchard PCZT spends any wallet output that is actively
/// locked by an unrecognized owner.
pub enum PcztLockError<E> {
    /// Reading canonical active-lock evidence failed.
    Source(E),
    /// An Orchard action carries bytes that are not a valid nullifier.
    MalformedNullifier([u8; 32]),
    /// A currently active locked row has no stored nullifier, so the validator cannot prove that
    /// the PCZT does not spend it and fails closed.
    UnverifiableLockedOutput(OutputRef),
    /// A currently active spend row names an output without a stored nullifier, so conflict
    /// validation cannot prove independence and fails closed.
    UnverifiableSpentOutput(OutputRef),
    /// A currently active delivery reservation has no verifiable nullifier or canonical lock-owner
    /// binding, so validation fails closed.
    UnverifiableReservedOutput(OutputRef),
    /// The PCZT spends this exact wallet output, which is actively locked by an owner the caller
    /// did not recognize.
    InputLocked(OutputRef),
    /// The PCZT spends an actively reserved source that is not owned by the exact authorized
    /// delivery run binding.
    InputReserved(OutputRef),
    /// A different current-main-chain or unexpired pending wallet transaction already spends this
    /// exact output. The candidate may be an idempotent retry only when its txid is identical.
    InputAlreadySpent {
        /// The conflicting Orchard output.
        output: OutputRef,
        /// The active wallet spender's txid.
        spender_txid: zcash_protocol::TxId,
    },
    /// The fully authorized PCZT could not be extracted to derive its candidate txid.
    Extract(::pczt::roles::tx_extractor::Error),
}

impl<E: fmt::Debug> fmt::Debug for PcztLockError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Source(error) => f.debug_tuple("Source").field(error).finish(),
            Self::MalformedNullifier(_) => f.write_str("MalformedNullifier(<redacted>)"),
            Self::UnverifiableLockedOutput(output) => f
                .debug_tuple("UnverifiableLockedOutput")
                .field(output)
                .finish(),
            Self::UnverifiableSpentOutput(output) => f
                .debug_tuple("UnverifiableSpentOutput")
                .field(output)
                .finish(),
            Self::UnverifiableReservedOutput(output) => f
                .debug_tuple("UnverifiableReservedOutput")
                .field(output)
                .finish(),
            Self::InputLocked(output) => f.debug_tuple("InputLocked").field(output).finish(),
            Self::InputReserved(output) => f.debug_tuple("InputReserved").field(output).finish(),
            Self::InputAlreadySpent {
                output,
                spender_txid,
            } => f
                .debug_struct("InputAlreadySpent")
                .field("output", output)
                .field("spender_txid", spender_txid)
                .finish(),
            Self::Extract(error) => f.debug_tuple("Extract").field(error).finish(),
        }
    }
}

impl<E: fmt::Display> fmt::Display for PcztLockError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Source(e) => write!(f, "reading active Orchard locks failed: {e}"),
            Self::MalformedNullifier(_) => {
                f.write_str("an Orchard PCZT action has an invalid nullifier: <redacted>")
            }
            Self::UnverifiableLockedOutput(output) => write!(
                f,
                "an active Orchard lock has no verifiable nullifier: {output:?}"
            ),
            Self::UnverifiableSpentOutput(output) => write!(
                f,
                "an actively spent Orchard output has no verifiable nullifier: {output:?}"
            ),
            Self::UnverifiableReservedOutput(output) => write!(
                f,
                "an active Orchard reservation lacks verifiable run binding evidence: {output:?}"
            ),
            Self::InputLocked(output) => write!(
                f,
                "the PCZT spends an output locked by an unrecognized owner: {output:?}"
            ),
            Self::InputReserved(output) => write!(
                f,
                "the PCZT spends an output reserved by a different delivery run: {output:?}"
            ),
            Self::InputAlreadySpent {
                output,
                spender_txid,
            } => write!(
                f,
                "the PCZT spends {output:?}, already spent by active transaction {spender_txid}"
            ),
            Self::Extract(e) => write!(f, "extracting the candidate PCZT failed: {e:?}"),
        }
    }
}

impl<E> core::error::Error for PcztLockError<E> where E: fmt::Debug + fmt::Display {}

/// The PCZT lock-validation error type for a canonical lock source `S`.
pub type PcztLockValidationError<S> = PcztLockError<<S as PcztLockValidationSource>::Error>;

/// The exact identity and expected value of a wallet-received output.
///
/// [`OutputRef`] provides consensus identity (`txid`, pool, and output index), while `value` guards
/// against accepting a different or corrupt row under the expected migration denomination. The
/// SQLite pool-migration implementation currently supports only Ironwood output references; every
/// other pool is reported as [`ReceivedOutputAvailability::Unknown`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExactReceivedOutput {
    output_ref: OutputRef,
    value: Zatoshis,
}

impl ExactReceivedOutput {
    /// Constructs an exact received-output identity.
    pub const fn new(output_ref: OutputRef, value: Zatoshis) -> Self {
        Self { output_ref, value }
    }

    /// Returns the consensus output reference.
    pub const fn output_ref(&self) -> OutputRef {
        self.output_ref
    }

    /// Returns the expected value of the received output.
    pub const fn value(&self) -> Zatoshis {
        self.value
    }
}

/// Why an exact received output is known to the wallet but is not currently spendable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceivedOutputUnavailable {
    /// The receiving transaction has not yet reached the supplied confirmations policy.
    PendingConfirmations {
        /// The number of additional confirmations required.
        remaining: u32,
    },
    /// The wallet cannot construct a witness at its current canonical anchor, or required note
    /// reconstruction metadata is absent.
    WitnessUnavailable,
    /// The output is actively locked by an owner not admitted by the supplied [`LockFilter`].
    Locked,
    /// An unmined, unexpired wallet transaction currently spends the output. This is not accepted
    /// as current-main-chain historical spendability evidence.
    PendingSpend,
    /// Spending this output alone would cost at least its value under the wallet's normal ZIP 317
    /// economic-input threshold.
    Uneconomic,
}

/// Current or historical spendability of an exact wallet-received output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceivedOutputAvailability {
    /// No exact row exists for the scoped account, its value differs, its pool is unsupported, or
    /// the receiving transaction is not mined on the wallet's current main chain. A reorg therefore
    /// fails closed to this state even if an old spend relation remains in the database.
    Unknown,
    /// The exact output is known but cannot currently be selected for the given policy.
    Unavailable(ReceivedOutputUnavailable),
    /// The exact output satisfies the same confirmation, anchor, witness, economic, and lock
    /// predicates as normal wallet note selection.
    Spendable,
    /// A transaction spending the exact output is mined on the current main chain. The source
    /// transaction is also current-main-chain mined and has met the supplied confirmations policy,
    /// so this is current-main-chain historical spendability evidence. A reorg can revert this
    /// classification to [`Unknown`](Self::Unknown).
    Spent {
        /// The main-chain height of the spending transaction.
        mined_height: BlockHeight,
    },
}

/// Schema-free exact received-output availability queries for migration completion.
///
/// Implementations evaluate the supplied target height, confirmations policy, and owner-scoped
/// lock filter using the same canonical wallet evidence and eligibility rules as ordinary note
/// selection. They must never infer availability from migration state alone.
pub trait ReceivedOutputAvailabilitySource {
    /// Backend-specific storage error.
    type Error;

    /// Returns the current or historically proven availability of `output`.
    fn received_output_availability(
        &self,
        output: ExactReceivedOutput,
        target_height: TargetHeight,
        confirmations_policy: ConfirmationsPolicy,
        lock_filter: LockFilter<'_>,
    ) -> Result<ReceivedOutputAvailability, Self::Error>;
}

/// Availability evidence for one canonical migration transfer output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MigrationOutputAvailability {
    transaction_id: MigrationTxId,
    output: ExactReceivedOutput,
    availability: ReceivedOutputAvailability,
}

impl MigrationOutputAvailability {
    /// Constructs availability evidence for a canonical migration transfer output.
    pub const fn new(
        transaction_id: MigrationTxId,
        output: ExactReceivedOutput,
        availability: ReceivedOutputAvailability,
    ) -> Self {
        Self {
            transaction_id,
            output,
            availability,
        }
    }

    /// Returns the migration transaction that created this output.
    pub const fn transaction_id(&self) -> MigrationTxId {
        self.transaction_id
    }

    /// Returns the exact Ironwood output identity and expected denomination.
    pub const fn output(&self) -> ExactReceivedOutput {
        self.output
    }

    /// Returns the canonical wallet availability classification.
    pub const fn availability(&self) -> ReceivedOutputAvailability {
        self.availability
    }
}

/// Result of attempting to finalize a chain-observed complete migration.
#[derive(Clone, PartialEq, Eq)]
pub enum MigrationCompletion {
    /// At least one transfer output is not yet current-chain spendable (or proven spent). No owner
    /// token or lock was changed.
    Pending(Vec<MigrationOutputAvailability>),
    /// Every destination output is spendable (or current-chain spent) under the caller's normal
    /// wallet policy, while the source reservation remains held until storage finality.
    SpendablePendingFinality(Vec<MigrationOutputAvailability>),
    /// Every transfer output passed the finality predicate and the owner tokens/remaining locks
    /// were atomically cleared in this returned canonical state.
    Finalized(MigrationState),
}

impl fmt::Debug for MigrationCompletion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (status, output_count) = match self {
            Self::Pending(evidence) => ("pending", Some(evidence.len())),
            Self::SpendablePendingFinality(evidence) => {
                ("spendable_pending_finality", Some(evidence.len()))
            }
            Self::Finalized(_) => ("finalized", None),
        };
        f.debug_struct("MigrationCompletion")
            .field("status", &status)
            .field("output_count", &output_count)
            .field("evidence", &"<redacted>")
            .finish()
    }
}

/// Atomic store result for destination spendability and the separate source-reservation horizon.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MigrationFinalizationAudit {
    evidence: Vec<MigrationOutputAvailability>,
    storage_finality: StorageFinality,
}

impl MigrationFinalizationAudit {
    /// Constructs the result of one atomic storage audit.
    pub fn new(
        evidence: Vec<MigrationOutputAvailability>,
        storage_finality: StorageFinality,
    ) -> Self {
        Self {
            evidence,
            storage_finality,
        }
    }

    /// Exact destination-output evidence under the caller's wallet policy.
    pub fn evidence(&self) -> &[MigrationOutputAvailability] {
        &self.evidence
    }

    /// Fixed-horizon storage finality for source reservation release.
    pub const fn storage_finality(&self) -> StorageFinality {
        self.storage_finality
    }

    fn into_evidence(self) -> Vec<MigrationOutputAvailability> {
        self.evidence
    }
}

/// Failure deriving or persisting exact transfer-output completion evidence.
#[derive(Debug)]
pub enum CompletionError<E> {
    /// No canonical migration exists to audit/finalize.
    MigrationNotFound,
    /// The supplied state is not the all-mined, chain-observed `Complete` state.
    NotComplete,
    /// A stored transfer's PCZT cannot be parsed.
    Pczt(::pczt::ParseError),
    /// A supposedly mined transfer PCZT cannot be extracted as a fully authorized transaction.
    Extract(::pczt::roles::tx_extractor::Error),
    /// A stored transfer does not have the canonical one-Ironwood-output shape or denomination.
    MalformedTransfer(MigrationTxId),
    /// The canonical state has no transfer rows and therefore cannot represent a completed pool
    /// migration.
    MalformedState,
    /// Two stored transfer rows extract to the same consensus Ironwood output identity.
    DuplicateOutput(OutputRef),
    /// Canonical transaction rows contain a mixed or multiple-owner state that cannot be released
    /// safely as one migration.
    OwnerCorruption,
    /// Atomically auditing the exact outputs and, when satisfied, clearing the canonical owner and
    /// remaining locks failed.
    Store(E),
    /// Pre-finality current-chain evidence was lost and explicit migration recovery is required.
    RecoveryRequired,
}

impl<E: fmt::Display> fmt::Display for CompletionError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MigrationNotFound => f.write_str("no canonical migration is persisted"),
            Self::NotComplete => {
                f.write_str("the migration is not complete with every transaction mined")
            }
            Self::Pczt(e) => write!(f, "decoding a completed transfer PCZT failed: {e:?}"),
            Self::Extract(e) => write!(f, "extracting a completed transfer PCZT failed: {e:?}"),
            Self::MalformedTransfer(id) => write!(
                f,
                "migration transaction {} is not a canonical transfer",
                u32::from(*id)
            ),
            Self::MalformedState => {
                f.write_str("the completed migration contains no transfer transactions")
            }
            Self::DuplicateOutput(output) => write!(
                f,
                "multiple migration transfers resolve to the same output: {output:?}"
            ),
            Self::OwnerCorruption => {
                f.write_str("the canonical completed migration has inconsistent lock owners")
            }
            Self::Store(e) => write!(f, "auditing/finalizing migration outputs failed: {e}"),
            Self::RecoveryRequired => {
                f.write_str("migration completion evidence requires explicit reorg recovery")
            }
        }
    }
}

impl<E> core::error::Error for CompletionError<E> where E: fmt::Debug + fmt::Display {}

/// A spendable Orchard note as the adapter tracks it. The stable output reference is retained so a
/// committed migration can reserve the exact notes revealed by its PCZT nullifiers, rather than
/// re-identifying them by value or by their transient position in a selection result.
#[derive(Clone, Copy)]
struct SpendableNote {
    note: OrchardNote,
    position: Position,
    value: u64,
    output_ref: OutputRef,
}

fn selection_target<W, St>(wallet: &W) -> Result<TargetHeight, AdapterError<W, St>>
where
    W: WalletRead + InputSource,
    St: PoolMigrationRead,
{
    let tip = wallet
        .chain_height()
        .map_err(Error::WalletRead)?
        .ok_or(Error::ChainTipUnknown)?;
    Ok(TargetHeight::from(u32::from(tip) + 1))
}

fn select_spendable_orchard<W, St>(
    wallet: &W,
    account: <W as InputSource>::AccountId,
    lock_filter: LockFilter<'_>,
) -> Result<Vec<SpendableNote>, AdapterError<W, St>>
where
    W: WalletRead + InputSource,
    <W as InputSource>::AccountId: Copy,
    St: PoolMigrationRead,
{
    let target = selection_target::<W, St>(wallet)?;
    let received = wallet
        .select_unspent_notes(account, &[ShieldedPool::Orchard], target, &[], lock_filter)
        .map_err(Error::InputSource)?;
    let mut notes: Vec<SpendableNote> = received
        .orchard()
        .iter()
        .map(|rn| {
            let note = *rn.note();
            let value = note.value().inner();
            SpendableNote {
                note,
                position: rn.note_commitment_tree_position(),
                value,
                output_ref: OutputRef::new(
                    *rn.txid(),
                    PoolType::Shielded(ShieldedPool::Orchard),
                    u32::from(rn.output_index()),
                ),
            }
        })
        .collect();
    notes.sort_by_key(|note| note.position);
    Ok(notes)
}

fn resolve_pending_input_refs<W, St>(
    wallet: &W,
    account: <W as InputSource>::AccountId,
    orchard_fvk: &FullViewingKey,
    state: &MigrationState,
) -> Result<Vec<OutputRef>, AdapterError<W, St>>
where
    W: WalletRead + InputSource,
    <W as InputSource>::AccountId: Copy,
    St: PoolMigrationRead,
{
    let notes = select_spendable_orchard::<W, St>(wallet, account, LockFilter::Unfiltered)?;
    let by_nullifier: BTreeMap<Nullifier, OutputRef> = notes
        .into_iter()
        .map(|note| (note.note.nullifier(orchard_fvk), note.output_ref))
        .collect();

    let mut outputs = BTreeSet::new();
    for transaction in state.transactions() {
        if matches!(
            transaction.state(),
            MigrationTxState::Broadcast { .. } | MigrationTxState::Mined { .. }
        ) {
            continue;
        }

        let pczt = ::pczt::Pczt::parse(transaction.pczt()).map_err(Error::Pczt)?;
        // Match by durable consensus nullifier, never by witness presence. Proving fills the real
        // spends' deferred witnesses, so witness shape cannot identify them after a restart; dummy
        // padding nullifiers simply do not match canonical wallet notes.
        let action_spends: Vec<Nullifier> = pczt
            .orchard()
            .actions()
            .iter()
            .map(|action| {
                let bytes = action.spend().nullifier();
                Option::<Nullifier>::from(Nullifier::from_bytes(bytes))
                    .ok_or(Error::MalformedNullifier(*bytes))
            })
            .collect::<Result<_, _>>()?;

        let matched = action_spends
            .iter()
            .filter_map(|nf| by_nullifier.get(nf).copied())
            .inspect(|output| {
                outputs.insert(*output);
            })
            .count();

        // A transaction with no migration dependency spends an already-mined wallet note, not an
        // output of an earlier preparation layer. Every such input must therefore resolve at
        // initial commit. Missing dependent inputs are expected until their parent is mined and
        // scanned; a later persist/refresh acquires them under the same durable owner.
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
                            state.preparation().layers().get(layer)?.get(index)
                        })
                        .map(|preparation| preparation.inputs().len())
                });
        if transaction.depends_on().is_empty()
            && expected_root_inputs.is_none_or(|expected| matched != expected)
        {
            return Err(Error::RootInputNotFound(transaction.id()));
        }
    }

    Ok(outputs.into_iter().collect())
}

/// Checks every Orchard action in a fully authorized `pczt` against account-independent canonical
/// active-lock, typed delivery-reservation, and active-spend rows. It rejects an input locked or
/// reserved outside `authorization` and rejects a second current-chain/unexpired wallet spender
/// while allowing an exact same-txid idempotent retry.
///
/// This is a finalization-time guard for the advisory note-locking model. In particular, a PCZT can
/// be constructed before a pool migration acquires its locks; applying this function immediately
/// before finalization prevents that stale artifact from spending through the later lock. Ordinary
/// transaction finalization passes [`OrchardReservationAuthorization::ORDINARY`]. A migration
/// delivery path passes exactly the distinct source-reservation owner and canonical wallet
/// lock-owner binding recovered for its run. Because the source resolves stored nullifiers
/// directly across ALL accounts, callers cannot accidentally bypass validation with a wrong
/// account identifier or full viewing key, and economically unselectable/dust rows are still
/// protected.
///
/// Run this inside the same `WalletDb::transactionally` closure as PCZT extraction/storage. A
/// DBActor (or equivalent single-writer executor) then gives an in-process serialized validation
/// boundary. Locks are advisory rather than a consensus primitive: another PROCESS can still
/// acquire a lock after that SQLite transaction commits and before network broadcast unless the
/// application provides a cross-process transaction/broadcast coupling, so delivery code should
/// retain its normal conflict/retry handling and revalidate at its last available boundary.
pub fn validate_pczt_orchard_locks<S>(
    source: &S,
    pczt: &::pczt::Pczt,
    authorization: OrchardReservationAuthorization,
) -> Result<(), PcztLockValidationError<S>>
where
    S: PcztLockValidationSource,
{
    let candidate_txid = TransactionExtractor::new(pczt.clone())
        .extract()
        .map_err(PcztLockError::Extract)?
        .txid();
    let action_nullifiers = pczt
        .orchard()
        .actions()
        .iter()
        .map(|action| {
            let bytes = *action.spend().nullifier();
            Option::<Nullifier>::from(Nullifier::from_bytes(&bytes))
                .ok_or(PcztLockError::MalformedNullifier(bytes))
        })
        .collect::<Result<BTreeSet<_>, _>>()?;

    let active_locks = source
        .active_orchard_locks()
        .map_err(PcztLockError::Source)?;
    for lock in active_locks {
        let nullifier = lock
            .nullifier()
            .ok_or(PcztLockError::UnverifiableLockedOutput(lock.output()))?;
        if action_nullifiers.contains(&nullifier)
            && authorization
                .binding()
                .is_none_or(|(_, canonical_lock_owner)| canonical_lock_owner != lock.owner())
        {
            return Err(PcztLockError::InputLocked(lock.output()));
        }
    }

    let active_reservations = source
        .active_orchard_reservations()
        .map_err(PcztLockError::Source)?;
    for reservation in active_reservations {
        let nullifier =
            reservation
                .nullifier()
                .ok_or(PcztLockError::UnverifiableReservedOutput(
                    reservation.output(),
                ))?;
        if action_nullifiers.contains(&nullifier) {
            let canonical_lock_owner = reservation.canonical_lock_owner().ok_or(
                PcztLockError::UnverifiableReservedOutput(reservation.output()),
            )?;
            if authorization.binding()
                != Some((reservation.reservation_owner(), canonical_lock_owner))
            {
                return Err(PcztLockError::InputReserved(reservation.output()));
            }
        }
    }

    let active_spends = source
        .active_orchard_spends()
        .map_err(PcztLockError::Source)?;
    for spend in active_spends {
        let nullifier = spend
            .nullifier()
            .ok_or(PcztLockError::UnverifiableSpentOutput(spend.output()))?;
        if action_nullifiers.contains(&nullifier) && spend.spender_txid() != candidate_txid {
            return Err(PcztLockError::InputAlreadySpent {
                output: spend.output(),
                spender_txid: spend.spender_txid(),
            });
        }
    }

    Ok(())
}

/// Atomic note-locking operations required by [`LockedWalletMigration`].
///
/// The migration engine and its ordinary [`PoolMigrationWrite`] store remain pool-agnostic. A
/// wallet store that also implements this trait can atomically acquire owner-scoped output locks
/// and persist the canonical migration state, or atomically release only the migration's owners
/// while persisting a terminal state. Implementations must roll back every lock mutation if the
/// state write fails, and must roll back the state write if any lock cannot be acquired.
pub trait PoolMigrationLockStore: PoolMigrationWrite {
    /// Compare the canonical migration with `expected`, then lock `outputs` under `owner` through
    /// `lock_expiry_height` and replace it with `state` as one atomic operation. `None` means the
    /// caller expects no canonical migration (initial persist).
    fn lock_outputs_and_replace_migration(
        &mut self,
        expected: Option<&MigrationState>,
        state: &MigrationState,
        outputs: &[OutputRef],
        owner: LockOwner,
        lock_expiry_height: BlockHeight,
    ) -> Result<(), Self::Error>;

    /// Compare the canonical migration with `expected`, release every output lock held by one of
    /// `owners` for this migration's account, and replace it with `state`, as one atomic operation.
    /// Locks held by any other owner must remain untouched.
    fn release_locks_and_replace_migration(
        &mut self,
        expected: &MigrationState,
        state: &MigrationState,
        owners: &BTreeSet<LockOwner>,
    ) -> Result<(), Self::Error>;

    /// In one storage transaction, compare the canonical migration with `expected`, classify every
    /// exact transfer `output` against current wallet/chain evidence, and only if every output is
    /// spendable or current-main-chain spent, release `owners` and replace the migration with
    /// `finalized`. If any output is pending, return all evidence without changing state or locks.
    ///
    /// This is deliberately a narrow migration-specific composition seam over the wallet's normal
    /// output-lock and received-output queries. Implementations must acquire their write snapshot
    /// before reading evidence so another connection cannot change chain/note/spend rows between a
    /// successful audit and owner clearing. The arguments deliberately keep both sides of the
    /// canonical compare-and-swap, its exact output evidence, and the caller's wallet policy
    /// explicit at this storage-atomic boundary.
    #[allow(clippy::too_many_arguments)]
    fn finalize_migration_if_outputs_available(
        &mut self,
        expected: &MigrationState,
        finalized: &MigrationState,
        owners: &BTreeSet<LockOwner>,
        outputs: &[(MigrationTxId, ExactReceivedOutput)],
        target_height: TargetHeight,
        confirmations_policy: ConfirmationsPolicy,
        lock_filter: LockFilter<'_>,
    ) -> Result<MigrationFinalizationAudit, Self::Error>;
}

fn state_for_lock_owner(
    state: &MigrationState,
    owner: LockOwner,
    retain_owner: bool,
) -> Result<MigrationState, MigrationTxId> {
    let mut owned = state.clone();
    for transaction in &mut owned.transactions {
        if transaction
            .lock_owner
            .is_some_and(|existing| existing != *owner.as_bytes())
        {
            return Err(transaction.id);
        }
        transaction.lock_owner = retain_owner.then_some(*owner.as_bytes());
    }
    Ok(owned)
}

/// Atomically persists `state` together with locks on every currently-resolvable exact Orchard
/// input fixed by its PCZTs.
///
/// This is the external-signer form of [`LockedWalletMigration::persist_with_locks`]. It requires
/// only the account's Orchard [`FullViewingKey`], not spend authority, so imported and hardware
/// accounts can reserve migration inputs after building an unsigned migration through their own
/// backend. A non-terminal state durably records `owner` on every migration transaction; a
/// `Failed`/cancelled state clears those tokens and releases only locks held by `owner`. A first
/// chain-observed `Complete` state deliberately RETAINS them: completion is reversible across a
/// reorg until [`finalize_completed_migration`] proves that every exact Ironwood output is
/// current-main-chain spendable (or current-main-chain spent). The lock mutation and canonical
/// state replacement are a single [`PoolMigrationLockStore`] operation.
///
/// Call this again after synchronization: dependent preparation outputs do not exist at initial
/// commit and are acquired under the same owner as soon as they are scanned.
pub fn persist_migration_with_locks<W, St>(
    wallet: &W,
    account: <W as InputSource>::AccountId,
    orchard_fvk: &FullViewingKey,
    store: &mut St,
    owner: LockOwner,
    expected: Option<&MigrationState>,
    state: &MigrationState,
) -> Result<MigrationState, AdapterError<W, St>>
where
    W: WalletRead + InputSource,
    <W as InputSource>::AccountId: Copy,
    St: PoolMigrationLockStore,
{
    let failed = matches!(state.status(), crate::engine::MigrationStatus::Failed);
    let owned = state_for_lock_owner(state, owner, !failed).map_err(Error::LockOwnerMismatch)?;
    if failed {
        store
            .release_locks_and_replace_migration(
                expected.ok_or(Error::MigrationNotFound)?,
                &owned,
                &BTreeSet::from([owner]),
            )
            .map_err(Error::Store)?;
    } else {
        let outputs = resolve_pending_input_refs::<W, St>(wallet, account, orchard_fvk, &owned)?;
        // Migration locks are explicitly owner-released on cancellation or exact-output
        // finalization. Tying their lifetime to a transaction's expiry creates an unsafe gap: an
        // expired transfer or a later reorg can require a canonical rebuild after the source note
        // has already become selectable by an ordinary spend. Keep the reservation active for the
        // representable lifetime of the wallet instead; restart/reorg paths recover the same owner
        // and explicit terminal paths release it atomically.
        let lock_expiry_height = BlockHeight::from_u32(u32::MAX);
        store
            .lock_outputs_and_replace_migration(
                expected,
                &owned,
                &outputs,
                owner,
                lock_expiry_height,
            )
            .map_err(Error::Store)?;
    }
    Ok(owned)
}

/// Finalizes an all-mined migration only after canonical wallet evidence proves every exact
/// Ironwood transfer output is currently spendable or has a current-main-chain mined spender.
///
/// The exact tuple is derived here, not by the application: each fully authorized stored transfer
/// PCZT is extracted to obtain its consensus txid, its canonical Ironwood action index is `0`, and
/// its expected value comes from [`MigrationState::transfer_amount`]. The store acquires one atomic
/// write snapshot before rechecking the canonical state and reading every availability row; no
/// other connection can change the chain/note/spend evidence between a successful audit and owner
/// clearing. If any output is `Unknown` or `Unavailable`, this returns
/// [`MigrationCompletion::Pending`] and retains the durable owner/locks unchanged. Only when every
/// output is [`ReceivedOutputAvailability::Spendable`] or
/// [`ReceivedOutputAvailability::Spent`] are owner tokens and remaining locks atomically cleared.
///
/// `Spent` is current-main-chain historical evidence, not an irreversible consensus fact. A later
/// source or spender reorg makes the availability query return `Unknown`; the caller then rewinds
/// the affected transaction to `Broadcast`, and the now-reversible state recomputation moves the
/// migration out of `Complete`. Persisting that state with
/// [`update_migration_transaction_with_locks`] bootstraps the explicit recovery `owner` if
/// finalization had already cleared it. The caller generates that token once for the reorg recovery
/// attempt; compare-and-swap persistence makes concurrent attempts deterministic (exactly one
/// canonical owner wins), and the winner is then recovered from state on restart.
pub fn finalize_completed_migration<St>(
    store: &mut St,
    target_height: TargetHeight,
    confirmations_policy: ConfirmationsPolicy,
    lock_filter: LockFilter<'_>,
) -> Result<MigrationCompletion, CompletionError<<St as PoolMigrationRead>::Error>>
where
    St: PoolMigrationLockStore,
{
    let state = store
        .get_migration()
        .map_err(CompletionError::Store)?
        .ok_or(CompletionError::MigrationNotFound)?;
    if !matches!(state.status(), crate::engine::MigrationStatus::Complete)
        || state
            .transactions()
            .iter()
            .any(|transaction| !matches!(transaction.state(), MigrationTxState::Mined { .. }))
    {
        return Err(CompletionError::NotComplete);
    }

    let canonical_owners: BTreeSet<[u8; 32]> = state
        .transactions()
        .iter()
        .filter_map(|transaction| transaction.lock_owner())
        .collect();
    let owner = if canonical_owners.is_empty() {
        if state
            .transactions()
            .iter()
            .all(|transaction| transaction.lock_owner().is_none())
        {
            None
        } else {
            return Err(CompletionError::OwnerCorruption);
        }
    } else if canonical_owners.len() == 1 {
        let canonical = *canonical_owners
            .iter()
            .next()
            .expect("a one-element set has a first element");
        if state
            .transactions()
            .iter()
            .all(|transaction| transaction.lock_owner() == Some(canonical))
        {
            Some(LockOwner::new(canonical))
        } else {
            return Err(CompletionError::OwnerCorruption);
        }
    } else {
        return Err(CompletionError::OwnerCorruption);
    };

    let mut outputs = Vec::new();
    let mut output_refs = BTreeSet::new();
    for transaction in state.transactions().iter().filter(|transaction| {
        matches!(
            transaction.kind(),
            crate::engine::MigrationTxKind::Transfer { .. }
        )
    }) {
        let parsed = ::pczt::Pczt::parse(transaction.pczt()).map_err(CompletionError::Pczt)?;
        let expected_value = state
            .transfer_amount(transaction)
            .ok_or(CompletionError::MalformedTransfer(transaction.id()))?;
        let actions = parsed.ironwood().actions();
        if actions.len() != 1 || *actions[0].output().value() != Some(u64::from(expected_value)) {
            return Err(CompletionError::MalformedTransfer(transaction.id()));
        }
        let extracted = TransactionExtractor::new(parsed)
            .extract()
            .map_err(CompletionError::Extract)?;
        let output = ExactReceivedOutput::new(
            OutputRef::new(
                extracted.txid(),
                PoolType::Shielded(ShieldedPool::Ironwood),
                0,
            ),
            expected_value,
        );
        if !output_refs.insert(output.output_ref()) {
            return Err(CompletionError::DuplicateOutput(output.output_ref()));
        }
        outputs.push((transaction.id(), output));
    }

    if outputs.is_empty() {
        return Err(CompletionError::MalformedState);
    }
    let mut finalized = state.clone();
    let owners = owner.into_iter().collect::<BTreeSet<_>>();
    if !owners.is_empty() {
        for transaction in &mut finalized.transactions {
            transaction.lock_owner = None;
        }
    }
    let audit = store
        .finalize_migration_if_outputs_available(
            &state,
            &finalized,
            &owners,
            &outputs,
            target_height,
            confirmations_policy,
            lock_filter,
        )
        .map_err(CompletionError::Store)?;
    let storage_finality = audit.storage_finality();
    if matches!(storage_finality, StorageFinality::RecoveryRequired(_)) {
        return Err(CompletionError::RecoveryRequired);
    }
    let evidence = audit.into_evidence();
    if evidence.iter().any(|entry| {
        !matches!(
            entry.availability(),
            ReceivedOutputAvailability::Spendable | ReceivedOutputAvailability::Spent { .. }
        )
    }) {
        return Ok(MigrationCompletion::Pending(evidence));
    }
    if matches!(storage_finality, StorageFinality::Finalized(_)) {
        Ok(MigrationCompletion::Finalized(finalized))
    } else {
        Ok(MigrationCompletion::SpendablePendingFinality(evidence))
    }
}

/// Marks `expected` failed, then atomically releases only `owner`'s migration locks while
/// persisting the terminal state. A completed migration is rejected without a write; it must be
/// exact-output finalized or explicitly rewound after a reorg.
pub fn cancel_migration_and_release_locks<W, St>(
    wallet: &W,
    account: <W as InputSource>::AccountId,
    orchard_fvk: &FullViewingKey,
    store: &mut St,
    owner: LockOwner,
    expected: &MigrationState,
) -> Result<MigrationState, AdapterError<W, St>>
where
    W: WalletRead + InputSource,
    <W as InputSource>::AccountId: Copy,
    St: PoolMigrationLockStore,
{
    if matches!(expected.status, crate::engine::MigrationStatus::Complete) {
        return Err(Error::MigrationComplete);
    }
    let mut cancelled = expected.clone();
    cancelled.status = crate::engine::MigrationStatus::Failed;
    persist_migration_with_locks(
        wallet,
        account,
        orchard_fvk,
        store,
        owner,
        Some(expected),
        &cancelled,
    )
}

/// Applies a transaction lifecycle update through the same atomic whole-migration boundary used
/// for commit and refresh.
///
/// This preserves the durable owner, acquires any newly scanned dependent input, recomputes the
/// canonical migration status, and releases `owner`'s locks if this update makes the migration
/// terminal. It intentionally does not call the store's narrower
/// [`PoolMigrationWrite::update_transaction`] operation, which cannot compose the state update with
/// note-lock mutations.
///
/// The parameters intentionally keep wallet authority, store authority, canonical CAS state, and
/// the transaction lifecycle update distinct; collapsing them would obscure which values are
/// authenticated together at the atomic persistence boundary.
#[allow(clippy::too_many_arguments)]
pub fn update_migration_transaction_with_locks<W, St>(
    wallet: &W,
    account: <W as InputSource>::AccountId,
    orchard_fvk: &FullViewingKey,
    store: &mut St,
    owner: LockOwner,
    expected: &MigrationState,
    id: MigrationTxId,
    state: MigrationTxState,
) -> Result<MigrationState, AdapterError<W, St>>
where
    W: WalletRead + InputSource,
    <W as InputSource>::AccountId: Copy,
    St: PoolMigrationLockStore,
{
    let mut migration = expected.clone();
    let transaction = migration
        .transactions
        .iter_mut()
        .find(|transaction| transaction.id == id)
        .ok_or(Error::TransactionNotFound(id))?;
    transaction.state = state;
    if matches!(expected.status(), crate::engine::MigrationStatus::Complete)
        && !matches!(state, MigrationTxState::Mined { .. })
    {
        // `MigrationState::recompute_status` normally treats terminal states as irreversible so a
        // cancelled migration cannot be resurrected. This API is the explicit exception for a
        // chain-observed completion reorg: the caller supplies the exact canonical state and new
        // recovery owner, and the store compare-and-swap decides which recovery attempt wins.
        migration.status = crate::engine::MigrationStatus::InProgress;
    }
    migration.recompute_status();
    persist_migration_with_locks(
        wallet,
        account,
        orchard_fvk,
        store,
        owner,
        Some(expected),
        &migration,
    )
}

/// A migration wallet built over a `zcash_client_backend` wallet `W`, an account, its
/// [`UnifiedSpendingKey`], and a migration store `St`.
///
/// The wallet is held by a shared borrow: the migration never touches the note commitment tree
/// (anchors and witnesses are deferred to proving time), so nothing here needs `&mut W`.
pub struct WalletMigration<'a, W, St>
where
    W: WalletRead + InputSource,
{
    wallet: &'a W,
    account: <W as InputSource>::AccountId,
    usk: UnifiedSpendingKey,
    store: St,
}

impl<'a, W, St> WalletMigration<'a, W, St>
where
    W: WalletRead + InputSource,
    <W as InputSource>::AccountId: Copy,
    St: PoolMigrationRead,
{
    /// Wrap a wallet, an account, its spending key, and a store as a migration wallet.
    pub fn new(
        wallet: &'a W,
        account: <W as InputSource>::AccountId,
        usk: UnifiedSpendingKey,
        store: St,
    ) -> Self {
        Self {
            wallet,
            account,
            usk,
            store,
        }
    }

    /// Recover the store.
    pub fn into_store(self) -> St {
        self.store
    }

    /// The account's spendable Orchard notes, sorted by tree position so the index is stable across
    /// calls (the engine maps a value index from `spendable_orchard_note_values` back to a note by
    /// the same order).
    fn spendable_orchard_with_filter(
        &self,
        lock_filter: LockFilter<'_>,
    ) -> Result<Vec<SpendableNote>, AdapterError<W, St>> {
        select_spendable_orchard::<W, St>(self.wallet, self.account, lock_filter)
    }

    fn spendable_orchard(&self) -> Result<Vec<SpendableNote>, AdapterError<W, St>> {
        self.spendable_orchard_with_filter(LockFilter::Policy(&LockedInputPolicy::Exclude))
    }
}

impl<'a, W, St> MigrationBackend for WalletMigration<'a, W, St>
where
    W: WalletRead + InputSource,
    <W as InputSource>::AccountId: Copy,
    St: PoolMigrationRead,
{
    type Error = AdapterError<W, St>;

    fn spendable_orchard_note_values(&self) -> Result<Vec<Zatoshis>, Self::Error> {
        self.spendable_orchard()?
            .into_iter()
            .enumerate()
            .map(|(i, note)| Zatoshis::from_u64(note.value).map_err(|_| Error::InvalidNoteValue(i)))
            .collect()
    }

    fn chain_tip_height(&self) -> Result<BlockHeight, Self::Error> {
        self.wallet
            .chain_height()
            .map_err(Error::WalletRead)?
            .ok_or(Error::ChainTipUnknown)
    }
}

impl<'a, W, St> MigrationCrypto for WalletMigration<'a, W, St>
where
    W: WalletRead + InputSource,
    <W as InputSource>::AccountId: Copy,
    St: PoolMigrationRead,
{
    type Error = AdapterError<W, St>;

    fn orchard_fvk(&self) -> Result<FullViewingKey, Self::Error> {
        Ok(FullViewingKey::from(self.usk.orchard()))
    }

    fn resolve_wallet_note(&self, index: usize) -> Result<OrchardNote, Self::Error> {
        let notes = self.spendable_orchard()?;
        Ok(notes.get(index).ok_or(Error::NoteNotFound(index))?.note)
    }

    fn sign(&self, pczt: ::pczt::Pczt) -> Result<::pczt::Pczt, Self::Error> {
        let ask = SpendAuthorizingKey::from(self.usk.orchard());
        sign_pczt(pczt, &ask).map_err(Error::Sign)
    }
}

/// A wallet-backed migration adapter that reserves the exact inputs fixed by the committed PCZTs.
///
/// This wraps [`WalletMigration`] without changing the canonical planner, scheduler, PCZT builder,
/// or store schema. When the engine persists a non-terminal state, the adapter matches each real
/// Orchard spend nullifier to the wallet's exact output reference and asks the store to acquire the
/// owner-scoped locks atomically with the state write. Re-persisting after synchronization picks up
/// preparation outputs that did not exist at initial commit. `Failed` releases only this
/// migration owner's remaining locks; provisional `Complete` retains its owner until exact-output
/// finalization succeeds.
pub struct LockedWalletMigration<'a, W, St>
where
    W: WalletRead + InputSource,
{
    inner: WalletMigration<'a, W, St>,
    owner: LockOwner,
    last_persisted_state: Option<MigrationState>,
}

impl<'a, W, St> LockedWalletMigration<'a, W, St>
where
    W: WalletRead + InputSource,
    <W as InputSource>::AccountId: Copy,
    St: PoolMigrationLockStore,
{
    /// Wrap a wallet, account, spending key, lock-capable store, and durable lock owner.
    ///
    /// Generate `owner` with [`LockOwner::random`] for a new migration. On restart, recover the
    /// owner from the persisted migration (for example through the SQLite store's
    /// `migration_lock_owners` accessor) and pass the same token so re-acquisition is idempotent.
    pub fn new(
        wallet: &'a W,
        account: <W as InputSource>::AccountId,
        usk: UnifiedSpendingKey,
        store: St,
        owner: LockOwner,
    ) -> Self {
        Self {
            inner: WalletMigration::new(wallet, account, usk, store),
            owner,
            last_persisted_state: None,
        }
    }

    /// Resume from an exact canonical state previously read from `store`, refreshing all currently
    /// resolvable exact input locks before returning.
    ///
    /// The retained snapshot is the compare-and-swap expectation for the next write, preventing a
    /// stale adapter from overwriting a newer lifecycle transition. An existing owner is validated
    /// and its expired/lost locks are reacquired through the same CAS transaction; therefore no
    /// delivery/next-due path can observe a resumed migration before refresh succeeds. An ownerless
    /// finalized `Complete` state is the sole no-write case: it stays finalized until an explicit
    /// reorg lifecycle update bootstraps a caller-supplied recovery owner. Use [`Self::new`] only
    /// when the store is expected to contain no migration.
    pub fn resume(
        wallet: &'a W,
        account: <W as InputSource>::AccountId,
        usk: UnifiedSpendingKey,
        store: St,
        owner: LockOwner,
        canonical: MigrationState,
    ) -> Result<Self, AdapterError<W, St>> {
        let refresh_existing_owner = canonical
            .transactions()
            .iter()
            .any(|transaction| transaction.lock_owner().is_some());
        let mut resumed = Self {
            inner: WalletMigration::new(wallet, account, usk, store),
            owner,
            last_persisted_state: Some(canonical),
        };
        if refresh_existing_owner {
            let state = resumed
                .last_persisted_state
                .clone()
                .expect("the canonical resume snapshot was just installed");
            resumed.persist_with_locks(&state)?;
        }
        Ok(resumed)
    }

    /// Recover the wrapped store.
    pub fn into_store(self) -> St {
        self.inner.into_store()
    }

    /// The account's spendable Orchard notes, admitting only locks held by this migration and
    /// preferring that tier over unlocked notes. Planning before the first persist still sees every
    /// unlocked note, while resume and expired-transfer rebuild can resolve the exact notes that
    /// this adapter atomically reserved; foreign owners remain excluded.
    fn spendable_orchard(&self) -> Result<Vec<SpendableNote>, AdapterError<W, St>> {
        let policy = LockedInputPolicy::PreferLocked(NonEmptyBTreeSet::singleton(self.owner));
        self.inner
            .spendable_orchard_with_filter(LockFilter::Policy(&policy))
    }

    /// Persist the current migration and refresh every currently-resolvable input lock. Call this
    /// after synchronization makes a preparation output available, and after state transitions.
    /// A failed/cancelled state releases only this migration's locks instead; provisional Complete
    /// retains them pending exact-output finalization.
    pub fn persist_with_locks(
        &mut self,
        state: &MigrationState,
    ) -> Result<MigrationState, AdapterError<W, St>> {
        let orchard_fvk = FullViewingKey::from(self.inner.usk.orchard());
        let persisted = persist_migration_with_locks(
            self.inner.wallet,
            self.inner.account,
            &orchard_fvk,
            &mut self.inner.store,
            self.owner,
            self.last_persisted_state.as_ref(),
            state,
        )?;
        self.last_persisted_state = Some(persisted.clone());
        Ok(persisted)
    }

    /// Cancel a non-complete migration and atomically release its remaining locks. Upstream uses
    /// the terminal [`MigrationStatus::Failed`](crate::engine::MigrationStatus::Failed) state for a
    /// cancelled migration; attempting to cancel a completed migration fails without a write.
    pub fn cancel_and_release(&mut self) -> Result<MigrationState, AdapterError<W, St>> {
        let orchard_fvk = FullViewingKey::from(self.inner.usk.orchard());
        let expected = self
            .last_persisted_state
            .as_ref()
            .ok_or(Error::MigrationNotFound)?
            .clone();
        let cancelled = cancel_migration_and_release_locks(
            self.inner.wallet,
            self.inner.account,
            &orchard_fvk,
            &mut self.inner.store,
            self.owner,
            &expected,
        )?;
        self.last_persisted_state = Some(cancelled.clone());
        Ok(cancelled)
    }
}

impl<'a, W, St> MigrationBackend for LockedWalletMigration<'a, W, St>
where
    W: WalletRead + InputSource,
    <W as InputSource>::AccountId: Copy,
    St: PoolMigrationLockStore,
{
    type Error = AdapterError<W, St>;

    fn spendable_orchard_note_values(&self) -> Result<Vec<Zatoshis>, Self::Error> {
        self.spendable_orchard()?
            .into_iter()
            .enumerate()
            .map(|(i, note)| Zatoshis::from_u64(note.value).map_err(|_| Error::InvalidNoteValue(i)))
            .collect()
    }

    fn chain_tip_height(&self) -> Result<BlockHeight, Self::Error> {
        self.inner.chain_tip_height()
    }
}

impl<'a, W, St> MigrationCrypto for LockedWalletMigration<'a, W, St>
where
    W: WalletRead + InputSource,
    <W as InputSource>::AccountId: Copy,
    St: PoolMigrationLockStore,
{
    type Error = AdapterError<W, St>;

    fn orchard_fvk(&self) -> Result<FullViewingKey, Self::Error> {
        self.inner.orchard_fvk()
    }

    fn resolve_wallet_note(&self, index: usize) -> Result<OrchardNote, Self::Error> {
        let notes = self.spendable_orchard()?;
        Ok(notes.get(index).ok_or(Error::NoteNotFound(index))?.note)
    }

    fn sign(&self, pczt: ::pczt::Pczt) -> Result<::pczt::Pczt, Self::Error> {
        self.inner.sign(pczt)
    }
}

impl<'a, W, St> PoolMigrationRead for LockedWalletMigration<'a, W, St>
where
    W: WalletRead + InputSource,
    <W as InputSource>::AccountId: Copy,
    St: PoolMigrationLockStore,
{
    type Error = AdapterError<W, St>;

    fn get_migration(&self) -> Result<Option<MigrationState>, Self::Error> {
        self.inner.get_migration()
    }
}

impl<'a, W, St> PoolMigrationWrite for LockedWalletMigration<'a, W, St>
where
    W: WalletRead + InputSource,
    <W as InputSource>::AccountId: Copy,
    St: PoolMigrationLockStore,
{
    fn replace_migration(&mut self, state: &MigrationState) -> Result<(), Self::Error> {
        self.persist_with_locks(state).map(|_| ())
    }

    fn update_transaction(
        &mut self,
        id: MigrationTxId,
        state: MigrationTxState,
    ) -> Result<(), Self::Error> {
        let orchard_fvk = FullViewingKey::from(self.inner.usk.orchard());
        let expected = self
            .last_persisted_state
            .as_ref()
            .ok_or(Error::MigrationNotFound)?
            .clone();
        let persisted = update_migration_transaction_with_locks(
            self.inner.wallet,
            self.inner.account,
            &orchard_fvk,
            &mut self.inner.store,
            self.owner,
            &expected,
            id,
            state,
        )?;
        self.last_persisted_state = Some(persisted);
        Ok(())
    }
}

/// Commit and sign a migration through [`LockedWalletMigration`], returning the exact state stored
/// with its durable owner token. The lock-capable store atomically acquires the root PCZTs' exact
/// wallet inputs and persists this state; no unlocked intermediate state is written.
pub fn commit_preparation_locked<P, W, St, R>(
    params: &P,
    target_height: BlockHeight,
    backend: &mut LockedWalletMigration<'_, W, St>,
    plan: &crate::engine::MigrationPlan,
    rng: &mut R,
) -> Result<MigrationState, crate::engine::CommitError<AdapterError<W, St>>>
where
    P: zcash_protocol::consensus::Parameters + Clone,
    W: WalletRead + InputSource,
    <W as InputSource>::AccountId: Copy,
    St: PoolMigrationLockStore,
    R: rand_core::RngCore + rand_core::CryptoRng,
{
    crate::engine::commit_preparation(params, target_height, backend, plan, rng)?;
    backend
        .last_persisted_state
        .clone()
        .ok_or(crate::engine::CommitError::NoMigrationInProgress)
}

/// The result of building and atomically reserving an externally-signed migration.
pub type UnsignedLockedMigrationResult<W, St> = Result<
    (MigrationState, Vec<crate::engine::UnsignedMigrationTx>),
    crate::engine::CommitError<AdapterError<W, St>>,
>;

/// Build an externally-signed migration through [`LockedWalletMigration`]. The unsigned PCZTs and
/// the exact owner-bearing persisted state are returned together; root inputs are locked atomically
/// with that state before any unsigned artifact leaves this call.
pub fn build_preparation_unsigned_locked<P, W, St, R>(
    params: &P,
    target_height: BlockHeight,
    backend: &mut LockedWalletMigration<'_, W, St>,
    plan: &crate::engine::MigrationPlan,
    rng: &mut R,
) -> UnsignedLockedMigrationResult<W, St>
where
    P: zcash_protocol::consensus::Parameters + Clone,
    W: WalletRead + InputSource,
    <W as InputSource>::AccountId: Copy,
    St: PoolMigrationLockStore,
    R: rand_core::RngCore + rand_core::CryptoRng,
{
    let (_, unsigned) =
        crate::engine::build_preparation_unsigned(params, target_height, backend, plan, rng)?;
    let state = backend
        .last_persisted_state
        .clone()
        .ok_or(crate::engine::CommitError::NoMigrationInProgress)?;
    Ok((state, unsigned))
}

impl<'a, W, St> PoolMigrationRead for WalletMigration<'a, W, St>
where
    W: WalletRead + InputSource,
    <W as InputSource>::AccountId: Copy,
    St: PoolMigrationRead,
{
    type Error = AdapterError<W, St>;

    fn get_migration(&self) -> Result<Option<MigrationState>, Self::Error> {
        self.store.get_migration().map_err(Error::Store)
    }
}

impl<'a, W, St> PoolMigrationWrite for WalletMigration<'a, W, St>
where
    W: WalletRead + InputSource,
    <W as InputSource>::AccountId: Copy,
    St: PoolMigrationWrite,
{
    fn replace_migration(&mut self, state: &MigrationState) -> Result<(), Self::Error> {
        self.store.replace_migration(state).map_err(Error::Store)
    }

    fn update_transaction(
        &mut self,
        id: MigrationTxId,
        state: MigrationTxState,
    ) -> Result<(), Self::Error> {
        self.store
            .update_transaction(id, state)
            .map_err(Error::Store)
    }
}

/// Why proving a migration transaction through the wallet-backed prover failed. `TE` is the
/// wallet's commitment-tree error type ([`WalletCommitmentTrees::Error`]); `NE` is its note-source
/// error type ([`InputSource::Error`]); `RE` is its chain-state error type
/// ([`WalletRead::Error`]).
#[derive(Debug)]
pub enum WalletProveError<TE, NE, RE> {
    /// The PCZT has no real Orchard spend whose witness is still deferred. A migration transfer
    /// spends one funding note and a preparation transaction one or more, so the Orchard bundle
    /// carries at least one action with an absent witness (the fabricated dummy spends keep their
    /// own); none means the PCZT is not a deferred-anchor migration transaction awaiting proof.
    NoRealSpend,
    /// No spendable Orchard note in the wallet matches a spend's revealed nullifier, so its tree
    /// position is unknown: the note the transaction spends is not among the account's unspent
    /// notes (it was never scanned, or has already been spent).
    UnknownSpentNote(Nullifier),
    /// A deferred-witness Orchard spend's nullifier bytes are not a valid Orchard nullifier, so the
    /// PCZT is not a well-formed migration transaction awaiting proof.
    MalformedNullifier([u8; 32]),
    /// Looking up the note-selection target height (the chain tip) through the wallet failed.
    TargetHeight(RE),
    /// The wallet knows of no block data, so the note-selection target height (the chain tip) is
    /// unavailable.
    ChainTipUnknown,
    /// Enumerating the account's spendable Orchard notes (to locate each spend by nullifier) failed.
    Notes(NE),
    /// A commitment tree (the Orchard source tree, or the Ironwood destination tree for a transfer)
    /// has no root at the anchor checkpoint (the checkpoint was never created, or was pruned before
    /// proving; see issue #2700).
    AnchorNotFound(BlockHeight),
    /// A spent note has no witness at the anchor checkpoint (the checkpoint was pruned, or the
    /// note's position is not marked in the tree).
    WitnessNotFound(BlockHeight),
    /// The wallet backend tracks no Ironwood commitment tree, so a transfer's Ironwood destination
    /// anchor cannot be resolved (the backend does not support the Ironwood pool).
    IronwoodTreeUnavailable,
    /// A commitment-tree query failed.
    Tree(ShardTreeError<TE>),
    /// Installing the Orchard source or Ironwood destination anchor through the PCZT `Updater` role
    /// failed.
    Anchor(AnchorUpdateError),
    /// Installing a spend witness through the PCZT `Updater` role failed.
    Witness(SpendWitnessUpdateError),
    /// Creating the Orchard or Ironwood proof failed. The two proof roles return distinct error
    /// types and `pczt` does not export the Ironwood one, so the failure is carried as a labeled
    /// diagnostic string rather than a typed value.
    Prove(alloc::string::String),
}

impl<TE, NE, RE> From<ShardTreeError<TE>> for WalletProveError<TE, NE, RE> {
    fn from(e: ShardTreeError<TE>) -> Self {
        WalletProveError::Tree(e)
    }
}

impl<TE: fmt::Debug, NE: fmt::Debug, RE: fmt::Debug> fmt::Display for WalletProveError<TE, NE, RE> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WalletProveError::NoRealSpend => {
                f.write_str("the PCZT has no deferred-witness Orchard spend to prove")
            }
            WalletProveError::UnknownSpentNote(nf) => {
                write!(
                    f,
                    "no spendable Orchard note matches spend nullifier {nf:?}"
                )
            }
            WalletProveError::MalformedNullifier(bytes) => {
                write!(
                    f,
                    "a spend's nullifier bytes are not a valid nullifier: {bytes:?}"
                )
            }
            WalletProveError::TargetHeight(e) => {
                write!(
                    f,
                    "looking up the note-selection target height failed: {e:?}"
                )
            }
            WalletProveError::ChainTipUnknown => {
                f.write_str("the wallet knows of no block data, so the chain tip is unavailable")
            }
            WalletProveError::Notes(e) => {
                write!(f, "enumerating spendable Orchard notes failed: {e:?}")
            }
            WalletProveError::AnchorNotFound(h) => write!(
                f,
                "a commitment tree has no root at the anchor checkpoint {}",
                u32::from(*h)
            ),
            WalletProveError::WitnessNotFound(h) => write!(
                f,
                "a spent note has no witness at the anchor checkpoint {}",
                u32::from(*h)
            ),
            WalletProveError::IronwoodTreeUnavailable => {
                f.write_str("the wallet backend tracks no Ironwood commitment tree")
            }
            WalletProveError::Tree(e) => write!(f, "commitment-tree query failed: {e:?}"),
            WalletProveError::Anchor(e) => write!(f, "installing an anchor failed: {e:?}"),
            WalletProveError::Witness(e) => write!(f, "installing a spend witness failed: {e:?}"),
            WalletProveError::Prove(msg) => write!(f, "creating a bundle proof failed: {msg}"),
        }
    }
}

impl<TE: fmt::Debug, NE: fmt::Debug, RE: fmt::Debug> core::error::Error
    for WalletProveError<TE, NE, RE>
{
}

/// The wallet-backed prover's error for a wallet `W`: a [`WalletProveError`] over the wallet's
/// commitment-tree, note-source, and chain-state error types.
type ProverError<W> = WalletProveError<
    <W as WalletCommitmentTrees>::Error,
    <W as InputSource>::Error,
    <W as WalletRead>::Error,
>;

/// A wallet-backed prover for migration transactions: the mutable counterpart to [`WalletMigration`].
///
/// Proving resolves a transaction's DEFERRED Orchard anchor and its spends' Merkle witnesses against
/// a checkpoint (ZIP 374), which needs MUTABLE access to the wallet's Orchard commitment tree
/// ([`WalletCommitmentTrees::with_orchard_tree_mut`], whose witness resolution caches into the
/// tree). That is why proving lives here, borrowing the wallet as `&mut W`, rather than on the
/// shared-borrow [`WalletMigration`] used to build and sign.
///
/// Each spend is located by the nullifier it reveals: the prover enumerates the account's unspent
/// Orchard notes ([`InputSource::select_unspent_notes`]), recomputes each note's nullifier under the
/// account's full viewing key, and matches. This serves both a transfer (one funding-note spend
/// plus an Ironwood output) and a preparation transaction (one or more spends, no Ironwood). The
/// anchor checkpoint the witnesses are taken against must still exist in the tree at proving time
/// (the wallet backend must retain that checkpoint until the migration's transfers are proven).
pub struct WalletMigrationProver<'a, W>
where
    W: InputSource,
{
    wallet: &'a mut W,
    account: <W as InputSource>::AccountId,
    fvk: FullViewingKey,
}

impl<'a, W> WalletMigrationProver<'a, W>
where
    W: InputSource,
{
    /// Wrap a wallet (borrowed mutably for commitment-tree access), the account whose notes the
    /// migration spends, and that account's Orchard full viewing key (used to recompute each spent
    /// note's nullifier when locating it among the account's unspent notes).
    pub fn new(
        wallet: &'a mut W,
        account: <W as InputSource>::AccountId,
        fvk: FullViewingKey,
    ) -> Self {
        Self {
            wallet,
            account,
            fvk,
        }
    }
}

impl<'a, W> WalletMigrationProver<'a, W>
where
    W: WalletCommitmentTrees + InputSource + WalletRead,
    <W as InputSource>::AccountId: Copy,
{
    /// Prove one migration transaction's Orchard bundle (and its Ironwood bundle, when it has one)
    /// against `anchor_height`: install the source anchor and every deferred spend's witness through the
    /// PCZT `Updater` role, then run the provers. Shared by
    /// [`prove_transfer`](MigrationProver::prove_transfer) (a transfer: one Orchard spend plus an
    /// Ironwood output) and [`prove_preparation`](MigrationProver::prove_preparation) (a preparation:
    /// one or more Orchard spends, no Ironwood).
    ///
    /// The anchor and witnesses are resolved at `anchor_height`, but the spent notes are located at
    /// the wallet's standard note-selection target height (the chain tip, from
    /// [`WalletRead::get_target_and_anchor_heights`]), so a note already spent by a mined migration
    /// transaction is excluded from the candidate set.
    fn prove_orchard(
        &mut self,
        pczt: ::pczt::Pczt,
        anchor_height: BlockHeight,
    ) -> Result<::pczt::Pczt, ProverError<W>> {
        // Every Orchard action whose witness is still deferred is a real spend to witness; the padded
        // dummy spends keep their (arbitrary) witnesses from build time (ZIP 374).
        let real_spends: Vec<(usize, Nullifier)> = pczt
            .orchard()
            .actions()
            .iter()
            .enumerate()
            .filter(|(_, action)| action.spend().witness().is_none())
            .map(|(index, action)| {
                let bytes = action.spend().nullifier();
                Option::<Nullifier>::from(Nullifier::from_bytes(bytes))
                    .map(|nf| (index, nf))
                    .ok_or(WalletProveError::MalformedNullifier(*bytes))
            })
            .collect::<Result<_, _>>()?;
        if real_spends.is_empty() {
            return Err(WalletProveError::NoRealSpend);
        }

        // Locate each spend in the wallet's note store: map every unspent Orchard note's nullifier
        // (recomputed under the account FVK) to its commitment-tree position, then look up each spend.
        // Select notes at the wallet's standard note-selection target height (the chain tip), not the
        // witness anchor, so a note already spent by a mined migration transaction is excluded from
        // consideration. Only the target is needed here; `min_confirmations` bounds only the (unused)
        // anchor height, so the minimum is passed to avoid a spurious absence near genesis.
        let (target, _anchor) = self
            .wallet
            .get_target_and_anchor_heights(NonZeroU32::MIN)
            .map_err(WalletProveError::TargetHeight)?
            .ok_or(WalletProveError::ChainTipUnknown)?;
        let received = self
            .wallet
            .select_unspent_notes(
                self.account,
                &[ShieldedPool::Orchard],
                target,
                &[],
                LockFilter::Unfiltered,
            )
            .map_err(WalletProveError::Notes)?;
        let positions: BTreeMap<Nullifier, Position> = received
            .orchard()
            .iter()
            .map(|rn| {
                (
                    rn.note().nullifier(&self.fvk),
                    rn.note_commitment_tree_position(),
                )
            })
            .collect();
        let spend_positions: Vec<(usize, Position)> = real_spends
            .iter()
            .map(|(index, nf)| {
                positions
                    .get(nf)
                    .map(|pos| (*index, *pos))
                    .ok_or(WalletProveError::UnknownSpentNote(*nf))
            })
            .collect::<Result<_, _>>()?;

        // A transfer carries an Ironwood output bundle; a preparation transaction is Orchard-only.
        let has_ironwood = !pczt.ironwood().actions().is_empty();

        // Resolve the source anchor (the tree root at the checkpoint) and each spend's Merkle witness
        // against it, mirroring `create_proposed_transactions`.
        let (anchor, witnesses): (Anchor, Vec<(usize, MerklePath)>) = self
            .wallet
            .with_orchard_tree_mut::<_, _, ProverError<W>>(|tree| {
                let root: Anchor = tree
                    .root_at_checkpoint_id(&anchor_height)?
                    .ok_or(WalletProveError::AnchorNotFound(anchor_height))?
                    .into();
                let mut witnesses = Vec::with_capacity(spend_positions.len());
                for (index, position) in &spend_positions {
                    let path: MerklePath = tree
                        .witness_at_checkpoint_id_caching(*position, &anchor_height)?
                        .ok_or(WalletProveError::WitnessNotFound(anchor_height))?
                        .into();
                    witnesses.push((*index, path));
                }
                Ok((root, witnesses))
            })?;

        // A transfer's Ironwood destination bundle must anchor at the SAME height as its Orchard
        // source bundle: all anchors in a transaction are computed for one height. Resolve the
        // Ironwood tree root at `anchor_height` (its output-only action's padding spend is a value-0
        // dummy whose Merkle path the circuit does not enforce, so no Ironwood witness is installed,
        // but the anchor must still be a real historical Ironwood root the consensus rules accept:
        // the empty-tree root is only valid while no Ironwood notes have been committed).
        let ironwood_anchor: Option<Anchor> = if has_ironwood {
            Some(
                self.wallet
                    .with_ironwood_tree_mut::<_, Anchor, ProverError<W>>(|tree| {
                        Ok(tree
                            .root_at_checkpoint_id(&anchor_height)?
                            .ok_or(WalletProveError::AnchorNotFound(anchor_height))?
                            .into())
                    })?
                    .ok_or(WalletProveError::IronwoodTreeUnavailable)?,
            )
        } else {
            None
        };

        // Install the deferred data through the Updater role: the Orchard source anchor and every
        // spend's witness, plus (for a transfer) the Ironwood destination anchor.
        let mut updater = Updater::new(pczt)
            .set_orchard_anchor(anchor)
            .map_err(WalletProveError::Anchor)?
            .set_orchard_spend_witnesses(witnesses)
            .map_err(WalletProveError::Witness)?;
        if let Some(ironwood_anchor) = ironwood_anchor {
            updater = updater
                .set_ironwood_anchor(ironwood_anchor)
                .map_err(WalletProveError::Anchor)?;
        }
        let updated = updater.finish();

        // Prove the Orchard bundle, and the Ironwood bundle too when present, with the single
        // post-NU6.3 Orchard proving key.
        let pk = cached_orchard_proving_key(OrchardCircuitVersion::PostNu6_3);
        let orchard_proven = Prover::new(updated)
            .create_orchard_proof(pk)
            .map_err(|e| WalletProveError::Prove(alloc::format!("orchard proof: {e:?}")))?;
        let proven = if has_ironwood {
            orchard_proven
                .create_ironwood_proof(pk)
                .map_err(|e| WalletProveError::Prove(alloc::format!("ironwood proof: {e:?}")))?
        } else {
            orchard_proven
        };
        Ok(proven.finish())
    }
}

impl<'a, W> MigrationProver for WalletMigrationProver<'a, W>
where
    W: WalletCommitmentTrees + InputSource + WalletRead,
    <W as InputSource>::AccountId: Copy,
{
    type Error = ProverError<W>;

    fn prove_transfer(
        &mut self,
        pczt: ::pczt::Pczt,
        anchor_boundary: BlockHeight,
    ) -> Result<::pczt::Pczt, Self::Error> {
        self.prove_orchard(pczt, anchor_boundary)
    }

    fn prove_preparation(
        &mut self,
        pczt: ::pczt::Pczt,
        anchor: BlockHeight,
    ) -> Result<::pczt::Pczt, Self::Error> {
        self.prove_orchard(pczt, anchor)
    }
}

#[cfg(all(test, feature = "wallet"))]
mod tests {
    use super::*;

    use rand_core::{CryptoRng, RngCore};
    use zcash_protocol::consensus::Parameters;

    use crate::engine::commit_preparation;

    /// Compile-time proof that `WalletMigration` over ANY `zcash_client_backend` wallet `W` and ANY
    /// migration store `St` satisfies every trait bound `commit_preparation` requires (backend +
    /// crypto + store, all sharing one error type). Naming the generic function instantiated at
    /// `WalletMigration<W, St>` forces the type checker to verify that instantiation's bounds hold;
    /// if the four trait impls ever stop lining up with the commit path, this stops compiling. It
    /// is never called and needs no wallet instance, so it pulls in no test-only wallet dependency
    /// (which would otherwise force `zcash_client_backend`'s Orchard feature on across the whole
    /// workspace's test build).
    #[allow(dead_code)]
    fn assert_commit_bounds<'a, P, W, St, R>()
    where
        P: Parameters + Clone,
        W: WalletRead + InputSource + 'a,
        <W as InputSource>::AccountId: Copy,
        St: PoolMigrationWrite,
        R: RngCore + CryptoRng,
    {
        let _ = commit_preparation::<P, WalletMigration<'a, W, St>, R>;
    }
}
