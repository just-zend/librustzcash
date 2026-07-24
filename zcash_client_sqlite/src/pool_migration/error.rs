//! The pool-migration store's error type.

use std::fmt;

use zcash_client_backend::wallet::OutputRef;
use zcash_pool_migration::engine::MigrationTxId;

/// A failure reading or writing the pool-migration store.
#[derive(Debug)]
pub enum Error {
    /// A `rusqlite` (SQLite) error.
    Db(rusqlite::Error),
    /// The account a store was requested for (by [`AccountUuid`]) does not exist in the wallet's
    /// `accounts` table, so its migration cannot be scoped to an account row.
    ///
    /// [`AccountUuid`]: crate::AccountUuid
    AccountUnknown,
    /// A stored value could not be decoded back into the engine's types (an out-of-range amount, an
    /// unrecognized discriminant, or a missing column for the stored variant). The `&'static str`
    /// names the field.
    Corrupt(&'static str),
    /// The migration state to be written contains a preparation layer with no transactions, or a
    /// transaction with neither inputs nor outputs. The schema stores the layers/transactions grid
    /// only through the input and output rows, so such a state would read back with its grid
    /// coordinates silently renumbered; a plan produced by the engine never contains these. The
    /// `&'static str` names the offending structure.
    Unrepresentable(&'static str),
    /// An exact migration input is already locked by another active owner.
    LockConflict(OutputRef),
    /// An output supplied to an account-scoped migration store does not belong to that account (or
    /// is not an Orchard output known to the wallet). Treating this as a typed failure prevents a
    /// store for one account from reserving another account's note.
    OutputNotOwned(OutputRef),
    /// The persisted migration is owned by a different lock owner than the caller attempting an
    /// atomic refresh or release.
    CanonicalOwnerMismatch,
    /// The canonical migration changed (or appeared/disappeared) since the caller's snapshot.
    /// The atomic operation is rolled back rather than overwriting the newer state.
    CanonicalStateMismatch,
    /// The additive delivery-control schema is missing, future, or corrupt.
    DeliverySchemaIncompatible,
    /// A delivery operation was requested through the context-free canonical store constructor.
    /// Policy decoding and validation require Rust-owned network consensus parameters.
    DeliveryContextUnavailable,
    /// Retired standalone-engine state was detected. Runtime migration and conflicting spend paths
    /// must remain closed until explicit recovery is completed.
    LegacyRecoveryRequired,
    /// Canonical state does not contain exactly one lock owner from which to derive the run id.
    DeliveryRunUnavailable,
    /// The caller's run identity does not match the canonical migration owner.
    DeliveryRunMismatch,
    /// Another scheduled or immediate delivery run already owns live account authority.
    DeliveryLaneConflict,
    /// The wallet-derived immediate proposal would spend more Orchard value than the user's
    /// confirmed gross-amount authorization.
    ImmediateAmountLimitExceeded,
    /// The delivery row changed since the caller's snapshot.
    DeliveryRevisionMismatch,
    /// A submission policy is required for the requested operation.
    DeliveryPolicyMissing,
    /// The supplied submission-policy fingerprint differs from the immutable binding.
    DeliveryPolicyMismatch,
    /// A different submission policy is already bound to this run.
    DeliveryPolicyAlreadyBound,
    /// The supplied policy or sanitized failure reason exceeds its durable storage bound.
    DeliveryValueTooLarge,
    /// The delivery phase does not permit the requested transition.
    DeliveryPhaseMismatch,
    /// No claim in the required lifecycle state exists for the transaction.
    DeliveryClaimUnavailable,
    /// The callback token does not own the live claim.
    DeliveryClaimTokenMismatch,
    /// The callback arrived after the claim lease expired.
    DeliveryClaimLeaseExpired,
    /// Materialized bytes do not match the exact canonical transaction and PCZT digest.
    DeliveryArtifactMismatch,
    /// Canonical PCZT/state changed after exact bytes may have reached the network.
    DeliveryExposedStateChanged(MigrationTxId),
    /// Canonical replacement attempted to remove a transaction that still has a delivery record.
    DeliveryClaimedTransactionRemoved(MigrationTxId),
    /// Canonical state records network exposure without a matching exact delivery record.
    DeliveryUntrackedExposure(MigrationTxId),
    /// Exposed transaction state remains unresolved, so locks/state cannot safely be abandoned.
    DeliveryNotSafeToAbandon,
    /// A pre-finality chain rewind invalidated completion evidence; explicit recovery is required.
    DeliveryRecoveryRequired,
    /// A wallet-storage operation used while releasing migration locks failed.
    Wallet(crate::error::SqliteClientError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Db(e) => write!(f, "pool-migration store database error: {e}"),
            Error::AccountUnknown => {
                write!(f, "pool-migration store: no such account in the wallet")
            }
            Error::Corrupt(field) => {
                write!(f, "pool-migration store: corrupt stored value for {field}")
            }
            Error::Unrepresentable(what) => {
                write!(f, "pool-migration store: cannot represent {what}")
            }
            Error::LockConflict(output) => {
                write!(f, "pool-migration input is already locked: {output:?}")
            }
            Error::OutputNotOwned(output) => write!(
                f,
                "pool-migration input does not belong to the scoped account: {output:?}"
            ),
            Error::CanonicalOwnerMismatch => f.write_str(
                "pool-migration lock owner does not match the canonical persisted migration",
            ),
            Error::CanonicalStateMismatch => {
                f.write_str("pool-migration canonical state changed before the atomic write")
            }
            Error::DeliverySchemaIncompatible => {
                f.write_str("pool-migration delivery schema is unavailable or incompatible")
            }
            Error::DeliveryContextUnavailable => f.write_str(
                "pool-migration delivery requires Rust-derived network consensus context",
            ),
            Error::LegacyRecoveryRequired => f.write_str(
                "retired standalone Ironwood migration state requires explicit recovery",
            ),
            Error::DeliveryRunUnavailable => {
                f.write_str("canonical migration does not have exactly one durable run owner")
            }
            Error::DeliveryRunMismatch => {
                f.write_str("delivery run identity does not match canonical state")
            }
            Error::DeliveryLaneConflict => {
                f.write_str("another live migration delivery run already owns this account")
            }
            Error::ImmediateAmountLimitExceeded => f.write_str(
                "wallet-derived immediate migration exceeds the authorized gross amount",
            ),
            Error::DeliveryRevisionMismatch => {
                f.write_str("delivery revision changed before the atomic write")
            }
            Error::DeliveryPolicyMissing => {
                f.write_str("delivery submission policy has not been bound")
            }
            Error::DeliveryPolicyMismatch => {
                f.write_str("delivery submission policy fingerprint mismatch")
            }
            Error::DeliveryPolicyAlreadyBound => {
                f.write_str("a different immutable submission policy is already bound")
            }
            Error::DeliveryValueTooLarge => {
                f.write_str("delivery policy or sanitized reason exceeds its size limit")
            }
            Error::DeliveryPhaseMismatch => {
                f.write_str("delivery phase does not permit this operation")
            }
            Error::DeliveryClaimUnavailable => {
                f.write_str("delivery claim is unavailable in the required lifecycle state")
            }
            Error::DeliveryClaimTokenMismatch => {
                f.write_str("delivery callback token does not own the live claim")
            }
            Error::DeliveryClaimLeaseExpired => {
                f.write_str("delivery claim lease expired before the callback")
            }
            Error::DeliveryArtifactMismatch => {
                f.write_str("materialized transaction does not match canonical migration state")
            }
            Error::DeliveryExposedStateChanged(id) => write!(
                f,
                "canonical transaction {} changed after network exposure",
                u32::from(*id)
            ),
            Error::DeliveryClaimedTransactionRemoved(id) => write!(
                f,
                "canonical transaction {} cannot be removed while delivery evidence exists",
                u32::from(*id)
            ),
            Error::DeliveryUntrackedExposure(id) => write!(
                f,
                "canonical transaction {} was exposed without a delivery record",
                u32::from(*id)
            ),
            Error::DeliveryNotSafeToAbandon => {
                f.write_str("delivery still has unresolved network-exposed transaction bytes")
            }
            Error::DeliveryRecoveryRequired => {
                f.write_str("pool-migration storage finality requires explicit reorg recovery")
            }
            Error::Wallet(e) => write!(f, "pool-migration wallet operation failed: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Db(e) => Some(e),
            Error::Wallet(e) => Some(e),
            Error::AccountUnknown
            | Error::Corrupt(_)
            | Error::Unrepresentable(_)
            | Error::LockConflict(_)
            | Error::OutputNotOwned(_)
            | Error::CanonicalOwnerMismatch
            | Error::CanonicalStateMismatch
            | Error::DeliverySchemaIncompatible
            | Error::DeliveryContextUnavailable
            | Error::LegacyRecoveryRequired
            | Error::DeliveryRunUnavailable
            | Error::DeliveryRunMismatch
            | Error::DeliveryLaneConflict
            | Error::ImmediateAmountLimitExceeded
            | Error::DeliveryRevisionMismatch
            | Error::DeliveryPolicyMissing
            | Error::DeliveryPolicyMismatch
            | Error::DeliveryPolicyAlreadyBound
            | Error::DeliveryValueTooLarge
            | Error::DeliveryPhaseMismatch
            | Error::DeliveryClaimUnavailable
            | Error::DeliveryClaimTokenMismatch
            | Error::DeliveryClaimLeaseExpired
            | Error::DeliveryArtifactMismatch
            | Error::DeliveryExposedStateChanged(_)
            | Error::DeliveryClaimedTransactionRemoved(_)
            | Error::DeliveryUntrackedExposure(_)
            | Error::DeliveryNotSafeToAbandon
            | Error::DeliveryRecoveryRequired => None,
        }
    }
}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Error::Db(e)
    }
}

impl From<zcash_protocol::value::BalanceError> for Error {
    /// A stored `INTEGER` amount outside the valid `Zatoshis` range (negative or above the money
    /// cap) is corrupt data.
    fn from(_: zcash_protocol::value::BalanceError) -> Self {
        Error::Corrupt("amount out of range")
    }
}
