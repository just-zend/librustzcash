//! Durable delivery coordination for pool-migration transactions.
//!
//! [`MigrationState`] remains the sole authority for the canonical migration plan, PCZT bytes,
//! schedule, and transaction lifecycle. This module adds crash-safe delivery capabilities and
//! exact-artifact evidence without changing the upstream state machine.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::{
    fmt,
    num::{NonZeroU32, NonZeroU64},
};

use blake2b_simd::Params;
use corez::io::{self, Read, Write};
use pczt::roles::{combiner::Combiner, tx_extractor::TransactionExtractor};
use rand_core::{CryptoRng, RngCore};
use zcash_client_backend::{fees::StandardFeeRule, proposal::Proposal, wallet::LockOwner};
use zcash_encoding::{CompactSize, Optional, Vector};
use zcash_primitives::transaction::{Transaction, builder::DEFAULT_TX_EXPIRY_DELTA};
use zcash_protocol::{
    TxId,
    consensus::{BlockHeight, BranchId, NetworkType, NetworkUpgrade, Parameters},
    value::Zatoshis,
};

use crate::{
    engine::{
        MigrationState, MigrationStatus, MigrationTransaction, MigrationTxId, MigrationTxKind,
        MigrationTxState, PoolMigrationRead, RebuiltTransferSuccessor,
    },
    note_splitting::NoteSplitPlan,
    preparation::{PrepInput, PrepOutput, PrepTransaction, PreparationPlan},
};

const DIGEST_LENGTH: usize = 32;
const STATE_PERSONAL: &[u8; 16] = b"ZcashMigStateV1!";
const PCZT_PERSONAL: &[u8; 16] = b"ZcashMigPcztV1!!";
const TRANSACTION_BINDING_PERSONAL: &[u8; 16] = b"ZcashMigTxBindV1";
const POLICY_PERSONAL: &[u8; 16] = b"ZcashMigPolicyV1";
const LEGACY_PERSONAL: &[u8; 16] = b"ZcashMigLegacyV1";
const CONSENSUS_PERSONAL: &[u8; 16] = b"ZcashMigConsens1";
const IMMEDIATE_PROPOSAL_PERSONAL: &[u8; 16] = b"ZcashMigImmedV1!";
const EXACT_TRANSACTION_PERSONAL: &[u8; 16] = b"ZcashMigExactV1!";
const FINALITY_ARCHIVE_PERSONAL: &[u8; 16] = b"ZcashMigArchiv1!";

/// The first revision persisted by the delivery-control schema.
const FIRST_DELIVERY_REVISION: u64 = 1;

/// Version of the lossless canonical migration-state archive and fingerprint input.
pub const MIGRATION_STATE_ARCHIVE_VERSION: u8 = 1;
/// Version of the canonical transaction-binding fingerprint input.
const TRANSACTION_BINDING_CODEC_VERSION: u8 = 1;
/// Version of the canonical consensus fingerprint input.
const CONSENSUS_CODEC_VERSION: u8 = 1;
/// Version of the canonical submission-policy encoding.
const SUBMISSION_POLICY_CODEC_VERSION: u8 = 1;
/// Version of the Rust-owned immediate-proposal envelope.
const IMMEDIATE_PROPOSAL_CODEC_VERSION: u8 = 2;
/// Version of the canonical finalized-transfer archive.
const FINALITY_ARCHIVE_CODEC_VERSION: u8 = 2;

const NETWORK_MAIN_TAG: u8 = 0;
const NETWORK_TEST_TAG: u8 = 1;
const NETWORK_REGTEST_TAG: u8 = 2;
const TRANSPORT_DIRECT_TLS_TAG: u8 = 0;
const TRANSPORT_TOR_ONION_TAG: u8 = 1;
const TRANSPORT_LOOPBACK_DEVELOPMENT_TAG: u8 = 2;
/// Stable canonical-policy tag for a public TLS endpoint reached through Tor.
const TRANSPORT_TOR_PROXY_TLS_TAG: u8 = 3;
const TRANSACTION_KIND_PREPARATION_TAG: u8 = 0;
const TRANSACTION_KIND_TRANSFER_TAG: u8 = 1;
const ARTIFACT_SCHEDULED_TAG: u8 = 0;
const ARTIFACT_IMMEDIATE_TAG: u8 = 1;
const PREPARATION_INPUT_WALLET_TAG: u8 = 0;
const PREPARATION_INPUT_PRIOR_TAG: u8 = 1;
const PREPARATION_OUTPUT_FUNDING_TAG: u8 = 0;
const PREPARATION_OUTPUT_INTERMEDIATE_TAG: u8 = 1;
const PREPARATION_OUTPUT_CHANGE_TAG: u8 = 2;

/// Maximum size of a normalized submission endpoint.
pub const MAX_SUBMISSION_ENDPOINT_BYTES: usize = 2_048;
/// Maximum size of canonical submission-policy bytes accepted by a durable store.
pub const MAX_SUBMISSION_POLICY_BYTES: usize = 4_096;
/// Maximum opaque upstream proposal payload accepted inside the Rust-owned immediate envelope.
pub const MAX_IMMEDIATE_PROPOSAL_PAYLOAD_BYTES: usize = 4_194_304;
/// Maximum complete canonical immediate-proposal envelope size.
///
/// The envelope adds one codec-version byte, four target-height bytes, four expiry-height bytes,
/// four consensus-branch-ID bytes, and the five-byte CompactSize encoding required for the
/// maximum payload length.
pub const MAX_IMMEDIATE_PROPOSAL_ENVELOPE_BYTES: usize = MAX_IMMEDIATE_PROPOSAL_PAYLOAD_BYTES + 18;
/// Maximum exact PCZT size retained while an external signer owns authorization.
pub const MAX_EXTERNAL_SIGNING_PCZT_BYTES: usize = 4_194_304;
/// Maximum exact consensus transaction size retained as durable delivery evidence.
pub const MAX_EXACT_TRANSACTION_BYTES: usize = 4_194_304;
/// Maximum number of exact transfer records retained in one finality archive.
pub const MAX_FINALITY_ARCHIVE_TRANSFERS: usize = 100_000;
/// Maximum byte length of one canonical finalized-transfer archive.
pub const MAX_FINALITY_ARCHIVE_BYTES: usize = 16 * 1_024 * 1_024;
/// Maximum byte length of one lossless canonical migration-state archive.
pub const MAX_MIGRATION_STATE_ARCHIVE_BYTES: usize = 64 * 1_024 * 1_024;
/// Maximum number of elements in any migration-state archive collection.
pub const MAX_MIGRATION_STATE_ARCHIVE_ITEMS: usize = 100_000;
/// Number of confirmations, including the expiry height, retained before sources from a positively
/// resolved unmined artifact may be released.
pub const RESOLVED_UNMINED_RELEASE_CONFIRMATIONS: u32 = 101;

const ONION_V3_SERVICE_LABEL_LENGTH: usize = 56;
const ONION_SUFFIX: &str = ".onion";
const HTTPS_SCHEME: &str = "https://";
const HTTP_SCHEME: &str = "http://";

const CONSENSUS_UPGRADES: &[NetworkUpgrade] = &[
    NetworkUpgrade::Overwinter,
    NetworkUpgrade::Sapling,
    NetworkUpgrade::Blossom,
    NetworkUpgrade::Heartwood,
    NetworkUpgrade::Canopy,
    NetworkUpgrade::Nu5,
    NetworkUpgrade::Nu6,
    NetworkUpgrade::Nu6_1,
    NetworkUpgrade::Nu6_2,
    NetworkUpgrade::Nu6_3,
    #[cfg(zcash_unstable = "nu7")]
    NetworkUpgrade::Nu7,
];

fn digest(personal: &[u8; 16], bytes: &[u8]) -> [u8; DIGEST_LENGTH] {
    let hash = Params::new()
        .hash_length(DIGEST_LENGTH)
        .personal(personal)
        .hash(bytes);
    hash.as_bytes()
        .try_into()
        .expect("the configured BLAKE2b output is exactly 32 bytes")
}

fn write_u32<W: Write>(mut writer: W, value: u32) -> io::Result<()> {
    writer.write_all(&value.to_le_bytes())
}

fn read_u32<R: Read>(mut reader: R) -> io::Result<u32> {
    let mut bytes = [0; size_of::<u32>()];
    reader.read_exact(&mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

fn write_u64<W: Write>(mut writer: W, value: u64) -> io::Result<()> {
    writer.write_all(&value.to_le_bytes())
}

fn read_u64<R: Read>(mut reader: R) -> io::Result<u64> {
    let mut bytes = [0; size_of::<u64>()];
    reader.read_exact(&mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}

fn write_byte<W: Write>(mut writer: W, value: u8) -> io::Result<()> {
    writer.write_all(&[value])
}

fn read_byte<R: Read>(mut reader: R) -> io::Result<u8> {
    let mut byte = [0];
    reader.read_exact(&mut byte)?;
    Ok(byte[0])
}

fn write_bytes<W: Write>(writer: W, bytes: &[u8]) -> io::Result<()> {
    Vector::write(writer, bytes, |writer, byte| writer.write_all(&[*byte]))
}

fn read_limited_bytes<R: Read>(mut reader: R, maximum: usize) -> io::Result<Vec<u8>> {
    let length: usize = CompactSize::read_t(&mut reader)?;
    if length > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "encoded byte vector exceeds its semantic size limit",
        ));
    }
    let mut bytes = vec![0; length];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn read_limited_vector<R: Read, E>(
    mut reader: R,
    maximum: usize,
    mut read_element: impl FnMut(&mut R) -> io::Result<E>,
) -> io::Result<Vec<E>> {
    let length: usize = CompactSize::read_t(&mut reader)?;
    if length > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "encoded vector exceeds its semantic item limit",
        ));
    }
    let mut values = Vec::with_capacity(length);
    for _ in 0..length {
        values.push(read_element(&mut reader)?);
    }
    Ok(values)
}

fn write_network<W: Write>(writer: W, network: NetworkType) -> io::Result<()> {
    write_byte(
        writer,
        match network {
            NetworkType::Main => NETWORK_MAIN_TAG,
            NetworkType::Test => NETWORK_TEST_TAG,
            NetworkType::Regtest => NETWORK_REGTEST_TAG,
        },
    )
}

fn read_network<R: Read>(reader: R) -> io::Result<NetworkType> {
    match read_byte(reader)? {
        NETWORK_MAIN_TAG => Ok(NetworkType::Main),
        NETWORK_TEST_TAG => Ok(NetworkType::Test),
        NETWORK_REGTEST_TAG => Ok(NetworkType::Regtest),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unknown submission network tag",
        )),
    }
}

macro_rules! fixed_bytes_type {
    ($(#[$meta:meta])* $name:ident, $debug_name:literal) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; DIGEST_LENGTH]);

        impl $name {
            pub(crate) const fn from_bytes(bytes: [u8; DIGEST_LENGTH]) -> Self {
                Self(bytes)
            }

            /// Returns the complete fixed-width representation.
            pub const fn as_bytes(&self) -> &[u8; DIGEST_LENGTH] {
                &self.0
            }

            /// Writes the fixed-width representation.
            pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
                writer.write_all(&self.0)
            }

            /// Reads the fixed-width representation.
            pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
                let mut bytes = [0; DIGEST_LENGTH];
                reader.read_exact(&mut bytes)?;
                Ok(Self::from_bytes(bytes))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!($debug_name, "(<redacted>)"))
            }
        }
    };
}

fixed_bytes_type!(
    /// A deterministic digest of the complete canonical [`MigrationState`].
    MigrationStateFingerprint,
    "MigrationStateFingerprint"
);
fixed_bytes_type!(
    /// Digest of one exact canonical PCZT.
    PcztDigest,
    "PcztDigest"
);
fixed_bytes_type!(
    /// Digest of the immutable canonical fields to which an exposed artifact is bound.
    MigrationTransactionFingerprint,
    "MigrationTransactionFingerprint"
);
fixed_bytes_type!(
    /// Digest of immutable schema/provenance evidence from the retired standalone engine.
    LegacySchemaFingerprint,
    "LegacySchemaFingerprint"
);
fixed_bytes_type!(
    /// Rust-derived fingerprint of a canonical submission policy.
    PolicyFingerprint,
    "PolicyFingerprint"
);
fixed_bytes_type!(
    /// Rust-derived fingerprint of network consensus activation parameters.
    ConsensusFingerprint,
    "ConsensusFingerprint"
);
fixed_bytes_type!(
    /// Digest of an immediate-lane proposal before exact transaction materialization.
    ImmediateProposalDigest,
    "ImmediateProposalDigest"
);
fixed_bytes_type!(
    /// Digest of exact serialized network transaction bytes.
    ExactTransactionDigest,
    "ExactTransactionDigest"
);
fixed_bytes_type!(
    /// Digest of a canonical finalized-transfer evidence archive.
    FinalityArchiveFingerprint,
    "FinalityArchiveFingerprint"
);

impl PcztDigest {
    /// Hashes exact serialized PCZT bytes under the PCZT domain.
    pub fn from_pczt(pczt: &[u8]) -> Self {
        Self::from_bytes(digest(PCZT_PERSONAL, pczt))
    }
}

impl LegacySchemaFingerprint {
    /// Hashes an exact SQLite schema declaration under the retired-engine domain.
    pub fn from_schema_sql(schema_sql: &[u8]) -> Self {
        Self::from_bytes(digest(LEGACY_PERSONAL, schema_sql))
    }
}

impl ImmediateProposalDigest {
    fn from_proposal_bytes(proposal: &[u8]) -> Self {
        Self::from_bytes(digest(IMMEDIATE_PROPOSAL_PERSONAL, proposal))
    }
}

impl ExactTransactionDigest {
    fn from_transaction_bytes(transaction: &[u8]) -> Self {
        Self::from_bytes(digest(EXACT_TRANSACTION_PERSONAL, transaction))
    }
}

/// Error returned when an opaque upstream immediate-proposal payload is not safely bounded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ImmediateProposalError {
    /// A proposal payload must contain upstream canonical proposal bytes.
    EmptyPayload,
    /// The proposal payload exceeds [`MAX_IMMEDIATE_PROPOSAL_PAYLOAD_BYTES`].
    PayloadTooLarge,
    /// The expiry height is not the builder-defined offset from the proposal target height.
    InvalidExpiryHeight,
}

/// Bounded opaque upstream proposal payload placed inside the Rust-owned canonical envelope.
#[derive(Clone, PartialEq, Eq)]
pub struct ImmediateProposalPayload(Vec<u8>);

impl TryFrom<Vec<u8>> for ImmediateProposalPayload {
    type Error = ImmediateProposalError;

    fn try_from(payload: Vec<u8>) -> Result<Self, Self::Error> {
        if payload.is_empty() {
            return Err(ImmediateProposalError::EmptyPayload);
        }
        if payload.len() > MAX_IMMEDIATE_PROPOSAL_PAYLOAD_BYTES {
            return Err(ImmediateProposalError::PayloadTooLarge);
        }
        Ok(Self(payload))
    }
}

impl ImmediateProposalPayload {
    /// Returns the bounded upstream canonical proposal payload.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for ImmediateProposalPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ImmediateProposalPayload(<redacted>)")
    }
}

/// Rust-owned, versioned canonical envelope for an immediate migration proposal.
#[derive(Clone, PartialEq, Eq)]
pub struct ImmediateProposal {
    target_height: BlockHeight,
    expiry_height: BlockHeight,
    branch_id: BranchId,
    payload: ImmediateProposalPayload,
}

impl ImmediateProposal {
    /// Binds the target height, consensus branch, and builder-derived expiry to a bounded
    /// upstream canonical proposal payload.
    pub fn new(
        target_height: BlockHeight,
        expiry_height: BlockHeight,
        branch_id: BranchId,
        payload: ImmediateProposalPayload,
    ) -> Result<Self, ImmediateProposalError> {
        let expected_expiry = u32::from(target_height)
            .checked_add(DEFAULT_TX_EXPIRY_DELTA)
            .map(BlockHeight::from_u32)
            .ok_or(ImmediateProposalError::InvalidExpiryHeight)?;
        if expiry_height != expected_expiry {
            return Err(ImmediateProposalError::InvalidExpiryHeight);
        }
        Ok(Self {
            target_height,
            expiry_height,
            branch_id,
            payload,
        })
    }

    /// Returns the proposal target height that selected the transaction consensus branch.
    pub const fn target_height(&self) -> BlockHeight {
        self.target_height
    }

    /// Returns the consensus expiry height.
    pub const fn expiry_height(&self) -> BlockHeight {
        self.expiry_height
    }

    /// Returns the immutable consensus branch selected at the proposal target height.
    pub const fn branch_id(&self) -> BranchId {
        self.branch_id
    }

    /// Returns the bounded upstream proposal payload.
    pub const fn payload(&self) -> &ImmediateProposalPayload {
        &self.payload
    }

    /// Writes the complete versioned canonical proposal envelope.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        write_byte(&mut writer, IMMEDIATE_PROPOSAL_CODEC_VERSION)?;
        write_u32(&mut writer, u32::from(self.target_height))?;
        write_u32(&mut writer, u32::from(self.expiry_height))?;
        write_u32(&mut writer, u32::from(self.branch_id))?;
        write_bytes(writer, self.payload.as_bytes())
    }

    /// Reads and validates a complete canonical proposal envelope.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        if read_byte(&mut reader)? != IMMEDIATE_PROPOSAL_CODEC_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unsupported immediate-proposal codec version",
            ));
        }
        let target_height = BlockHeight::from_u32(read_u32(&mut reader)?);
        let expiry_height = BlockHeight::from_u32(read_u32(&mut reader)?);
        let branch_id = BranchId::try_from(read_u32(&mut reader)?).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "unknown immediate-proposal consensus branch ID",
            )
        })?;
        let payload = ImmediateProposalPayload::try_from(read_limited_bytes(
            reader,
            MAX_IMMEDIATE_PROPOSAL_PAYLOAD_BYTES,
        )?)
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "immediate-proposal payload is empty or too large",
            )
        })?;
        Self::new(target_height, expiry_height, branch_id, payload).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "immediate-proposal expiry does not match its target height",
            )
        })
    }

    /// Decodes an exact canonical envelope and rejects trailing bytes.
    pub fn decode(canonical_bytes: &[u8]) -> io::Result<Self> {
        let mut reader = canonical_bytes;
        let proposal = Self::read(&mut reader)?;
        if !reader.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "trailing bytes after immediate-proposal envelope",
            ));
        }
        Ok(proposal)
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        canonical_bytes(|writer| self.write(writer))
            .expect("writing a canonical immediate proposal to a Vec is infallible")
    }

    /// Returns the Rust-derived digest of the complete canonical envelope.
    pub fn digest(&self) -> ImmediateProposalDigest {
        ImmediateProposalDigest::from_proposal_bytes(&self.canonical_bytes())
    }
}

impl fmt::Debug for ImmediateProposal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ImmediateProposal")
            .field("target_height", &self.target_height)
            .field("expiry_height", &self.expiry_height)
            .field("branch_id", &self.branch_id)
            .field("payload", &"<redacted>")
            .finish()
    }
}

/// Monotonically increasing delivery-control revision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeliveryRevision(u64);

impl DeliveryRevision {
    /// The first revision of a newly-created delivery-control record.
    pub const INITIAL: Self = Self(FIRST_DELIVERY_REVISION);

    pub(crate) const fn from_stored(value: u64) -> Option<Self> {
        if value < FIRST_DELIVERY_REVISION {
            None
        } else {
            Some(Self(value))
        }
    }

    /// Returns the scalar persisted at the storage boundary.
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Returns the next revision, or `None` if the counter is exhausted.
    pub const fn checked_next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// Writes this revision as a fixed-width little-endian counter.
    pub fn write<W: Write>(&self, writer: W) -> io::Result<()> {
        write_u64(writer, self.0)
    }

    /// Reads a revision written by [`write`](Self::write).
    pub fn read<R: Read>(reader: R) -> io::Result<Self> {
        Self::from_stored(read_u64(reader)?).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "a delivery revision must be non-zero",
            )
        })
    }
}

/// Rust-generated identity of one monotonic-clock session.
///
/// A process or device restart creates a new session. A lease from any other session is expired
/// rather than comparing unrelated monotonic epochs.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LeaseClockSession([u8; DIGEST_LENGTH]);

impl LeaseClockSession {
    /// Generates a session identity using a caller-supplied CSPRNG capability.
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut bytes = [0; DIGEST_LENGTH];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub(crate) const fn from_stored(bytes: [u8; DIGEST_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Returns the complete fixed-width representation.
    pub const fn as_bytes(&self) -> &[u8; DIGEST_LENGTH] {
        &self.0
    }

    /// Writes the complete fixed-width representation.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.0)
    }

    /// Reads a session identity written by [`write`](Self::write).
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut bytes = [0; DIGEST_LENGTH];
        reader.read_exact(&mut bytes)?;
        Ok(Self::from_stored(bytes))
    }
}

impl fmt::Debug for LeaseClockSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LeaseClockSession(<redacted>)")
    }
}

/// Instant from a monotonic clock bound to one process/device clock session.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct MonotonicLeaseInstant {
    session: LeaseClockSession,
    tick_millis: u64,
}

impl MonotonicLeaseInstant {
    /// Creates an instant from a Rust-generated clock session and that clock's current tick.
    pub const fn new(session: LeaseClockSession, tick_millis: u64) -> Self {
        Self {
            session,
            tick_millis,
        }
    }

    /// Returns the clock session to persist with this instant.
    pub const fn session(self) -> LeaseClockSession {
        self.session
    }

    /// Returns the monotonic clock tick in milliseconds.
    pub const fn tick_millis(self) -> u64 {
        self.tick_millis
    }

    /// Computes the end of a lease, returning `None` on monotonic-counter overflow.
    pub const fn checked_add(self, duration: LeaseDuration) -> Option<Self> {
        match self.tick_millis.checked_add(duration.as_millis().get()) {
            Some(tick_millis) => Some(Self::new(self.session, tick_millis)),
            None => None,
        }
    }

    /// Writes the session identity and fixed-width little-endian monotonic tick.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        self.session.write(&mut writer)?;
        write_u64(writer, self.tick_millis)
    }

    /// Reads an instant written by [`write`](Self::write).
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let session = LeaseClockSession::read(&mut reader)?;
        Ok(Self::new(session, read_u64(reader)?))
    }
}

impl fmt::Debug for MonotonicLeaseInstant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MonotonicLeaseInstant")
            .field("session", &"<redacted>")
            .field("tick_millis", &self.tick_millis)
            .finish()
    }
}

/// Non-zero, bounded duration of an expiring delivery claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LeaseDuration(NonZeroU64);

impl LeaseDuration {
    /// Maximum duration accepted at the semantic storage boundary (15 minutes).
    ///
    /// Store and FFI implementations may select shorter capability-specific constants, but no
    /// caller can construct an effectively permanent lease through this public type.
    pub const MAX_MILLIS: u64 = 15 * 60 * 1_000;

    /// Creates a lease duration from milliseconds.
    ///
    /// Returns `None` for a zero-length lease or a duration longer than
    /// [`MAX_MILLIS`](Self::MAX_MILLIS).
    pub const fn from_millis(milliseconds: u64) -> Option<Self> {
        if milliseconds > Self::MAX_MILLIS {
            return None;
        }
        match NonZeroU64::new(milliseconds) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// Returns the non-zero duration at the storage boundary.
    pub const fn as_millis(self) -> NonZeroU64 {
        self.0
    }

    /// Writes this duration as fixed-width little-endian milliseconds.
    pub fn write<W: Write>(&self, writer: W) -> io::Result<()> {
        write_u64(writer, self.0.get())
    }

    /// Reads a non-zero, bounded duration written by [`write`](Self::write).
    pub fn read<R: Read>(reader: R) -> io::Result<Self> {
        Self::from_millis(read_u64(reader)?).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "a lease duration must be non-zero and no longer than 15 minutes",
            )
        })
    }
}

/// Canonical Rust-owned identity of one migration run.
///
/// This value is independent of the canonical Orchard lock owner and must be carried in full by
/// every FFI binding.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MigrationRunIdentity([u8; DIGEST_LENGTH]);

impl MigrationRunIdentity {
    /// Generates a run identity using a caller-supplied CSPRNG capability.
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut bytes = [0; DIGEST_LENGTH];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub(crate) const fn from_stored(bytes: [u8; DIGEST_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Returns the complete fixed-width representation.
    pub const fn as_bytes(&self) -> &[u8; DIGEST_LENGTH] {
        &self.0
    }

    /// Writes the complete fixed-width representation.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.0)
    }

    /// Reads an identity written by [`write`](Self::write).
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut bytes = [0; DIGEST_LENGTH];
        reader.read_exact(&mut bytes)?;
        Ok(Self::from_stored(bytes))
    }
}

impl fmt::Debug for MigrationRunIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MigrationRunIdentity(<redacted>)")
    }
}

/// Rust-generated owner of exact migration source reservations.
///
/// Scheduled and immediate lanes use this same owner type; it is distinct from the delivery run
/// identity so replacement and source-lock authority cannot be aliased accidentally.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourceReservationOwner([u8; DIGEST_LENGTH]);

impl SourceReservationOwner {
    /// Generates a reservation owner using a caller-supplied CSPRNG capability.
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut bytes = [0; DIGEST_LENGTH];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub(crate) const fn from_stored(bytes: [u8; DIGEST_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Returns the complete fixed-width representation.
    pub const fn as_bytes(&self) -> &[u8; DIGEST_LENGTH] {
        &self.0
    }

    /// Writes the complete fixed-width representation.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.0)
    }

    /// Reads an owner written by [`write`](Self::write).
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut bytes = [0; DIGEST_LENGTH];
        reader.read_exact(&mut bytes)?;
        Ok(Self::from_stored(bytes))
    }

    /// Decodes one complete fixed-width owner and rejects trailing bytes.
    pub fn decode(canonical_bytes: &[u8]) -> io::Result<Self> {
        let mut reader = canonical_bytes;
        let owner = Self::read(&mut reader)?;
        if !reader.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "trailing bytes after source-reservation owner",
            ));
        }
        Ok(owner)
    }
}

impl fmt::Debug for SourceReservationOwner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SourceReservationOwner(<redacted>)")
    }
}

/// Unforgeable Rust-generated token for one claim attempt.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClaimToken([u8; DIGEST_LENGTH]);

impl ClaimToken {
    /// Generates a token using a caller-supplied CSPRNG capability.
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut bytes = [0; DIGEST_LENGTH];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub(crate) const fn from_stored(bytes: [u8; DIGEST_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Returns the complete fixed-width representation.
    pub const fn as_bytes(&self) -> &[u8; DIGEST_LENGTH] {
        &self.0
    }

    /// Writes the complete fixed-width representation.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.0)
    }

    /// Reads a token written by [`write`](Self::write).
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut bytes = [0; DIGEST_LENGTH];
        reader.read_exact(&mut bytes)?;
        Ok(Self::from_stored(bytes))
    }
}

impl fmt::Debug for ClaimToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClaimToken(<redacted>)")
    }
}

struct MigrationPlanFingerprintInput<'a>(&'a MigrationState);

impl MigrationPlanFingerprintInput<'_> {
    fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        let state = self.0;
        let split = state.note_split();
        Vector::write(&mut writer, split.crossing_values(), |writer, value| {
            write_u64(writer, u64::from(*value))
        })?;
        write_u64(&mut writer, u64::from(split.note_fee_buffer()))?;
        Optional::write(&mut writer, split.change(), |writer, value| {
            write_u64(writer, u64::from(value))
        })?;
        write_u64(&mut writer, u64::from(split.prep_fees()))?;
        write_u64(&mut writer, u64::from(split.total_input()))?;
        write_u64(&mut writer, u64::from(split.total_migratable()))?;

        Vector::write(
            &mut writer,
            state.preparation().layers(),
            |writer, layer| {
                Vector::write(writer, layer, |writer, transaction| {
                    Vector::write(
                        &mut *writer,
                        transaction.inputs(),
                        |writer, input| match input {
                            PrepInput::Wallet { index, value } => {
                                write_byte(&mut *writer, PREPARATION_INPUT_WALLET_TAG)?;
                                CompactSize::write(&mut *writer, *index)?;
                                write_u64(writer, u64::from(*value))
                            }
                            PrepInput::Prior {
                                layer,
                                transaction,
                                output,
                                value,
                            } => {
                                write_byte(&mut *writer, PREPARATION_INPUT_PRIOR_TAG)?;
                                CompactSize::write(&mut *writer, *layer)?;
                                CompactSize::write(&mut *writer, *transaction)?;
                                CompactSize::write(&mut *writer, *output)?;
                                write_u64(writer, u64::from(*value))
                            }
                        },
                    )?;
                    Vector::write(&mut *writer, transaction.outputs(), |writer, output| {
                        write_byte(
                            &mut *writer,
                            match output {
                                PrepOutput::Funding(_) => PREPARATION_OUTPUT_FUNDING_TAG,
                                PrepOutput::Intermediate(_) => PREPARATION_OUTPUT_INTERMEDIATE_TAG,
                                PrepOutput::Change(_) => PREPARATION_OUTPUT_CHANGE_TAG,
                            },
                        )?;
                        write_u64(writer, u64::from(output.value()))
                    })
                })
            },
        )?;
        Vector::write(
            &mut writer,
            state.preparation().direct_funding_notes(),
            |writer, (index, value)| {
                CompactSize::write(&mut *writer, *index)?;
                write_u64(writer, u64::from(*value))
            },
        )
    }
}

struct ImmutableTransactionFingerprintInput<'a>(&'a crate::engine::MigrationTransaction);

impl ImmutableTransactionFingerprintInput<'_> {
    fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        let transaction = self.0;
        transaction.id().write(&mut writer)?;
        match transaction.kind() {
            MigrationTxKind::Preparation { layer, index } => {
                write_byte(&mut writer, TRANSACTION_KIND_PREPARATION_TAG)?;
                CompactSize::write(&mut writer, layer)?;
                CompactSize::write(&mut writer, index)?;
            }
            MigrationTxKind::Transfer { crossing } => {
                write_byte(&mut writer, TRANSACTION_KIND_TRANSFER_TAG)?;
                CompactSize::write(&mut writer, crossing)?;
            }
        }
        write_bytes(&mut writer, transaction.pczt())?;
        Vector::write(
            &mut writer,
            transaction.depends_on(),
            |writer, dependency| dependency.write(writer),
        )?;
        write_u32(&mut writer, u32::from(transaction.scheduled_height()))?;
        write_u32(&mut writer, u32::from(transaction.expiry_height()))?;
        Optional::write(
            &mut writer,
            transaction.anchor_boundary(),
            |writer, height| write_u32(writer, u32::from(height)),
        )
    }
}

/// Immutable attempt identity across authorization, proving, and reservation lifecycle mutations.
///
/// PCZT bytes intentionally are not encoded here: external signing and proving replace those
/// bytes without creating a new transaction attempt. The exact PCZT remains covered by
/// [`PcztDigest`] and the complete [`MigrationState`] fingerprint/archive. Expired rebuilding
/// changes schedule, expiry, and anchor metadata and therefore creates a distinct attempt. The
/// canonical lock owner is likewise excluded: clearing it at terminal source release must not
/// invalidate the immutable identity of the attempt whose evidence is retained for finality.
struct TransactionAttemptFingerprintInput<'a>(&'a crate::engine::MigrationTransaction);

impl TransactionAttemptFingerprintInput<'_> {
    fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        let transaction = self.0;
        transaction.id().write(&mut writer)?;
        match transaction.kind() {
            MigrationTxKind::Preparation { layer, index } => {
                write_byte(&mut writer, TRANSACTION_KIND_PREPARATION_TAG)?;
                CompactSize::write(&mut writer, layer)?;
                CompactSize::write(&mut writer, index)?;
            }
            MigrationTxKind::Transfer { crossing } => {
                write_byte(&mut writer, TRANSACTION_KIND_TRANSFER_TAG)?;
                CompactSize::write(&mut writer, crossing)?;
            }
        }
        Vector::write(
            &mut writer,
            transaction.depends_on(),
            |writer, dependency| dependency.write(writer),
        )?;
        write_u32(&mut writer, u32::from(transaction.scheduled_height()))?;
        write_u32(&mut writer, u32::from(transaction.expiry_height()))?;
        Optional::write(
            &mut writer,
            transaction.anchor_boundary(),
            |writer, height| write_u32(writer, u32::from(height)),
        )
    }
}

struct TransactionBindingFingerprintInput<'a> {
    state: &'a MigrationState,
    transaction: &'a crate::engine::MigrationTransaction,
}

impl TransactionBindingFingerprintInput<'_> {
    fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        write_byte(&mut writer, TRANSACTION_BINDING_CODEC_VERSION)?;
        MigrationPlanFingerprintInput(self.state).write(&mut writer)?;
        TransactionAttemptFingerprintInput(self.transaction).write(writer)
    }
}

struct StateFingerprintInput<'a>(&'a MigrationState);

impl StateFingerprintInput<'_> {
    fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        let state = self.0;
        write_byte(&mut writer, MIGRATION_STATE_ARCHIVE_VERSION)?;
        write_bytes(&mut writer, state.status().as_ref().as_bytes())?;
        MigrationPlanFingerprintInput(state).write(&mut writer)?;
        Vector::write(&mut writer, state.transactions(), |writer, transaction| {
            ImmutableTransactionFingerprintInput(transaction).write(&mut *writer)?;
            write_bytes(&mut *writer, transaction.state().as_ref().as_bytes())?;
            Optional::write(
                &mut *writer,
                transaction.state().broadcast_txid(),
                |writer, txid| writer.write_all(&txid),
            )?;
            Optional::write(
                &mut *writer,
                transaction.state().mined_height(),
                |writer, height| write_u32(writer, u32::from(height)),
            )?;
            Optional::write(&mut *writer, transaction.lock_owner(), |writer, owner| {
                writer.write_all(&owner)
            })
        })
    }
}

/// Lossless, versioned canonical bytes for one complete [`MigrationState`].
///
/// The fingerprint is over these exact bytes, including transaction lifecycle and lock-owner
/// fields, so a durable store can archive predecessor canonical state without reconstructing it
/// from partial delivery evidence.
#[derive(Clone, PartialEq, Eq)]
pub struct EncodedMigrationStateArchive {
    canonical_bytes: Vec<u8>,
    fingerprint: MigrationStateFingerprint,
}

impl EncodedMigrationStateArchive {
    /// Returns the exact versioned canonical archive bytes.
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    /// Returns the fingerprint of the exact canonical archive bytes.
    pub const fn fingerprint(&self) -> MigrationStateFingerprint {
        self.fingerprint
    }

    /// Consumes the archive into exact versioned canonical bytes.
    pub fn into_canonical_bytes(self) -> Vec<u8> {
        self.canonical_bytes
    }
}

impl fmt::Debug for EncodedMigrationStateArchive {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncodedMigrationStateArchive")
            .field("canonical_bytes", &"<redacted>")
            .field("fingerprint", &"<redacted>")
            .finish()
    }
}

fn invalid_state_archive(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn read_archive_string<R: Read>(reader: R) -> io::Result<String> {
    String::from_utf8(read_limited_bytes(reader, 32)?)
        .map_err(|_| invalid_state_archive("migration-state archive string is not UTF-8"))
}

fn read_migration_plan_archive<R: Read>(
    mut reader: R,
) -> io::Result<(NoteSplitPlan, PreparationPlan)> {
    let crossing_values =
        read_limited_vector(&mut reader, MAX_MIGRATION_STATE_ARCHIVE_ITEMS, |reader| {
            Zatoshis::read(reader)
        })?;
    let note_fee_buffer = Zatoshis::read(&mut reader)?;
    let change = Optional::read(&mut reader, Zatoshis::read)?;
    let prep_fees = Zatoshis::read(&mut reader)?;
    let total_input = Zatoshis::read(&mut reader)?;
    let total_migratable = Zatoshis::read(&mut reader)?;
    let note_split = NoteSplitPlan::from_stored_parts(
        crossing_values,
        note_fee_buffer,
        change,
        prep_fees,
        total_input,
        total_migratable,
    )
    .map_err(|_| invalid_state_archive("migration-state archive contains an invalid note split"))?;

    let layers = read_limited_vector(&mut reader, MAX_MIGRATION_STATE_ARCHIVE_ITEMS, |reader| {
        read_limited_vector(reader, MAX_MIGRATION_STATE_ARCHIVE_ITEMS, |reader| {
            let inputs =
                read_limited_vector(&mut *reader, MAX_MIGRATION_STATE_ARCHIVE_ITEMS, |reader| {
                    let tag = read_byte(&mut *reader)?;
                    match tag {
                        PREPARATION_INPUT_WALLET_TAG => Ok(PrepInput::Wallet {
                            index: CompactSize::read_t(&mut *reader)?,
                            value: Zatoshis::read(reader)?,
                        }),
                        PREPARATION_INPUT_PRIOR_TAG => Ok(PrepInput::Prior {
                            layer: CompactSize::read_t(&mut *reader)?,
                            transaction: CompactSize::read_t(&mut *reader)?,
                            output: CompactSize::read_t(&mut *reader)?,
                            value: Zatoshis::read(reader)?,
                        }),
                        _ => Err(invalid_state_archive(
                            "unknown preparation-input tag in migration-state archive",
                        )),
                    }
                })?;
            let outputs =
                read_limited_vector(&mut *reader, MAX_MIGRATION_STATE_ARCHIVE_ITEMS, |reader| {
                    let tag = read_byte(&mut *reader)?;
                    let value = Zatoshis::read(reader)?;
                    match tag {
                        PREPARATION_OUTPUT_FUNDING_TAG => Ok(PrepOutput::Funding(value)),
                        PREPARATION_OUTPUT_INTERMEDIATE_TAG => Ok(PrepOutput::Intermediate(value)),
                        PREPARATION_OUTPUT_CHANGE_TAG => Ok(PrepOutput::Change(value)),
                        _ => Err(invalid_state_archive(
                            "unknown preparation-output tag in migration-state archive",
                        )),
                    }
                })?;
            Ok(PrepTransaction::from_parts(inputs, outputs))
        })
    })?;
    let direct_funding =
        read_limited_vector(&mut reader, MAX_MIGRATION_STATE_ARCHIVE_ITEMS, |reader| {
            Ok((CompactSize::read_t(&mut *reader)?, Zatoshis::read(reader)?))
        })?;
    Ok((
        note_split,
        PreparationPlan::from_parts(layers, direct_funding),
    ))
}

fn read_migration_transaction_archive<R: Read>(mut reader: R) -> io::Result<MigrationTransaction> {
    let id = MigrationTxId::read(&mut reader)?;
    let kind = match read_byte(&mut reader)? {
        TRANSACTION_KIND_PREPARATION_TAG => MigrationTxKind::Preparation {
            layer: CompactSize::read_t(&mut reader)?,
            index: CompactSize::read_t(&mut reader)?,
        },
        TRANSACTION_KIND_TRANSFER_TAG => MigrationTxKind::Transfer {
            crossing: CompactSize::read_t(&mut reader)?,
        },
        _ => {
            return Err(invalid_state_archive(
                "unknown transaction-kind tag in migration-state archive",
            ));
        }
    };
    let pczt = read_limited_bytes(&mut reader, MAX_EXTERNAL_SIGNING_PCZT_BYTES)?;
    let depends_on =
        read_limited_vector(&mut reader, MAX_MIGRATION_STATE_ARCHIVE_ITEMS, |reader| {
            MigrationTxId::read(reader)
        })?;
    let scheduled_height = BlockHeight::from_u32(read_u32(&mut reader)?);
    let expiry_height = BlockHeight::from_u32(read_u32(&mut reader)?);
    let anchor_boundary = Optional::read(&mut reader, |reader| {
        Ok(BlockHeight::from_u32(read_u32(reader)?))
    })?;
    let state_name = read_archive_string(&mut reader)?;
    let broadcast_txid = Optional::read(&mut reader, |reader| {
        let mut txid = [0; DIGEST_LENGTH];
        reader.read_exact(&mut txid)?;
        Ok(txid)
    })?;
    let mined_height = Optional::read(&mut reader, |reader| {
        Ok(BlockHeight::from_u32(read_u32(reader)?))
    })?;
    let state =
        MigrationTxState::from_stored(&state_name, broadcast_txid, mined_height).map_err(|_| {
            invalid_state_archive("invalid transaction state in migration-state archive")
        })?;
    let lock_owner = Optional::read(&mut reader, |reader| {
        let mut owner = [0; DIGEST_LENGTH];
        reader.read_exact(&mut owner)?;
        Ok(owner)
    })?;
    Ok(MigrationTransaction::from_parts(
        id,
        kind,
        pczt,
        depends_on,
        scheduled_height,
        expiry_height,
        anchor_boundary,
        state,
        lock_owner,
    ))
}

/// Encodes every canonical migration-state field into a bounded, versioned, lossless archive.
pub fn encode_migration_state_archive(
    state: &MigrationState,
) -> io::Result<EncodedMigrationStateArchive> {
    let canonical_bytes = canonical_bytes(|writer| StateFingerprintInput(state).write(writer))?;
    if canonical_bytes.len() > MAX_MIGRATION_STATE_ARCHIVE_BYTES {
        return Err(invalid_state_archive(
            "migration-state archive exceeds its semantic byte limit",
        ));
    }
    let fingerprint =
        MigrationStateFingerprint::from_bytes(digest(STATE_PERSONAL, &canonical_bytes));
    Ok(EncodedMigrationStateArchive {
        canonical_bytes,
        fingerprint,
    })
}

/// Decodes one complete canonical migration-state archive and verifies its stored fingerprint.
///
/// Unknown/future versions, non-canonical nested encodings, semantic overflows, fingerprint
/// mismatches, and any trailing bytes fail closed.
pub fn decode_migration_state_archive(
    canonical_bytes: &[u8],
    expected_fingerprint: MigrationStateFingerprint,
) -> io::Result<MigrationState> {
    if canonical_bytes.len() > MAX_MIGRATION_STATE_ARCHIVE_BYTES {
        return Err(invalid_state_archive(
            "migration-state archive exceeds its semantic byte limit",
        ));
    }
    let mut reader = canonical_bytes;
    if read_byte(&mut reader)? != MIGRATION_STATE_ARCHIVE_VERSION {
        return Err(invalid_state_archive(
            "unsupported migration-state archive version",
        ));
    }
    let status_name = read_archive_string(&mut reader)?;
    let status = MigrationStatus::try_from(status_name.as_str())
        .map_err(|_| invalid_state_archive("invalid status in migration-state archive"))?;
    let (note_split, preparation) = read_migration_plan_archive(&mut reader)?;
    let transactions =
        read_limited_vector(&mut reader, MAX_MIGRATION_STATE_ARCHIVE_ITEMS, |reader| {
            read_migration_transaction_archive(reader)
        })?;
    if !reader.is_empty() {
        return Err(invalid_state_archive(
            "trailing bytes after migration-state archive",
        ));
    }
    let state = MigrationState::from_parts(status, note_split, preparation, transactions);
    let actual_fingerprint =
        MigrationStateFingerprint::from_bytes(digest(STATE_PERSONAL, canonical_bytes));
    if actual_fingerprint != expected_fingerprint
        || migration_state_fingerprint(&state) != expected_fingerprint
    {
        return Err(invalid_state_archive(
            "migration-state archive fingerprint mismatch",
        ));
    }
    Ok(state)
}

fn canonical_bytes(
    write: impl FnOnce(&mut Vec<u8>) -> io::Result<()>,
) -> Result<Vec<u8>, io::Error> {
    let mut bytes = Vec::new();
    write(&mut bytes)?;
    Ok(bytes)
}

/// Fingerprints the immutable plan and delivery-relevant fields of one canonical transaction.
pub fn migration_transaction_fingerprint(
    state: &MigrationState,
    transaction: &crate::engine::MigrationTransaction,
) -> MigrationTransactionFingerprint {
    let bytes = canonical_bytes(|writer| {
        TransactionBindingFingerprintInput { state, transaction }.write(writer)
    })
    .expect("writing a canonical fingerprint input to a Vec is infallible");
    MigrationTransactionFingerprint::from_bytes(digest(TRANSACTION_BINDING_PERSONAL, &bytes))
}

/// Fingerprints every canonical migration-state field, including exact PCZT bytes and lifecycle.
pub fn migration_state_fingerprint(state: &MigrationState) -> MigrationStateFingerprint {
    let bytes = canonical_bytes(|writer| StateFingerprintInput(state).write(writer))
        .expect("writing a canonical fingerprint input to a Vec is infallible");
    MigrationStateFingerprint::from_bytes(digest(STATE_PERSONAL, &bytes))
}

struct ConsensusFingerprintInput<'a, P>(&'a P);

impl<P: Parameters> ConsensusFingerprintInput<'_, P> {
    fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        write_byte(&mut writer, CONSENSUS_CODEC_VERSION)?;
        write_network(&mut writer, self.0.network_type())?;
        Vector::write(&mut writer, CONSENSUS_UPGRADES, |writer, upgrade| {
            write_u32(&mut *writer, u32::from(upgrade.branch_id()))?;
            Optional::write(
                writer,
                self.0.activation_height(*upgrade),
                |writer, height| write_u32(writer, u32::from(height)),
            )
        })
    }
}

impl ConsensusFingerprint {
    /// Derives a fingerprint from the complete known upgrade-activation schedule.
    pub fn from_parameters<P: Parameters>(parameters: &P) -> Self {
        let bytes = canonical_bytes(|writer| ConsensusFingerprintInput(parameters).write(writer))
            .expect("writing a canonical consensus fingerprint input to a Vec is infallible");
        Self::from_bytes(digest(CONSENSUS_PERSONAL, &bytes))
    }
}

/// Rust-derived network and consensus identity used to validate submission policy.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SubmissionContext {
    network: NetworkType,
    consensus_fingerprint: ConsensusFingerprint,
}

impl SubmissionContext {
    /// Derives the context from consensus parameters owned by Rust.
    pub fn from_parameters<P: Parameters>(parameters: &P) -> Self {
        Self {
            network: parameters.network_type(),
            consensus_fingerprint: ConsensusFingerprint::from_parameters(parameters),
        }
    }

    fn from_codec(network: NetworkType, consensus_fingerprint: ConsensusFingerprint) -> Self {
        Self {
            network,
            consensus_fingerprint,
        }
    }

    /// Returns the expected network.
    pub const fn network(&self) -> NetworkType {
        self.network
    }

    /// Returns the expected consensus fingerprint.
    pub const fn consensus_fingerprint(&self) -> ConsensusFingerprint {
        self.consensus_fingerprint
    }
}

impl fmt::Debug for SubmissionContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SubmissionContext")
            .field("network", &self.network)
            .field("consensus_fingerprint", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EndpointClass {
    DirectTls,
    TorProxyTls,
    TorOnion,
    LoopbackDevelopment,
}

/// Error returned when a submission endpoint is not canonical or not permitted for its transport.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EndpointValidationError {
    /// The endpoint is empty or exceeds its maximum encoded length.
    InvalidLength,
    /// The endpoint is not canonical printable ASCII.
    InvalidCharacters,
    /// The endpoint uses a scheme forbidden for its transport.
    InvalidScheme,
    /// Credentials, queries, fragments, or non-root paths are not accepted.
    UnsupportedUrlComponent,
    /// The host or optional port is malformed.
    InvalidAuthority,
    /// A public TLS endpoint is not a canonical public DNS name.
    DirectEndpointNotPublic,
    /// A Tor endpoint is not a canonical v3 onion service name.
    InvalidOnionService,
    /// The development exception is not an explicit loopback host.
    InvalidLoopbackHost,
}

impl fmt::Display for EndpointValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidLength => "submission endpoint length is invalid",
            Self::InvalidCharacters => "submission endpoint contains non-canonical characters",
            Self::InvalidScheme => "submission endpoint scheme is not allowed",
            Self::UnsupportedUrlComponent => {
                "submission endpoint contains an unsupported URL component"
            }
            Self::InvalidAuthority => "submission endpoint authority is invalid",
            Self::DirectEndpointNotPublic => {
                "public TLS endpoint must use a canonical public DNS name"
            }
            Self::InvalidOnionService => "Tor endpoint must use a canonical v3 onion service",
            Self::InvalidLoopbackHost => "development endpoint must use an explicit loopback host",
        })
    }
}

impl core::error::Error for EndpointValidationError {}

fn validate_hostname(host: &str) -> bool {
    if host.is_empty() || host.starts_with('.') || host.ends_with('.') {
        return false;
    }
    for label in host.split('.') {
        if label.is_empty() || label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return false;
        }
    }
    true
}

/// Accepts a canonical DNS name and rejects every literal or legacy numeric-IP spelling.
///
/// This is deliberately DNS-only. Classifying IP address ranges without DNS or routing context is
/// not a stable authorization boundary, and URL/network stacks have historically accepted
/// noncanonical one- to four-component numeric spellings in addition to dotted-decimal IPv4.
fn validate_public_dns_hostname(host: &str) -> bool {
    if !validate_hostname(host)
        || host == "localhost"
        || host.ends_with(ONION_SUFFIX)
        || !host.contains('.')
    {
        return false;
    }

    let final_label_has_letter = host
        .rsplit_once('.')
        .is_some_and(|(_, label)| label.bytes().any(|byte| byte.is_ascii_lowercase()));
    let is_numeric_address_spelling = host.split('.').all(|label| {
        label.bytes().all(|byte| byte.is_ascii_digit())
            || label.strip_prefix("0x").is_some_and(|digits| {
                !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
    });
    final_label_has_letter && !is_numeric_address_spelling
}

fn validate_port(port: &str) -> bool {
    if port.is_empty() || (port.len() > 1 && port.starts_with('0')) {
        return false;
    }
    port.parse::<u16>().is_ok_and(|port| port != 0)
}

fn split_authority(authority: &str) -> Option<(&str, Option<&str>)> {
    if authority.starts_with('[') {
        let close = authority.find(']')?;
        let host = authority.get(..=close)?;
        let remainder = authority.get(close + 1..)?;
        if remainder.is_empty() {
            Some((host, None))
        } else {
            Some((host, Some(remainder.strip_prefix(':')?)))
        }
    } else if let Some((host, port)) = authority.rsplit_once(':') {
        Some((host, Some(port)))
    } else {
        Some((authority, None))
    }
}

fn validate_endpoint(value: &str, class: EndpointClass) -> Result<(), EndpointValidationError> {
    if value.is_empty() || value.len() > MAX_SUBMISSION_ENDPOINT_BYTES {
        return Err(EndpointValidationError::InvalidLength);
    }
    if !value.is_ascii()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
    {
        return Err(EndpointValidationError::InvalidCharacters);
    }

    let remainder =
        match class {
            EndpointClass::DirectTls | EndpointClass::TorProxyTls => value
                .strip_prefix(HTTPS_SCHEME)
                .ok_or(EndpointValidationError::InvalidScheme)?,
            EndpointClass::TorOnion => value
                .strip_prefix(HTTP_SCHEME)
                .or_else(|| value.strip_prefix(HTTPS_SCHEME))
                .ok_or(EndpointValidationError::InvalidScheme)?,
            EndpointClass::LoopbackDevelopment => value
                .strip_prefix(HTTP_SCHEME)
                .ok_or(EndpointValidationError::InvalidScheme)?,
        };
    if remainder.contains('@') || remainder.contains('?') || remainder.contains('#') {
        return Err(EndpointValidationError::UnsupportedUrlComponent);
    }
    let authority = match remainder.split_once('/') {
        Some((authority, "")) => authority,
        Some(_) => return Err(EndpointValidationError::UnsupportedUrlComponent),
        None => remainder,
    };
    let (host, port) =
        split_authority(authority).ok_or(EndpointValidationError::InvalidAuthority)?;
    if port.is_some_and(|port| !validate_port(port)) {
        return Err(EndpointValidationError::InvalidAuthority);
    }

    match class {
        EndpointClass::DirectTls | EndpointClass::TorProxyTls => {
            if !validate_public_dns_hostname(host) {
                return Err(EndpointValidationError::DirectEndpointNotPublic);
            }
        }
        EndpointClass::TorOnion => {
            let label = host
                .strip_suffix(ONION_SUFFIX)
                .ok_or(EndpointValidationError::InvalidOnionService)?;
            if label.len() != ONION_V3_SERVICE_LABEL_LENGTH
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || (b'2'..=b'7').contains(&byte))
            {
                return Err(EndpointValidationError::InvalidOnionService);
            }
        }
        EndpointClass::LoopbackDevelopment => {
            if !matches!(host, "localhost" | "127.0.0.1" | "[::1]") {
                return Err(EndpointValidationError::InvalidLoopbackHost);
            }
        }
    }
    Ok(())
}

macro_rules! endpoint_type {
    ($(#[$meta:meta])* $name:ident, $class:expr, $debug_name:literal) => {
        $(#[$meta])*
        #[derive(Clone, PartialEq, Eq)]
        pub struct $name(String);

        impl TryFrom<String> for $name {
            type Error = EndpointValidationError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                validate_endpoint(&value, $class)?;
                let normalized = value.strip_suffix('/').unwrap_or(&value).to_string();
                Ok(Self(normalized))
            }
        }

        impl $name {
            /// Returns the validated canonical endpoint.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!($debug_name, "(<redacted>)"))
            }
        }
    };
}

endpoint_type!(
    /// A public DNS endpoint that requires direct TLS transport.
    DirectTlsEndpoint,
    EndpointClass::DirectTls,
    "DirectTlsEndpoint"
);
endpoint_type!(
    /// A public DNS TLS endpoint reached through an isolated Tor proxy.
    TorProxyTlsEndpoint,
    EndpointClass::TorProxyTls,
    "TorProxyTlsEndpoint"
);
endpoint_type!(
    /// A canonical v3 onion endpoint reached through Tor.
    TorOnionEndpoint,
    EndpointClass::TorOnion,
    "TorOnionEndpoint"
);
endpoint_type!(
    /// An explicitly insecure loopback-only endpoint for development.
    LoopbackDevelopmentEndpoint,
    EndpointClass::LoopbackDevelopment,
    "LoopbackDevelopmentEndpoint"
);

/// Rust-validated transport and endpoint for transaction submission.
#[derive(Clone, PartialEq, Eq)]
pub enum SubmissionTransport {
    /// Direct transport to a public DNS TLS endpoint.
    DirectTls(DirectTlsEndpoint),
    /// Tor-proxied transport to a public DNS TLS endpoint.
    TorProxyTls(TorProxyTlsEndpoint),
    /// Tor transport to a v3 onion service.
    TorOnion(TorOnionEndpoint),
    /// Explicitly insecure loopback transport for development only.
    LoopbackDevelopment(LoopbackDevelopmentEndpoint),
}

impl SubmissionTransport {
    fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        let (tag, endpoint) = match self {
            Self::DirectTls(endpoint) => (TRANSPORT_DIRECT_TLS_TAG, endpoint.as_str()),
            Self::TorProxyTls(endpoint) => (TRANSPORT_TOR_PROXY_TLS_TAG, endpoint.as_str()),
            Self::TorOnion(endpoint) => (TRANSPORT_TOR_ONION_TAG, endpoint.as_str()),
            Self::LoopbackDevelopment(endpoint) => {
                (TRANSPORT_LOOPBACK_DEVELOPMENT_TAG, endpoint.as_str())
            }
        };
        write_byte(&mut writer, tag)?;
        write_bytes(writer, endpoint.as_bytes())
    }

    fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let tag = read_byte(&mut reader)?;
        let endpoint = read_limited_bytes(&mut reader, MAX_SUBMISSION_ENDPOINT_BYTES)?;
        let endpoint = String::from_utf8(endpoint).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "submission endpoint is not UTF-8",
            )
        })?;
        let invalid = |_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "submission endpoint does not satisfy its transport contract",
            )
        };
        match tag {
            TRANSPORT_DIRECT_TLS_TAG => DirectTlsEndpoint::try_from(endpoint)
                .map(Self::DirectTls)
                .map_err(invalid),
            TRANSPORT_TOR_PROXY_TLS_TAG => TorProxyTlsEndpoint::try_from(endpoint)
                .map(Self::TorProxyTls)
                .map_err(invalid),
            TRANSPORT_TOR_ONION_TAG => TorOnionEndpoint::try_from(endpoint)
                .map(Self::TorOnion)
                .map_err(invalid),
            TRANSPORT_LOOPBACK_DEVELOPMENT_TAG => LoopbackDevelopmentEndpoint::try_from(endpoint)
                .map(Self::LoopbackDevelopment)
                .map_err(invalid),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unknown submission transport tag",
            )),
        }
    }

    /// Returns the validated endpoint without changing its transport type.
    pub fn endpoint(&self) -> &str {
        match self {
            Self::DirectTls(endpoint) => endpoint.as_str(),
            Self::TorProxyTls(endpoint) => endpoint.as_str(),
            Self::TorOnion(endpoint) => endpoint.as_str(),
            Self::LoopbackDevelopment(endpoint) => endpoint.as_str(),
        }
    }
}

impl fmt::Debug for SubmissionTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::DirectTls(_) => "SubmissionTransport::DirectTls(<redacted>)",
            Self::TorProxyTls(_) => "SubmissionTransport::TorProxyTls(<redacted>)",
            Self::TorOnion(_) => "SubmissionTransport::TorOnion(<redacted>)",
            Self::LoopbackDevelopment(_) => "SubmissionTransport::LoopbackDevelopment(<redacted>)",
        })
    }
}

/// Typed request to bind one immutable submission policy.
#[derive(Clone, PartialEq, Eq)]
pub struct SubmissionPolicyRequest {
    context: SubmissionContext,
    transport: SubmissionTransport,
}

impl SubmissionPolicyRequest {
    /// Creates a request from a Rust-derived context and validated transport.
    pub const fn new(context: SubmissionContext, transport: SubmissionTransport) -> Self {
        Self { context, transport }
    }

    /// Returns the declared Rust-derived context.
    pub const fn context(&self) -> SubmissionContext {
        self.context
    }

    /// Returns the validated transport.
    pub const fn transport(&self) -> &SubmissionTransport {
        &self.transport
    }

    /// Writes the complete, versioned canonical policy request.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        write_byte(&mut writer, SUBMISSION_POLICY_CODEC_VERSION)?;
        write_network(&mut writer, self.context.network)?;
        self.context.consensus_fingerprint.write(&mut writer)?;
        self.transport.write(writer)
    }

    /// Reads and validates a complete policy request written by [`write`](Self::write).
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        if read_byte(&mut reader)? != SUBMISSION_POLICY_CODEC_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unsupported submission-policy codec version",
            ));
        }
        let network = read_network(&mut reader)?;
        let consensus_fingerprint = ConsensusFingerprint::read(&mut reader)?;
        let transport = SubmissionTransport::read(reader)?;
        Ok(Self::new(
            SubmissionContext::from_codec(network, consensus_fingerprint),
            transport,
        ))
    }
}

impl fmt::Debug for SubmissionPolicyRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SubmissionPolicyRequest")
            .field("network", &self.context.network)
            .field("consensus_fingerprint", &"<redacted>")
            .field("transport", &self.transport)
            .finish()
    }
}

/// Rust-owned, privacy-safe reason a submission policy could not be accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PolicyValidationFailure {
    /// Canonical bytes could not be decoded.
    InvalidEncoding,
    /// The policy exceeds its stable maximum encoded size.
    PolicyTooLarge,
    /// The declared network differs from the wallet's Rust-derived network.
    NetworkMismatch,
    /// The consensus activation fingerprint differs from the wallet's Rust-derived fingerprint.
    ConsensusMismatch,
}

impl PolicyValidationFailure {
    /// Returns the stable storage discriminant.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidEncoding => "invalid_encoding",
            Self::PolicyTooLarge => "policy_too_large",
            Self::NetworkMismatch => "network_mismatch",
            Self::ConsensusMismatch => "consensus_mismatch",
        }
    }

    /// Parses a stable storage discriminant.
    pub fn from_stored(value: &str) -> Option<Self> {
        match value {
            "invalid_encoding" => Some(Self::InvalidEncoding),
            "policy_too_large" => Some(Self::PolicyTooLarge),
            "network_mismatch" => Some(Self::NetworkMismatch),
            "consensus_mismatch" => Some(Self::ConsensusMismatch),
            _ => None,
        }
    }
}

/// Immutable, validated submission policy and its Rust-derived fingerprint.
#[derive(Clone, PartialEq, Eq)]
pub struct SubmissionPolicy {
    request: SubmissionPolicyRequest,
    canonical_bytes: Vec<u8>,
    fingerprint: PolicyFingerprint,
}

impl SubmissionPolicy {
    /// Validates a request against the current Rust-derived wallet context.
    pub fn validate(
        request: SubmissionPolicyRequest,
        expected_context: SubmissionContext,
    ) -> Result<Self, PolicyValidationFailure> {
        if request.context.network != expected_context.network {
            return Err(PolicyValidationFailure::NetworkMismatch);
        }
        if request.context.consensus_fingerprint != expected_context.consensus_fingerprint {
            return Err(PolicyValidationFailure::ConsensusMismatch);
        }
        let canonical_bytes = canonical_bytes(|writer| request.write(writer))
            .expect("writing canonical policy bytes to a Vec is infallible");
        if canonical_bytes.len() > MAX_SUBMISSION_POLICY_BYTES {
            return Err(PolicyValidationFailure::PolicyTooLarge);
        }
        let fingerprint = PolicyFingerprint::from_bytes(digest(POLICY_PERSONAL, &canonical_bytes));
        Ok(Self {
            request,
            canonical_bytes,
            fingerprint,
        })
    }

    /// Decodes canonical stored bytes and verifies both their fingerprint and current context.
    pub fn decode(
        canonical_bytes: Vec<u8>,
        stored_fingerprint: PolicyFingerprint,
        expected_context: SubmissionContext,
    ) -> Result<Self, PolicyValidationFailure> {
        if canonical_bytes.len() > MAX_SUBMISSION_POLICY_BYTES {
            return Err(PolicyValidationFailure::PolicyTooLarge);
        }
        let mut reader = canonical_bytes.as_slice();
        let request = SubmissionPolicyRequest::read(&mut reader)
            .map_err(|_| PolicyValidationFailure::InvalidEncoding)?;
        if !reader.is_empty() {
            return Err(PolicyValidationFailure::InvalidEncoding);
        }
        let policy = Self::validate(request, expected_context)?;
        if policy.fingerprint != stored_fingerprint || policy.canonical_bytes != canonical_bytes {
            return Err(PolicyValidationFailure::InvalidEncoding);
        }
        Ok(policy)
    }

    /// Returns the typed validated request.
    pub const fn request(&self) -> &SubmissionPolicyRequest {
        &self.request
    }

    /// Returns exact canonical policy bytes.
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    /// Returns the Rust-derived policy fingerprint.
    pub const fn fingerprint(&self) -> PolicyFingerprint {
        self.fingerprint
    }
}

impl fmt::Debug for SubmissionPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SubmissionPolicy(<redacted>)")
    }
}

/// Failure while validating or merging a durable external-signing PCZT.
#[derive(Debug)]
#[non_exhaustive]
pub enum ExternalSigningPcztError {
    /// PCZT bytes are empty or exceed [`MAX_EXTERNAL_SIGNING_PCZT_BYTES`].
    InvalidLength,
    /// PCZT version or encoding is invalid.
    Parse(pczt::ParseError),
    /// The returned signer PCZT changes data that cannot be merged with the staged PCZT.
    Merge(pczt::roles::combiner::Error),
    /// The merged logical PCZT cannot be encoded canonically.
    Encode(pczt::EncodingError),
    /// Stored signed bytes are not the canonical merge bound to the staged PCZT.
    BindingMismatch,
}

impl fmt::Display for ExternalSigningPcztError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidLength => "external-signing PCZT length is invalid",
            Self::Parse(_) => "external-signing PCZT encoding is invalid",
            Self::Merge(_) => "external signer changed non-mergeable PCZT data",
            Self::Encode(_) => "merged external-signing PCZT cannot be encoded",
            Self::BindingMismatch => "signed PCZT is not bound to the staged PCZT",
        })
    }
}

impl core::error::Error for ExternalSigningPcztError {}

fn validate_pczt_length(pczt: &[u8]) -> Result<(), ExternalSigningPcztError> {
    if pczt.is_empty() || pczt.len() > MAX_EXTERNAL_SIGNING_PCZT_BYTES {
        Err(ExternalSigningPcztError::InvalidLength)
    } else {
        Ok(())
    }
}

/// Exact canonical PCZT durably staged before it crosses an external-signing boundary.
#[derive(Clone, PartialEq, Eq)]
pub struct ExternalSigningPczt {
    digest: PcztDigest,
    bytes: Vec<u8>,
}

impl ExternalSigningPczt {
    /// Parses and retains exact versioned PCZT bytes for crash-safe external signing.
    pub fn parse(bytes: Vec<u8>) -> Result<Self, ExternalSigningPcztError> {
        validate_pczt_length(&bytes)?;
        pczt::Pczt::parse(&bytes).map_err(ExternalSigningPcztError::Parse)?;
        Ok(Self {
            digest: PcztDigest::from_pczt(&bytes),
            bytes,
        })
    }

    /// Returns the digest of exact staged bytes.
    pub const fn digest(&self) -> PcztDigest {
        self.digest
    }

    /// Returns exact staged PCZT bytes for reacquisition by the same external signer flow.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Merges a signer-returned PCZT while binding it to this exact staged PCZT.
    pub fn merge_signed(
        &self,
        signer_returned: Vec<u8>,
    ) -> Result<SignedPcztEvidence, ExternalSigningPcztError> {
        validate_pczt_length(&signer_returned)?;
        let staged = pczt::Pczt::parse(&self.bytes).map_err(ExternalSigningPcztError::Parse)?;
        let signed =
            pczt::Pczt::parse(&signer_returned).map_err(ExternalSigningPcztError::Parse)?;
        let merged = Combiner::new(vec![staged, signed])
            .combine()
            .map_err(ExternalSigningPcztError::Merge)?;
        let bytes = merged
            .serialize()
            .map_err(ExternalSigningPcztError::Encode)?;
        SignedPcztEvidence::decode(self, bytes)
    }
}

impl fmt::Debug for ExternalSigningPczt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ExternalSigningPczt(<redacted>)")
    }
}

/// Canonical signed-PCZT merge durably bound to one exact staged PCZT.
#[derive(Clone, PartialEq, Eq)]
pub struct SignedPcztEvidence {
    staged_digest: PcztDigest,
    signed_digest: PcztDigest,
    bytes: Vec<u8>,
}

impl SignedPcztEvidence {
    /// Revalidates canonical signed bytes and their merge binding to exact staged evidence.
    pub fn decode(
        staged: &ExternalSigningPczt,
        bytes: Vec<u8>,
    ) -> Result<Self, ExternalSigningPcztError> {
        validate_pczt_length(&bytes)?;
        let staged_pczt =
            pczt::Pczt::parse(staged.bytes()).map_err(ExternalSigningPcztError::Parse)?;
        let signed_pczt = pczt::Pczt::parse(&bytes).map_err(ExternalSigningPcztError::Parse)?;
        let canonical_signed = signed_pczt
            .clone()
            .serialize()
            .map_err(ExternalSigningPcztError::Encode)?;
        if canonical_signed != bytes {
            return Err(ExternalSigningPcztError::BindingMismatch);
        }
        let rebound = Combiner::new(vec![staged_pczt, signed_pczt])
            .combine()
            .map_err(ExternalSigningPcztError::Merge)?
            .serialize()
            .map_err(ExternalSigningPcztError::Encode)?;
        if rebound != bytes {
            return Err(ExternalSigningPcztError::BindingMismatch);
        }
        Ok(Self {
            staged_digest: staged.digest(),
            signed_digest: PcztDigest::from_pczt(&bytes),
            bytes,
        })
    }

    /// Returns the exact staged-PCZT binding.
    pub const fn staged_digest(&self) -> PcztDigest {
        self.staged_digest
    }

    /// Returns the exact signed-PCZT digest.
    pub const fn signed_digest(&self) -> PcztDigest {
        self.signed_digest
    }

    /// Returns canonical merged signed-PCZT bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for SignedPcztEvidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SignedPcztEvidence(<redacted>)")
    }
}

/// Delivery lane that owns an exact artifact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveryLane {
    /// A transaction planned by the canonical scheduled migration engine.
    Scheduled,
    /// An immediate migration transaction built through the ordinary proposal path.
    Immediate,
}

/// Component responsible for obtaining transaction authorization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignerOwnership {
    /// The SDK obtains authorization using wallet-held signing capability.
    Sdk,
    /// An external signer owns authorization and returns exact authorized bytes.
    External,
}

/// Account-scoped intent to migrate currently eligible Orchard sources immediately, bounded by
/// the user's confirmed gross-amount authorization.
///
/// The intent deliberately carries no caller-selected sources, destination, dependency graph,
/// target height, proposal bytes, or expiry. Its amount is only an upper bound: the implementing
/// wallet store derives the exact gross input amount and every other proposal value from one
/// revision-consistent wallet view, rejects a proposal above the bound, and reserves the exact
/// derived sources before returning any proposal representation.
pub struct ImmediateMigrationIntent<AccountId> {
    account_id: AccountId,
    signer_ownership: SignerOwnership,
    maximum_gross_amount: Zatoshis,
}

impl<AccountId> ImmediateMigrationIntent<AccountId> {
    /// Selects an account, authorization owner, and user-confirmed gross-amount ceiling without
    /// accepting caller-authored proposal data.
    pub const fn new(
        account_id: AccountId,
        signer_ownership: SignerOwnership,
        maximum_gross_amount: Zatoshis,
    ) -> Self {
        Self {
            account_id,
            signer_ownership,
            maximum_gross_amount,
        }
    }

    /// Returns the account whose wallet state authoritatively determines the migration proposal.
    pub const fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    /// Returns authorization ownership.
    pub const fn signer_ownership(&self) -> SignerOwnership {
        self.signer_ownership
    }

    /// Returns the maximum total value of Orchard sources that this intent authorizes.
    pub const fn maximum_gross_amount(&self) -> Zatoshis {
        self.maximum_gross_amount
    }
}

impl<AccountId: fmt::Debug> fmt::Debug for ImmediateMigrationIntent<AccountId> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ImmediateMigrationIntent")
            .field("account_id", &self.account_id)
            .field("signer_ownership", &self.signer_ownership)
            .field("maximum_gross_amount", &self.maximum_gross_amount)
            .finish()
    }
}

/// Rust-generated identity of one immediate-lane artifact.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ImmediateArtifactIdentity([u8; DIGEST_LENGTH]);

impl ImmediateArtifactIdentity {
    /// Generates an identity using a caller-supplied CSPRNG capability.
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut bytes = [0; DIGEST_LENGTH];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub(crate) const fn from_stored(bytes: [u8; DIGEST_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Returns the complete fixed-width representation.
    pub const fn as_bytes(&self) -> &[u8; DIGEST_LENGTH] {
        &self.0
    }

    /// Writes the complete fixed-width representation.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.0)
    }

    /// Reads an identity written by [`write`](Self::write).
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut bytes = [0; DIGEST_LENGTH];
        reader.read_exact(&mut bytes)?;
        Ok(Self::from_stored(bytes))
    }
}

impl fmt::Debug for ImmediateArtifactIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ImmediateArtifactIdentity(<redacted>)")
    }
}

/// Identity of one exact scheduled transaction attempt.
///
/// [`MigrationTxId`] remains stable when an expired transfer is rebuilt, so the immutable
/// transaction fingerprint is part of delivery identity to distinguish old exposed evidence from
/// its canonical replacement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScheduledArtifactIdentity {
    transaction_id: MigrationTxId,
    transaction_fingerprint: MigrationTransactionFingerprint,
}

impl ScheduledArtifactIdentity {
    /// Binds one canonical row identity to one exact immutable transaction attempt.
    pub const fn new(
        transaction_id: MigrationTxId,
        transaction_fingerprint: MigrationTransactionFingerprint,
    ) -> Self {
        Self {
            transaction_id,
            transaction_fingerprint,
        }
    }

    /// Returns the stable canonical row identity.
    pub const fn transaction_id(self) -> MigrationTxId {
        self.transaction_id
    }

    /// Returns the exact immutable attempt fingerprint.
    pub const fn transaction_fingerprint(self) -> MigrationTransactionFingerprint {
        self.transaction_fingerprint
    }
}

/// Stable identity of a scheduled or immediate delivery artifact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveryArtifactIdentity {
    /// Exact canonical scheduled transaction attempt.
    Scheduled(ScheduledArtifactIdentity),
    /// Rust-generated immediate-lane identity.
    Immediate(ImmediateArtifactIdentity),
}

impl DeliveryArtifactIdentity {
    /// Returns the lane selected by this identity.
    pub const fn lane(self) -> DeliveryLane {
        match self {
            Self::Scheduled(_) => DeliveryLane::Scheduled,
            Self::Immediate(_) => DeliveryLane::Immediate,
        }
    }
}

/// Immutable canonical evidence behind a scheduled delivery artifact.
#[derive(Clone, PartialEq, Eq)]
pub struct ScheduledArtifactEvidence {
    transaction_id: MigrationTxId,
    pczt_digest: PcztDigest,
    transaction_fingerprint: MigrationTransactionFingerprint,
    expiry_height: BlockHeight,
    canonical_pczt: Vec<u8>,
}

impl ScheduledArtifactEvidence {
    /// Returns the exact scheduled attempt identity.
    pub const fn identity(&self) -> ScheduledArtifactIdentity {
        ScheduledArtifactIdentity::new(self.transaction_id, self.transaction_fingerprint)
    }

    /// Returns the canonical transaction row identity.
    pub const fn transaction_id(&self) -> MigrationTxId {
        self.transaction_id
    }

    /// Returns the digest of exact canonical PCZT bytes.
    pub const fn pczt_digest(&self) -> PcztDigest {
        self.pczt_digest
    }

    /// Returns the immutable transaction binding.
    pub const fn transaction_fingerprint(&self) -> MigrationTransactionFingerprint {
        self.transaction_fingerprint
    }

    /// Returns the canonical consensus expiry height.
    pub const fn expiry_height(&self) -> BlockHeight {
        self.expiry_height
    }

    /// Returns exact canonical PCZT bytes.
    pub fn canonical_pczt(&self) -> &[u8] {
        &self.canonical_pczt
    }
}

impl fmt::Debug for ScheduledArtifactEvidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScheduledArtifactEvidence")
            .field("transaction_id", &self.transaction_id)
            .field("pczt_digest", &"<redacted>")
            .field("transaction_fingerprint", &"<redacted>")
            .field("canonical_pczt", &"<redacted>")
            .finish()
    }
}

/// Derives immutable scheduled-artifact evidence from canonical state.
pub fn scheduled_artifact_evidence(
    state: &MigrationState,
    transaction_id: MigrationTxId,
) -> Option<ScheduledArtifactEvidence> {
    state
        .transactions()
        .iter()
        .find(|transaction| transaction.id() == transaction_id)
        .map(|transaction| ScheduledArtifactEvidence {
            transaction_id,
            pczt_digest: PcztDigest::from_pczt(transaction.pczt()),
            transaction_fingerprint: migration_transaction_fingerprint(state, transaction),
            expiry_height: transaction.expiry_height(),
            canonical_pczt: transaction.pczt().to_vec(),
        })
}

/// Immutable proposal evidence behind an immediate delivery artifact.
#[derive(Clone, PartialEq, Eq)]
pub struct ImmediateArtifactEvidence {
    identity: ImmediateArtifactIdentity,
    proposal_digest: ImmediateProposalDigest,
    expiry_height: BlockHeight,
    canonical_proposal: Vec<u8>,
}

impl ImmediateArtifactEvidence {
    /// Derives immutable evidence from a store-owned wallet proposal envelope.
    ///
    /// Constructing evidence does not grant source authority; only a store-owned implementation of
    /// [`ReservedImmediateArtifact`] returned after atomic reservation commit does so.
    pub fn from_proposal(
        identity: ImmediateArtifactIdentity,
        proposal: &ImmediateProposal,
    ) -> Self {
        let canonical_proposal = proposal.canonical_bytes();
        let proposal_digest = ImmediateProposalDigest::from_proposal_bytes(&canonical_proposal);
        Self {
            identity,
            proposal_digest,
            expiry_height: proposal.expiry_height(),
            canonical_proposal,
        }
    }

    /// Returns the immediate artifact identity.
    pub const fn identity(&self) -> ImmediateArtifactIdentity {
        self.identity
    }

    /// Returns the canonical proposal digest.
    pub const fn proposal_digest(&self) -> ImmediateProposalDigest {
        self.proposal_digest
    }

    /// Returns the consensus expiry height bound by the proposal.
    pub const fn expiry_height(&self) -> BlockHeight {
        self.expiry_height
    }

    /// Returns exact canonical proposal evidence.
    pub fn canonical_proposal(&self) -> &[u8] {
        &self.canonical_proposal
    }
}

impl fmt::Debug for ImmediateArtifactEvidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ImmediateArtifactEvidence")
            .field("identity", &"<redacted>")
            .field("proposal_digest", &"<redacted>")
            .field("canonical_proposal", &"<redacted>")
            .finish()
    }
}

/// Immutable source evidence for one scheduled or immediate artifact.
#[derive(Clone, PartialEq, Eq)]
pub enum DeliveryArtifactEvidence {
    /// Evidence copied exactly from canonical scheduled state.
    Scheduled(ScheduledArtifactEvidence),
    /// Evidence copied exactly from a canonical immediate proposal.
    Immediate(ImmediateArtifactEvidence),
}

impl DeliveryArtifactEvidence {
    /// Returns the stable artifact identity.
    pub const fn identity(&self) -> DeliveryArtifactIdentity {
        match self {
            Self::Scheduled(evidence) => DeliveryArtifactIdentity::Scheduled(evidence.identity()),
            Self::Immediate(evidence) => DeliveryArtifactIdentity::Immediate(evidence.identity),
        }
    }

    /// Returns the artifact lane.
    pub const fn lane(&self) -> DeliveryLane {
        self.identity().lane()
    }

    /// Returns the canonical transaction row identity for the scheduled lane.
    pub const fn scheduled_transaction_id(&self) -> Option<MigrationTxId> {
        match self {
            Self::Scheduled(evidence) => Some(evidence.transaction_id),
            Self::Immediate(_) => None,
        }
    }

    /// Returns the PCZT digest for the scheduled lane.
    pub const fn pczt_digest(&self) -> Option<PcztDigest> {
        match self {
            Self::Scheduled(evidence) => Some(evidence.pczt_digest),
            Self::Immediate(_) => None,
        }
    }

    /// Returns the immutable canonical transaction binding for the scheduled lane.
    pub const fn transaction_fingerprint(&self) -> Option<MigrationTransactionFingerprint> {
        match self {
            Self::Scheduled(evidence) => Some(evidence.transaction_fingerprint),
            Self::Immediate(_) => None,
        }
    }

    /// Returns the exact source-evidence expiry height.
    pub const fn expiry_height(&self) -> BlockHeight {
        match self {
            Self::Scheduled(evidence) => evidence.expiry_height,
            Self::Immediate(evidence) => evidence.expiry_height,
        }
    }

    /// Returns exact canonical PCZT bytes for the scheduled lane.
    pub fn canonical_pczt(&self) -> Option<&[u8]> {
        match self {
            Self::Scheduled(evidence) => Some(evidence.canonical_pczt()),
            Self::Immediate(_) => None,
        }
    }
}

impl fmt::Debug for DeliveryArtifactEvidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Scheduled(evidence) => evidence.fmt(f),
            Self::Immediate(evidence) => evidence.fmt(f),
        }
    }
}

/// Exact network transaction bytes bound to scheduled or immediate source evidence.
#[derive(Clone, PartialEq, Eq)]
pub struct ExactTransaction {
    artifact_identity: DeliveryArtifactIdentity,
    txid: TxId,
    consensus_expiry_height: BlockHeight,
    digest: ExactTransactionDigest,
    bytes: Vec<u8>,
}

impl ExactTransaction {
    fn from_transaction(
        artifact_identity: DeliveryArtifactIdentity,
        transaction: &Transaction,
    ) -> Result<Self, ExactTransactionError> {
        let mut bytes = Vec::new();
        transaction
            .write(&mut bytes)
            .map_err(|_| ExactTransactionError::Serialize)?;
        if bytes.len() > MAX_EXACT_TRANSACTION_BYTES {
            return Err(ExactTransactionError::TooLarge);
        }
        Ok(Self {
            artifact_identity,
            txid: transaction.txid(),
            consensus_expiry_height: transaction.expiry_height(),
            digest: ExactTransactionDigest::from_transaction_bytes(&bytes),
            bytes,
        })
    }

    /// Returns the scheduled or immediate source identity.
    pub const fn artifact_identity(&self) -> DeliveryArtifactIdentity {
        self.artifact_identity
    }

    /// Returns the canonical transaction row identity for the scheduled lane.
    pub const fn scheduled_transaction_id(&self) -> Option<MigrationTxId> {
        match self.artifact_identity {
            DeliveryArtifactIdentity::Scheduled(identity) => Some(identity.transaction_id()),
            DeliveryArtifactIdentity::Immediate(_) => None,
        }
    }

    /// Returns the consensus transaction identifier.
    pub const fn txid(&self) -> TxId {
        self.txid
    }

    /// Returns the expiry height parsed from the exact transaction.
    pub const fn consensus_expiry_height(&self) -> BlockHeight {
        self.consensus_expiry_height
    }

    /// Returns the digest of exact serialized transaction bytes.
    pub const fn digest(&self) -> ExactTransactionDigest {
        self.digest
    }

    /// Returns exact serialized transaction bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for ExactTransaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ExactTransaction(<redacted>)")
    }
}

/// Failure while deriving exact network transaction evidence.
#[derive(Debug)]
#[non_exhaustive]
pub enum ExactTransactionError {
    /// The canonical transaction identity is absent.
    TransactionNotFound(MigrationTxId),
    /// The supplied scheduled identity does not match the immutable canonical attempt.
    ArtifactIdentityMismatch(MigrationTxId),
    /// Canonical PCZT parsing failed.
    Pczt(pczt::ParseError),
    /// The canonical PCZT is not fully authorized.
    Extract(pczt::roles::tx_extractor::Error),
    /// Exact transaction serialization failed.
    Serialize,
    /// Exact transaction bytes exceed [`MAX_EXACT_TRANSACTION_BYTES`].
    TooLarge,
    /// Exact immediate-lane transaction bytes could not be decoded.
    Decode(io::Error),
    /// Extra bytes followed the exact immediate-lane transaction.
    TrailingBytes,
    /// Decoded immediate-lane bytes were not the canonical transaction encoding.
    NonCanonicalEncoding,
    /// Supplied PCZT bytes conflict with the canonical scheduled PCZT instead of extending it.
    CanonicalPcztConflict,
    /// The canonical state is not yet proved or chain-exposed.
    NotFullyAuthorized(MigrationTxId),
    /// Stored expiry metadata differs from the exact consensus transaction.
    ExpiryMetadataMismatch {
        /// Canonical migration transaction identity.
        transaction_id: MigrationTxId,
        /// Expiry height stored in canonical migration metadata.
        metadata: BlockHeight,
        /// Expiry height parsed from exact transaction bytes.
        consensus: BlockHeight,
    },
    /// The immediate proposal expiry differs from the exact consensus transaction.
    ImmediateExpiryMismatch {
        /// Expiry bound by the canonical immediate proposal envelope.
        proposal: BlockHeight,
        /// Expiry parsed from exact transaction bytes.
        consensus: BlockHeight,
    },
}

impl fmt::Display for ExactTransactionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TransactionNotFound(id) => {
                write!(f, "migration transaction {} not found", u32::from(*id))
            }
            Self::ArtifactIdentityMismatch(id) => write!(
                f,
                "migration transaction {} has a different immutable attempt identity",
                u32::from(*id)
            ),
            Self::Pczt(error) => write!(f, "parsing canonical PCZT failed: {error:?}"),
            Self::Extract(error) => write!(f, "extracting canonical PCZT failed: {error:?}"),
            Self::Serialize => f.write_str("serializing the exact transaction failed"),
            Self::TooLarge => f.write_str("exact transaction exceeds its byte limit"),
            Self::Decode(error) => write!(f, "decoding exact transaction bytes failed: {error}"),
            Self::TrailingBytes => f.write_str("trailing bytes follow the exact transaction"),
            Self::NonCanonicalEncoding => {
                f.write_str("exact transaction bytes are not canonically encoded")
            }
            Self::CanonicalPcztConflict => {
                f.write_str("supplied PCZT conflicts with canonical scheduled evidence")
            }
            Self::NotFullyAuthorized(id) => write!(
                f,
                "migration transaction {} is not proved or chain-exposed",
                u32::from(*id)
            ),
            Self::ExpiryMetadataMismatch {
                transaction_id,
                metadata,
                consensus,
            } => write!(
                f,
                "migration transaction {} expiry metadata {} differs from consensus expiry {}",
                u32::from(*transaction_id),
                u32::from(*metadata),
                u32::from(*consensus)
            ),
            Self::ImmediateExpiryMismatch {
                proposal,
                consensus,
            } => write!(
                f,
                "immediate proposal expiry {} differs from consensus expiry {}",
                u32::from(*proposal),
                u32::from(*consensus)
            ),
        }
    }
}

impl core::error::Error for ExactTransactionError {}

/// Extracts exact transaction bytes fixed by a canonical scheduled PCZT.
pub fn exact_transaction(
    state: &MigrationState,
    transaction_id: MigrationTxId,
) -> Result<ExactTransaction, ExactTransactionError> {
    let transaction = state
        .transactions()
        .iter()
        .find(|transaction| transaction.id() == transaction_id)
        .ok_or(ExactTransactionError::TransactionNotFound(transaction_id))?;
    if !matches!(
        transaction.state(),
        MigrationTxState::Proved
            | MigrationTxState::Broadcast { .. }
            | MigrationTxState::Mined { .. }
    ) {
        return Err(ExactTransactionError::NotFullyAuthorized(transaction_id));
    }
    let pczt = pczt::Pczt::parse(transaction.pczt()).map_err(ExactTransactionError::Pczt)?;
    let extracted = TransactionExtractor::new(pczt)
        .extract()
        .map_err(ExactTransactionError::Extract)?;
    if extracted.expiry_height() != transaction.expiry_height() {
        return Err(ExactTransactionError::ExpiryMetadataMismatch {
            transaction_id,
            metadata: transaction.expiry_height(),
            consensus: extracted.expiry_height(),
        });
    }
    let identity = ScheduledArtifactIdentity::new(
        transaction_id,
        migration_transaction_fingerprint(state, transaction),
    );
    ExactTransaction::from_transaction(DeliveryArtifactIdentity::Scheduled(identity), &extracted)
}

/// Extracts an exact scheduled transaction from canonical externally returned PCZT bytes.
///
/// This recovery-only boundary binds the candidate to the immutable attempt in `state`, requires a
/// canonical conflict-free extension of that attempt's PCZT, and verifies the exact consensus
/// expiry before returning immutable transaction evidence. It does not mutate canonical state;
/// the owning store must commit the matching PCZT/lifecycle transition and mined evidence in one
/// CAS transaction.
pub fn exact_scheduled_transaction_from_pczt(
    state: &MigrationState,
    scheduled_identity: ScheduledArtifactIdentity,
    canonical_pczt_bytes: &[u8],
) -> Result<ExactTransaction, ExactTransactionError> {
    let transaction_id = scheduled_identity.transaction_id();
    let transaction = state
        .transactions()
        .iter()
        .find(|transaction| transaction.id() == transaction_id)
        .ok_or(ExactTransactionError::TransactionNotFound(transaction_id))?;
    if migration_transaction_fingerprint(state, transaction)
        != scheduled_identity.transaction_fingerprint()
    {
        return Err(ExactTransactionError::ArtifactIdentityMismatch(
            transaction_id,
        ));
    }

    let predecessor = pczt::Pczt::parse(transaction.pczt()).map_err(ExactTransactionError::Pczt)?;
    let candidate = pczt::Pczt::parse(canonical_pczt_bytes).map_err(ExactTransactionError::Pczt)?;
    let canonical = candidate
        .clone()
        .serialize()
        .map_err(|_| ExactTransactionError::Serialize)?;
    if canonical.as_slice() != canonical_pczt_bytes {
        return Err(ExactTransactionError::NonCanonicalEncoding);
    }
    let combined = Combiner::new(vec![predecessor, candidate.clone()])
        .combine()
        .map_err(|_| ExactTransactionError::CanonicalPcztConflict)?
        .serialize()
        .map_err(|_| ExactTransactionError::Serialize)?;
    if combined.as_slice() != canonical_pczt_bytes {
        return Err(ExactTransactionError::CanonicalPcztConflict);
    }
    let extracted = TransactionExtractor::new(candidate)
        .extract()
        .map_err(ExactTransactionError::Extract)?;
    if extracted.expiry_height() != transaction.expiry_height() {
        return Err(ExactTransactionError::ExpiryMetadataMismatch {
            transaction_id,
            metadata: transaction.expiry_height(),
            consensus: extracted.expiry_height(),
        });
    }
    ExactTransaction::from_transaction(
        DeliveryArtifactIdentity::Scheduled(scheduled_identity),
        &extracted,
    )
}

/// Serializes an already-parsed immediate-lane transaction into immutable exact evidence.
pub fn exact_immediate_transaction(
    evidence: &ImmediateArtifactEvidence,
    transaction: &Transaction,
) -> Result<ExactTransaction, ExactTransactionError> {
    if transaction.expiry_height() != evidence.expiry_height() {
        return Err(ExactTransactionError::ImmediateExpiryMismatch {
            proposal: evidence.expiry_height(),
            consensus: transaction.expiry_height(),
        });
    }
    ExactTransaction::from_transaction(
        DeliveryArtifactIdentity::Immediate(evidence.identity),
        transaction,
    )
}

/// Decodes canonical exact bytes for an immediate proposal and binds them to its immutable
/// artifact identity and expiry.
pub fn decode_exact_immediate_transaction(
    evidence: &ImmediateArtifactEvidence,
    exact_bytes: &[u8],
    branch_id: BranchId,
) -> Result<ExactTransaction, ExactTransactionError> {
    if exact_bytes.len() > MAX_EXACT_TRANSACTION_BYTES {
        return Err(ExactTransactionError::TooLarge);
    }
    let mut reader = exact_bytes;
    let transaction =
        Transaction::read(&mut reader, branch_id).map_err(ExactTransactionError::Decode)?;
    if !reader.is_empty() {
        return Err(ExactTransactionError::TrailingBytes);
    }
    let mut canonical = Vec::new();
    transaction
        .write(&mut canonical)
        .map_err(|_| ExactTransactionError::Serialize)?;
    if canonical.as_slice() != exact_bytes {
        return Err(ExactTransactionError::NonCanonicalEncoding);
    }
    exact_immediate_transaction(evidence, &transaction)
}

/// Exact mined-transfer evidence retained after source reservations are released.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FinalizedTransferEvidence {
    artifact_identity: DeliveryArtifactIdentity,
    txid: TxId,
    exact_transaction_digest: ExactTransactionDigest,
    mined_height: BlockHeight,
}

impl fmt::Debug for FinalizedTransferEvidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FinalizedTransferEvidence(<redacted>)")
    }
}

impl FinalizedTransferEvidence {
    /// Creates exact finality evidence from one mined delivery artifact.
    pub const fn new(
        artifact_identity: DeliveryArtifactIdentity,
        txid: TxId,
        exact_transaction_digest: ExactTransactionDigest,
        mined_height: BlockHeight,
    ) -> Self {
        Self {
            artifact_identity,
            txid,
            exact_transaction_digest,
            mined_height,
        }
    }

    /// Returns the artifact identity.
    pub const fn artifact_identity(self) -> DeliveryArtifactIdentity {
        self.artifact_identity
    }

    /// Returns the exact mined transaction identifier.
    pub const fn txid(self) -> TxId {
        self.txid
    }

    /// Returns the digest of exact serialized transaction bytes.
    pub const fn exact_transaction_digest(self) -> ExactTransactionDigest {
        self.exact_transaction_digest
    }

    /// Returns the active-chain mined height used for finalization.
    pub const fn mined_height(self) -> BlockHeight {
        self.mined_height
    }

    fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        match self.artifact_identity {
            DeliveryArtifactIdentity::Scheduled(identity) => {
                write_byte(&mut writer, ARTIFACT_SCHEDULED_TAG)?;
                identity.transaction_id().write(&mut writer)?;
                identity.transaction_fingerprint().write(&mut writer)?;
            }
            DeliveryArtifactIdentity::Immediate(identity) => {
                write_byte(&mut writer, ARTIFACT_IMMEDIATE_TAG)?;
                identity.write(&mut writer)?;
            }
        }
        self.txid.write(&mut writer)?;
        self.exact_transaction_digest.write(&mut writer)?;
        write_u32(writer, u32::from(self.mined_height))
    }

    fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let artifact_identity = match read_byte(&mut reader)? {
            ARTIFACT_SCHEDULED_TAG => {
                DeliveryArtifactIdentity::Scheduled(ScheduledArtifactIdentity::new(
                    MigrationTxId::read(&mut reader)?,
                    MigrationTransactionFingerprint::read(&mut reader)?,
                ))
            }
            ARTIFACT_IMMEDIATE_TAG => {
                DeliveryArtifactIdentity::Immediate(ImmediateArtifactIdentity::read(&mut reader)?)
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unknown finalized artifact lane tag",
                ));
            }
        };
        let txid = TxId::read(&mut reader)?;
        let exact_transaction_digest = ExactTransactionDigest::read(&mut reader)?;
        let mined_height = BlockHeight::from_u32(read_u32(reader)?);
        Ok(Self::new(
            artifact_identity,
            txid,
            exact_transaction_digest,
            mined_height,
        ))
    }
}

/// Failure while constructing a canonical finalized-transfer archive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FinalityArchiveError {
    /// At least one exact transfer is required.
    Empty,
    /// The archive exceeds [`MAX_FINALITY_ARCHIVE_TRANSFERS`].
    TooManyTransfers,
    /// The canonical archive exceeds [`MAX_FINALITY_ARCHIVE_BYTES`].
    TooLarge,
    /// Artifact identities or transaction identifiers are duplicated.
    DuplicateTransfer,
    /// A mined height follows the claimed release horizon.
    MinedAfterRelease,
}

/// Versioned immutable audit evidence retained after finality and reservation release.
#[derive(Clone, PartialEq, Eq)]
pub struct FinalityArchive {
    release: ReservationRelease,
    transfers: Vec<FinalizedTransferEvidence>,
    fingerprint: FinalityArchiveFingerprint,
}

impl fmt::Debug for FinalityArchive {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FinalityArchive")
            .field("release", &"<redacted>")
            .field("transfer_count", &self.transfers.len())
            .field("transfers", &"<redacted>")
            .field("fingerprint", &"<redacted>")
            .finish()
    }
}

impl FinalityArchive {
    /// Validates exact finalized-transfer evidence and computes its canonical fingerprint.
    pub fn new(
        release: ReservationRelease,
        transfers: Vec<FinalizedTransferEvidence>,
    ) -> Result<Self, FinalityArchiveError> {
        if transfers.is_empty() {
            return Err(FinalityArchiveError::Empty);
        }
        if transfers.len() > MAX_FINALITY_ARCHIVE_TRANSFERS {
            return Err(FinalityArchiveError::TooManyTransfers);
        }
        for (index, transfer) in transfers.iter().enumerate() {
            if transfer.mined_height() > release.release_at() {
                return Err(FinalityArchiveError::MinedAfterRelease);
            }
            if transfers[..index].iter().any(|prior| {
                prior.artifact_identity() == transfer.artifact_identity()
                    || prior.txid() == transfer.txid()
            }) {
                return Err(FinalityArchiveError::DuplicateTransfer);
            }
        }
        let mut archive = Self {
            release,
            transfers,
            fingerprint: FinalityArchiveFingerprint::from_bytes([0; DIGEST_LENGTH]),
        };
        let bytes = archive.canonical_bytes();
        if bytes.len() > MAX_FINALITY_ARCHIVE_BYTES {
            return Err(FinalityArchiveError::TooLarge);
        }
        archive.fingerprint =
            FinalityArchiveFingerprint::from_bytes(digest(FINALITY_ARCHIVE_PERSONAL, &bytes));
        Ok(archive)
    }

    /// Returns the source-reservation release horizon.
    pub const fn release(&self) -> ReservationRelease {
        self.release
    }

    /// Returns all exact finalized transfers.
    pub fn transfers(&self) -> &[FinalizedTransferEvidence] {
        &self.transfers
    }

    /// Returns the canonical archive fingerprint.
    pub const fn fingerprint(&self) -> FinalityArchiveFingerprint {
        self.fingerprint
    }

    /// Audits immutable finality evidence against one revision-consistent active-chain view.
    ///
    /// `fully_scanned_height` and `observed_transfers` must come from the same wallet-store read
    /// transaction. Rewinding below the persisted release horizon fails closed even when the
    /// archived transaction identifiers later reappear on another branch.
    pub fn audit(
        &self,
        fully_scanned_height: BlockHeight,
        observed_transfers: &[FinalizedTransferEvidence],
    ) -> FinalityAuditResult {
        if fully_scanned_height < self.release.release_at() {
            return FinalityAuditResult::RecoveryRequired(
                StorageRecoveryReason::RewoundBeyondFinalityHorizon,
            );
        }
        if self.transfers.iter().any(|archived| {
            observed_transfers
                .iter()
                .filter(|observed| observed.txid() == archived.txid())
                .count()
                != 1
                || !observed_transfers
                    .iter()
                    .any(|observed| observed == archived)
        }) {
            return FinalityAuditResult::RecoveryRequired(
                StorageRecoveryReason::TransferEvidenceLost,
            );
        }
        FinalityAuditResult::Consistent
    }

    /// Writes the complete versioned canonical archive.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        write_byte(&mut writer, FINALITY_ARCHIVE_CODEC_VERSION)?;
        write_u32(&mut writer, u32::from(self.release.release_at()))?;
        Vector::write(writer, &self.transfers, |writer, transfer| {
            transfer.write(writer)
        })
    }

    /// Reads and validates a complete canonical archive.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        if read_byte(&mut reader)? != FINALITY_ARCHIVE_CODEC_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unsupported finality-archive codec version",
            ));
        }
        let release = ReservationRelease::at(BlockHeight::from_u32(read_u32(&mut reader)?));
        let count: usize = CompactSize::read_t(&mut reader)?;
        if count > MAX_FINALITY_ARCHIVE_TRANSFERS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "finality archive exceeds its transfer limit",
            ));
        }
        let mut transfers = Vec::with_capacity(count);
        for _ in 0..count {
            transfers.push(FinalizedTransferEvidence::read(&mut reader)?);
        }
        Self::new(release, transfers).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "finality archive violates exact evidence invariants",
            )
        })
    }

    /// Decodes one complete canonical archive and rejects trailing bytes.
    pub fn decode(canonical_bytes: &[u8]) -> io::Result<Self> {
        if canonical_bytes.len() > MAX_FINALITY_ARCHIVE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "finality archive exceeds its byte limit",
            ));
        }
        let mut reader = canonical_bytes;
        let archive = Self::read(&mut reader)?;
        if !reader.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "trailing bytes after finality archive",
            ));
        }
        Ok(archive)
    }

    /// Returns the complete versioned canonical archive bytes.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        canonical_bytes(|writer| self.write(writer))
            .expect("writing a canonical finality archive to a Vec is infallible")
    }
}

/// Result of auditing immutable release evidence against the active chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FinalityAuditResult {
    /// Every exact archived transfer remains mined at its recorded height.
    Consistent,
    /// Delivery and ordinary mutation must fail closed pending explicit recovery.
    RecoveryRequired(StorageRecoveryReason),
}

/// Durable control phase layered over canonical migration state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveryPhase {
    /// Workers may acquire delivery claims.
    Active,
    /// No new claim may be acquired; exposed artifacts remain recoverable.
    Paused,
    /// Cancellation was requested, but exposed bytes are not chain-safe to release.
    Abandoning,
    /// Every exposed artifact was mined or positively expired.
    Abandoned,
}

impl DeliveryPhase {
    /// Returns the stable storage discriminant.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Abandoning => "abandoning",
            Self::Abandoned => "abandoned",
        }
    }

    /// Parses a stable storage discriminant.
    pub fn from_stored(value: &str) -> Option<Self> {
        match value {
            "active" => Some(Self::Active),
            "paused" => Some(Self::Paused),
            "abandoning" => Some(Self::Abandoning),
            "abandoned" => Some(Self::Abandoned),
            _ => None,
        }
    }
}

/// Fixed release horizon for retained migration-source reservations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReservationRelease {
    release_at: BlockHeight,
}

impl ReservationRelease {
    /// Creates a release horizon from the fully-scanned active-chain height at which release is safe.
    pub const fn at(release_at: BlockHeight) -> Self {
        Self { release_at }
    }

    /// Returns the fully-scanned active-chain release height.
    pub const fn release_at(self) -> BlockHeight {
        self.release_at
    }

    /// Derives the fixed release horizon for positively expired, unmined exposure.
    ///
    /// Returning `None` on height overflow fails closed instead of silently shortening the reorg
    /// horizon.
    pub fn after_resolved_unmined_expiry(expiry_height: BlockHeight) -> Option<Self> {
        u32::from(expiry_height)
            .checked_add(RESOLVED_UNMINED_RELEASE_CONFIRMATIONS - 1)
            .map(BlockHeight::from_u32)
            .map(Self::at)
    }
}

/// Reason durable source-reservation state requires explicit recovery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageRecoveryReason {
    /// Current-chain evidence for a transfer disappeared before its release horizon.
    TransferEvidenceLost,
    /// The wallet rewound beyond an already-finalized stability horizon.
    RewoundBeyondFinalityHorizon,
    /// Persisted finality evidence is internally inconsistent.
    CorruptFinalityEvidence,
    /// An externally exposed PCZT reached expiry, but a reserved source was spent or the active
    /// chain could not positively prove every reserved source remained unspent.
    ExternalSigningExposureUnresolved,
}

/// Storage-level finality for source reservations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageFinality {
    /// No migration run exists and no migration source reservation is retained.
    NoRun,
    /// Canonical migration is not yet all-mined; ordinary spends remain blocked.
    Active,
    /// Canonical completion is visible and destination funds may be spendable, while exact source
    /// reservations remain until the contained release horizon.
    CompletePendingFinality(ReservationRelease),
    /// Source reservations were released at the contained stable height.
    Finalized(ReservationRelease),
    /// Explicit recovery is required before delivery or reservation mutation.
    RecoveryRequired(StorageRecoveryReason),
}

impl StorageFinality {
    /// Returns the stable storage discriminant.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoRun => "no_run",
            Self::Active => "active",
            Self::CompletePendingFinality(_) => "complete_pending_finality",
            Self::Finalized(_) => "finalized",
            Self::RecoveryRequired(_) => "recovery_required",
        }
    }

    /// Returns a release horizon when one exists.
    pub const fn release(self) -> Option<ReservationRelease> {
        match self {
            Self::CompletePendingFinality(release) | Self::Finalized(release) => Some(release),
            Self::NoRun | Self::Active | Self::RecoveryRequired(_) => None,
        }
    }
}

/// Capability protected by an unforgeable attempt token and monotonic lease.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimKind {
    /// Build, prove, sign, and finalize source evidence into exact network bytes.
    Materialization,
    /// Submit already-staged exact bytes once to the bound transport.
    Submission,
    /// Resolve a prior ambiguous transport call without resubmitting bytes.
    OutcomeResolution,
}

impl ClaimKind {
    /// Returns the stable storage discriminant.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Materialization => "materialization",
            Self::Submission => "submission",
            Self::OutcomeResolution => "outcome_resolution",
        }
    }

    /// Parses a stable storage discriminant.
    pub fn from_stored(value: &str) -> Option<Self> {
        match value {
            "materialization" => Some(Self::Materialization),
            "submission" => Some(Self::Submission),
            "outcome_resolution" => Some(Self::OutcomeResolution),
            _ => None,
        }
    }
}

/// One live token-bound delivery lease.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeliveryLease {
    kind: ClaimKind,
    token: ClaimToken,
    acquired_at: MonotonicLeaseInstant,
    expires_at: MonotonicLeaseInstant,
}

/// Failure while reconstructing persisted monotonic lease evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum LeaseValidationError {
    /// Acquisition and expiry belong to different monotonic clock sessions.
    ClockSessionMismatch,
    /// Expiry does not follow acquisition in the same monotonic epoch.
    NonIncreasingExpiry,
}

/// Validity of a persisted lease at a current monotonic instant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaseValidity {
    /// The lease is live in the current clock session.
    Live,
    /// The monotonic deadline has been reached.
    Expired,
    /// The process/device clock session changed, so the old lease fails closed.
    ClockSessionChanged,
    /// The current clock tick precedes acquisition in the same session, so the clock rolled back.
    ClockRollback,
}

impl DeliveryLease {
    /// Creates a lease after checked monotonic expiry computation.
    pub fn new(
        kind: ClaimKind,
        token: ClaimToken,
        acquired_at: MonotonicLeaseInstant,
        duration: LeaseDuration,
    ) -> Option<Self> {
        acquired_at
            .checked_add(duration)
            .and_then(|expires_at| Self::from_parts(kind, token, acquired_at, expires_at).ok())
    }

    /// Reconstructs a stored lease only when its clock session and interval are valid.
    pub fn from_parts(
        kind: ClaimKind,
        token: ClaimToken,
        acquired_at: MonotonicLeaseInstant,
        expires_at: MonotonicLeaseInstant,
    ) -> Result<Self, LeaseValidationError> {
        if acquired_at.session != expires_at.session {
            return Err(LeaseValidationError::ClockSessionMismatch);
        }
        if acquired_at.tick_millis >= expires_at.tick_millis {
            return Err(LeaseValidationError::NonIncreasingExpiry);
        }
        Ok(Self {
            kind,
            token,
            acquired_at,
            expires_at,
        })
    }

    /// Returns the protected capability.
    pub const fn kind(self) -> ClaimKind {
        self.kind
    }

    /// Returns the unforgeable attempt token.
    pub const fn token(self) -> ClaimToken {
        self.token
    }

    /// Returns the monotonic acquisition instant.
    pub const fn acquired_at(self) -> MonotonicLeaseInstant {
        self.acquired_at
    }

    /// Returns the monotonic expiry instant.
    pub const fn expires_at(self) -> MonotonicLeaseInstant {
        self.expires_at
    }

    /// Evaluates the lease against the current clock capability.
    ///
    /// A clock-session change or rollback fails closed instead of extending a stale lease.
    pub fn validity_at(self, now: MonotonicLeaseInstant) -> LeaseValidity {
        if now.session != self.acquired_at.session {
            LeaseValidity::ClockSessionChanged
        } else if now.tick_millis < self.acquired_at.tick_millis {
            LeaseValidity::ClockRollback
        } else if now.tick_millis >= self.expires_at.tick_millis {
            LeaseValidity::Expired
        } else {
            LeaseValidity::Live
        }
    }
}

/// Durable status of one exact delivery artifact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimStatus {
    /// Materialization capability is currently leased.
    Materializing,
    /// A known-unsent local attempt failed before exact bytes reached a transport.
    MaterializationFailed,
    /// Exact PCZT bytes are durably staged and may be reacquired by an external signer.
    AwaitingExternalSignature,
    /// Exact transaction bytes are durably staged.
    Staged,
    /// Submission capability is currently leased and transport has not yet resolved.
    Submitting,
    /// A transport call began but its outcome is unknown; only resolution may be claimed.
    OutcomeUnknown,
    /// The network accepted exact bytes; mining is pending.
    Broadcasted,
    /// Exact bytes are mined on the currently scanned active chain.
    Confirmed,
    /// Exact bytes are positively expired and unmined.
    ExpiredUnmined,
    /// An externally exposed exact PCZT reached consensus expiry before exact transaction bytes
    /// returned, and a fully scanned active-chain view positively proved every reserved source
    /// remained unspent.
    ///
    /// The staged PCZT evidence remains durable for audit, but the signing capability is retired
    /// and source reservations may be released by the normal abandonment transition. A spent
    /// source or ambiguous scan evidence must enter recovery instead of using this status.
    ExternalSigningExpiredUnmined,
}

impl ClaimStatus {
    /// Returns the stable storage discriminant.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Materializing => "materializing",
            Self::MaterializationFailed => "materialization_failed",
            Self::AwaitingExternalSignature => "awaiting_external_signature",
            Self::Staged => "staged",
            Self::Submitting => "submitting",
            Self::OutcomeUnknown => "outcome_unknown",
            Self::Broadcasted => "broadcasted",
            Self::Confirmed => "confirmed",
            Self::ExpiredUnmined => "expired_unmined",
            Self::ExternalSigningExpiredUnmined => "external_signing_expired_unmined",
        }
    }

    /// Parses a stable storage discriminant.
    pub fn from_stored(value: &str) -> Option<Self> {
        match value {
            "materializing" => Some(Self::Materializing),
            "materialization_failed" => Some(Self::MaterializationFailed),
            "awaiting_external_signature" => Some(Self::AwaitingExternalSignature),
            "staged" => Some(Self::Staged),
            "submitting" => Some(Self::Submitting),
            "outcome_unknown" => Some(Self::OutcomeUnknown),
            "broadcasted" => Some(Self::Broadcasted),
            "confirmed" => Some(Self::Confirmed),
            "expired_unmined" => Some(Self::ExpiredUnmined),
            "external_signing_expired_unmined" => Some(Self::ExternalSigningExpiredUnmined),
            _ => None,
        }
    }

    /// Whether a transport call may have exposed exact bytes to the network.
    pub const fn is_chain_exposed(self) -> bool {
        matches!(
            self,
            Self::Submitting | Self::OutcomeUnknown | Self::Broadcasted | Self::Confirmed
        )
    }

    /// Whether this status proves that exact transaction bytes previously crossed a network
    /// transport boundary, including terminal records retained after that exposure resolved.
    pub const fn has_chain_exposure_history(self) -> bool {
        matches!(
            self,
            Self::Submitting
                | Self::OutcomeUnknown
                | Self::Broadcasted
                | Self::Confirmed
                | Self::ExpiredUnmined
        )
    }

    const fn permitted_lease(self) -> Option<ClaimKind> {
        match self {
            Self::Materializing => Some(ClaimKind::Materialization),
            Self::AwaitingExternalSignature => Some(ClaimKind::Materialization),
            Self::Submitting => Some(ClaimKind::Submission),
            Self::OutcomeUnknown | Self::Broadcasted => Some(ClaimKind::OutcomeResolution),
            Self::MaterializationFailed
            | Self::Staged
            | Self::Confirmed
            | Self::ExpiredUnmined
            | Self::ExternalSigningExpiredUnmined => None,
        }
    }

    /// Whether all possible chain exposure represented by this status has been positively
    /// resolved.
    pub const fn is_exposure_terminal(self) -> bool {
        matches!(
            self,
            Self::Confirmed | Self::ExpiredUnmined | Self::ExternalSigningExpiredUnmined
        )
    }
}

/// Rust-owned privacy-safe reason retained for a known-unsent failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveryFailureReason {
    /// Local proving, signing, or finalization failed.
    MaterializationFailed,
    /// A materialization lease expired before exact bytes were staged.
    MaterializationLeaseExpired,
    /// External signing was explicitly cancelled before exact bytes existed.
    SigningCancelled,
    /// Transport setup failed before a network call began.
    TransportSetupFailed,
    /// The transport positively reported that no network call began.
    TransportDidNotBegin,
    /// A submission lease expired before transport invocation began.
    SubmissionLeaseExpired,
    /// A transport call began and must be resolved without resubmission.
    TransportOutcomeUnknown,
}

impl DeliveryFailureReason {
    /// Returns the stable storage discriminant.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MaterializationFailed => "materialization_failed",
            Self::MaterializationLeaseExpired => "materialization_lease_expired",
            Self::SigningCancelled => "signing_cancelled",
            Self::TransportSetupFailed => "transport_setup_failed",
            Self::TransportDidNotBegin => "transport_did_not_begin",
            Self::SubmissionLeaseExpired => "submission_lease_expired",
            Self::TransportOutcomeUnknown => "transport_outcome_unknown",
        }
    }

    /// Parses a stable storage discriminant.
    pub fn from_stored(value: &str) -> Option<Self> {
        match value {
            "materialization_failed" => Some(Self::MaterializationFailed),
            "materialization_lease_expired" => Some(Self::MaterializationLeaseExpired),
            "signing_cancelled" => Some(Self::SigningCancelled),
            "transport_setup_failed" => Some(Self::TransportSetupFailed),
            "transport_did_not_begin" => Some(Self::TransportDidNotBegin),
            "submission_lease_expired" => Some(Self::SubmissionLeaseExpired),
            "transport_outcome_unknown" => Some(Self::TransportOutcomeUnknown),
            _ => None,
        }
    }

    /// Whether this reason is valid for the durable status that retains it.
    pub const fn is_valid_for(self, status: ClaimStatus) -> bool {
        matches!(
            (status, self),
            (
                ClaimStatus::MaterializationFailed,
                Self::MaterializationFailed
                    | Self::MaterializationLeaseExpired
                    | Self::SigningCancelled
            ) | (
                ClaimStatus::Staged,
                Self::TransportSetupFailed
                    | Self::TransportDidNotBegin
                    | Self::SubmissionLeaseExpired
            ) | (ClaimStatus::OutcomeUnknown, Self::TransportOutcomeUnknown)
        )
    }
}

/// Invalid combination of fields while reconstructing a delivery claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClaimValidationError {
    /// The active lease does not match the status capability.
    InvalidLease,
    /// Exact transaction evidence is missing or present for the wrong status.
    InvalidExactTransaction,
    /// Exact bytes are bound to a different artifact identity.
    ArtifactIdentityMismatch,
    /// Exact transaction expiry differs from immutable source evidence.
    ExpiryMismatch,
    /// A local failure reason is present for a status that did not fail locally.
    InvalidFailureReason,
    /// External-signing ownership, status, or staged evidence is inconsistent.
    InvalidExternalSigningState,
    /// Signed PCZT evidence is not bound to exact staged PCZT evidence.
    SignedPcztBindingMismatch,
}

/// One exact-artifact claim returned to a delivery worker.
#[derive(Clone, PartialEq, Eq)]
pub struct DeliveryClaim {
    evidence: DeliveryArtifactEvidence,
    signer_ownership: SignerOwnership,
    status: ClaimStatus,
    lease: Option<DeliveryLease>,
    external_signing_pczt: Option<ExternalSigningPczt>,
    signed_pczt: Option<SignedPcztEvidence>,
    exact_transaction: Option<ExactTransaction>,
    policy_fingerprint: PolicyFingerprint,
    last_error: Option<DeliveryFailureReason>,
}

impl DeliveryClaim {
    /// Reconstructs a claim only when its status, capability lease, and exact evidence agree.
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        evidence: DeliveryArtifactEvidence,
        signer_ownership: SignerOwnership,
        status: ClaimStatus,
        lease: Option<DeliveryLease>,
        external_signing_pczt: Option<ExternalSigningPczt>,
        signed_pczt: Option<SignedPcztEvidence>,
        exact_transaction: Option<ExactTransaction>,
        policy_fingerprint: PolicyFingerprint,
        last_error: Option<DeliveryFailureReason>,
    ) -> Result<Self, ClaimValidationError> {
        match (status.permitted_lease(), lease) {
            (Some(permitted), Some(actual)) if permitted == actual.kind() => {}
            (Some(ClaimKind::OutcomeResolution | ClaimKind::Materialization), None)
                if matches!(
                    status,
                    ClaimStatus::OutcomeUnknown
                        | ClaimStatus::Broadcasted
                        | ClaimStatus::AwaitingExternalSignature
                ) => {}
            (None, None) => {}
            _ => return Err(ClaimValidationError::InvalidLease),
        }
        let exact_required = matches!(
            status,
            ClaimStatus::Staged
                | ClaimStatus::Submitting
                | ClaimStatus::OutcomeUnknown
                | ClaimStatus::Broadcasted
                | ClaimStatus::Confirmed
                | ClaimStatus::ExpiredUnmined
        );
        if exact_required != exact_transaction.is_some() {
            return Err(ClaimValidationError::InvalidExactTransaction);
        }
        if exact_transaction
            .as_ref()
            .is_some_and(|transaction| transaction.artifact_identity() != evidence.identity())
        {
            return Err(ClaimValidationError::ArtifactIdentityMismatch);
        }
        if exact_transaction.as_ref().is_some_and(|transaction| {
            transaction.consensus_expiry_height() != evidence.expiry_height()
        }) {
            return Err(ClaimValidationError::ExpiryMismatch);
        }
        if signed_pczt.as_ref().is_some_and(|signed| {
            external_signing_pczt
                .as_ref()
                .is_none_or(|staged| signed.staged_digest() != staged.digest())
        }) {
            return Err(ClaimValidationError::SignedPcztBindingMismatch);
        }
        match signer_ownership {
            SignerOwnership::Sdk if external_signing_pczt.is_some() || signed_pczt.is_some() => {
                return Err(ClaimValidationError::InvalidExternalSigningState);
            }
            SignerOwnership::External => {
                if matches!(
                    status,
                    ClaimStatus::AwaitingExternalSignature
                        | ClaimStatus::ExternalSigningExpiredUnmined
                ) && external_signing_pczt.is_none()
                {
                    return Err(ClaimValidationError::InvalidExternalSigningState);
                }
                if exact_transaction.is_some()
                    && (external_signing_pczt.is_none() || signed_pczt.is_none())
                {
                    return Err(ClaimValidationError::InvalidExternalSigningState);
                }
            }
            SignerOwnership::Sdk => {}
        }
        if matches!(
            status,
            ClaimStatus::AwaitingExternalSignature | ClaimStatus::ExternalSigningExpiredUnmined
        ) && signer_ownership != SignerOwnership::External
        {
            return Err(ClaimValidationError::InvalidExternalSigningState);
        }
        if external_signing_pczt.is_some()
            && !matches!(
                status,
                ClaimStatus::AwaitingExternalSignature
                    | ClaimStatus::Staged
                    | ClaimStatus::Submitting
                    | ClaimStatus::OutcomeUnknown
                    | ClaimStatus::Broadcasted
                    | ClaimStatus::Confirmed
                    | ClaimStatus::ExpiredUnmined
                    | ClaimStatus::ExternalSigningExpiredUnmined
            )
        {
            return Err(ClaimValidationError::InvalidExternalSigningState);
        }
        match last_error {
            Some(reason) if !reason.is_valid_for(status) => {
                return Err(ClaimValidationError::InvalidFailureReason);
            }
            None if matches!(
                status,
                ClaimStatus::MaterializationFailed | ClaimStatus::OutcomeUnknown
            ) =>
            {
                return Err(ClaimValidationError::InvalidFailureReason);
            }
            _ => {}
        }
        Ok(Self {
            evidence,
            signer_ownership,
            status,
            lease,
            external_signing_pczt,
            signed_pczt,
            exact_transaction,
            policy_fingerprint,
            last_error,
        })
    }

    /// Returns immutable source evidence.
    pub const fn evidence(&self) -> &DeliveryArtifactEvidence {
        &self.evidence
    }

    /// Returns the stable artifact identity.
    pub const fn artifact_identity(&self) -> DeliveryArtifactIdentity {
        self.evidence.identity()
    }

    /// Returns the lane.
    pub const fn lane(&self) -> DeliveryLane {
        self.evidence.lane()
    }

    /// Returns the canonical transaction row identity for the scheduled lane.
    pub const fn scheduled_transaction_id(&self) -> Option<MigrationTxId> {
        self.evidence.scheduled_transaction_id()
    }

    /// Returns the PCZT digest for the scheduled lane.
    pub const fn pczt_digest(&self) -> Option<PcztDigest> {
        self.evidence.pczt_digest()
    }

    /// Returns the immutable transaction binding for the scheduled lane.
    pub const fn transaction_fingerprint(&self) -> Option<MigrationTransactionFingerprint> {
        self.evidence.transaction_fingerprint()
    }

    /// Returns authorization ownership.
    pub const fn signer_ownership(&self) -> SignerOwnership {
        self.signer_ownership
    }

    /// Returns durable delivery status.
    pub const fn status(&self) -> ClaimStatus {
        self.status
    }

    /// Returns a live lease, if one exists.
    pub const fn lease(&self) -> Option<DeliveryLease> {
        self.lease
    }

    /// Returns the currently leased capability, if one exists.
    pub const fn claim_kind(&self) -> Option<ClaimKind> {
        match self.lease {
            Some(lease) => Some(lease.kind()),
            None => None,
        }
    }

    /// Returns the currently leased Rust-generated token, if one exists.
    pub const fn token(&self) -> Option<ClaimToken> {
        match self.lease {
            Some(lease) => Some(lease.token()),
            None => None,
        }
    }

    /// Returns the monotonic lease expiry, if one exists.
    pub const fn lease_expires_at(&self) -> Option<MonotonicLeaseInstant> {
        match self.lease {
            Some(lease) => Some(lease.expires_at()),
            None => None,
        }
    }

    /// Returns exact crash-safe PCZT evidence staged for an external signer.
    pub const fn external_signing_pczt(&self) -> Option<&ExternalSigningPczt> {
        self.external_signing_pczt.as_ref()
    }

    /// Whether an exact PCZT crossed an external signer boundary and remains relevant to source
    /// reservation safety.
    pub const fn has_external_signing_exposure(&self) -> bool {
        self.external_signing_pczt.is_some()
    }

    /// Whether exact bytes crossed either the network or external-signer boundary at any point.
    pub const fn has_exposure_history(&self) -> bool {
        self.status.has_chain_exposure_history() || self.has_external_signing_exposure()
    }

    /// Returns canonical signer-merge evidence bound to the staged PCZT.
    pub const fn signed_pczt(&self) -> Option<&SignedPcztEvidence> {
        self.signed_pczt.as_ref()
    }

    /// Returns the consensus expiry height.
    pub const fn expiry_height(&self) -> BlockHeight {
        self.evidence.expiry_height()
    }

    /// Returns exact transaction evidence after successful materialization.
    pub const fn exact_transaction(&self) -> Option<&ExactTransaction> {
        self.exact_transaction.as_ref()
    }

    /// Returns the exact transaction identifier after materialization.
    pub const fn txid(&self) -> Option<TxId> {
        match self.exact_transaction.as_ref() {
            Some(transaction) => Some(transaction.txid()),
            None => None,
        }
    }

    /// Returns the immutable policy fingerprint.
    pub const fn policy_fingerprint(&self) -> PolicyFingerprint {
        self.policy_fingerprint
    }

    /// Returns the privacy-safe last failure reason.
    pub const fn last_error(&self) -> Option<DeliveryFailureReason> {
        self.last_error
    }
}

impl fmt::Debug for DeliveryClaim {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeliveryClaim")
            .field("artifact_identity", &"<redacted>")
            .field("lane", &self.lane())
            .field("signer_ownership", &self.signer_ownership)
            .field("status", &self.status)
            .field("lease", &self.lease.map(|_| "<redacted>"))
            .field(
                "external_signing_pczt",
                &self.external_signing_pczt.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "signed_pczt",
                &self.signed_pczt.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "exact_transaction",
                &self.exact_transaction.as_ref().map(|_| "<redacted>"),
            )
            .field("policy_fingerprint", &"<redacted>")
            .field("last_error", &self.last_error)
            .finish()
    }
}

/// Provenance version of the additive delivery schema.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DeliverySchemaVersion(NonZeroU32);

impl DeliverySchemaVersion {
    /// Creates a non-zero semantic schema version.
    pub const fn new(version: NonZeroU32) -> Self {
        Self(version)
    }

    /// Converts a storage scalar, returning `None` for the invalid zero version.
    pub const fn from_u32(version: u32) -> Option<Self> {
        match NonZeroU32::new(version) {
            Some(version) => Some(Self::new(version)),
            None => None,
        }
    }

    /// Returns the storage scalar.
    pub const fn as_u32(self) -> u32 {
        self.0.get()
    }
}

/// Provenance of the delivery-control extension schema.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliverySchemaProvenance {
    /// The exact compatible schema version is installed.
    Compatible(DeliverySchemaVersion),
    /// The extension schema is absent.
    Unavailable,
    /// A newer schema is installed and cannot be interpreted safely.
    Future(DeliverySchemaVersion),
    /// The schema shape or provenance evidence is corrupt.
    Corrupt,
}

/// Number of exact retired standalone schema objects requiring recovery.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct LegacySchemaObjectCount(NonZeroU32);

impl LegacySchemaObjectCount {
    /// Creates a non-zero exact-object count.
    pub const fn new(objects: NonZeroU32) -> Self {
        Self(objects)
    }

    /// Returns the count at the storage boundary.
    pub const fn as_u32(self) -> u32 {
        self.0.get()
    }
}

/// One-time retirement disposition for standalone `ext_ironwood_migration_*` state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LegacyCutoverStatus {
    /// No standalone schema objects or run rows exist.
    Fresh,
    /// Exact legacy evidence must be resolved before migration or ordinary spending continues.
    RecoveryRequired(LegacySchemaObjectCount),
}

/// Result of one transport call made under a live submission claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubmissionOutcome {
    /// The server accepted exact bytes; mining remains pending.
    Accepted,
    /// No transport call began, so exact bytes may become claimable again.
    KnownUnsent,
    /// A transport call began but its outcome is ambiguous and may only be resolved.
    Unknown,
}

/// Reason the authoritative migration runtime is unavailable or unsafe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeUnavailableReason {
    /// The additive delivery schema is absent.
    SchemaUnavailable,
    /// The additive delivery schema is newer than this runtime.
    FutureSchema(DeliverySchemaVersion),
    /// Delivery schema or persisted delivery data is corrupt.
    CorruptDeliveryState,
    /// Retired standalone state requires explicit recovery.
    LegacyCutoverRecovery(LegacySchemaObjectCount),
    /// No validated policy is bound to the active run.
    SubmissionPolicyMissing,
    /// The stored policy does not match current Rust-derived network consensus.
    SubmissionPolicyMismatch,
    /// Canonical and delivery fingerprints or exact evidence disagree.
    DeliveryInconsistent,
    /// A live immediate run in a pre-chain, forward-exposure-capable state predates durable
    /// persistence of the user's maximum authorized gross spend. Read-only state and non-exposing
    /// recovery remain available, but no new exposure capability may be issued.
    MissingSpendAuthorization,
    /// A rewind or missing active-chain evidence requires finality recovery.
    FinalityRecovery(StorageRecoveryReason),
}

/// Availability of one atomic canonical-plus-delivery runtime snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MigrationRuntimeAvailability {
    /// Canonical and delivery state are revision-consistent and safe to interpret.
    Available,
    /// Runtime interpretation must fail closed for the contained reason.
    Unavailable(RuntimeUnavailableReason),
}

/// Whether exact resulting Ironwood funds are spendable under normal wallet policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DestinationSpendability {
    /// No current or retained migration run has destination evidence to evaluate, or an abandoned
    /// unexposed run never created destination funds.
    NotApplicable,
    /// Resulting funds are not yet scanned and spendable.
    NotSpendable,
    /// Resulting funds are scanned and spendable.
    Spendable,
    /// Resulting funds were scanned and subsequently spent; migration completion remains satisfied.
    AlreadySpent,
}

/// Scope under which an ordinary transaction may be proposed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OrdinarySpendScope {
    /// No migration source reservation remains.
    Unrestricted,
    /// Ordinary selection must exclude retained migration sources until the release horizon.
    ExcludingMigrationSources(ReservationRelease),
}

/// Reason ordinary proposal creation must fail closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OrdinarySpendBlockReason {
    /// Canonical migration is still active, independently of any individual destination note.
    MigrationActive,
    /// Resulting Ironwood funds are not yet spendable.
    DestinationNotSpendable,
    /// Authoritative runtime state is unavailable.
    RuntimeUnavailable(RuntimeUnavailableReason),
    /// Source-reservation finality explicitly requires recovery.
    FinalityRecovery(StorageRecoveryReason),
}

/// Authoritative Rust-derived ordinary-spend authorization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OrdinarySpendAuthorization {
    /// Proposal creation may continue within the contained source-selection scope.
    Allowed(OrdinarySpendScope),
    /// Proposal creation must fail closed for the contained reason.
    Blocked(OrdinarySpendBlockReason),
}

impl OrdinarySpendAuthorization {
    /// Derives authorization without conflating destination spendability with reservation finality.
    pub const fn derive(
        runtime: MigrationRuntimeAvailability,
        destination: DestinationSpendability,
        finality: StorageFinality,
    ) -> Self {
        if let MigrationRuntimeAvailability::Unavailable(reason) = runtime {
            return Self::Blocked(OrdinarySpendBlockReason::RuntimeUnavailable(reason));
        }
        match finality {
            StorageFinality::NoRun => Self::Allowed(OrdinarySpendScope::Unrestricted),
            StorageFinality::Active => Self::Blocked(OrdinarySpendBlockReason::MigrationActive),
            StorageFinality::RecoveryRequired(reason) => {
                Self::Blocked(OrdinarySpendBlockReason::FinalityRecovery(reason))
            }
            StorageFinality::CompletePendingFinality(release) => match destination {
                DestinationSpendability::NotApplicable | DestinationSpendability::NotSpendable => {
                    Self::Blocked(OrdinarySpendBlockReason::DestinationNotSpendable)
                }
                DestinationSpendability::Spendable | DestinationSpendability::AlreadySpent => {
                    Self::Allowed(OrdinarySpendScope::ExcludingMigrationSources(release))
                }
            },
            StorageFinality::Finalized(_) => match destination {
                DestinationSpendability::NotApplicable => {
                    Self::Allowed(OrdinarySpendScope::Unrestricted)
                }
                DestinationSpendability::NotSpendable => {
                    Self::Blocked(OrdinarySpendBlockReason::DestinationNotSpendable)
                }
                DestinationSpendability::Spendable | DestinationSpendability::AlreadySpent => {
                    Self::Allowed(OrdinarySpendScope::Unrestricted)
                }
            },
        }
    }
}

/// Reason account deletion must fail closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccountDeletionBlockReason {
    /// The owning runtime could not establish authoritative delivery state.
    RuntimeUnavailable(RuntimeUnavailableReason),
    /// A run still owns unresolved delivery or source-reservation authority.
    UnresolvedDelivery(MigrationRunIdentity),
}

/// Authoritative account-deletion decision derived from an owning runtime snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccountDeletionAuthorization {
    /// No unresolved migration authority prevents deletion.
    Allowed,
    /// Deletion must fail closed for the contained reason.
    Blocked(AccountDeletionBlockReason),
}

/// Reason a generic canonical migration mutation must fail closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanonicalMutationBlockReason {
    /// The owning runtime could not establish authoritative delivery state.
    RuntimeUnavailable(RuntimeUnavailableReason),
    /// A delivery run exists and must be mutated only through its CAS delivery API.
    DeliveryOwned(MigrationRunIdentity),
}

/// Gate applied by production stores before any generic canonical migration mutation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanonicalMutationAuthorization {
    /// No delivery run owns the canonical migration state.
    Allowed,
    /// The generic mutation must fail closed for the contained reason.
    Blocked(CanonicalMutationBlockReason),
}

/// Minimal delivery-authorized canonical mutation performed under materialization capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanonicalMaterializationPurpose {
    /// Install the exact canonical PCZT returned by an external signer.
    ExternalSignature,
    /// Replace a signed PCZT with its exact proved canonical PCZT.
    Proof,
}

/// Invalid or over-broad canonical transition requested through delivery authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CanonicalMaterializationTransitionError {
    /// Immediate artifacts have no scheduled canonical state to mutate.
    InvalidArtifactLane,
    /// The exact scheduled artifact does not occur once in both states.
    ArtifactNotFound,
    /// The scheduled row exists but belongs to a different immutable attempt.
    ArtifactFingerprintMismatch,
    /// A canonical field outside the exact target PCZT/lifecycle pair changed.
    UnrelatedCanonicalMutation,
    /// The target lifecycle transition is not AwaitingSignature -> Signed or Signed -> Proved.
    InvalidTransitionOrdering,
    /// The successor did not replace the target PCZT bytes.
    PcztUnchanged,
    /// A proved successor was not a canonical, conflict-free enrichment of the exact signed PCZT,
    /// or it could not be extracted as an exact consensus transaction.
    InvalidProofEnrichment,
}

fn validate_canonical_proof_enrichment(
    predecessor_pczt: &[u8],
    successor_state: &MigrationState,
    transaction_id: MigrationTxId,
) -> Result<ExactTransaction, CanonicalMaterializationTransitionError> {
    let successor_transaction = successor_state
        .transactions()
        .iter()
        .find(|transaction| transaction.id() == transaction_id)
        .ok_or(CanonicalMaterializationTransitionError::ArtifactNotFound)?;
    let predecessor = pczt::Pczt::parse(predecessor_pczt)
        .map_err(|_| CanonicalMaterializationTransitionError::InvalidProofEnrichment)?;
    let successor = pczt::Pczt::parse(successor_transaction.pczt())
        .map_err(|_| CanonicalMaterializationTransitionError::InvalidProofEnrichment)?;
    let canonical_successor = successor
        .clone()
        .serialize()
        .map_err(|_| CanonicalMaterializationTransitionError::InvalidProofEnrichment)?;
    if canonical_successor.as_slice() != successor_transaction.pczt() {
        return Err(CanonicalMaterializationTransitionError::InvalidProofEnrichment);
    }
    let combined = Combiner::new(vec![predecessor, successor])
        .combine()
        .and_then(|combined| {
            combined
                .serialize()
                .map_err(|_| pczt::roles::combiner::Error::DataMismatch)
        })
        .map_err(|_| CanonicalMaterializationTransitionError::InvalidProofEnrichment)?;
    if combined.as_slice() != successor_transaction.pczt() {
        return Err(CanonicalMaterializationTransitionError::InvalidProofEnrichment);
    }
    exact_transaction(successor_state, transaction_id)
        .map_err(|_| CanonicalMaterializationTransitionError::InvalidProofEnrichment)
}

/// Sealed request for one narrow, claim-authorized canonical materialization transition.
#[derive(Clone, PartialEq, Eq)]
pub struct CanonicalMaterializationTransition {
    expected_revision: DeliveryRevision,
    run_identity: MigrationRunIdentity,
    expected_state_fingerprint: MigrationStateFingerprint,
    artifact_identity: DeliveryArtifactIdentity,
    token: ClaimToken,
    purpose: CanonicalMaterializationPurpose,
    proof_transaction: Option<ExactTransaction>,
    expected_policy_fingerprint: PolicyFingerprint,
    successor_state: MigrationState,
}

impl fmt::Debug for CanonicalMaterializationTransition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CanonicalMaterializationTransition")
            .field("expected_revision", &self.expected_revision)
            .field("run_identity", &"<redacted>")
            .field("expected_state_fingerprint", &"<redacted>")
            .field("artifact_identity", &"<redacted>")
            .field("token", &"<redacted>")
            .field("purpose", &self.purpose)
            .field(
                "proof_transaction",
                &self.proof_transaction.as_ref().map(|_| "<redacted>"),
            )
            .field("expected_policy_fingerprint", &"<redacted>")
            .field("successor_state", &"<redacted>")
            .finish()
    }
}

impl CanonicalMaterializationTransition {
    /// Validates and seals the only canonical mutations allowed under a materialization claim.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        expected_state: &MigrationState,
        artifact_identity: DeliveryArtifactIdentity,
        token: ClaimToken,
        expected_policy_fingerprint: PolicyFingerprint,
        successor_state: MigrationState,
    ) -> Result<Self, CanonicalMaterializationTransitionError> {
        let DeliveryArtifactIdentity::Scheduled(target_identity) = artifact_identity else {
            return Err(CanonicalMaterializationTransitionError::InvalidArtifactLane);
        };
        let target_id = target_identity.transaction_id();
        let mut matching_targets = expected_state
            .transactions()
            .iter()
            .filter(|transaction| transaction.id() == target_id);
        let Some(expected_target) = matching_targets.next() else {
            return Err(CanonicalMaterializationTransitionError::ArtifactNotFound);
        };
        if matching_targets.next().is_some() {
            return Err(CanonicalMaterializationTransitionError::ArtifactNotFound);
        }
        if migration_transaction_fingerprint(expected_state, expected_target)
            != target_identity.transaction_fingerprint()
        {
            return Err(CanonicalMaterializationTransitionError::ArtifactFingerprintMismatch);
        }
        if expected_state.status() != successor_state.status()
            || expected_state.note_split() != successor_state.note_split()
            || expected_state.preparation() != successor_state.preparation()
            || expected_state.transactions().len() != successor_state.transactions().len()
        {
            return Err(CanonicalMaterializationTransitionError::UnrelatedCanonicalMutation);
        }

        let mut target_transition = None;
        let mut proof_transaction = None;
        for (expected, successor) in expected_state
            .transactions()
            .iter()
            .zip(successor_state.transactions())
        {
            if expected.id() != target_id {
                if expected != successor {
                    return Err(
                        CanonicalMaterializationTransitionError::UnrelatedCanonicalMutation,
                    );
                }
                continue;
            }
            if target_transition.is_some() || successor.id() != target_id {
                return Err(CanonicalMaterializationTransitionError::ArtifactNotFound);
            }
            if expected.kind() != successor.kind()
                || expected.depends_on() != successor.depends_on()
                || expected.scheduled_height() != successor.scheduled_height()
                || expected.expiry_height() != successor.expiry_height()
                || expected.anchor_boundary() != successor.anchor_boundary()
                || expected.lock_owner() != successor.lock_owner()
            {
                return Err(CanonicalMaterializationTransitionError::UnrelatedCanonicalMutation);
            }
            if expected.pczt() == successor.pczt() {
                return Err(CanonicalMaterializationTransitionError::PcztUnchanged);
            }
            let purpose = match (expected.state(), successor.state()) {
                (MigrationTxState::AwaitingSignature, MigrationTxState::Signed) => {
                    CanonicalMaterializationPurpose::ExternalSignature
                }
                (MigrationTxState::Signed, MigrationTxState::Proved) => {
                    proof_transaction = Some(validate_canonical_proof_enrichment(
                        expected.pczt(),
                        &successor_state,
                        target_id,
                    )?);
                    CanonicalMaterializationPurpose::Proof
                }
                _ => {
                    return Err(CanonicalMaterializationTransitionError::InvalidTransitionOrdering);
                }
            };
            target_transition = Some(purpose);
        }
        let purpose =
            target_transition.ok_or(CanonicalMaterializationTransitionError::ArtifactNotFound)?;
        Ok(Self {
            expected_revision,
            run_identity,
            expected_state_fingerprint: migration_state_fingerprint(expected_state),
            artifact_identity,
            token,
            purpose,
            proof_transaction,
            expected_policy_fingerprint,
            successor_state,
        })
    }

    /// Returns the expected delivery CAS revision.
    pub const fn expected_revision(&self) -> DeliveryRevision {
        self.expected_revision
    }

    /// Returns the exact delivery run that owns the canonical state.
    pub const fn run_identity(&self) -> MigrationRunIdentity {
        self.run_identity
    }

    /// Returns the fingerprint of the exact expected canonical state.
    pub const fn expected_state_fingerprint(&self) -> MigrationStateFingerprint {
        self.expected_state_fingerprint
    }

    /// Returns the exact scheduled artifact allowed to change.
    pub const fn artifact_identity(&self) -> DeliveryArtifactIdentity {
        self.artifact_identity
    }

    /// Returns the Rust-generated live materialization token.
    pub const fn token(&self) -> ClaimToken {
        self.token
    }

    /// Returns the single permitted transition purpose derived from both canonical states.
    pub const fn purpose(&self) -> CanonicalMaterializationPurpose {
        self.purpose
    }

    /// Returns the required capability kind.
    pub const fn claim_kind(&self) -> ClaimKind {
        ClaimKind::Materialization
    }

    /// Returns the exact transaction extracted while sealing a proof transition.
    pub const fn proof_transaction(&self) -> Option<&ExactTransaction> {
        self.proof_transaction.as_ref()
    }

    /// Returns the immutable policy fingerprint that must still own the run.
    pub const fn expected_policy_fingerprint(&self) -> PolicyFingerprint {
        self.expected_policy_fingerprint
    }

    /// Returns the exact successor canonical state to persist atomically.
    pub const fn successor_state(&self) -> &MigrationState {
        &self.successor_state
    }
}

/// Atomic canonical-state and delivery-revision result of one materialization transition.
#[derive(Clone, PartialEq, Eq)]
pub struct CanonicalMaterializationReceipt {
    canonical_state: MigrationState,
    delivery: DeliverySnapshot,
}

impl fmt::Debug for CanonicalMaterializationReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CanonicalMaterializationReceipt")
            .field("canonical_state", &"<redacted>")
            .field("delivery", &self.delivery)
            .finish()
    }
}

impl CanonicalMaterializationReceipt {
    /// Reconstructs a receipt only after the exact canonical successor and delivery CAS committed.
    pub fn from_committed_parts(
        request: CanonicalMaterializationTransition,
        delivery: DeliverySnapshot,
    ) -> Option<Self> {
        let DeliveryArtifactIdentity::Scheduled(scheduled_identity) = request.artifact_identity()
        else {
            return None;
        };
        let successor_transaction = request
            .successor_state()
            .transactions()
            .iter()
            .find(|transaction| transaction.id() == scheduled_identity.transaction_id())?;
        let mut matching_claims = delivery
            .claims()
            .iter()
            .filter(|claim| claim.artifact_identity() == request.artifact_identity());
        let claim = matching_claims.next()?;
        if matching_claims.next().is_some()
            || claim.policy_fingerprint() != request.expected_policy_fingerprint()
        {
            return None;
        }
        let purpose_matches = match request.purpose() {
            CanonicalMaterializationPurpose::ExternalSignature => {
                claim.signer_ownership() == SignerOwnership::External
                    && claim.status() == ClaimStatus::AwaitingExternalSignature
                    && claim.claim_kind() == Some(ClaimKind::Materialization)
                    && claim.token() == Some(request.token())
                    && claim.lease().is_some()
                    && claim.exact_transaction().is_none()
                    && claim
                        .signed_pczt()
                        .is_some_and(|signed| signed.bytes() == successor_transaction.pczt())
            }
            CanonicalMaterializationPurpose::Proof => {
                let exact = request.proof_transaction()?;
                claim.status() == ClaimStatus::Staged
                    && claim.lease().is_none()
                    && claim.token().is_none()
                    && claim.claim_kind().is_none()
                    && claim.exact_transaction() == Some(exact)
                    && claim.evidence().canonical_pczt() == Some(successor_transaction.pczt())
            }
        };
        if delivery.revision() != request.expected_revision().checked_next()?
            || delivery.run_identity() != request.run_identity()
            || delivery.run_fingerprint()
                != DeliveryRunFingerprint::Scheduled(migration_state_fingerprint(
                    request.successor_state(),
                ))
            || !purpose_matches
        {
            return None;
        }
        Some(Self {
            canonical_state: request.successor_state,
            delivery,
        })
    }

    /// Returns the exact canonical state committed by the CAS.
    pub const fn canonical_state(&self) -> &MigrationState {
        &self.canonical_state
    }

    /// Returns the delivery snapshot and new revision committed by the same CAS.
    pub const fn delivery(&self) -> &DeliverySnapshot {
        &self.delivery
    }
}

/// Atomic canonical-state and delivery-revision result of submission or chain reconciliation.
#[derive(Clone, PartialEq, Eq)]
pub struct CanonicalDeliveryReceipt {
    canonical_state: MigrationState,
    delivery: DeliverySnapshot,
}

impl fmt::Debug for CanonicalDeliveryReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CanonicalDeliveryReceipt")
            .field("canonical_state", &"<redacted>")
            .field("delivery", &self.delivery)
            .finish()
    }
}

impl CanonicalDeliveryReceipt {
    /// Reconstructs a receipt only after canonical state and the next delivery revision committed
    /// together for the same run.
    pub fn from_committed_parts(
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        canonical_state: MigrationState,
        delivery: DeliverySnapshot,
    ) -> Option<Self> {
        if delivery.revision() != expected_revision.checked_next()?
            || delivery.run_identity() != run_identity
            || delivery.run_fingerprint()
                != DeliveryRunFingerprint::Scheduled(migration_state_fingerprint(&canonical_state))
        {
            return None;
        }
        Some(Self {
            canonical_state,
            delivery,
        })
    }

    /// Returns exact canonical state committed by the action.
    pub const fn canonical_state(&self) -> &MigrationState {
        &self.canonical_state
    }

    /// Returns the delivery snapshot and incremented revision committed by the same action.
    pub const fn delivery(&self) -> &DeliverySnapshot {
        &self.delivery
    }
}

/// Narrow reason an exact canonical successor may replace a delivery-owned run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReservationRolloverPurpose {
    /// A terminal predecessor is replaced by a newly committed engine migration.
    ReplaceTerminal,
}

/// Invalid or over-broad canonical successor supplied to a reservation rollover.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReservationRolloverValidationError {
    /// A terminal replacement was requested for a non-terminal predecessor.
    PredecessorNotTerminal,
    /// A terminal replacement did not carry a new non-terminal migration.
    InvalidTerminalReplacement,
    /// The engine-built successor already carried canonical lock ownership.
    SuccessorAlreadyOwned,
}

/// Compare-and-swap request for replacing one run while retaining all predecessor reservations.
#[derive(Clone, PartialEq, Eq)]
pub struct ReservationRollover {
    expected_revision: DeliveryRevision,
    predecessor_run_identity: MigrationRunIdentity,
    predecessor_reservation_owner: SourceReservationOwner,
    expected_predecessor_fingerprint: MigrationStateFingerprint,
    purpose: ReservationRolloverPurpose,
    successor_state: MigrationState,
}

impl fmt::Debug for ReservationRollover {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReservationRollover")
            .field("expected_revision", &self.expected_revision)
            .field("predecessor_run_identity", &"<redacted>")
            .field("predecessor_reservation_owner", &"<redacted>")
            .field("expected_predecessor_fingerprint", &"<redacted>")
            .field("purpose", &self.purpose)
            .field("successor_state", &"<redacted>")
            .finish()
    }
}

impl ReservationRollover {
    /// Seals replacement of a terminal predecessor with a newly committed engine migration.
    ///
    /// The store derives the successor fingerprint from `successor_state`; callers cannot supply a
    /// detached metadata fingerprint. The store generates the successor run and owner identities.
    pub fn replace_terminal(
        expected_revision: DeliveryRevision,
        predecessor_run_identity: MigrationRunIdentity,
        predecessor_reservation_owner: SourceReservationOwner,
        expected_predecessor: &MigrationState,
        successor_state: MigrationState,
    ) -> Result<Self, ReservationRolloverValidationError> {
        if !expected_predecessor.is_terminal() {
            return Err(ReservationRolloverValidationError::PredecessorNotTerminal);
        }
        if successor_state.is_terminal() || &successor_state == expected_predecessor {
            return Err(ReservationRolloverValidationError::InvalidTerminalReplacement);
        }
        if successor_state
            .transactions()
            .iter()
            .any(|transaction| transaction.lock_owner().is_some())
        {
            return Err(ReservationRolloverValidationError::SuccessorAlreadyOwned);
        }
        Ok(Self {
            expected_revision,
            predecessor_run_identity,
            predecessor_reservation_owner,
            expected_predecessor_fingerprint: migration_state_fingerprint(expected_predecessor),
            purpose: ReservationRolloverPurpose::ReplaceTerminal,
            successor_state,
        })
    }

    /// Returns the expected predecessor revision.
    pub const fn expected_revision(&self) -> DeliveryRevision {
        self.expected_revision
    }

    /// Returns the exact predecessor run identity.
    pub const fn predecessor_run_identity(&self) -> MigrationRunIdentity {
        self.predecessor_run_identity
    }

    /// Returns the predecessor reservation owner that must remain retained.
    pub const fn predecessor_reservation_owner(&self) -> SourceReservationOwner {
        self.predecessor_reservation_owner
    }

    /// Returns the exact expected predecessor canonical fingerprint.
    pub const fn expected_predecessor_fingerprint(&self) -> MigrationStateFingerprint {
        self.expected_predecessor_fingerprint
    }

    /// Returns the sealed, narrow reason for rollover.
    pub const fn purpose(&self) -> ReservationRolloverPurpose {
        self.purpose
    }

    /// Returns the exact canonical scheduled state that must be committed as the successor.
    pub const fn successor_state(&self) -> &MigrationState {
        &self.successor_state
    }

    /// Stamps the store-generated canonical lock owner uniformly onto the sealed successor.
    ///
    /// [`replace_terminal`](Self::replace_terminal) already proved every transaction was unowned,
    /// so this is the only permitted delta between the engine-built successor and the canonical
    /// state committed by the rollover store transaction.
    pub fn successor_state_with_lock_owner(&self, generated_owner: LockOwner) -> MigrationState {
        let mut successor = self.successor_state.clone();
        for transaction in &mut successor.transactions {
            transaction.lock_owner = Some(*generated_owner.as_bytes());
        }
        successor
    }
}

/// Invalid or over-broad canonical successor supplied for an in-run transfer-attempt rebuild.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExpiredTransferRebuildValidationError {
    /// The exact expired transfer attempt was absent or its fingerprint disagreed.
    ArtifactMismatch,
    /// A rebuild changed canonical data outside the exact transfer attempt.
    UnrelatedCanonicalMutation,
    /// The rebuilt artifact was not a non-mined transfer.
    InvalidRebuildTarget,
    /// Replacement schedule, expiry, PCZT, or lifecycle did not advance as a fresh attempt.
    InvalidRebuildSuccessor,
}

/// Compare-and-swap request for rebuilding one expired transfer attempt within its existing run.
///
/// Unlike [`ReservationRollover`], this operation never creates a successor run or reservation
/// owner. It archives the exact old `(transaction row, attempt fingerprint)` and atomically
/// installs a new attempt plus a fresh materialization capability under the same run and owner.
#[derive(Clone, PartialEq, Eq)]
pub struct ExpiredTransferRebuild {
    expected_revision: DeliveryRevision,
    run_identity: MigrationRunIdentity,
    source_reservation_owner: SourceReservationOwner,
    expected_state_fingerprint: MigrationStateFingerprint,
    prior_artifact: ScheduledArtifactIdentity,
    signer_ownership: SignerOwnership,
    successor_state: MigrationState,
}

impl fmt::Debug for ExpiredTransferRebuild {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExpiredTransferRebuild")
            .field("expected_revision", &self.expected_revision)
            .field("run_identity", &"<redacted>")
            .field("source_reservation_owner", &"<redacted>")
            .field("expected_state_fingerprint", &"<redacted>")
            .field("prior_artifact", &"<redacted>")
            .field("signer_ownership", &self.signer_ownership)
            .field("successor_state", &"<redacted>")
            .finish()
    }
}

impl ExpiredTransferRebuild {
    /// Seals one exact upstream-built replacement for a positively expired transfer attempt.
    ///
    /// This validates the narrow canonical shape only. The store must additionally prove from its
    /// own fully scanned active-chain view that the prior attempt is terminal ExpiredUnmined (or
    /// ExternalSigningExpiredUnmined), every reserved source remains unspent, and the successor's
    /// schedule, expiry, and PCZT came from the upstream rebuild operation before committing.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        source_reservation_owner: SourceReservationOwner,
        expected_state: &MigrationState,
        prior_artifact: ScheduledArtifactIdentity,
        signer_ownership: SignerOwnership,
        rebuilt_successor: RebuiltTransferSuccessor,
    ) -> Result<Self, ExpiredTransferRebuildValidationError> {
        let (sealed_predecessor, successor_state, rebuilt_transaction_id, external_signer) =
            rebuilt_successor.into_parts();
        if &sealed_predecessor != expected_state
            || rebuilt_transaction_id != prior_artifact.transaction_id()
            || external_signer != matches!(signer_ownership, SignerOwnership::External)
        {
            return Err(ExpiredTransferRebuildValidationError::ArtifactMismatch);
        }
        if expected_state.status() != successor_state.status()
            || expected_state.note_split() != successor_state.note_split()
            || expected_state.preparation() != successor_state.preparation()
            || expected_state.transactions().len() != successor_state.transactions().len()
        {
            return Err(ExpiredTransferRebuildValidationError::UnrelatedCanonicalMutation);
        }
        let target_id = prior_artifact.transaction_id();
        let mut found = false;
        for (expected, successor) in expected_state
            .transactions()
            .iter()
            .zip(successor_state.transactions())
        {
            if expected.id() != target_id {
                if expected != successor {
                    return Err(ExpiredTransferRebuildValidationError::UnrelatedCanonicalMutation);
                }
                continue;
            }
            if found
                || successor.id() != target_id
                || migration_transaction_fingerprint(expected_state, expected)
                    != prior_artifact.transaction_fingerprint()
            {
                return Err(ExpiredTransferRebuildValidationError::ArtifactMismatch);
            }
            found = true;
            if !matches!(expected.kind(), MigrationTxKind::Transfer { .. })
                || expected.kind() != successor.kind()
                || expected.depends_on() != successor.depends_on()
                || expected.lock_owner() != successor.lock_owner()
                || matches!(expected.state(), MigrationTxState::Mined { .. })
            {
                return Err(ExpiredTransferRebuildValidationError::InvalidRebuildTarget);
            }
            let expected_successor_state = match signer_ownership {
                SignerOwnership::Sdk => MigrationTxState::Signed,
                SignerOwnership::External => MigrationTxState::AwaitingSignature,
            };
            if successor.state() != expected_successor_state
                || successor.pczt() == expected.pczt()
                || u32::from(successor.scheduled_height()) <= u32::from(expected.scheduled_height())
                || u32::from(successor.expiry_height()) <= u32::from(expected.expiry_height())
            {
                return Err(ExpiredTransferRebuildValidationError::InvalidRebuildSuccessor);
            }
        }
        if !found {
            return Err(ExpiredTransferRebuildValidationError::ArtifactMismatch);
        }
        Ok(Self {
            expected_revision,
            run_identity,
            source_reservation_owner,
            expected_state_fingerprint: migration_state_fingerprint(expected_state),
            prior_artifact,
            signer_ownership,
            successor_state,
        })
    }

    /// Returns the expected delivery CAS revision.
    pub const fn expected_revision(&self) -> DeliveryRevision {
        self.expected_revision
    }

    /// Returns the existing run identity that must remain unchanged.
    pub const fn run_identity(&self) -> MigrationRunIdentity {
        self.run_identity
    }

    /// Returns the existing reservation owner that must remain unchanged.
    pub const fn source_reservation_owner(&self) -> SourceReservationOwner {
        self.source_reservation_owner
    }

    /// Returns the exact expected canonical-state fingerprint.
    pub const fn expected_state_fingerprint(&self) -> MigrationStateFingerprint {
        self.expected_state_fingerprint
    }

    /// Returns the immutable old attempt identity that must be archived.
    pub const fn prior_artifact(&self) -> ScheduledArtifactIdentity {
        self.prior_artifact
    }

    /// Returns the signer owner selected for the replacement attempt.
    pub const fn signer_ownership(&self) -> SignerOwnership {
        self.signer_ownership
    }

    /// Returns the exact canonical scheduled state that must replace the old attempt.
    pub const fn successor_state(&self) -> &MigrationState {
        &self.successor_state
    }

    /// Returns the replacement attempt identity derived from the exact successor state.
    pub fn successor_artifact(&self) -> ScheduledArtifactIdentity {
        let transaction = self
            .successor_state
            .transactions()
            .iter()
            .find(|transaction| transaction.id() == self.prior_artifact.transaction_id())
            .expect("validated rebuild successor contains the target transaction");
        ScheduledArtifactIdentity::new(
            transaction.id(),
            migration_transaction_fingerprint(&self.successor_state, transaction),
        )
    }

    /// Derives the canonical fingerprint after replacing the exact attempt.
    pub fn successor_fingerprint(&self) -> DeliveryRunFingerprint {
        DeliveryRunFingerprint::Scheduled(migration_state_fingerprint(&self.successor_state))
    }
}

/// Durable evidence returned after an atomic source-reservation rollover.
#[derive(Clone, PartialEq, Eq)]
pub struct ReservationRolloverReceipt {
    predecessor_run_identity: MigrationRunIdentity,
    retained_predecessor_owner: SourceReservationOwner,
    canonical_state: MigrationState,
    successor: DeliverySnapshot,
}

impl fmt::Debug for ReservationRolloverReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReservationRolloverReceipt")
            .field("predecessor_run_identity", &"<redacted>")
            .field("retained_predecessor_owner", &"<redacted>")
            .field("canonical_state", &"<redacted>")
            .field("successor", &self.successor)
            .finish()
    }
}

impl ReservationRolloverReceipt {
    /// Reconstructs committed rollover evidence for a store implementation.
    ///
    /// The store must call this only after its CAS persists `request.successor_state()`, creates
    /// `successor`, and durably retains every reservation owned by
    /// `retained_predecessor_owner` in the same transaction.
    pub fn from_committed_parts(
        request: ReservationRollover,
        canonical_state: MigrationState,
        successor: DeliverySnapshot,
    ) -> Option<Self> {
        let canonical_owner = canonical_state
            .transactions()
            .first()
            .and_then(MigrationTransaction::lock_owner)?;
        if canonical_state
            .transactions()
            .iter()
            .any(|transaction| transaction.lock_owner() != Some(canonical_owner))
            || canonical_state
                != request.successor_state_with_lock_owner(LockOwner::new(canonical_owner))
        {
            return None;
        }
        if successor.revision() != request.expected_revision().checked_next()?
            || successor.run_identity() == request.predecessor_run_identity()
            || successor.source_reservation_owner() == request.predecessor_reservation_owner()
            || successor.run_fingerprint()
                != DeliveryRunFingerprint::Scheduled(migration_state_fingerprint(&canonical_state))
        {
            return None;
        }
        Some(Self {
            predecessor_run_identity: request.predecessor_run_identity(),
            retained_predecessor_owner: request.predecessor_reservation_owner(),
            canonical_state,
            successor,
        })
    }

    /// Returns the predecessor run whose reservations remain retained.
    pub const fn predecessor_run_identity(&self) -> MigrationRunIdentity {
        self.predecessor_run_identity
    }

    /// Returns the predecessor reservation owner retained by the rollover.
    pub const fn retained_predecessor_owner(&self) -> SourceReservationOwner {
        self.retained_predecessor_owner
    }

    /// Returns the exact store-owned canonical successor committed by the rollover CAS.
    pub const fn canonical_state(&self) -> &MigrationState {
        &self.canonical_state
    }

    /// Returns the successor delivery snapshot committed by the same CAS.
    pub const fn successor(&self) -> &DeliverySnapshot {
        &self.successor
    }
}

/// Durable evidence returned after an expired transfer attempt was rebuilt within one run.
#[derive(Clone, PartialEq, Eq)]
pub struct ExpiredTransferRebuildReceipt {
    archived_attempt: ScheduledArtifactIdentity,
    replacement_attempt: ScheduledArtifactIdentity,
    canonical_state: MigrationState,
    delivery: DeliverySnapshot,
}

impl fmt::Debug for ExpiredTransferRebuildReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExpiredTransferRebuildReceipt")
            .field("archived_attempt", &"<redacted>")
            .field("replacement_attempt", &"<redacted>")
            .field("canonical_state", &"<redacted>")
            .field("delivery", &self.delivery)
            .finish()
    }
}

impl ExpiredTransferRebuildReceipt {
    /// Reconstructs a receipt only after the attempt archive, canonical successor, replacement
    /// claim, and delivery CAS committed atomically.
    ///
    /// The replacement must remain under the old run and source-reservation owner. Its current
    /// claim must carry a fresh Rust-generated materialization lease; the archived identity must no
    /// longer appear among current claims. Implementations must additionally reject every callback
    /// using an archived token even when its transaction row identifier is reused.
    pub fn from_committed_parts(
        request: ExpiredTransferRebuild,
        delivery: DeliverySnapshot,
    ) -> Option<Self> {
        let replacement_attempt = request.successor_artifact();
        let replacement_claims = delivery
            .claims()
            .iter()
            .filter(|claim| {
                claim.artifact_identity()
                    == DeliveryArtifactIdentity::Scheduled(replacement_attempt)
            })
            .collect::<Vec<_>>();
        if delivery.revision() != request.expected_revision().checked_next()?
            || delivery.run_identity() != request.run_identity()
            || delivery.source_reservation_owner() != request.source_reservation_owner()
            || delivery.run_fingerprint() != request.successor_fingerprint()
            || replacement_attempt == request.prior_artifact()
            || delivery.claims().iter().any(|claim| {
                claim.artifact_identity()
                    == DeliveryArtifactIdentity::Scheduled(request.prior_artifact())
            })
            || replacement_claims.len() != 1
            || replacement_claims[0].signer_ownership() != request.signer_ownership()
            || replacement_claims[0].status() != ClaimStatus::Materializing
            || replacement_claims[0].claim_kind() != Some(ClaimKind::Materialization)
            || replacement_claims[0].token().is_none()
        {
            return None;
        }
        Some(Self {
            archived_attempt: request.prior_artifact(),
            replacement_attempt,
            canonical_state: request.successor_state,
            delivery,
        })
    }

    /// Returns the immutable old attempt archived by the rebuild transaction.
    pub const fn archived_attempt(&self) -> ScheduledArtifactIdentity {
        self.archived_attempt
    }

    /// Returns the new generation-safe identity installed under the same transaction row.
    pub const fn replacement_attempt(&self) -> ScheduledArtifactIdentity {
        self.replacement_attempt
    }

    /// Returns the exact canonical state committed by the rebuild transaction.
    pub const fn canonical_state(&self) -> &MigrationState {
        &self.canonical_state
    }

    /// Returns the same-run delivery snapshot and incremented revision committed atomically.
    pub const fn delivery(&self) -> &DeliverySnapshot {
        &self.delivery
    }
}

/// Invalid combination while reconstructing one runtime-consistent delivery snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SnapshotValidationError {
    /// A policy and policy-validation failure cannot both be authoritative.
    ConflictingPolicyState,
    /// A claim is bound to a different policy than the snapshot.
    ClaimPolicyMismatch,
    /// A claim belongs to a different delivery lane than its run.
    ClaimLaneMismatch,
    /// Scheduled delivery cannot carry immediate-only gross-amount authorization.
    UnexpectedImmediateGrossAuthorization,
    /// Finalized exposed storage omitted immutable release evidence needed for future rewind audits.
    MissingFinalityArchive,
    /// Finality evidence was attached before reservation release or without a retained run.
    UnexpectedFinalityArchive,
    /// The archive and storage-finality release horizons disagree.
    FinalityReleaseMismatch,
    /// A delivery snapshot cannot claim that no run exists.
    RunWithoutStorageFinality,
    /// Active or pending-finality storage omitted its live source reservations.
    MissingActiveSourceReservations,
    /// Finalized storage still has live source-reservation rows.
    FinalizedWithLiveSourceReservations,
}

/// Immutable fingerprint of scheduled canonical state or one immediate proposal run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveryRunFingerprint {
    /// Complete canonical scheduled migration-state fingerprint.
    Scheduled(MigrationStateFingerprint),
    /// Exact immediate proposal fingerprint.
    Immediate(ImmediateProposalDigest),
}

impl DeliveryRunFingerprint {
    /// Returns the run's delivery lane.
    pub const fn lane(self) -> DeliveryLane {
        match self {
            Self::Scheduled(_) => DeliveryLane::Scheduled,
            Self::Immediate(_) => DeliveryLane::Immediate,
        }
    }
}

/// One revision-consistent delivery-control view.
#[derive(Clone, PartialEq, Eq)]
pub struct DeliverySnapshot {
    revision: DeliveryRevision,
    run_identity: MigrationRunIdentity,
    run_fingerprint: DeliveryRunFingerprint,
    source_reservation_owner: SourceReservationOwner,
    phase: DeliveryPhase,
    storage_finality: StorageFinality,
    active_source_reservation_count: u64,
    finality_archive: Option<FinalityArchive>,
    submission_policy: Option<SubmissionPolicy>,
    policy_validation_failure: Option<PolicyValidationFailure>,
    /// The user-confirmed ceiling persisted with an immediate run. `None` is valid only as
    /// fail-closed evidence for an immediate row created before gross authorization was required,
    /// or for the scheduled lane where this authority does not apply.
    immediate_maximum_gross_amount: Option<Zatoshis>,
    claims: Vec<DeliveryClaim>,
}

impl DeliverySnapshot {
    fn has_resolved_unmined_exposure(phase: DeliveryPhase, claims: &[DeliveryClaim]) -> bool {
        if phase != DeliveryPhase::Abandoned {
            return false;
        }
        let mut found_exposure = false;
        for claim in claims {
            if claim.lease().is_some() {
                return false;
            }
            if claim.has_exposure_history() {
                if !matches!(
                    claim.status(),
                    ClaimStatus::ExpiredUnmined | ClaimStatus::ExternalSigningExpiredUnmined
                ) {
                    return false;
                }
                found_exposure = true;
            }
        }
        found_exposure
    }

    fn resolved_unmined_release_from_claims(
        phase: DeliveryPhase,
        active_source_reservation_count: u64,
        claims: &[DeliveryClaim],
    ) -> Option<ReservationRelease> {
        if active_source_reservation_count != 0
            || !Self::has_resolved_unmined_exposure(phase, claims)
        {
            return None;
        }
        let mut max_exposed_expiry = None;
        for claim in claims {
            if claim.lease().is_some() {
                return None;
            }
            if claim.has_exposure_history() {
                if !matches!(
                    claim.status(),
                    ClaimStatus::ExpiredUnmined | ClaimStatus::ExternalSigningExpiredUnmined
                ) {
                    return None;
                }
                let expiry = claim.expiry_height();
                if max_exposed_expiry.is_none_or(|prior| expiry > prior) {
                    max_exposed_expiry = Some(expiry);
                }
            }
        }
        max_exposed_expiry.and_then(ReservationRelease::after_resolved_unmined_expiry)
    }

    fn resolved_unmined_release_matches(
        phase: DeliveryPhase,
        storage_finality: StorageFinality,
        active_source_reservation_count: u64,
        claims: &[DeliveryClaim],
    ) -> bool {
        let StorageFinality::Finalized(actual_release) = storage_finality else {
            return false;
        };
        Self::resolved_unmined_release_from_claims(phase, active_source_reservation_count, claims)
            == Some(actual_release)
    }

    /// Reconstructs a snapshot after validating policy authority across all claims.
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        run_fingerprint: DeliveryRunFingerprint,
        source_reservation_owner: SourceReservationOwner,
        phase: DeliveryPhase,
        storage_finality: StorageFinality,
        active_source_reservation_count: u64,
        finality_archive: Option<FinalityArchive>,
        submission_policy: Option<SubmissionPolicy>,
        policy_validation_failure: Option<PolicyValidationFailure>,
        claims: Vec<DeliveryClaim>,
    ) -> Result<Self, SnapshotValidationError> {
        Self::from_parts_with_immediate_gross_authorization(
            revision,
            run_identity,
            run_fingerprint,
            source_reservation_owner,
            phase,
            storage_finality,
            active_source_reservation_count,
            finality_archive,
            submission_policy,
            policy_validation_failure,
            None,
            claims,
        )
    }

    /// Reconstructs a snapshot carrying durable immediate gross-amount authorization.
    ///
    /// Stores use this constructor only after reading the versioned authorization record in the
    /// same atomic view as the immediate proposal. A missing authorization remains representable so
    /// an older row can be projected as unavailable without fabricating user consent.
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts_with_immediate_gross_authorization(
        revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        run_fingerprint: DeliveryRunFingerprint,
        source_reservation_owner: SourceReservationOwner,
        phase: DeliveryPhase,
        storage_finality: StorageFinality,
        active_source_reservation_count: u64,
        finality_archive: Option<FinalityArchive>,
        submission_policy: Option<SubmissionPolicy>,
        policy_validation_failure: Option<PolicyValidationFailure>,
        immediate_maximum_gross_amount: Option<Zatoshis>,
        claims: Vec<DeliveryClaim>,
    ) -> Result<Self, SnapshotValidationError> {
        if submission_policy.is_some() && policy_validation_failure.is_some() {
            return Err(SnapshotValidationError::ConflictingPolicyState);
        }
        if run_fingerprint.lane() == DeliveryLane::Scheduled
            && immediate_maximum_gross_amount.is_some()
        {
            return Err(SnapshotValidationError::UnexpectedImmediateGrossAuthorization);
        }
        if let Some(policy) = submission_policy.as_ref()
            && claims
                .iter()
                .any(|claim| claim.policy_fingerprint() != policy.fingerprint())
        {
            return Err(SnapshotValidationError::ClaimPolicyMismatch);
        }
        if claims
            .iter()
            .any(|claim| claim.lane() != run_fingerprint.lane())
        {
            return Err(SnapshotValidationError::ClaimLaneMismatch);
        }
        let released_without_exposure = phase == DeliveryPhase::Abandoned
            && matches!(storage_finality, StorageFinality::Finalized(_))
            && active_source_reservation_count == 0
            && claims
                .iter()
                .all(|claim| claim.lease().is_none() && !claim.has_exposure_history());
        let released_after_resolved_unmined_exposure = Self::resolved_unmined_release_matches(
            phase,
            storage_finality,
            active_source_reservation_count,
            &claims,
        );
        let recovering_after_resolved_unmined_exposure = matches!(
            storage_finality,
            StorageFinality::RecoveryRequired(StorageRecoveryReason::RewoundBeyondFinalityHorizon)
        ) && Self::has_resolved_unmined_exposure(
            phase, &claims,
        );
        match storage_finality {
            StorageFinality::NoRun => {
                return Err(SnapshotValidationError::RunWithoutStorageFinality);
            }
            StorageFinality::Active | StorageFinality::CompletePendingFinality(_)
                if active_source_reservation_count == 0 =>
            {
                return Err(SnapshotValidationError::MissingActiveSourceReservations);
            }
            StorageFinality::Finalized(_) if active_source_reservation_count != 0 => {
                return Err(SnapshotValidationError::FinalizedWithLiveSourceReservations);
            }
            _ => {}
        }
        match (storage_finality, finality_archive.as_ref()) {
            (StorageFinality::Finalized(release), Some(archive))
                if archive.release() == release => {}
            (StorageFinality::Finalized(_), None)
                if released_without_exposure || released_after_resolved_unmined_exposure => {}
            (
                StorageFinality::RecoveryRequired(
                    StorageRecoveryReason::RewoundBeyondFinalityHorizon,
                ),
                Some(_),
            ) => {}
            (
                StorageFinality::RecoveryRequired(
                    StorageRecoveryReason::RewoundBeyondFinalityHorizon,
                ),
                None,
            ) if recovering_after_resolved_unmined_exposure => {}
            (StorageFinality::Finalized(_), None)
            | (
                StorageFinality::RecoveryRequired(
                    StorageRecoveryReason::RewoundBeyondFinalityHorizon,
                ),
                None,
            ) => return Err(SnapshotValidationError::MissingFinalityArchive),
            (StorageFinality::Finalized(_), Some(_)) => {
                return Err(SnapshotValidationError::FinalityReleaseMismatch);
            }
            (
                StorageFinality::NoRun
                | StorageFinality::Active
                | StorageFinality::CompletePendingFinality(_),
                Some(_),
            ) => return Err(SnapshotValidationError::UnexpectedFinalityArchive),
            (StorageFinality::RecoveryRequired(_), Some(_)) => {}
            (_, None) => {}
        }
        Ok(Self {
            revision,
            run_identity,
            run_fingerprint,
            source_reservation_owner,
            phase,
            storage_finality,
            active_source_reservation_count,
            finality_archive,
            submission_policy,
            policy_validation_failure,
            immediate_maximum_gross_amount,
            claims,
        })
    }

    /// Returns the optimistic-concurrency revision.
    pub const fn revision(&self) -> DeliveryRevision {
        self.revision
    }

    /// Returns the dedicated Rust-generated run identity.
    pub const fn run_identity(&self) -> MigrationRunIdentity {
        self.run_identity
    }

    /// Returns the scheduled canonical or immediate proposal run fingerprint.
    pub const fn run_fingerprint(&self) -> DeliveryRunFingerprint {
        self.run_fingerprint
    }

    /// Returns the run's delivery lane.
    pub const fn lane(&self) -> DeliveryLane {
        self.run_fingerprint.lane()
    }

    /// Returns the dedicated durable source-reservation owner.
    pub const fn source_reservation_owner(&self) -> SourceReservationOwner {
        self.source_reservation_owner
    }

    /// Returns the canonical state fingerprint for the scheduled lane.
    pub const fn state_fingerprint(&self) -> Option<MigrationStateFingerprint> {
        match self.run_fingerprint {
            DeliveryRunFingerprint::Scheduled(fingerprint) => Some(fingerprint),
            DeliveryRunFingerprint::Immediate(_) => None,
        }
    }

    /// Returns the delivery control phase.
    pub const fn phase(&self) -> DeliveryPhase {
        self.phase
    }

    /// Returns source-reservation finality.
    pub const fn storage_finality(&self) -> StorageFinality {
        self.storage_finality
    }

    /// Returns the exact number of live source-reservation rows owned by this run.
    pub const fn active_source_reservation_count(&self) -> u64 {
        self.active_source_reservation_count
    }

    /// Returns immutable finality evidence retained after source-reservation release.
    pub const fn finality_archive(&self) -> Option<&FinalityArchive> {
        self.finality_archive.as_ref()
    }

    /// Returns the validated immutable policy, if bound.
    pub const fn submission_policy(&self) -> Option<&SubmissionPolicy> {
        self.submission_policy.as_ref()
    }

    /// Returns a durable policy-validation failure when no policy is bound.
    pub const fn policy_validation_failure(&self) -> Option<PolicyValidationFailure> {
        self.policy_validation_failure
    }

    /// Returns the durable user-confirmed gross ceiling for an immediate run.
    ///
    /// `None` on an immediate snapshot means the row predates this authority boundary and the
    /// enclosing runtime must remain unavailable. Scheduled runs always return `None`.
    pub const fn immediate_maximum_gross_amount(&self) -> Option<Zatoshis> {
        self.immediate_maximum_gross_amount
    }

    /// Returns exact delivery claims.
    pub fn claims(&self) -> &[DeliveryClaim] {
        &self.claims
    }

    /// Whether an abandoned run released every source without any network or external-signer
    /// exposure, so no finalized-transfer archive is required and the tombstone may be deleted.
    pub fn released_without_exposure(&self) -> bool {
        self.phase == DeliveryPhase::Abandoned
            && matches!(self.storage_finality, StorageFinality::Finalized(_))
            && self.active_source_reservation_count == 0
            && self.finality_archive.is_none()
            && self
                .claims
                .iter()
                .all(|claim| claim.lease().is_none() && !claim.has_exposure_history())
    }

    /// Whether every exposed artifact was positively resolved unmined and sources remained
    /// reserved through the exact expiry-derived reorg horizon before release.
    ///
    /// Stores must fail closed with [`StorageRecoveryReason::RewoundBeyondFinalityHorizon`] if a
    /// later fully scanned height falls below the returned snapshot's release height.
    pub fn released_after_resolved_unmined_exposure(&self) -> bool {
        self.finality_archive.is_none()
            && Self::resolved_unmined_release_matches(
                self.phase,
                self.storage_finality,
                self.active_source_reservation_count,
                &self.claims,
            )
    }

    /// Whether every chain- or external-signer-exposed artifact has resolved to mined or a
    /// positively proved unmined expiry.
    pub fn safe_to_cancel(&self) -> bool {
        self.claims.iter().all(|claim| {
            (!claim.status().is_chain_exposed() && !claim.has_external_signing_exposure())
                || claim.status().is_exposure_terminal()
        })
    }
}

impl fmt::Debug for DeliverySnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeliverySnapshot")
            .field("revision", &self.revision)
            .field("run_identity", &"<redacted>")
            .field("run_fingerprint", &"<redacted>")
            .field("source_reservation_owner", &"<redacted>")
            .field("phase", &self.phase)
            .field("storage_finality", &self.storage_finality.as_str())
            .field(
                "active_source_reservation_count",
                &self.active_source_reservation_count,
            )
            .field(
                "finality_archive",
                &self.finality_archive.as_ref().map(|_| "<redacted>"),
            )
            .field("submission_policy", &self.submission_policy)
            .field("policy_validation_failure", &self.policy_validation_failure)
            .field(
                "immediate_gross_authorization",
                &self.immediate_maximum_gross_amount.map(|_| "<redacted>"),
            )
            .field("claims", &self.claims)
            .field("safe_to_cancel", &self.safe_to_cancel())
            .finish()
    }
}

/// Invalid canonical-plus-delivery evidence for a retained predecessor run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RetainedRunValidationError {
    /// Scheduled canonical state and delivery fingerprint disagree, or an immediate run carried
    /// scheduled canonical state.
    CanonicalDeliveryMismatch,
    /// A retained run cannot claim that no run or source reservation exists.
    MissingStorageFinality,
    /// A retained run omitted destination evidence even though it was not abandoned unexposed.
    MissingDestinationEvidence,
}

/// Exact owning evidence for one retained predecessor run.
///
/// Rollover may replace the current canonical run while predecessor reservations and finality
/// evidence remain authoritative. Keeping the predecessor's canonical state beside its delivery
/// snapshot prevents a successor fingerprint from hiding stale or inconsistent historical state.
#[derive(Clone, PartialEq, Eq)]
pub struct RetainedMigrationRun {
    canonical_state: Option<MigrationState>,
    delivery: DeliverySnapshot,
    destination_spendability: DestinationSpendability,
}

impl fmt::Debug for RetainedMigrationRun {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RetainedMigrationRun")
            .field(
                "canonical_state",
                &self.canonical_state.as_ref().map(|_| "<redacted>"),
            )
            .field("delivery", &self.delivery)
            .field("destination_spendability", &self.destination_spendability)
            .finish()
    }
}

impl RetainedMigrationRun {
    /// Reconstructs one retained run only when its canonical and delivery identities agree.
    pub fn from_observed(
        canonical_state: Option<MigrationState>,
        delivery: DeliverySnapshot,
        destination_spendability: DestinationSpendability,
    ) -> Result<Self, RetainedRunValidationError> {
        let consistent = match (canonical_state.as_ref(), delivery.run_fingerprint()) {
            (Some(state), DeliveryRunFingerprint::Scheduled(fingerprint)) => {
                migration_state_fingerprint(state) == fingerprint
            }
            (None, DeliveryRunFingerprint::Immediate(_)) => true,
            _ => false,
        };
        if !consistent {
            return Err(RetainedRunValidationError::CanonicalDeliveryMismatch);
        }
        if matches!(delivery.storage_finality(), StorageFinality::NoRun) {
            return Err(RetainedRunValidationError::MissingStorageFinality);
        }
        if destination_spendability == DestinationSpendability::NotApplicable
            && !delivery.released_without_exposure()
        {
            return Err(RetainedRunValidationError::MissingDestinationEvidence);
        }
        Ok(Self {
            canonical_state,
            delivery,
            destination_spendability,
        })
    }

    /// Returns exact retained canonical state for a scheduled predecessor.
    pub const fn canonical_state(&self) -> Option<&MigrationState> {
        self.canonical_state.as_ref()
    }

    /// Returns exact retained delivery and source-reservation evidence.
    pub const fn delivery(&self) -> &DeliverySnapshot {
        &self.delivery
    }

    /// Returns destination completion/spendability evidence for this exact predecessor.
    pub const fn destination_spendability(&self) -> DestinationSpendability {
        self.destination_spendability
    }
}

/// One run-scoped result from an atomic account-level finality audit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RunFinalityAudit {
    run_identity: MigrationRunIdentity,
    result: FinalityAuditResult,
}

impl RunFinalityAudit {
    /// Records the audit result for one exact current or retained run.
    pub const fn new(run_identity: MigrationRunIdentity, result: FinalityAuditResult) -> Self {
        Self {
            run_identity,
            result,
        }
    }

    /// Returns the audited run identity.
    pub const fn run_identity(self) -> MigrationRunIdentity {
        self.run_identity
    }

    /// Returns the active-chain audit result.
    pub const fn result(self) -> FinalityAuditResult {
        self.result
    }
}

/// Post-commit capability exposing one immediate proposal and its durable reservation evidence.
///
/// The concrete artifact type is owned by the implementing wallet store, which can therefore keep
/// all constructors private. Implementations must expose it only after the proposal was derived
/// from wallet-owned eligible sources and the source reservations, evidence, policy, run, and
/// materialization claim committed atomically.
pub trait ReservedImmediateArtifact {
    /// Wallet-native note-reference type carried by the derived proposal.
    type NoteRef;

    /// Returns the exact wallet-derived proposal whose sources are already durably reserved.
    fn wallet_proposal(&self) -> &Proposal<StandardFeeRule, Self::NoteRef>;

    /// Returns the owning post-commit delivery snapshot.
    fn snapshot(&self) -> &DeliverySnapshot;

    /// Returns exact proposal evidence only after reservation commit succeeded.
    fn evidence(&self) -> &ImmediateArtifactEvidence;
}

/// One owning, account-scoped canonical-plus-delivery runtime snapshot.
///
/// Construction derives availability and ordinary-spend authorization from the same observed
/// values, including every retained predecessor created by rollover, so callers cannot combine a
/// stale canonical state with newer delivery metadata or hide historical reservations behind the
/// current run.
#[derive(Clone, PartialEq, Eq)]
pub struct MigrationRuntimeSnapshot {
    canonical_state: Option<MigrationState>,
    delivery: Option<DeliverySnapshot>,
    retained_predecessors: Vec<RetainedMigrationRun>,
    schema_provenance: DeliverySchemaProvenance,
    legacy_cutover: LegacyCutoverStatus,
    current_destination_spendability: DestinationSpendability,
    aggregate_destination_spendability: DestinationSpendability,
    aggregate_storage_finality: StorageFinality,
    availability: MigrationRuntimeAvailability,
    ordinary_spend_authorization: OrdinarySpendAuthorization,
    account_deletion_authorization: AccountDeletionAuthorization,
    canonical_mutation_authorization: CanonicalMutationAuthorization,
}

impl fmt::Debug for MigrationRuntimeSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MigrationRuntimeSnapshot")
            .field(
                "canonical_state",
                &self.canonical_state.as_ref().map(|_| "<redacted>"),
            )
            .field("delivery", &self.delivery)
            .field(
                "retained_predecessor_count",
                &self.retained_predecessors.len(),
            )
            .field("retained_predecessors", &"<redacted>")
            .field("schema_provenance", &self.schema_provenance)
            .field("legacy_cutover", &self.legacy_cutover)
            .field(
                "current_destination_spendability",
                &self.current_destination_spendability,
            )
            .field(
                "aggregate_destination_spendability",
                &self.aggregate_destination_spendability,
            )
            .field(
                "aggregate_storage_finality",
                &self.aggregate_storage_finality.as_str(),
            )
            .field("availability", &self.availability)
            .finish()
    }
}

impl MigrationRuntimeSnapshot {
    /// Builds one owning runtime snapshot and derives all fail-closed availability decisions.
    ///
    /// `destination_spendability` describes only the current run and must be
    /// [`DestinationSpendability::NotApplicable`] exactly when both current canonical and delivery
    /// state are absent, or when the current delivery is an abandoned unexposed tombstone that
    /// never produced destination funds. Retained predecessors use the sentinel only for that same
    /// tombstone shape.
    pub fn from_observed(
        canonical_state: Option<MigrationState>,
        delivery: Option<DeliverySnapshot>,
        retained_predecessors: Vec<RetainedMigrationRun>,
        schema_provenance: DeliverySchemaProvenance,
        legacy_cutover: LegacyCutoverStatus,
        destination_spendability: DestinationSpendability,
    ) -> Self {
        let availability = match schema_provenance {
            DeliverySchemaProvenance::Unavailable => MigrationRuntimeAvailability::Unavailable(
                RuntimeUnavailableReason::SchemaUnavailable,
            ),
            DeliverySchemaProvenance::Future(version) => MigrationRuntimeAvailability::Unavailable(
                RuntimeUnavailableReason::FutureSchema(version),
            ),
            DeliverySchemaProvenance::Corrupt => MigrationRuntimeAvailability::Unavailable(
                RuntimeUnavailableReason::CorruptDeliveryState,
            ),
            DeliverySchemaProvenance::Compatible(_) => match legacy_cutover {
                LegacyCutoverStatus::RecoveryRequired(objects) => {
                    MigrationRuntimeAvailability::Unavailable(
                        RuntimeUnavailableReason::LegacyCutoverRecovery(objects),
                    )
                }
                LegacyCutoverStatus::Fresh => {
                    let destination_not_applicable =
                        destination_spendability == DestinationSpendability::NotApplicable;
                    let destination_may_be_absent = canonical_state.is_none() && delivery.is_none()
                        || delivery
                            .as_ref()
                            .is_some_and(DeliverySnapshot::released_without_exposure);
                    let current = if destination_not_applicable != destination_may_be_absent {
                        MigrationRuntimeAvailability::Unavailable(
                            RuntimeUnavailableReason::DeliveryInconsistent,
                        )
                    } else {
                        Self::delivery_availability(canonical_state.as_ref(), delivery.as_ref())
                    };
                    if current != MigrationRuntimeAvailability::Available {
                        current
                    } else {
                        Self::retained_availability(delivery.as_ref(), &retained_predecessors)
                    }
                }
            },
        };
        let current_storage_finality = match delivery.as_ref() {
            Some(snapshot) => snapshot.storage_finality(),
            None if canonical_state.is_none() => StorageFinality::NoRun,
            None => StorageFinality::Active,
        };
        let aggregate_storage_finality = Self::derive_aggregate_storage_finality(
            current_storage_finality,
            &retained_predecessors,
        );
        let aggregate_destination_spendability = Self::derive_aggregate_destination_spendability(
            destination_spendability,
            &retained_predecessors,
        );
        let ordinary_spend_authorization = OrdinarySpendAuthorization::derive(
            availability,
            aggregate_destination_spendability,
            aggregate_storage_finality,
        );
        let unresolved_delivery = delivery
            .as_ref()
            .map(|snapshot| (snapshot.run_identity(), snapshot))
            .into_iter()
            .chain(
                retained_predecessors
                    .iter()
                    .map(|retained| (retained.delivery().run_identity(), retained.delivery())),
            )
            .find(|(_, snapshot)| {
                !matches!(snapshot.storage_finality(), StorageFinality::Finalized(_))
                    || !snapshot.safe_to_cancel()
            });
        let account_deletion_authorization = match (availability, unresolved_delivery) {
            (MigrationRuntimeAvailability::Unavailable(reason), _) => {
                AccountDeletionAuthorization::Blocked(
                    AccountDeletionBlockReason::RuntimeUnavailable(reason),
                )
            }
            (MigrationRuntimeAvailability::Available, Some((run_identity, _))) => {
                AccountDeletionAuthorization::Blocked(
                    AccountDeletionBlockReason::UnresolvedDelivery(run_identity),
                )
            }
            (MigrationRuntimeAvailability::Available, None) => {
                AccountDeletionAuthorization::Allowed
            }
        };
        let mutation_owner = delivery
            .as_ref()
            .filter(|snapshot| !snapshot.released_without_exposure())
            .map(DeliverySnapshot::run_identity)
            .or_else(|| {
                retained_predecessors
                    .iter()
                    .map(RetainedMigrationRun::delivery)
                    .find(|snapshot| !snapshot.released_without_exposure())
                    .map(DeliverySnapshot::run_identity)
            });
        let canonical_mutation_authorization = match (availability, mutation_owner) {
            (MigrationRuntimeAvailability::Unavailable(reason), _) => {
                CanonicalMutationAuthorization::Blocked(
                    CanonicalMutationBlockReason::RuntimeUnavailable(reason),
                )
            }
            (MigrationRuntimeAvailability::Available, None) => {
                CanonicalMutationAuthorization::Allowed
            }
            (MigrationRuntimeAvailability::Available, Some(run_identity)) => {
                CanonicalMutationAuthorization::Blocked(
                    CanonicalMutationBlockReason::DeliveryOwned(run_identity),
                )
            }
        };
        Self {
            canonical_state,
            delivery,
            retained_predecessors,
            schema_provenance,
            legacy_cutover,
            current_destination_spendability: destination_spendability,
            aggregate_destination_spendability,
            aggregate_storage_finality,
            availability,
            ordinary_spend_authorization,
            account_deletion_authorization,
            canonical_mutation_authorization,
        }
    }

    fn delivery_availability(
        canonical_state: Option<&MigrationState>,
        delivery: Option<&DeliverySnapshot>,
    ) -> MigrationRuntimeAvailability {
        let snapshot = match (canonical_state, delivery) {
            (None, None) => return MigrationRuntimeAvailability::Available,
            (Some(state), Some(snapshot))
                if snapshot.run_fingerprint()
                    == DeliveryRunFingerprint::Scheduled(migration_state_fingerprint(state)) =>
            {
                snapshot
            }
            (None, Some(snapshot)) if snapshot.lane() == DeliveryLane::Immediate => snapshot,
            _ => {
                return MigrationRuntimeAvailability::Unavailable(
                    RuntimeUnavailableReason::DeliveryInconsistent,
                );
            }
        };
        if let StorageFinality::RecoveryRequired(reason) = snapshot.storage_finality() {
            return MigrationRuntimeAvailability::Unavailable(
                RuntimeUnavailableReason::FinalityRecovery(reason),
            );
        }
        if snapshot.lane() == DeliveryLane::Immediate
            && snapshot.claims().is_empty()
            && !matches!(
                snapshot.phase(),
                DeliveryPhase::Abandoning | DeliveryPhase::Abandoned
            )
        {
            return MigrationRuntimeAvailability::Unavailable(
                RuntimeUnavailableReason::DeliveryInconsistent,
            );
        }
        if snapshot.lane() == DeliveryLane::Immediate
            && snapshot.immediate_maximum_gross_amount().is_none()
            && snapshot.claims().first().is_some_and(|claim| {
                matches!(
                    claim.status(),
                    ClaimStatus::Materializing
                        | ClaimStatus::MaterializationFailed
                        | ClaimStatus::AwaitingExternalSignature
                        | ClaimStatus::Staged
                )
            })
        {
            return MigrationRuntimeAvailability::Unavailable(
                RuntimeUnavailableReason::MissingSpendAuthorization,
            );
        }
        if snapshot.submission_policy().is_none()
            && !(snapshot.released_without_exposure()
                && snapshot.policy_validation_failure().is_none())
        {
            return MigrationRuntimeAvailability::Unavailable(
                if snapshot.policy_validation_failure().is_some() {
                    RuntimeUnavailableReason::SubmissionPolicyMismatch
                } else {
                    RuntimeUnavailableReason::SubmissionPolicyMissing
                },
            );
        }
        MigrationRuntimeAvailability::Available
    }

    fn retained_availability(
        current: Option<&DeliverySnapshot>,
        retained_predecessors: &[RetainedMigrationRun],
    ) -> MigrationRuntimeAvailability {
        for (index, retained) in retained_predecessors.iter().enumerate() {
            let snapshot = retained.delivery();
            if current.is_some_and(|current| {
                current.run_identity() == snapshot.run_identity()
                    || current.source_reservation_owner() == snapshot.source_reservation_owner()
            }) || retained_predecessors[..index].iter().any(|prior| {
                prior.delivery().run_identity() == snapshot.run_identity()
                    || prior.delivery().source_reservation_owner()
                        == snapshot.source_reservation_owner()
            }) {
                return MigrationRuntimeAvailability::Unavailable(
                    RuntimeUnavailableReason::DeliveryInconsistent,
                );
            }
            if let StorageFinality::RecoveryRequired(reason) = snapshot.storage_finality() {
                return MigrationRuntimeAvailability::Unavailable(
                    RuntimeUnavailableReason::FinalityRecovery(reason),
                );
            }
            if snapshot.submission_policy().is_none()
                && !(snapshot.released_without_exposure()
                    && snapshot.policy_validation_failure().is_none())
            {
                return MigrationRuntimeAvailability::Unavailable(
                    if snapshot.policy_validation_failure().is_some() {
                        RuntimeUnavailableReason::SubmissionPolicyMismatch
                    } else {
                        RuntimeUnavailableReason::SubmissionPolicyMissing
                    },
                );
            }
        }
        MigrationRuntimeAvailability::Available
    }

    fn derive_aggregate_storage_finality(
        current: StorageFinality,
        retained_predecessors: &[RetainedMigrationRun],
    ) -> StorageFinality {
        let mut recovery = None;
        let mut active = false;
        let mut pending = false;
        let mut release_height = None;

        for finality in core::iter::once(current).chain(
            retained_predecessors
                .iter()
                .map(|retained| retained.delivery().storage_finality()),
        ) {
            match finality {
                StorageFinality::RecoveryRequired(reason) => {
                    recovery.get_or_insert(reason);
                }
                StorageFinality::Active => active = true,
                StorageFinality::CompletePendingFinality(release) => {
                    pending = true;
                    let height = release.release_at();
                    if release_height.is_none_or(|prior| u32::from(height) > u32::from(prior)) {
                        release_height = Some(height);
                    }
                }
                StorageFinality::Finalized(release) => {
                    let height = release.release_at();
                    if release_height.is_none_or(|prior| u32::from(height) > u32::from(prior)) {
                        release_height = Some(height);
                    }
                }
                StorageFinality::NoRun => {}
            }
        }

        if let Some(reason) = recovery {
            StorageFinality::RecoveryRequired(reason)
        } else if active {
            StorageFinality::Active
        } else if pending {
            StorageFinality::CompletePendingFinality(ReservationRelease::at(
                release_height.expect("pending finality always carries a release height"),
            ))
        } else if let Some(release_height) = release_height {
            StorageFinality::Finalized(ReservationRelease::at(release_height))
        } else {
            StorageFinality::NoRun
        }
    }

    fn derive_aggregate_destination_spendability(
        current: DestinationSpendability,
        retained_predecessors: &[RetainedMigrationRun],
    ) -> DestinationSpendability {
        retained_predecessors
            .iter()
            .map(RetainedMigrationRun::destination_spendability)
            .fold(current, |aggregate, predecessor| {
                match (aggregate, predecessor) {
                    (DestinationSpendability::NotApplicable, value)
                    | (value, DestinationSpendability::NotApplicable) => value,
                    (DestinationSpendability::NotSpendable, _)
                    | (_, DestinationSpendability::NotSpendable) => {
                        DestinationSpendability::NotSpendable
                    }
                    (DestinationSpendability::Spendable, _)
                    | (_, DestinationSpendability::Spendable) => DestinationSpendability::Spendable,
                    (
                        DestinationSpendability::AlreadySpent,
                        DestinationSpendability::AlreadySpent,
                    ) => DestinationSpendability::AlreadySpent,
                }
            })
    }

    /// Returns owned canonical state for a scheduled run.
    pub const fn canonical_state(&self) -> Option<&MigrationState> {
        self.canonical_state.as_ref()
    }

    /// Returns owned delivery metadata for an active or retained run.
    pub const fn delivery(&self) -> Option<&DeliverySnapshot> {
        self.delivery.as_ref()
    }

    /// Returns every predecessor run whose source reservations or finality archive remain
    /// authoritative after rollover.
    pub fn retained_predecessors(&self) -> &[RetainedMigrationRun] {
        &self.retained_predecessors
    }

    /// Returns the most restrictive finality across the current run and all retained predecessors.
    pub const fn aggregate_storage_finality(&self) -> StorageFinality {
        self.aggregate_storage_finality
    }

    /// Whether every current and retained delivery artifact is safe to abandon.
    pub fn safe_to_cancel(&self) -> bool {
        self.delivery
            .as_ref()
            .is_none_or(DeliverySnapshot::safe_to_cancel)
            && self
                .retained_predecessors
                .iter()
                .all(|retained| retained.delivery().safe_to_cancel())
    }

    /// Returns exact delivery-schema provenance.
    pub const fn schema_provenance(&self) -> DeliverySchemaProvenance {
        self.schema_provenance
    }

    /// Returns the retired-engine cutover disposition.
    pub const fn legacy_cutover(&self) -> LegacyCutoverStatus {
        self.legacy_cutover
    }

    /// Returns destination completion/spendability evidence for the current run only.
    pub const fn current_destination_spendability(&self) -> DestinationSpendability {
        self.current_destination_spendability
    }

    /// Returns the most restrictive destination completion/spendability evidence across the
    /// current run and every retained predecessor.
    pub const fn destination_spendability(&self) -> DestinationSpendability {
        self.aggregate_destination_spendability
    }

    /// Returns authoritative runtime availability.
    pub const fn availability(&self) -> MigrationRuntimeAvailability {
        self.availability
    }

    /// Returns authoritative ordinary-spend authorization derived from this same snapshot.
    pub const fn ordinary_spend_authorization(&self) -> OrdinarySpendAuthorization {
        self.ordinary_spend_authorization
    }

    /// Returns the account-deletion gate derived from this same owning snapshot.
    pub const fn account_deletion_authorization(&self) -> AccountDeletionAuthorization {
        self.account_deletion_authorization
    }

    /// Returns the generic canonical-mutation gate derived from this same owning snapshot.
    pub const fn canonical_mutation_authorization(&self) -> CanonicalMutationAuthorization {
        self.canonical_mutation_authorization
    }
}

/// One account identity paired with its owning migration runtime snapshot.
#[derive(Clone, PartialEq, Eq)]
pub struct AccountMigrationRuntime<AccountId> {
    account_id: AccountId,
    runtime: MigrationRuntimeSnapshot,
}

impl<AccountId> fmt::Debug for AccountMigrationRuntime<AccountId> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccountMigrationRuntime")
            .field("account_id", &"<redacted>")
            .field("runtime", &self.runtime)
            .finish()
    }
}

impl<AccountId> AccountMigrationRuntime<AccountId> {
    /// Pairs a backend's semantic account identity with one owning runtime snapshot.
    pub const fn new(account_id: AccountId, runtime: MigrationRuntimeSnapshot) -> Self {
        Self {
            account_id,
            runtime,
        }
    }

    /// Returns the semantic account identity.
    pub const fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    /// Returns the owning account runtime.
    pub const fn runtime(&self) -> &MigrationRuntimeSnapshot {
        &self.runtime
    }
}

/// Error returned when an all-account runtime batch contains duplicate account identities.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RuntimeBatchValidationError {
    /// More than one runtime was supplied for the same account.
    DuplicateAccount,
}

/// One revision-consistent all-account migration runtime batch.
#[derive(Clone, PartialEq, Eq)]
pub struct MigrationRuntimeBatch<AccountId> {
    accounts: Vec<AccountMigrationRuntime<AccountId>>,
}

impl<AccountId> fmt::Debug for MigrationRuntimeBatch<AccountId> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MigrationRuntimeBatch")
            .field("account_count", &self.accounts.len())
            .field("accounts", &"<redacted>")
            .finish()
    }
}

impl<AccountId: Eq> MigrationRuntimeBatch<AccountId> {
    fn from_atomic_store_read(
        accounts: Vec<AccountMigrationRuntime<AccountId>>,
    ) -> Result<Self, RuntimeBatchValidationError> {
        for (index, account) in accounts.iter().enumerate() {
            if accounts[..index]
                .iter()
                .any(|prior| prior.account_id() == account.account_id())
            {
                return Err(RuntimeBatchValidationError::DuplicateAccount);
            }
        }
        Ok(Self { accounts })
    }

    /// Returns one owning runtime per account.
    pub fn accounts(&self) -> &[AccountMigrationRuntime<AccountId>] {
        &self.accounts
    }
}

/// Failure while producing an atomic all-account runtime batch.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RuntimeBatchReadError<StoreError> {
    /// The owning wallet store failed its atomic read.
    Store(StoreError),
    /// The store returned more than one owning runtime for an account.
    Invalid(RuntimeBatchValidationError),
}

/// Production integration for account-scoped migration authority and mutation gates.
///
/// Implementations must obtain canonical state, delivery state, source reservations, schema
/// provenance, cutover evidence, destination spendability, and chain evidence from one atomic
/// store view. Ordinary transaction proposal, account deletion, and generic canonical migration
/// mutation paths must consume the corresponding authorization returned here; they must not
/// rederive a weaker decision from individual tables.
pub trait MigrationRuntimeStore {
    /// Wallet-store or chain-view failure surfaced by an atomic runtime operation.
    type Error;
    /// Semantic wallet account identity.
    type AccountId: Eq;

    /// Store implementation hook for one atomic owning runtime read.
    #[doc(hidden)]
    fn load_account_migration_runtime_atomically(
        &mut self,
        account_id: &Self::AccountId,
    ) -> Result<Option<AccountMigrationRuntime<Self::AccountId>>, Self::Error>;

    /// Store implementation hook for one atomic all-account owning runtime read.
    #[doc(hidden)]
    fn load_all_account_migration_runtimes_atomically(
        &mut self,
    ) -> Result<Vec<AccountMigrationRuntime<Self::AccountId>>, Self::Error>;

    /// Returns one owning runtime from an atomic store read.
    fn account_migration_runtime(
        &mut self,
        account_id: &Self::AccountId,
    ) -> Result<Option<AccountMigrationRuntime<Self::AccountId>>, Self::Error> {
        self.load_account_migration_runtime_atomically(account_id)
    }

    /// Returns exactly one owning runtime per account from one atomic store read.
    fn all_account_migration_runtimes(
        &mut self,
    ) -> Result<MigrationRuntimeBatch<Self::AccountId>, RuntimeBatchReadError<Self::Error>> {
        MigrationRuntimeBatch::from_atomic_store_read(
            self.load_all_account_migration_runtimes_atomically()
                .map_err(RuntimeBatchReadError::Store)?,
        )
        .map_err(RuntimeBatchReadError::Invalid)
    }

    /// Returns the production ordinary-spend gate for an account.
    fn authorize_ordinary_spend(
        &mut self,
        account_id: &Self::AccountId,
    ) -> Result<Option<OrdinarySpendAuthorization>, Self::Error> {
        Ok(self
            .load_account_migration_runtime_atomically(account_id)?
            .map(|account| account.runtime().ordinary_spend_authorization()))
    }

    /// Returns the production account-deletion gate for an account.
    fn authorize_account_deletion(
        &mut self,
        account_id: &Self::AccountId,
    ) -> Result<Option<AccountDeletionAuthorization>, Self::Error> {
        Ok(self
            .load_account_migration_runtime_atomically(account_id)?
            .map(|account| account.runtime().account_deletion_authorization()))
    }

    /// Returns the production gate for generic canonical migration mutations.
    fn authorize_canonical_migration_mutation(
        &mut self,
        account_id: &Self::AccountId,
    ) -> Result<Option<CanonicalMutationAuthorization>, Self::Error> {
        Ok(self
            .load_account_migration_runtime_atomically(account_id)?
            .map(|account| account.runtime().canonical_mutation_authorization()))
    }

    /// Audits every current and retained predecessor finality archive or resolved-unmined release
    /// horizon against one revision-consistent active-chain view.
    ///
    /// The result must contain one entry for every run whose finality evidence remains retained.
    /// A run satisfying [`DeliverySnapshot::released_after_resolved_unmined_exposure`] has no mined
    /// transfer archive, but must still return recovery if the fully scanned height is below its
    /// expiry-derived release horizon. Omitting a predecessor is a store error and must fail closed.
    fn audit_finality_archives(
        &mut self,
        account_id: &Self::AccountId,
    ) -> Result<Vec<RunFinalityAudit>, Self::Error>;

    /// Atomically CAS-replaces one terminal run while retaining predecessor evidence and any
    /// source reservations that have not yet reached their release transition.
    ///
    /// The exact canonical successor state carried by `request`, its store-derived fingerprint,
    /// the successor run, successor owner, and returned receipt must commit together with durable
    /// predecessor canonical, delivery, reservation, and finality evidence. A stale revision, run
    /// identity, or owner fails without any write. Predecessor reservations remain until each
    /// predecessor reaches an explicit safe release transition; generic canonical mutation APIs
    /// must not bypass this operation. This operation is never used to rebuild one transaction
    /// attempt within a live run.
    fn rollover_source_reservations(
        &mut self,
        account_id: &Self::AccountId,
        request: ReservationRollover,
        policy: &SubmissionPolicy,
    ) -> Result<ReservationRolloverReceipt, Self::Error>;

    /// Atomically rebuilds one positively expired scheduled transfer within its existing run.
    ///
    /// The run identity and source-reservation owner must remain byte-for-byte unchanged. The store
    /// proves the old attempt is positively expired/unmined and every reserved source remains
    /// unspent from its own revision-consistent chain view, archives the exact old PCZT,
    /// transaction/outcome evidence, expiry, and generation-safe attempt fingerprint, then commits
    /// the canonical successor, replacement claim, and fresh Rust-generated materialization token
    /// in one CAS. Late callbacks carrying an archived token or attempt fingerprint must fail even
    /// though the canonical transaction row identifier is reused.
    fn rebuild_expired_transfer_attempt(
        &mut self,
        account_id: &Self::AccountId,
        request: ExpiredTransferRebuild,
        policy: &SubmissionPolicy,
    ) -> Result<ExpiredTransferRebuildReceipt, Self::Error>;
}

/// Crash-safe pre-exposure delivery for an immediate proposal that has no canonical
/// [`MigrationState`].
///
/// Implementations operate over a wallet-wide store. Every post-reservation operation is therefore
/// account-scoped and must reject a run, artifact, or claim handle owned by another account.
pub trait ImmediateMigrationDeliveryStore {
    /// Wallet-store, proposal, or chain-view failure surfaced by an immediate operation.
    type Error;
    /// Semantic wallet account identity selected by an immediate intent.
    type AccountId;
    /// Wallet-native note-reference type carried by the authoritative proposal.
    type NoteRef;
    /// Store-owned post-commit artifact whose constructors are private to that implementation.
    type ReservedArtifact: ReservedImmediateArtifact<NoteRef = Self::NoteRef>;

    /// Atomically reserves exact source notes, creates Rust-owned run/artifact/owner identities,
    /// binds policy and proposal evidence, and acquires the initial materialization lease.
    ///
    /// The store must derive a one-step send-max proposal from currently eligible Orchard sources,
    /// the account's own Ironwood receiver, its current target height, no prior-step dependencies,
    /// and the transaction builder's expiry. Within that same atomic wallet view it must derive the
    /// proposal's gross Orchard input value and reject it when it exceeds
    /// [`ImmediateMigrationIntent::maximum_gross_amount`]. It must revalidate those invariants and
    /// apply every source reservation and delivery write or none of them. Proposal evidence must
    /// not be exposed before commit; after an error no immediate run or source reservation may
    /// persist. The store samples its own monotonic clock; no caller-authored `now` value
    /// participates in authority.
    fn reserve_immediate_delivery(
        &mut self,
        intent: ImmediateMigrationIntent<Self::AccountId>,
        policy: &SubmissionPolicy,
        lease_duration: LeaseDuration,
    ) -> Result<Self::ReservedArtifact, Self::Error>;

    /// Atomically reconciles expired immediate leases and returns one owning runtime snapshot.
    ///
    /// For externally exposed PCZT evidence with no exact transaction, reconciliation may move to
    /// [`ClaimStatus::ExternalSigningExpiredUnmined`] only after the fully scanned active-chain
    /// height is strictly greater than the immutable PCZT expiry and every reserved source is
    /// positively unspent. Any spent source or ambiguous/unavailable source evidence must retain
    /// all evidence and reservations under
    /// [`StorageRecoveryReason::ExternalSigningExposureUnresolved`]. Mining must never be inferred
    /// without exact transaction bytes.
    fn immediate_runtime_snapshot(
        &mut self,
        account_id: &Self::AccountId,
    ) -> Result<MigrationRuntimeSnapshot, Self::Error>;

    /// Atomically reacquires bounded materialization authority for the same unexposed immediate
    /// artifact after a known-unsent materialization failure.
    ///
    /// The store must require the exact account, run, artifact, signer, and policy; an active run;
    /// [`ClaimStatus::MaterializationFailed`] with no lease; and no external-signing, signed-PCZT,
    /// exact-transaction, transaction-id, or chain-exposure history. It must re-derive the gross
    /// Orchard input amount from the persisted canonical proposal and reject reacquisition when it
    /// exceeds `maximum_gross_amount`. It generates a fresh token while preserving proposal
    /// evidence, source reservations, and every stable identity. It must never derive or reserve a
    /// replacement proposal. When the legacy row did not already carry durable gross-spend
    /// authorization, persisting that authorization, changing the claim, and advancing the
    /// revision are one all-or-none transaction: any error must leave all three unchanged.
    #[allow(clippy::too_many_arguments)]
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
    ) -> Result<DeliverySnapshot, Self::Error>;

    /// Atomically reacquires materialization capability for the same externally staged immediate
    /// artifact after its prior lease expired or its clock session became invalid.
    ///
    /// The store generates a fresh token and must preserve the exact staged PCZT, artifact
    /// identity, proposal evidence, source reservations, and signer ownership. This operation must
    /// reject any terminal expiry or recovery state and must never derive or reserve a replacement
    /// proposal.
    #[allow(clippy::too_many_arguments)]
    fn reacquire_immediate_external_signing(
        &mut self,
        account_id: &Self::AccountId,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        artifact_identity: ImmediateArtifactIdentity,
        lease_duration: LeaseDuration,
        expected_policy_fingerprint: PolicyFingerprint,
    ) -> Result<Option<DeliverySnapshot>, Self::Error>;

    /// Atomically stages exact PCZT bytes before exposing them to an external signer.
    #[allow(clippy::too_many_arguments)]
    fn stage_immediate_external_signing_pczt(
        &mut self,
        account_id: &Self::AccountId,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        artifact_identity: ImmediateArtifactIdentity,
        token: ClaimToken,
        pczt: &ExternalSigningPczt,
        expected_policy_fingerprint: PolicyFingerprint,
    ) -> Result<DeliverySnapshot, Self::Error>;

    /// Atomically stages a canonical signer merge bound to the previously staged exact PCZT.
    #[allow(clippy::too_many_arguments)]
    fn stage_immediate_signed_pczt(
        &mut self,
        account_id: &Self::AccountId,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        artifact_identity: ImmediateArtifactIdentity,
        token: ClaimToken,
        signed_pczt: &SignedPcztEvidence,
        expected_policy_fingerprint: PolicyFingerprint,
    ) -> Result<DeliverySnapshot, Self::Error>;

    /// Atomically stages exact network transaction bytes under materialization capability.
    #[allow(clippy::too_many_arguments)]
    fn stage_immediate_transaction(
        &mut self,
        account_id: &Self::AccountId,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        token: ClaimToken,
        artifact: &ExactTransaction,
        expected_policy_fingerprint: PolicyFingerprint,
    ) -> Result<DeliverySnapshot, Self::Error>;

    /// Atomically acquires one-shot submission capability for an immediate exact transaction.
    #[allow(clippy::too_many_arguments)]
    fn claim_immediate_submission(
        &mut self,
        account_id: &Self::AccountId,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        artifact_identity: ImmediateArtifactIdentity,
        lease_duration: LeaseDuration,
        expected_policy_fingerprint: PolicyFingerprint,
    ) -> Result<Option<DeliverySnapshot>, Self::Error>;

    /// Atomically acquires resolution-only capability for an outcome-unknown or broadcasted
    /// immediate artifact requiring chain reconciliation.
    #[allow(clippy::too_many_arguments)]
    fn claim_immediate_outcome_resolution(
        &mut self,
        account_id: &Self::AccountId,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        artifact_identity: ImmediateArtifactIdentity,
        lease_duration: LeaseDuration,
        expected_policy_fingerprint: PolicyFingerprint,
    ) -> Result<Option<DeliverySnapshot>, Self::Error>;

    /// Resumes an exact live immediate claim by echoing its Rust-generated token.
    #[allow(clippy::too_many_arguments)]
    fn resume_immediate_claim(
        &mut self,
        account_id: &Self::AccountId,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        artifact_identity: ImmediateArtifactIdentity,
        token: ClaimToken,
        expected_policy_fingerprint: PolicyFingerprint,
    ) -> Result<Option<DeliverySnapshot>, Self::Error>;

    /// Atomically renews a live immediate claim in the current clock session.
    #[allow(clippy::too_many_arguments)]
    fn renew_immediate_claim(
        &mut self,
        account_id: &Self::AccountId,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        artifact_identity: ImmediateArtifactIdentity,
        token: ClaimToken,
        lease_duration: LeaseDuration,
        expected_policy_fingerprint: PolicyFingerprint,
    ) -> Result<Option<DeliverySnapshot>, Self::Error>;

    /// Atomically records one immediate transport outcome.
    #[allow(clippy::too_many_arguments)]
    fn record_immediate_submission_outcome(
        &mut self,
        account_id: &Self::AccountId,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        artifact_identity: ImmediateArtifactIdentity,
        token: ClaimToken,
        outcome: SubmissionOutcome,
        expected_policy_fingerprint: PolicyFingerprint,
    ) -> Result<DeliverySnapshot, Self::Error>;

    /// Resolves immediate chain evidence without any resubmission capability.
    #[allow(clippy::too_many_arguments)]
    fn reconcile_immediate_submission(
        &mut self,
        account_id: &Self::AccountId,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        artifact_identity: ImmediateArtifactIdentity,
        token: ClaimToken,
    ) -> Result<DeliverySnapshot, Self::Error>;

    /// Releases an immediate claim only when exact bytes are known not to have reached transport.
    #[allow(clippy::too_many_arguments)]
    fn release_immediate_claim_known_unsent(
        &mut self,
        account_id: &Self::AccountId,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        artifact_identity: ImmediateArtifactIdentity,
        token: ClaimToken,
        reason: DeliveryFailureReason,
        expected_policy_fingerprint: PolicyFingerprint,
    ) -> Result<DeliverySnapshot, Self::Error>;

    /// Atomically pauses an immediate run without releasing source reservations.
    fn pause_immediate_delivery(
        &mut self,
        account_id: &Self::AccountId,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
    ) -> Result<DeliverySnapshot, Self::Error>;

    /// Atomically resumes a paused immediate run.
    fn resume_immediate_delivery(
        &mut self,
        account_id: &Self::AccountId,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
    ) -> Result<DeliverySnapshot, Self::Error>;

    /// Atomically begins immediate abandonment without releasing ambiguous artifacts.
    fn begin_immediate_abandonment(
        &mut self,
        account_id: &Self::AccountId,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
    ) -> Result<DeliverySnapshot, Self::Error>;

    /// Atomically finishes immediate abandonment and releases exact reservations only when safe.
    fn finish_immediate_abandonment(
        &mut self,
        account_id: &Self::AccountId,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
    ) -> Result<DeliverySnapshot, Self::Error>;
}

/// Crash-safe delivery metadata layered over a canonical migration store.
pub trait MigrationDeliveryStore: PoolMigrationRead {
    /// Returns exact delivery-schema provenance.
    fn delivery_schema_provenance(&self) -> Result<DeliverySchemaProvenance, Self::Error>;

    /// Returns the one-time retired-engine cutover disposition.
    fn legacy_cutover_status(&self) -> Result<LegacyCutoverStatus, Self::Error>;

    /// Atomically reconciles expired leases using store-owned time and returns one consistent view.
    ///
    /// For externally exposed PCZT evidence with no exact transaction, reconciliation may move to
    /// [`ClaimStatus::ExternalSigningExpiredUnmined`] only after the fully scanned active-chain
    /// height is strictly greater than the immutable PCZT expiry and every reserved source is
    /// positively unspent. Any spent source or ambiguous/unavailable source evidence must retain
    /// all evidence and reservations under
    /// [`StorageRecoveryReason::ExternalSigningExposureUnresolved`]. Mining must never be inferred
    /// without exact transaction bytes.
    fn delivery_snapshot(&mut self) -> Result<Option<DeliverySnapshot>, Self::Error>;

    /// Atomically binds an immutable validated policy to the expected canonical revision.
    fn bind_submission_policy(
        &mut self,
        expected_state: &MigrationState,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        policy: &SubmissionPolicy,
    ) -> Result<DeliverySnapshot, Self::Error>;

    /// Atomically records a typed policy-validation failure for the expected revision.
    fn record_policy_validation_failure(
        &mut self,
        expected_state: &MigrationState,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        failure: PolicyValidationFailure,
    ) -> Result<DeliverySnapshot, Self::Error>;

    /// Atomically acquires materialization capability for exact source evidence.
    ///
    /// When the exact matching artifact is already [`ClaimStatus::AwaitingExternalSignature`] and
    /// its prior lease is absent or invalid, this operation reacquires a fresh Rust-generated
    /// materialization token without replacing its staged PCZT or any source evidence.
    #[allow(clippy::too_many_arguments)]
    fn claim_materialization(
        &mut self,
        expected_state: &MigrationState,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        evidence: &DeliveryArtifactEvidence,
        signer_ownership: SignerOwnership,
        lease_duration: LeaseDuration,
        expected_policy_fingerprint: PolicyFingerprint,
    ) -> Result<Option<DeliverySnapshot>, Self::Error>;

    /// Atomically stages exact PCZT bytes before exposing them to an external signer.
    #[allow(clippy::too_many_arguments)]
    fn stage_external_signing_pczt(
        &mut self,
        expected_state: &MigrationState,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        artifact_identity: DeliveryArtifactIdentity,
        token: ClaimToken,
        pczt: &ExternalSigningPczt,
        expected_policy_fingerprint: PolicyFingerprint,
    ) -> Result<DeliverySnapshot, Self::Error>;

    /// Atomically stages canonical signer-merge evidence bound to the exact staged PCZT.
    #[allow(clippy::too_many_arguments)]
    fn stage_signed_pczt(
        &mut self,
        expected_state: &MigrationState,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        artifact_identity: DeliveryArtifactIdentity,
        token: ClaimToken,
        signed_pczt: &SignedPcztEvidence,
        expected_policy_fingerprint: PolicyFingerprint,
    ) -> Result<DeliverySnapshot, Self::Error>;

    /// Atomically applies one sealed, delivery-authorized canonical signing or proving transition.
    ///
    /// The store must load and match the exact expected canonical fingerprint, delivery revision,
    /// run, scheduled artifact, live materialization token/kind, and policy. It must independently
    /// revalidate the narrow transition against the loaded state. For
    /// [`CanonicalMaterializationPurpose::ExternalSignature`], the successor target PCZT must equal
    /// the already staged [`SignedPcztEvidence`] bytes. For
    /// [`CanonicalMaterializationPurpose::Proof`], the successor target must yield exact consensus
    /// transaction bytes with matching artifact/expiry evidence. Canonical successor state,
    /// delivery fingerprint, and incremented revision commit together or not at all. Replayed,
    /// stale, wrong-artifact, cross-run, or over-broad requests must not write.
    fn advance_canonical_materialization(
        &mut self,
        request: CanonicalMaterializationTransition,
    ) -> Result<CanonicalMaterializationReceipt, Self::Error>;

    /// Atomically acquires the one-shot submission capability for staged exact bytes.
    #[allow(clippy::too_many_arguments)]
    fn claim_submission(
        &mut self,
        expected_state: &MigrationState,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        artifact_identity: DeliveryArtifactIdentity,
        lease_duration: LeaseDuration,
        expected_policy_fingerprint: PolicyFingerprint,
    ) -> Result<Option<DeliverySnapshot>, Self::Error>;

    /// Atomically acquires resolution-only capability for an outcome-unknown or broadcasted
    /// artifact requiring chain reconciliation.
    #[allow(clippy::too_many_arguments)]
    fn claim_outcome_resolution(
        &mut self,
        expected_state: &MigrationState,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        artifact_identity: DeliveryArtifactIdentity,
        lease_duration: LeaseDuration,
        expected_policy_fingerprint: PolicyFingerprint,
    ) -> Result<Option<DeliverySnapshot>, Self::Error>;

    /// Resumes an exact live claim by echoing its Rust-generated token.
    #[allow(clippy::too_many_arguments)]
    fn resume_claim(
        &mut self,
        expected_state: &MigrationState,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        artifact_identity: DeliveryArtifactIdentity,
        token: ClaimToken,
        expected_policy_fingerprint: PolicyFingerprint,
    ) -> Result<Option<DeliverySnapshot>, Self::Error>;

    /// Atomically renews a live claim without changing its token or capability kind.
    #[allow(clippy::too_many_arguments)]
    fn renew_claim(
        &mut self,
        expected_state: &MigrationState,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        artifact_identity: DeliveryArtifactIdentity,
        token: ClaimToken,
        lease_duration: LeaseDuration,
        expected_policy_fingerprint: PolicyFingerprint,
    ) -> Result<Option<DeliverySnapshot>, Self::Error>;

    /// Atomically records the result of one submission attempt.
    ///
    /// `Accepted` must also advance the exact scheduled canonical artifact from `Proved` to
    /// `Broadcast` with the staged exact transaction's txid in the same CAS. Known-unsent and
    /// outcome-unknown results must not claim a canonical broadcast.
    #[allow(clippy::too_many_arguments)]
    fn record_submission_outcome(
        &mut self,
        expected_state: &MigrationState,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        artifact_identity: DeliveryArtifactIdentity,
        token: ClaimToken,
        outcome: SubmissionOutcome,
        expected_policy_fingerprint: PolicyFingerprint,
    ) -> Result<CanonicalDeliveryReceipt, Self::Error>;

    /// Atomically resolves chain evidence under an outcome-resolution claim without resubmission.
    ///
    /// Positive mining evidence must also advance the exact scheduled canonical artifact to
    /// `Mined` in the same CAS. Without exact bytes/txid, mining must never be inferred.
    #[allow(clippy::too_many_arguments)]
    fn reconcile_submission(
        &mut self,
        expected_state: &MigrationState,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        artifact_identity: DeliveryArtifactIdentity,
        token: ClaimToken,
    ) -> Result<CanonicalDeliveryReceipt, Self::Error>;

    /// Atomically reconciles every exact scheduled claim and canonical lifecycle against one
    /// store-owned fully-scanned active-chain view.
    ///
    /// Callers provide only stale-detection authority; they cannot supply a lifecycle state,
    /// transaction id, mined height, expiry result, or reservation disposition. The store derives
    /// those from retained exact bytes and active-chain evidence. It must support Proved/Broadcast
    /// -> Mined, Mined -> Broadcast after a reorg using the retained exact txid, and Mined(height A)
    /// -> Mined(height B) after re-mining. Reorg transitions must atomically reacquire/retain source
    /// reservations and roll finality back; ambiguous evidence enters recovery. `None` means the
    /// authoritative view required no write.
    fn reconcile_canonical_chain(
        &mut self,
        expected_state: &MigrationState,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
    ) -> Result<Option<CanonicalDeliveryReceipt>, Self::Error>;

    /// Atomically releases a claim only when exact bytes are known not to have reached transport.
    #[allow(clippy::too_many_arguments)]
    fn release_claim_known_unsent(
        &mut self,
        expected_state: &MigrationState,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
        artifact_identity: DeliveryArtifactIdentity,
        token: ClaimToken,
        reason: DeliveryFailureReason,
        expected_policy_fingerprint: PolicyFingerprint,
    ) -> Result<DeliverySnapshot, Self::Error>;

    /// Atomically prevents new claims while retaining all exact exposed evidence.
    fn pause_delivery(
        &mut self,
        expected_state: &MigrationState,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
    ) -> Result<DeliverySnapshot, Self::Error>;

    /// Atomically restores claim acquisition for a paused run.
    fn resume_delivery(
        &mut self,
        expected_state: &MigrationState,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
    ) -> Result<DeliverySnapshot, Self::Error>;

    /// Atomically begins abandonment without releasing possibly exposed artifacts.
    fn begin_abandonment(
        &mut self,
        expected_state: &MigrationState,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
    ) -> Result<DeliverySnapshot, Self::Error>;

    /// Atomically finishes abandonment after every exposed artifact is resolved.
    fn finish_abandonment(
        &mut self,
        expected_state: &MigrationState,
        expected_revision: DeliveryRevision,
        run_identity: MigrationRunIdentity,
    ) -> Result<DeliverySnapshot, Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use zcash_protocol::consensus::Network;

    const TEST_INSTANT_MILLIS: u64 = 1_000;
    const TEST_LEASE_MILLIS: u64 = 500;
    const TEST_RELEASE_HEIGHT: u32 = 2_000;
    const TEST_REVISION: u64 = 42;
    const TEST_CLOCK_SESSION_BYTE: u8 = 3;
    const OTHER_CLOCK_SESSION_BYTE: u8 = 4;
    const TEST_TOKEN_BYTE: u8 = 7;
    const TEST_FINGERPRINT_BYTE: u8 = 9;
    const TEST_ARTIFACT_BYTE: u8 = 11;
    const TEST_TXID_BYTE: u8 = 13;
    const TEST_TRANSACTION_BYTE: u8 = 15;
    const UNKNOWN_CODEC_TAG: u8 = u8::MAX;
    const TEST_ONION_LABEL: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn clock_session(byte: u8) -> LeaseClockSession {
        LeaseClockSession::from_stored([byte; DIGEST_LENGTH])
    }

    fn test_instant(tick_millis: u64) -> MonotonicLeaseInstant {
        MonotonicLeaseInstant::new(clock_session(TEST_CLOCK_SESSION_BYTE), tick_millis)
    }

    fn test_context() -> SubmissionContext {
        SubmissionContext::from_parameters(&Network::TestNetwork)
    }

    fn direct_transport() -> SubmissionTransport {
        SubmissionTransport::DirectTls(
            DirectTlsEndpoint::try_from("https://lightwalletd.example:9067".to_string()).unwrap(),
        )
    }

    fn validated_policy() -> SubmissionPolicy {
        let context = test_context();
        SubmissionPolicy::validate(
            SubmissionPolicyRequest::new(context, direct_transport()),
            context,
        )
        .unwrap()
    }

    fn immediate_proposal(payload: Vec<u8>) -> ImmediateProposal {
        ImmediateProposal::new(
            BlockHeight::from_u32(TEST_RELEASE_HEIGHT - DEFAULT_TX_EXPIRY_DELTA),
            BlockHeight::from_u32(TEST_RELEASE_HEIGHT),
            BranchId::Nu6_3,
            ImmediateProposalPayload::try_from(payload).unwrap(),
        )
        .unwrap()
    }

    fn external_signing_pczt() -> (Vec<u8>, ExternalSigningPczt) {
        use pczt::roles::creator::Creator;
        use zcash_protocol::consensus::BranchId;

        let bytes = Creator::new(
            u32::from(BranchId::Nu6_3),
            TEST_RELEASE_HEIGHT,
            133,
            None,
            None,
        )
        .unwrap()
        .build()
        .unwrap()
        .serialize()
        .unwrap();
        let staged = ExternalSigningPczt::parse(bytes.clone()).unwrap();
        (bytes, staged)
    }

    fn pczt_with_global_enrichment(pczt: &[u8], key: &str, value: u8) -> Vec<u8> {
        use pczt::roles::updater::Updater;

        Updater::new(pczt::Pczt::parse(pczt).unwrap())
            .update_global_with(|mut global| {
                global.set_proprietary(key.to_string(), vec![value]);
            })
            .finish()
            .serialize()
            .unwrap()
    }

    fn immediate_evidence() -> (ImmediateProposal, DeliveryArtifactEvidence) {
        let identity = ImmediateArtifactIdentity::from_stored([TEST_ARTIFACT_BYTE; DIGEST_LENGTH]);
        let proposal = immediate_proposal(vec![TEST_ARTIFACT_BYTE]);
        let evidence = DeliveryArtifactEvidence::Immediate(
            ImmediateArtifactEvidence::from_proposal(identity, &proposal),
        );
        (proposal, evidence)
    }

    fn empty_v6_transaction(expiry_height: BlockHeight) -> Transaction {
        use zcash_primitives::transaction::{Authorized, TransactionData};

        TransactionData::<Authorized>::from_parts_v6(
            BranchId::Nu6_3,
            133,
            expiry_height,
            #[cfg(all(zcash_unstable = "nu7", feature = "zip-233"))]
            Zatoshis::ZERO,
            None,
            None,
            None,
            None,
        )
        .freeze()
        .unwrap()
    }

    fn immediate_snapshot_with_claim(
        proposal: &ImmediateProposal,
        policy: SubmissionPolicy,
        claim: DeliveryClaim,
    ) -> DeliverySnapshot {
        DeliverySnapshot::from_parts_with_immediate_gross_authorization(
            DeliveryRevision::from_stored(TEST_REVISION).unwrap(),
            MigrationRunIdentity::from_stored([TEST_TOKEN_BYTE; DIGEST_LENGTH]),
            DeliveryRunFingerprint::Immediate(proposal.digest()),
            SourceReservationOwner::from_stored([TEST_FINGERPRINT_BYTE; DIGEST_LENGTH]),
            DeliveryPhase::Active,
            StorageFinality::Active,
            1,
            None,
            Some(policy.clone()),
            None,
            Some(Zatoshis::ZERO),
            vec![claim],
        )
        .unwrap()
    }

    fn empty_immediate_snapshot(
        run_byte: u8,
        owner_byte: u8,
        proposal_byte: u8,
        phase: DeliveryPhase,
        storage_finality: StorageFinality,
    ) -> DeliverySnapshot {
        let proposal = immediate_proposal(vec![proposal_byte]);
        DeliverySnapshot::from_parts_with_immediate_gross_authorization(
            DeliveryRevision::from_stored(TEST_REVISION).unwrap(),
            MigrationRunIdentity::from_stored([run_byte; DIGEST_LENGTH]),
            DeliveryRunFingerprint::Immediate(proposal.digest()),
            SourceReservationOwner::from_stored([owner_byte; DIGEST_LENGTH]),
            phase,
            storage_finality,
            1,
            None,
            Some(validated_policy()),
            None,
            Some(Zatoshis::ZERO),
            vec![],
        )
        .unwrap()
    }

    fn archive_test_state(
        status: MigrationStatus,
        transaction_state: MigrationTxState,
        pczt_byte: u8,
    ) -> MigrationState {
        let crossing = Zatoshis::from_u64(100).unwrap();
        let fee_buffer = Zatoshis::from_u64(1).unwrap();
        let change = Zatoshis::from_u64(2).unwrap();
        let prep_fees = Zatoshis::from_u64(3).unwrap();
        let total_input = Zatoshis::from_u64(106).unwrap();
        let note_split = NoteSplitPlan::from_stored_parts(
            vec![crossing],
            fee_buffer,
            Some(change),
            prep_fees,
            total_input,
            crossing,
        )
        .unwrap();
        let preparation = PreparationPlan::from_parts(
            vec![vec![PrepTransaction::from_parts(
                vec![PrepInput::Wallet {
                    index: 0,
                    value: total_input,
                }],
                vec![PrepOutput::Funding(crossing)],
            )]],
            vec![(1, crossing)],
        );
        let transaction = MigrationTransaction::from_parts(
            MigrationTxId::new(0),
            MigrationTxKind::Transfer { crossing: 0 },
            vec![pczt_byte, TEST_ARTIFACT_BYTE],
            vec![MigrationTxId::new(1)],
            BlockHeight::from_u32(TEST_RELEASE_HEIGHT - 10),
            BlockHeight::from_u32(TEST_RELEASE_HEIGHT),
            Some(BlockHeight::from_u32(TEST_RELEASE_HEIGHT - 20)),
            transaction_state,
            Some([TEST_TOKEN_BYTE; DIGEST_LENGTH]),
        );
        MigrationState::from_parts(status, note_split, preparation, vec![transaction])
    }

    #[test]
    fn sensitive_delivery_debug_output_is_redacted() {
        let revision = DeliveryRevision::from_stored(TEST_REVISION).unwrap();
        let run_identity = MigrationRunIdentity::from_stored([TEST_TOKEN_BYTE; DIGEST_LENGTH]);
        let source_owner =
            SourceReservationOwner::from_stored([TEST_FINGERPRINT_BYTE; DIGEST_LENGTH]);
        let policy = validated_policy();
        let canonical_state = archive_test_state(
            MigrationStatus::Committed,
            MigrationTxState::Signed,
            TEST_TRANSACTION_BYTE,
        );
        let artifact_identity =
            DeliveryArtifactIdentity::Scheduled(ScheduledArtifactIdentity::new(
                MigrationTxId::new(0),
                migration_transaction_fingerprint(
                    &canonical_state,
                    &canonical_state.transactions()[0],
                ),
            ));
        let exact_bytes = vec![211, 212, 213, 214, 215, 216];
        let exact = ExactTransaction {
            artifact_identity,
            txid: TxId::from_bytes([TEST_TXID_BYTE; DIGEST_LENGTH]),
            consensus_expiry_height: BlockHeight::from_u32(TEST_RELEASE_HEIGHT),
            digest: ExactTransactionDigest::from_transaction_bytes(&exact_bytes),
            bytes: exact_bytes,
        };
        let (immediate_proposal, immediate_evidence) = immediate_evidence();
        let confirmed_claim = DeliveryClaim::from_parts(
            immediate_evidence.clone(),
            SignerOwnership::Sdk,
            ClaimStatus::Confirmed,
            None,
            None,
            None,
            Some(ExactTransaction {
                artifact_identity: immediate_evidence.identity(),
                ..exact.clone()
            }),
            policy.fingerprint(),
            None,
        )
        .unwrap();
        let release = ReservationRelease::at(BlockHeight::from_u32(TEST_RELEASE_HEIGHT));
        let finalized = FinalizedTransferEvidence::new(
            immediate_evidence.identity(),
            confirmed_claim.txid().unwrap(),
            confirmed_claim.exact_transaction().unwrap().digest(),
            BlockHeight::from_u32(TEST_RELEASE_HEIGHT - 1),
        );
        let finality_archive = FinalityArchive::new(release, vec![finalized]).unwrap();
        let immediate_snapshot = DeliverySnapshot::from_parts(
            revision,
            run_identity,
            DeliveryRunFingerprint::Immediate(immediate_proposal.digest()),
            source_owner,
            DeliveryPhase::Active,
            StorageFinality::Finalized(release),
            0,
            Some(finality_archive.clone()),
            Some(policy.clone()),
            None,
            vec![confirmed_claim.clone()],
        )
        .unwrap();
        let scheduled_snapshot = DeliverySnapshot::from_parts(
            revision,
            run_identity,
            DeliveryRunFingerprint::Scheduled(migration_state_fingerprint(&canonical_state)),
            source_owner,
            DeliveryPhase::Active,
            StorageFinality::Active,
            1,
            None,
            Some(policy.clone()),
            None,
            vec![],
        )
        .unwrap();
        let transition = CanonicalMaterializationTransition {
            expected_revision: revision,
            run_identity,
            expected_state_fingerprint: migration_state_fingerprint(&canonical_state),
            artifact_identity,
            token: ClaimToken::from_stored([TEST_TOKEN_BYTE; DIGEST_LENGTH]),
            purpose: CanonicalMaterializationPurpose::Proof,
            proof_transaction: Some(exact.clone()),
            expected_policy_fingerprint: policy.fingerprint(),
            successor_state: canonical_state.clone(),
        };
        let materialization_receipt = CanonicalMaterializationReceipt {
            canonical_state: canonical_state.clone(),
            delivery: scheduled_snapshot.clone(),
        };
        let delivery_receipt = CanonicalDeliveryReceipt {
            canonical_state: canonical_state.clone(),
            delivery: scheduled_snapshot.clone(),
        };
        let completion = crate::wallet::MigrationCompletion::Finalized(canonical_state.clone());
        let rollover = ReservationRollover {
            expected_revision: revision,
            predecessor_run_identity: run_identity,
            predecessor_reservation_owner: source_owner,
            expected_predecessor_fingerprint: migration_state_fingerprint(&canonical_state),
            purpose: ReservationRolloverPurpose::ReplaceTerminal,
            successor_state: canonical_state.clone(),
        };
        let rebuild = ExpiredTransferRebuild {
            expected_revision: revision,
            run_identity,
            source_reservation_owner: source_owner,
            expected_state_fingerprint: migration_state_fingerprint(&canonical_state),
            prior_artifact: match artifact_identity {
                DeliveryArtifactIdentity::Scheduled(identity) => identity,
                DeliveryArtifactIdentity::Immediate(_) => unreachable!(),
            },
            signer_ownership: SignerOwnership::Sdk,
            successor_state: canonical_state.clone(),
        };
        let rollover_receipt = ReservationRolloverReceipt {
            predecessor_run_identity: run_identity,
            retained_predecessor_owner: source_owner,
            canonical_state: canonical_state.clone(),
            successor: scheduled_snapshot.clone(),
        };
        let rebuild_receipt = ExpiredTransferRebuildReceipt {
            archived_attempt: rebuild.prior_artifact,
            replacement_attempt: rebuild.prior_artifact,
            canonical_state: canonical_state.clone(),
            delivery: scheduled_snapshot,
        };
        let retained = RetainedMigrationRun::from_observed(
            None,
            immediate_snapshot.clone(),
            DestinationSpendability::Spendable,
        )
        .unwrap();
        let runtime = MigrationRuntimeSnapshot::from_observed(
            None,
            Some(immediate_snapshot.clone()),
            vec![retained.clone()],
            DeliverySchemaProvenance::Compatible(DeliverySchemaVersion::from_u32(1).unwrap()),
            LegacyCutoverStatus::Fresh,
            DestinationSpendability::Spendable,
        );
        let private_account_id = "private-account-identifier".to_string();
        let account_runtime =
            AccountMigrationRuntime::new(private_account_id.clone(), runtime.clone());
        let batch = MigrationRuntimeBatch {
            accounts: vec![account_runtime.clone()],
        };
        let malformed_nullifier = [0xD7; DIGEST_LENGTH];
        let wallet_error =
            crate::wallet::Error::<String, String, String>::MalformedNullifier(malformed_nullifier);
        let lock_error =
            crate::wallet::PcztLockError::<String>::MalformedNullifier(malformed_nullifier);

        let canonical_state_debug = format!("{canonical_state:?}");
        let pczt_debug = format!("{:?}", canonical_state.transactions()[0].pczt());
        let exact_bytes_debug = format!("{:?}", exact.bytes());
        let txid_debug = format!("{:?}", exact.txid());
        let malformed_nullifier_debug = format!("{malformed_nullifier:?}");
        let forbidden = [
            canonical_state_debug.as_str(),
            pczt_debug.as_str(),
            exact_bytes_debug.as_str(),
            txid_debug.as_str(),
            private_account_id.as_str(),
            malformed_nullifier_debug.as_str(),
        ];
        let values = [
            ("exact transaction", format!("{exact:?}")),
            ("delivery claim", format!("{confirmed_claim:?}")),
            ("finalized transfer", format!("{finalized:?}")),
            ("finality archive", format!("{finality_archive:?}")),
            ("delivery snapshot", format!("{immediate_snapshot:?}")),
            ("materialization transition", format!("{transition:?}")),
            (
                "materialization receipt",
                format!("{materialization_receipt:?}"),
            ),
            ("delivery receipt", format!("{delivery_receipt:?}")),
            ("migration completion", format!("{completion:?}")),
            ("reservation rollover", format!("{rollover:?}")),
            ("expired rebuild", format!("{rebuild:?}")),
            ("rollover receipt", format!("{rollover_receipt:?}")),
            ("rebuild receipt", format!("{rebuild_receipt:?}")),
            ("retained run", format!("{retained:?}")),
            ("runtime snapshot", format!("{runtime:?}")),
            ("account runtime", format!("{account_runtime:?}")),
            ("runtime batch", format!("{batch:?}")),
            ("wallet error", format!("{wallet_error:?}")),
            ("PCZT lock error", format!("{lock_error:?}")),
        ];
        for (name, debug) in values {
            assert!(
                debug.contains("<redacted>"),
                "{name} did not mark redaction"
            );
            for forbidden in &forbidden {
                assert!(
                    !debug.contains(forbidden),
                    "{name} leaked sensitive Debug material: {forbidden}"
                );
            }
        }
        for display in [wallet_error.to_string(), lock_error.to_string()] {
            assert!(display.contains("<redacted>"));
            assert!(!display.contains(&malformed_nullifier_debug));
        }
    }

    #[test]
    fn semantic_scalars_round_trip_and_reject_zero_overlong_or_overflow_leases() {
        let revision = DeliveryRevision::from_stored(TEST_REVISION).unwrap();
        let mut encoded = Vec::new();
        revision.write(&mut encoded).unwrap();
        assert_eq!(
            DeliveryRevision::read(encoded.as_slice()).unwrap(),
            revision
        );

        assert!(DeliveryRevision::read(0_u64.to_le_bytes().as_slice()).is_err());
        assert_eq!(DeliveryRevision::INITIAL.as_u64(), FIRST_DELIVERY_REVISION);

        let instant = test_instant(TEST_INSTANT_MILLIS);
        let duration = LeaseDuration::from_millis(TEST_LEASE_MILLIS).unwrap();
        assert_eq!(
            instant.checked_add(duration),
            Some(test_instant(TEST_INSTANT_MILLIS + TEST_LEASE_MILLIS))
        );
        let mut encoded_instant = Vec::new();
        instant.write(&mut encoded_instant).unwrap();
        assert_eq!(
            MonotonicLeaseInstant::read(encoded_instant.as_slice()).unwrap(),
            instant
        );
        assert!(LeaseDuration::from_millis(0).is_none());
        assert!(LeaseDuration::read(0_u64.to_le_bytes().as_slice()).is_err());
        assert!(LeaseDuration::from_millis(LeaseDuration::MAX_MILLIS).is_some());
        assert!(LeaseDuration::from_millis(LeaseDuration::MAX_MILLIS + 1).is_none());
        assert!(
            LeaseDuration::read((LeaseDuration::MAX_MILLIS + 1).to_le_bytes().as_slice()).is_err()
        );
        assert!(test_instant(u64::MAX).checked_add(duration).is_none());
    }

    #[test]
    fn persisted_monotonic_lease_expires_on_relaunch_or_clock_rollback() {
        let token = ClaimToken::from_stored([TEST_TOKEN_BYTE; DIGEST_LENGTH]);
        let acquired_at = test_instant(TEST_INSTANT_MILLIS);
        let duration = LeaseDuration::from_millis(TEST_LEASE_MILLIS).unwrap();
        let lease =
            DeliveryLease::new(ClaimKind::Submission, token, acquired_at, duration).unwrap();

        assert_eq!(
            lease.validity_at(test_instant(TEST_INSTANT_MILLIS)),
            LeaseValidity::Live
        );
        assert_eq!(
            lease.validity_at(test_instant(TEST_INSTANT_MILLIS + TEST_LEASE_MILLIS)),
            LeaseValidity::Expired
        );
        assert_eq!(
            lease.validity_at(test_instant(TEST_INSTANT_MILLIS - 1)),
            LeaseValidity::ClockRollback
        );
        assert_eq!(
            lease.validity_at(MonotonicLeaseInstant::new(
                clock_session(OTHER_CLOCK_SESSION_BYTE),
                TEST_INSTANT_MILLIS,
            )),
            LeaseValidity::ClockSessionChanged
        );
        assert_eq!(
            DeliveryLease::from_parts(
                ClaimKind::Submission,
                token,
                acquired_at,
                MonotonicLeaseInstant::new(
                    clock_session(OTHER_CLOCK_SESSION_BYTE),
                    TEST_INSTANT_MILLIS + TEST_LEASE_MILLIS,
                ),
            ),
            Err(LeaseValidationError::ClockSessionMismatch)
        );
        assert_eq!(
            DeliveryLease::from_parts(ClaimKind::Submission, token, acquired_at, acquired_at),
            Err(LeaseValidationError::NonIncreasingExpiry)
        );
    }

    #[test]
    fn endpoint_validation_is_transport_specific_and_canonical() {
        assert!(DirectTlsEndpoint::try_from("http://example.com".to_string()).is_err());
        assert!(DirectTlsEndpoint::try_from("https://localhost:9067".to_string()).is_err());
        assert!(DirectTlsEndpoint::try_from("https://service.onion".to_string()).is_err());
        assert!(DirectTlsEndpoint::try_from("https://EXAMPLE.com".to_string()).is_err());
        assert!(DirectTlsEndpoint::try_from("https://example.com:09067".to_string()).is_err());
        assert!(DirectTlsEndpoint::try_from("https://user@example.com".to_string()).is_err());
        assert!(DirectTlsEndpoint::try_from("https://example.com/path".to_string()).is_err());
        assert!(DirectTlsEndpoint::try_from("https://10.0.0.1:9067".to_string()).is_err());
        assert!(DirectTlsEndpoint::try_from("https://169.254.169.254:9067".to_string()).is_err());
        assert!(DirectTlsEndpoint::try_from("https://2130706433:9067".to_string()).is_err());
        assert!(DirectTlsEndpoint::try_from("https://0x7f000001:9067".to_string()).is_err());
        assert!(DirectTlsEndpoint::try_from("https://[::1]:9067".to_string()).is_err());

        assert!(
            TorProxyTlsEndpoint::try_from("https://lightwalletd.example:9067".to_string()).is_ok()
        );
        assert!(TorProxyTlsEndpoint::try_from("http://example.com:9067".to_string()).is_err());
        assert!(TorProxyTlsEndpoint::try_from("https://localhost:9067".to_string()).is_err());
        assert!(TorProxyTlsEndpoint::try_from("https://service.onion:9067".to_string()).is_err());
        assert!(TorProxyTlsEndpoint::try_from("https://10.0.0.1:9067".to_string()).is_err());
        assert!(TorProxyTlsEndpoint::try_from("https://192.168.1.1:9067".to_string()).is_err());
        assert!(TorProxyTlsEndpoint::try_from("https://169.254.169.254:9067".to_string()).is_err());
        assert!(TorProxyTlsEndpoint::try_from("https://0.0.0.0:9067".to_string()).is_err());
        assert!(TorProxyTlsEndpoint::try_from("https://127.1:9067".to_string()).is_err());
        assert!(TorProxyTlsEndpoint::try_from("https://2130706433:9067".to_string()).is_err());
        assert!(TorProxyTlsEndpoint::try_from("https://0x7f000001:9067".to_string()).is_err());
        assert!(TorProxyTlsEndpoint::try_from("https://[::1]:9067".to_string()).is_err());

        let onion = format!("http://{TEST_ONION_LABEL}.onion:9067");
        assert!(TorOnionEndpoint::try_from(onion).is_ok());
        assert!(TorOnionEndpoint::try_from("http://short.onion".to_string()).is_err());
        assert!(TorOnionEndpoint::try_from("http://example.com".to_string()).is_err());

        assert!(LoopbackDevelopmentEndpoint::try_from("http://127.0.0.1:9067".to_string()).is_ok());
        assert!(LoopbackDevelopmentEndpoint::try_from("http://[::1]:9067".to_string()).is_ok());
        assert!(
            LoopbackDevelopmentEndpoint::try_from("http://192.168.1.1:9067".to_string()).is_err()
        );
        assert!(
            LoopbackDevelopmentEndpoint::try_from("https://localhost:9067".to_string()).is_err()
        );
    }

    #[test]
    fn policy_codec_round_trips_and_rejects_corruption_or_mismatch() {
        let policy = validated_policy();
        let decoded = SubmissionPolicy::decode(
            policy.canonical_bytes().to_vec(),
            policy.fingerprint(),
            test_context(),
        )
        .unwrap();
        assert_eq!(decoded, policy);

        let mut unknown_version = policy.canonical_bytes().to_vec();
        unknown_version[0] = UNKNOWN_CODEC_TAG;
        assert_eq!(
            SubmissionPolicy::decode(unknown_version, policy.fingerprint(), test_context()),
            Err(PolicyValidationFailure::InvalidEncoding)
        );

        let mut unknown_network = policy.canonical_bytes().to_vec();
        unknown_network[1] = UNKNOWN_CODEC_TAG;
        assert_eq!(
            SubmissionPolicy::decode(unknown_network, policy.fingerprint(), test_context()),
            Err(PolicyValidationFailure::InvalidEncoding)
        );

        let mut unknown_transport = policy.canonical_bytes().to_vec();
        let transport_tag_offset = 1 + 1 + DIGEST_LENGTH;
        unknown_transport[transport_tag_offset] = UNKNOWN_CODEC_TAG;
        assert_eq!(
            SubmissionPolicy::decode(unknown_transport, policy.fingerprint(), test_context()),
            Err(PolicyValidationFailure::InvalidEncoding)
        );

        let mut malformed_length = policy.canonical_bytes().to_vec();
        let endpoint_length_offset = 1 + 1 + DIGEST_LENGTH + 1;
        malformed_length[endpoint_length_offset] = UNKNOWN_CODEC_TAG;
        assert_eq!(
            SubmissionPolicy::decode(malformed_length, policy.fingerprint(), test_context()),
            Err(PolicyValidationFailure::InvalidEncoding)
        );

        let mut trailing = policy.canonical_bytes().to_vec();
        trailing.push(0);
        assert_eq!(
            SubmissionPolicy::decode(trailing, policy.fingerprint(), test_context()),
            Err(PolicyValidationFailure::InvalidEncoding)
        );

        let main_context = SubmissionContext::from_parameters(&Network::MainNetwork);
        assert_eq!(
            SubmissionPolicy::validate(
                SubmissionPolicyRequest::new(test_context(), direct_transport()),
                main_context,
            ),
            Err(PolicyValidationFailure::NetworkMismatch)
        );

        let mismatched_consensus = SubmissionContext::from_codec(
            NetworkType::Test,
            ConsensusFingerprint::from_bytes([UNKNOWN_CODEC_TAG; DIGEST_LENGTH]),
        );
        assert_eq!(
            SubmissionPolicy::validate(
                SubmissionPolicyRequest::new(test_context(), direct_transport()),
                mismatched_consensus,
            ),
            Err(PolicyValidationFailure::ConsensusMismatch)
        );

        assert_eq!(
            SubmissionPolicy::decode(
                policy.canonical_bytes().to_vec(),
                PolicyFingerprint::from_bytes([UNKNOWN_CODEC_TAG; DIGEST_LENGTH]),
                test_context(),
            ),
            Err(PolicyValidationFailure::InvalidEncoding)
        );
    }

    #[test]
    fn policy_codec_preserves_public_tls_over_tor_as_a_distinct_transport() {
        let context = test_context();
        let transport = SubmissionTransport::TorProxyTls(
            TorProxyTlsEndpoint::try_from("https://lightwalletd.example:9067".to_string()).unwrap(),
        );
        let policy = SubmissionPolicy::validate(
            SubmissionPolicyRequest::new(context, transport.clone()),
            context,
        )
        .unwrap();
        let decoded = SubmissionPolicy::decode(
            policy.canonical_bytes().to_vec(),
            policy.fingerprint(),
            context,
        )
        .unwrap();
        assert_eq!(decoded.request().transport(), &transport);
        assert_eq!(
            decoded.request().transport().endpoint(),
            "https://lightwalletd.example:9067"
        );
    }

    #[test]
    fn outcome_unknown_and_broadcasted_only_accept_resolution_leases() {
        let token = ClaimToken::from_stored([TEST_TOKEN_BYTE; DIGEST_LENGTH]);
        let acquired_at = test_instant(TEST_INSTANT_MILLIS);
        let expires_at = test_instant(TEST_INSTANT_MILLIS + TEST_LEASE_MILLIS);
        let resolution =
            DeliveryLease::from_parts(ClaimKind::OutcomeResolution, token, acquired_at, expires_at)
                .unwrap();
        let submission =
            DeliveryLease::from_parts(ClaimKind::Submission, token, acquired_at, expires_at)
                .unwrap();
        assert_eq!(
            ClaimStatus::OutcomeUnknown.permitted_lease(),
            Some(ClaimKind::OutcomeResolution)
        );
        assert_eq!(resolution.kind(), ClaimKind::OutcomeResolution);
        assert_ne!(submission.kind(), ClaimKind::OutcomeResolution);
        assert!(!matches!(
            ClaimStatus::OutcomeUnknown.permitted_lease(),
            Some(kind) if kind == submission.kind()
        ));

        let identity = ImmediateArtifactIdentity::from_stored([TEST_ARTIFACT_BYTE; DIGEST_LENGTH]);
        let proposal = immediate_proposal(vec![TEST_ARTIFACT_BYTE]);
        let evidence = DeliveryArtifactEvidence::Immediate(
            ImmediateArtifactEvidence::from_proposal(identity, &proposal),
        );
        let exact_bytes = vec![TEST_TRANSACTION_BYTE];
        let exact_transaction = ExactTransaction {
            artifact_identity: DeliveryArtifactIdentity::Immediate(identity),
            txid: TxId::from_bytes([TEST_TXID_BYTE; DIGEST_LENGTH]),
            consensus_expiry_height: BlockHeight::from_u32(TEST_RELEASE_HEIGHT),
            digest: ExactTransactionDigest::from_transaction_bytes(&exact_bytes),
            bytes: exact_bytes,
        };
        let policy_fingerprint =
            PolicyFingerprint::from_bytes([TEST_FINGERPRINT_BYTE; DIGEST_LENGTH]);
        let claim = |lease| {
            DeliveryClaim::from_parts(
                evidence.clone(),
                SignerOwnership::Sdk,
                ClaimStatus::OutcomeUnknown,
                lease,
                None,
                None,
                Some(exact_transaction.clone()),
                policy_fingerprint,
                Some(DeliveryFailureReason::TransportOutcomeUnknown),
            )
        };
        assert!(claim(Some(resolution)).is_ok());
        assert!(claim(None).is_ok());
        assert_eq!(
            claim(Some(submission)),
            Err(ClaimValidationError::InvalidLease)
        );

        let broadcasted = |lease| {
            DeliveryClaim::from_parts(
                evidence.clone(),
                SignerOwnership::Sdk,
                ClaimStatus::Broadcasted,
                lease,
                None,
                None,
                Some(exact_transaction.clone()),
                policy_fingerprint,
                None,
            )
        };
        assert!(broadcasted(Some(resolution)).is_ok());
        assert!(broadcasted(None).is_ok());
        assert_eq!(
            broadcasted(Some(submission)),
            Err(ClaimValidationError::InvalidLease)
        );
    }

    #[test]
    fn delivery_failure_reason_matrix_is_status_and_claim_kind_specific() {
        let statuses = [
            ClaimStatus::Materializing,
            ClaimStatus::MaterializationFailed,
            ClaimStatus::AwaitingExternalSignature,
            ClaimStatus::Staged,
            ClaimStatus::Submitting,
            ClaimStatus::OutcomeUnknown,
            ClaimStatus::Broadcasted,
            ClaimStatus::Confirmed,
            ClaimStatus::ExpiredUnmined,
            ClaimStatus::ExternalSigningExpiredUnmined,
        ];
        let reasons = [
            DeliveryFailureReason::MaterializationFailed,
            DeliveryFailureReason::MaterializationLeaseExpired,
            DeliveryFailureReason::SigningCancelled,
            DeliveryFailureReason::TransportSetupFailed,
            DeliveryFailureReason::TransportDidNotBegin,
            DeliveryFailureReason::SubmissionLeaseExpired,
            DeliveryFailureReason::TransportOutcomeUnknown,
        ];

        for status in statuses {
            for reason in reasons {
                let expected = matches!(
                    (status, reason),
                    (
                        ClaimStatus::MaterializationFailed,
                        DeliveryFailureReason::MaterializationFailed
                            | DeliveryFailureReason::MaterializationLeaseExpired
                            | DeliveryFailureReason::SigningCancelled
                    ) | (
                        ClaimStatus::Staged,
                        DeliveryFailureReason::TransportSetupFailed
                            | DeliveryFailureReason::TransportDidNotBegin
                            | DeliveryFailureReason::SubmissionLeaseExpired
                    ) | (
                        ClaimStatus::OutcomeUnknown,
                        DeliveryFailureReason::TransportOutcomeUnknown
                    )
                );
                assert_eq!(reason.is_valid_for(status), expected);
            }
        }
    }

    #[test]
    fn spendability_does_not_wait_for_source_reservation_finality() {
        let release = ReservationRelease::at(BlockHeight::from_u32(TEST_RELEASE_HEIGHT));
        assert_eq!(
            OrdinarySpendAuthorization::derive(
                MigrationRuntimeAvailability::Available,
                DestinationSpendability::AlreadySpent,
                StorageFinality::CompletePendingFinality(release),
            ),
            OrdinarySpendAuthorization::Allowed(OrdinarySpendScope::ExcludingMigrationSources(
                release
            ))
        );
        assert_eq!(
            OrdinarySpendAuthorization::derive(
                MigrationRuntimeAvailability::Available,
                DestinationSpendability::Spendable,
                StorageFinality::Active,
            ),
            OrdinarySpendAuthorization::Blocked(OrdinarySpendBlockReason::MigrationActive)
        );
        assert_eq!(
            OrdinarySpendAuthorization::derive(
                MigrationRuntimeAvailability::Available,
                DestinationSpendability::NotSpendable,
                StorageFinality::CompletePendingFinality(release),
            ),
            OrdinarySpendAuthorization::Blocked(OrdinarySpendBlockReason::DestinationNotSpendable)
        );
        let recovery = StorageRecoveryReason::RewoundBeyondFinalityHorizon;
        assert_eq!(
            OrdinarySpendAuthorization::derive(
                MigrationRuntimeAvailability::Available,
                DestinationSpendability::Spendable,
                StorageFinality::RecoveryRequired(recovery),
            ),
            OrdinarySpendAuthorization::Blocked(OrdinarySpendBlockReason::FinalityRecovery(
                recovery
            ))
        );
        assert_eq!(
            OrdinarySpendAuthorization::derive(
                MigrationRuntimeAvailability::Available,
                DestinationSpendability::NotSpendable,
                StorageFinality::NoRun,
            ),
            OrdinarySpendAuthorization::Allowed(OrdinarySpendScope::Unrestricted)
        );
    }

    #[test]
    fn account_runtime_aggregates_predecessor_finality_and_destination_spendability() {
        let current_release = ReservationRelease::at(BlockHeight::from_u32(TEST_RELEASE_HEIGHT));
        let predecessor_release =
            ReservationRelease::at(BlockHeight::from_u32(TEST_RELEASE_HEIGHT + 100));
        let (proposal, evidence) = immediate_evidence();
        let policy = validated_policy();
        let current_claim = DeliveryClaim::from_parts(
            evidence,
            SignerOwnership::Sdk,
            ClaimStatus::MaterializationFailed,
            None,
            None,
            None,
            None,
            policy.fingerprint(),
            Some(DeliveryFailureReason::MaterializationFailed),
        )
        .unwrap();
        let current = DeliverySnapshot::from_parts_with_immediate_gross_authorization(
            DeliveryRevision::from_stored(TEST_REVISION).unwrap(),
            MigrationRunIdentity::from_stored([21; DIGEST_LENGTH]),
            DeliveryRunFingerprint::Immediate(proposal.digest()),
            SourceReservationOwner::from_stored([22; DIGEST_LENGTH]),
            DeliveryPhase::Paused,
            StorageFinality::CompletePendingFinality(current_release),
            1,
            None,
            Some(policy),
            None,
            Some(Zatoshis::ZERO),
            vec![current_claim],
        )
        .unwrap();
        let predecessor = RetainedMigrationRun::from_observed(
            None,
            empty_immediate_snapshot(
                31,
                32,
                33,
                DeliveryPhase::Abandoning,
                StorageFinality::CompletePendingFinality(predecessor_release),
            ),
            DestinationSpendability::NotSpendable,
        )
        .unwrap();
        let runtime = MigrationRuntimeSnapshot::from_observed(
            None,
            Some(current),
            vec![predecessor],
            DeliverySchemaProvenance::Compatible(DeliverySchemaVersion::from_u32(1).unwrap()),
            LegacyCutoverStatus::Fresh,
            DestinationSpendability::Spendable,
        );

        assert_eq!(
            runtime.aggregate_storage_finality(),
            StorageFinality::CompletePendingFinality(predecessor_release)
        );
        assert_eq!(
            runtime.current_destination_spendability(),
            DestinationSpendability::Spendable
        );
        assert_eq!(
            runtime.destination_spendability(),
            DestinationSpendability::NotSpendable
        );
        assert_eq!(
            runtime.ordinary_spend_authorization(),
            OrdinarySpendAuthorization::Blocked(OrdinarySpendBlockReason::DestinationNotSpendable)
        );
        assert!(matches!(
            runtime.account_deletion_authorization(),
            AccountDeletionAuthorization::Blocked(AccountDeletionBlockReason::UnresolvedDelivery(
                _
            ))
        ));
    }

    #[test]
    fn missing_immediate_authorization_is_diagnosed_only_at_forward_exposure_boundary() {
        let (proposal, evidence) = immediate_evidence();
        let policy = validated_policy();
        let exact_bytes = vec![TEST_TRANSACTION_BYTE];
        let exact = ExactTransaction {
            artifact_identity: evidence.identity(),
            txid: TxId::from_bytes([TEST_TXID_BYTE; DIGEST_LENGTH]),
            consensus_expiry_height: evidence.expiry_height(),
            digest: ExactTransactionDigest::from_transaction_bytes(&exact_bytes),
            bytes: exact_bytes,
        };
        let legacy_snapshot = |status, storage_finality| {
            let last_error = (status == ClaimStatus::OutcomeUnknown)
                .then_some(DeliveryFailureReason::TransportOutcomeUnknown);
            let claim = DeliveryClaim::from_parts(
                evidence.clone(),
                SignerOwnership::Sdk,
                status,
                None,
                None,
                None,
                Some(exact.clone()),
                policy.fingerprint(),
                last_error,
            )
            .unwrap();
            DeliverySnapshot::from_parts(
                DeliveryRevision::from_stored(TEST_REVISION).unwrap(),
                MigrationRunIdentity::from_stored([TEST_TOKEN_BYTE; DIGEST_LENGTH]),
                DeliveryRunFingerprint::Immediate(proposal.digest()),
                SourceReservationOwner::from_stored([TEST_FINGERPRINT_BYTE; DIGEST_LENGTH]),
                DeliveryPhase::Active,
                storage_finality,
                1,
                None,
                Some(policy.clone()),
                None,
                vec![claim],
            )
            .unwrap()
        };
        let availability = |snapshot| {
            MigrationRuntimeSnapshot::from_observed(
                None,
                Some(snapshot),
                vec![],
                DeliverySchemaProvenance::Compatible(DeliverySchemaVersion::from_u32(2).unwrap()),
                LegacyCutoverStatus::Fresh,
                DestinationSpendability::NotSpendable,
            )
            .availability()
        };

        assert_eq!(
            availability(empty_immediate_snapshot(
                0xA7,
                0xA8,
                0xA9,
                DeliveryPhase::Active,
                StorageFinality::Active,
            )),
            MigrationRuntimeAvailability::Unavailable(
                RuntimeUnavailableReason::DeliveryInconsistent
            ),
            "a claimless active immediate run cannot project as available",
        );
        assert_eq!(
            availability(empty_immediate_snapshot(
                0xAA,
                0xAB,
                0xAC,
                DeliveryPhase::Abandoning,
                StorageFinality::Active,
            )),
            MigrationRuntimeAvailability::Available,
            "a claimless abandonment tombstone must remain recoverable",
        );

        assert_eq!(
            availability(legacy_snapshot(
                ClaimStatus::Staged,
                StorageFinality::Active
            )),
            MigrationRuntimeAvailability::Unavailable(
                RuntimeUnavailableReason::MissingSpendAuthorization
            )
        );
        for status in [ClaimStatus::OutcomeUnknown, ClaimStatus::Confirmed] {
            assert_eq!(
                availability(legacy_snapshot(status, StorageFinality::Active)),
                MigrationRuntimeAvailability::Available,
                "{status:?} has chain evidence to reconcile but grants no new submission power",
            );
        }

        let recovery = StorageRecoveryReason::ExternalSigningExposureUnresolved;
        assert_eq!(
            availability(legacy_snapshot(
                ClaimStatus::Staged,
                StorageFinality::RecoveryRequired(recovery),
            )),
            MigrationRuntimeAvailability::Unavailable(RuntimeUnavailableReason::FinalityRecovery(
                recovery
            )),
            "finality recovery must take precedence over missing authorization",
        );

        let release = ReservationRelease::at(BlockHeight::from_u32(TEST_RELEASE_HEIGHT));
        let terminal = DeliverySnapshot::from_parts(
            DeliveryRevision::from_stored(TEST_REVISION).unwrap(),
            MigrationRunIdentity::from_stored([0xC1; DIGEST_LENGTH]),
            DeliveryRunFingerprint::Immediate(proposal.digest()),
            SourceReservationOwner::from_stored([0xC2; DIGEST_LENGTH]),
            DeliveryPhase::Abandoned,
            StorageFinality::Finalized(release),
            0,
            None,
            None,
            None,
            vec![],
        )
        .unwrap();
        let terminal_runtime = MigrationRuntimeSnapshot::from_observed(
            None,
            None,
            vec![
                RetainedMigrationRun::from_observed(
                    None,
                    terminal,
                    DestinationSpendability::NotApplicable,
                )
                .unwrap(),
            ],
            DeliverySchemaProvenance::Compatible(DeliverySchemaVersion::from_u32(2).unwrap()),
            LegacyCutoverStatus::Fresh,
            DestinationSpendability::NotApplicable,
        );
        assert_eq!(
            terminal_runtime.availability(),
            MigrationRuntimeAvailability::Available
        );
        assert_eq!(
            terminal_runtime.account_deletion_authorization(),
            AccountDeletionAuthorization::Allowed
        );
    }

    #[test]
    fn no_current_destination_is_neutral_for_retained_predecessors() {
        let release = ReservationRelease::at(BlockHeight::from_u32(TEST_RELEASE_HEIGHT));
        let predecessor = RetainedMigrationRun::from_observed(
            None,
            empty_immediate_snapshot(
                41,
                42,
                43,
                DeliveryPhase::Abandoning,
                StorageFinality::CompletePendingFinality(release),
            ),
            DestinationSpendability::Spendable,
        )
        .unwrap();
        let runtime = MigrationRuntimeSnapshot::from_observed(
            None,
            None,
            vec![predecessor],
            DeliverySchemaProvenance::Compatible(DeliverySchemaVersion::from_u32(1).unwrap()),
            LegacyCutoverStatus::Fresh,
            DestinationSpendability::NotApplicable,
        );

        assert_eq!(
            runtime.current_destination_spendability(),
            DestinationSpendability::NotApplicable
        );
        assert_eq!(
            runtime.destination_spendability(),
            DestinationSpendability::Spendable
        );
        assert_eq!(
            runtime.ordinary_spend_authorization(),
            OrdinarySpendAuthorization::Allowed(OrdinarySpendScope::ExcludingMigrationSources(
                release
            ))
        );
    }

    #[test]
    fn finalized_delivery_rejects_live_source_reservations() {
        let proposal = immediate_proposal(vec![TEST_ARTIFACT_BYTE]);
        assert_eq!(
            DeliverySnapshot::from_parts(
                DeliveryRevision::from_stored(TEST_REVISION).unwrap(),
                MigrationRunIdentity::from_stored([TEST_TOKEN_BYTE; DIGEST_LENGTH]),
                DeliveryRunFingerprint::Immediate(proposal.digest()),
                SourceReservationOwner::from_stored([TEST_FINGERPRINT_BYTE; DIGEST_LENGTH]),
                DeliveryPhase::Abandoned,
                StorageFinality::Finalized(ReservationRelease::at(BlockHeight::from_u32(
                    TEST_RELEASE_HEIGHT,
                ))),
                1,
                None,
                Some(validated_policy()),
                None,
                vec![],
            ),
            Err(SnapshotValidationError::FinalizedWithLiveSourceReservations)
        );
    }

    #[test]
    fn abandoned_unexposed_run_is_a_deletable_zero_reservation_tombstone() {
        let proposal = immediate_proposal(vec![TEST_ARTIFACT_BYTE]);
        let release = ReservationRelease::at(BlockHeight::from_u32(TEST_RELEASE_HEIGHT));
        let delivery = DeliverySnapshot::from_parts_with_immediate_gross_authorization(
            DeliveryRevision::from_stored(TEST_REVISION).unwrap(),
            MigrationRunIdentity::from_stored([TEST_TOKEN_BYTE; DIGEST_LENGTH]),
            DeliveryRunFingerprint::Immediate(proposal.digest()),
            SourceReservationOwner::from_stored([TEST_FINGERPRINT_BYTE; DIGEST_LENGTH]),
            DeliveryPhase::Abandoned,
            StorageFinality::Finalized(release),
            0,
            None,
            None,
            None,
            Some(Zatoshis::ZERO),
            vec![],
        )
        .unwrap();
        assert!(delivery.safe_to_cancel());
        assert!(delivery.released_without_exposure());

        let runtime = MigrationRuntimeSnapshot::from_observed(
            None,
            Some(delivery),
            vec![],
            DeliverySchemaProvenance::Compatible(DeliverySchemaVersion::from_u32(1).unwrap()),
            LegacyCutoverStatus::Fresh,
            DestinationSpendability::NotApplicable,
        );
        assert_eq!(
            runtime.availability(),
            MigrationRuntimeAvailability::Available
        );
        assert_eq!(
            runtime.ordinary_spend_authorization(),
            OrdinarySpendAuthorization::Allowed(OrdinarySpendScope::Unrestricted)
        );
        assert_eq!(
            runtime.account_deletion_authorization(),
            AccountDeletionAuthorization::Allowed
        );
        assert_eq!(
            runtime.canonical_mutation_authorization(),
            CanonicalMutationAuthorization::Allowed
        );

        let invalid_policy_tombstone =
            DeliverySnapshot::from_parts_with_immediate_gross_authorization(
                DeliveryRevision::from_stored(TEST_REVISION).unwrap(),
                MigrationRunIdentity::from_stored([TEST_TOKEN_BYTE; DIGEST_LENGTH]),
                DeliveryRunFingerprint::Immediate(proposal.digest()),
                SourceReservationOwner::from_stored([TEST_FINGERPRINT_BYTE; DIGEST_LENGTH]),
                DeliveryPhase::Abandoned,
                StorageFinality::Finalized(release),
                0,
                None,
                None,
                Some(PolicyValidationFailure::NetworkMismatch),
                Some(Zatoshis::ZERO),
                vec![],
            )
            .unwrap();
        let invalid_policy_runtime = MigrationRuntimeSnapshot::from_observed(
            None,
            Some(invalid_policy_tombstone),
            vec![],
            DeliverySchemaProvenance::Compatible(DeliverySchemaVersion::from_u32(1).unwrap()),
            LegacyCutoverStatus::Fresh,
            DestinationSpendability::NotApplicable,
        );
        assert_eq!(
            invalid_policy_runtime.availability(),
            MigrationRuntimeAvailability::Unavailable(
                RuntimeUnavailableReason::SubmissionPolicyMismatch
            )
        );
    }

    #[test]
    fn resolved_unmined_exposure_requires_exact_expiry_reorg_horizon() {
        let (proposal, evidence) = immediate_evidence();
        let policy = validated_policy();
        let expiry = evidence.expiry_height();
        let exact_bytes = vec![TEST_TRANSACTION_BYTE];
        let exact_transaction = ExactTransaction {
            artifact_identity: evidence.identity(),
            txid: TxId::from_bytes([TEST_TXID_BYTE; DIGEST_LENGTH]),
            consensus_expiry_height: expiry,
            digest: ExactTransactionDigest::from_transaction_bytes(&exact_bytes),
            bytes: exact_bytes,
        };
        let network_expired = DeliveryClaim::from_parts(
            evidence.clone(),
            SignerOwnership::Sdk,
            ClaimStatus::ExpiredUnmined,
            None,
            None,
            None,
            Some(exact_transaction),
            policy.fingerprint(),
            None,
        )
        .unwrap();
        let release = ReservationRelease::after_resolved_unmined_expiry(expiry).unwrap();
        let snapshot = DeliverySnapshot::from_parts(
            DeliveryRevision::from_stored(TEST_REVISION).unwrap(),
            MigrationRunIdentity::from_stored([TEST_TOKEN_BYTE; DIGEST_LENGTH]),
            DeliveryRunFingerprint::Immediate(proposal.digest()),
            SourceReservationOwner::from_stored([TEST_FINGERPRINT_BYTE; DIGEST_LENGTH]),
            DeliveryPhase::Abandoned,
            StorageFinality::Finalized(release),
            0,
            None,
            Some(policy.clone()),
            None,
            vec![network_expired.clone()],
        )
        .unwrap();
        assert!(snapshot.safe_to_cancel());
        assert!(!snapshot.released_without_exposure());
        assert!(snapshot.released_after_resolved_unmined_exposure());

        let rewind_recovery = DeliverySnapshot::from_parts(
            DeliveryRevision::from_stored(TEST_REVISION).unwrap(),
            MigrationRunIdentity::from_stored([TEST_TOKEN_BYTE; DIGEST_LENGTH]),
            DeliveryRunFingerprint::Immediate(proposal.digest()),
            SourceReservationOwner::from_stored([TEST_FINGERPRINT_BYTE; DIGEST_LENGTH]),
            DeliveryPhase::Abandoned,
            StorageFinality::RecoveryRequired(StorageRecoveryReason::RewoundBeyondFinalityHorizon),
            0,
            None,
            Some(policy.clone()),
            None,
            vec![network_expired.clone()],
        )
        .unwrap();
        assert_eq!(
            rewind_recovery.storage_finality(),
            StorageFinality::RecoveryRequired(StorageRecoveryReason::RewoundBeyondFinalityHorizon)
        );

        let too_early =
            ReservationRelease::at(BlockHeight::from_u32(u32::from(release.release_at()) - 1));
        assert_eq!(
            DeliverySnapshot::from_parts(
                DeliveryRevision::from_stored(TEST_REVISION).unwrap(),
                MigrationRunIdentity::from_stored([TEST_TOKEN_BYTE; DIGEST_LENGTH]),
                DeliveryRunFingerprint::Immediate(proposal.digest()),
                SourceReservationOwner::from_stored([TEST_FINGERPRINT_BYTE; DIGEST_LENGTH]),
                DeliveryPhase::Abandoned,
                StorageFinality::Finalized(too_early),
                0,
                None,
                Some(policy.clone()),
                None,
                vec![network_expired],
            ),
            Err(SnapshotValidationError::MissingFinalityArchive)
        );

        let (_, staged_pczt) = external_signing_pczt();
        let external_expired = DeliveryClaim::from_parts(
            evidence.clone(),
            SignerOwnership::External,
            ClaimStatus::ExternalSigningExpiredUnmined,
            None,
            Some(staged_pczt.clone()),
            None,
            None,
            policy.fingerprint(),
            None,
        )
        .unwrap();
        let external_snapshot = DeliverySnapshot::from_parts(
            DeliveryRevision::from_stored(TEST_REVISION).unwrap(),
            MigrationRunIdentity::from_stored([TEST_TOKEN_BYTE; DIGEST_LENGTH]),
            DeliveryRunFingerprint::Immediate(proposal.digest()),
            SourceReservationOwner::from_stored([TEST_FINGERPRINT_BYTE; DIGEST_LENGTH]),
            DeliveryPhase::Abandoned,
            StorageFinality::Finalized(release),
            0,
            None,
            Some(policy.clone()),
            None,
            vec![external_expired],
        )
        .unwrap();
        assert!(external_snapshot.released_after_resolved_unmined_exposure());

        let unresolved_external = DeliveryClaim::from_parts(
            evidence,
            SignerOwnership::External,
            ClaimStatus::AwaitingExternalSignature,
            None,
            Some(staged_pczt),
            None,
            None,
            policy.fingerprint(),
            None,
        )
        .unwrap();
        assert_eq!(
            DeliverySnapshot::from_parts(
                DeliveryRevision::from_stored(TEST_REVISION).unwrap(),
                MigrationRunIdentity::from_stored([TEST_TOKEN_BYTE; DIGEST_LENGTH]),
                DeliveryRunFingerprint::Immediate(proposal.digest()),
                SourceReservationOwner::from_stored([TEST_FINGERPRINT_BYTE; DIGEST_LENGTH]),
                DeliveryPhase::Abandoned,
                StorageFinality::Finalized(release),
                0,
                None,
                Some(policy),
                None,
                vec![unresolved_external],
            ),
            Err(SnapshotValidationError::MissingFinalityArchive)
        );
    }

    #[test]
    fn immediate_proposal_codec_round_trips_and_rejects_corruption() {
        let proposal = immediate_proposal(vec![TEST_ARTIFACT_BYTE, TEST_TOKEN_BYTE]);
        let canonical = proposal.canonical_bytes();
        assert_eq!(ImmediateProposal::decode(&canonical).unwrap(), proposal);

        let mut unknown_version = canonical.clone();
        unknown_version[0] = UNKNOWN_CODEC_TAG;
        assert!(ImmediateProposal::decode(&unknown_version).is_err());

        let mut trailing = canonical;
        trailing.push(UNKNOWN_CODEC_TAG);
        assert!(ImmediateProposal::decode(&trailing).is_err());
        assert_eq!(
            ImmediateProposalPayload::try_from(Vec::new()),
            Err(ImmediateProposalError::EmptyPayload)
        );
    }

    #[test]
    fn immediate_proposal_codec_enforces_the_exact_envelope_bound() {
        let proposal = immediate_proposal(vec![
            TEST_ARTIFACT_BYTE;
            MAX_IMMEDIATE_PROPOSAL_PAYLOAD_BYTES
        ]);
        let canonical = proposal.canonical_bytes();
        assert_eq!(canonical.len(), MAX_IMMEDIATE_PROPOSAL_ENVELOPE_BYTES);
        assert_eq!(ImmediateProposal::decode(&canonical).unwrap(), proposal);

        let mut oversized_envelope = canonical;
        oversized_envelope.push(UNKNOWN_CODEC_TAG);
        assert_eq!(
            oversized_envelope.len(),
            MAX_IMMEDIATE_PROPOSAL_ENVELOPE_BYTES + 1
        );
        assert!(ImmediateProposal::decode(&oversized_envelope).is_err());
        assert_eq!(
            ImmediateProposalPayload::try_from(vec![
                TEST_ARTIFACT_BYTE;
                MAX_IMMEDIATE_PROPOSAL_PAYLOAD_BYTES + 1
            ]),
            Err(ImmediateProposalError::PayloadTooLarge)
        );
    }

    #[test]
    fn exact_immediate_transaction_decoding_binds_canonical_bytes_and_proposal_expiry() {
        let (_, evidence) = immediate_evidence();
        let DeliveryArtifactEvidence::Immediate(evidence) = evidence else {
            unreachable!("test helper always returns immediate evidence");
        };
        let transaction = empty_v6_transaction(evidence.expiry_height());
        let exact = exact_immediate_transaction(&evidence, &transaction).unwrap();
        assert_eq!(exact.consensus_expiry_height(), evidence.expiry_height());
        let decoded =
            decode_exact_immediate_transaction(&evidence, exact.bytes(), BranchId::Nu6_3).unwrap();
        assert_eq!(decoded, exact);

        let mut trailing = exact.bytes().to_vec();
        trailing.push(UNKNOWN_CODEC_TAG);
        assert!(matches!(
            decode_exact_immediate_transaction(&evidence, &trailing, BranchId::Nu6_3),
            Err(ExactTransactionError::TrailingBytes)
        ));
        let oversized = vec![0; MAX_EXACT_TRANSACTION_BYTES + 1];
        assert!(matches!(
            decode_exact_immediate_transaction(&evidence, &oversized, BranchId::Nu6_3),
            Err(ExactTransactionError::TooLarge)
        ));

        let wrong_expiry = empty_v6_transaction(BlockHeight::from_u32(
            u32::from(evidence.expiry_height()) + 1,
        ));
        assert!(matches!(
            exact_immediate_transaction(&evidence, &wrong_expiry),
            Err(ExactTransactionError::ImmediateExpiryMismatch { proposal, consensus })
                if proposal == evidence.expiry_height()
                    && consensus == wrong_expiry.expiry_height()
        ));
    }

    #[test]
    fn finality_archive_round_trips_and_detects_rewind_or_lost_evidence() {
        let release = ReservationRelease::at(BlockHeight::from_u32(TEST_RELEASE_HEIGHT));
        let transfer = FinalizedTransferEvidence::new(
            DeliveryArtifactIdentity::Immediate(ImmediateArtifactIdentity::from_stored(
                [TEST_ARTIFACT_BYTE; DIGEST_LENGTH],
            )),
            TxId::from_bytes([TEST_TXID_BYTE; DIGEST_LENGTH]),
            ExactTransactionDigest::from_transaction_bytes(&[TEST_TRANSACTION_BYTE]),
            BlockHeight::from_u32(TEST_RELEASE_HEIGHT - 1),
        );
        let archive = FinalityArchive::new(release, vec![transfer]).unwrap();
        let canonical = archive.canonical_bytes();
        assert_eq!(FinalityArchive::decode(&canonical).unwrap(), archive);
        assert_eq!(
            archive.audit(BlockHeight::from_u32(TEST_RELEASE_HEIGHT), &[transfer]),
            FinalityAuditResult::Consistent
        );
        assert_eq!(
            archive.audit(BlockHeight::from_u32(TEST_RELEASE_HEIGHT - 1), &[transfer]),
            FinalityAuditResult::RecoveryRequired(
                StorageRecoveryReason::RewoundBeyondFinalityHorizon
            )
        );
        assert_eq!(
            archive.audit(BlockHeight::from_u32(TEST_RELEASE_HEIGHT), &[]),
            FinalityAuditResult::RecoveryRequired(StorageRecoveryReason::TransferEvidenceLost)
        );

        let mut trailing = canonical;
        trailing.push(UNKNOWN_CODEC_TAG);
        assert!(FinalityArchive::decode(&trailing).is_err());
        let oversized = vec![0; MAX_FINALITY_ARCHIVE_BYTES + 1];
        assert!(FinalityArchive::decode(&oversized).is_err());
    }

    #[test]
    fn finalized_exposed_history_requires_terminal_rollover_for_canonical_replacement() {
        let (proposal, evidence) = immediate_evidence();
        let policy = validated_policy();
        let exact_bytes = vec![TEST_TRANSACTION_BYTE];
        let exact = ExactTransaction {
            artifact_identity: evidence.identity(),
            txid: TxId::from_bytes([TEST_TXID_BYTE; DIGEST_LENGTH]),
            consensus_expiry_height: evidence.expiry_height(),
            digest: ExactTransactionDigest::from_transaction_bytes(&exact_bytes),
            bytes: exact_bytes,
        };
        let confirmed = DeliveryClaim::from_parts(
            evidence,
            SignerOwnership::Sdk,
            ClaimStatus::Confirmed,
            None,
            None,
            None,
            Some(exact.clone()),
            policy.fingerprint(),
            None,
        )
        .unwrap();
        let release = ReservationRelease::at(BlockHeight::from_u32(TEST_RELEASE_HEIGHT));
        let archive = FinalityArchive::new(
            release,
            vec![FinalizedTransferEvidence::new(
                exact.artifact_identity(),
                exact.txid(),
                exact.digest(),
                BlockHeight::from_u32(TEST_RELEASE_HEIGHT - 1),
            )],
        )
        .unwrap();
        let delivery = DeliverySnapshot::from_parts_with_immediate_gross_authorization(
            DeliveryRevision::from_stored(TEST_REVISION).unwrap(),
            MigrationRunIdentity::from_stored([TEST_TOKEN_BYTE; DIGEST_LENGTH]),
            DeliveryRunFingerprint::Immediate(proposal.digest()),
            SourceReservationOwner::from_stored([TEST_FINGERPRINT_BYTE; DIGEST_LENGTH]),
            DeliveryPhase::Active,
            StorageFinality::Finalized(release),
            0,
            Some(archive),
            Some(policy),
            None,
            Some(Zatoshis::ZERO),
            vec![confirmed],
        )
        .unwrap();
        let runtime = MigrationRuntimeSnapshot::from_observed(
            None,
            Some(delivery),
            vec![],
            DeliverySchemaProvenance::Compatible(DeliverySchemaVersion::from_u32(1).unwrap()),
            LegacyCutoverStatus::Fresh,
            DestinationSpendability::Spendable,
        );
        assert_eq!(
            runtime.account_deletion_authorization(),
            AccountDeletionAuthorization::Allowed
        );
        assert!(matches!(
            runtime.canonical_mutation_authorization(),
            CanonicalMutationAuthorization::Blocked(CanonicalMutationBlockReason::DeliveryOwned(_))
        ));
    }

    #[test]
    fn external_signer_evidence_binds_staged_and_returned_pczt() {
        use pczt::roles::creator::Creator;
        use zcash_protocol::consensus::BranchId;

        let (pczt, staged) = external_signing_pczt();
        let signed = staged.merge_signed(pczt).unwrap();
        assert_eq!(signed.staged_digest(), staged.digest());

        let mismatched = Creator::new(
            u32::from(BranchId::Nu6_3),
            TEST_RELEASE_HEIGHT + 1,
            133,
            None,
            None,
        )
        .unwrap()
        .build()
        .unwrap()
        .serialize()
        .unwrap();
        assert!(staged.merge_signed(mismatched).is_err());
        assert!(ExternalSigningPczt::parse(Vec::new()).is_err());
    }

    #[test]
    fn external_signer_exposure_blocks_cancellation_until_positive_source_unspent_expiry() {
        let policy = validated_policy();
        let policy_fingerprint = policy.fingerprint();
        let (proposal, evidence) = immediate_evidence();
        let (pczt_bytes, staged_pczt) = external_signing_pczt();

        let awaiting = DeliveryClaim::from_parts(
            evidence.clone(),
            SignerOwnership::External,
            ClaimStatus::AwaitingExternalSignature,
            None,
            Some(staged_pczt.clone()),
            None,
            None,
            policy_fingerprint,
            None,
        )
        .unwrap();
        assert!(awaiting.has_external_signing_exposure());
        assert!(
            !immediate_snapshot_with_claim(&proposal, policy.clone(), awaiting).safe_to_cancel()
        );

        let signed_pczt = staged_pczt.merge_signed(pczt_bytes).unwrap();
        let exact_bytes = vec![TEST_TRANSACTION_BYTE];
        let exact_transaction = ExactTransaction {
            artifact_identity: evidence.identity(),
            txid: TxId::from_bytes([TEST_TXID_BYTE; DIGEST_LENGTH]),
            consensus_expiry_height: evidence.expiry_height(),
            digest: ExactTransactionDigest::from_transaction_bytes(&exact_bytes),
            bytes: exact_bytes,
        };
        let staged_transaction = DeliveryClaim::from_parts(
            evidence.clone(),
            SignerOwnership::External,
            ClaimStatus::Staged,
            None,
            Some(staged_pczt.clone()),
            Some(signed_pczt),
            Some(exact_transaction),
            policy_fingerprint,
            None,
        )
        .unwrap();
        assert!(staged_transaction.has_external_signing_exposure());
        assert!(staged_transaction.exact_transaction().is_some());
        assert!(
            !immediate_snapshot_with_claim(&proposal, policy.clone(), staged_transaction)
                .safe_to_cancel()
        );

        let positively_expired = DeliveryClaim::from_parts(
            evidence,
            SignerOwnership::External,
            ClaimStatus::ExternalSigningExpiredUnmined,
            None,
            Some(staged_pczt),
            None,
            None,
            policy_fingerprint,
            None,
        )
        .unwrap();
        assert!(positively_expired.has_external_signing_exposure());
        assert!(positively_expired.exact_transaction().is_none());
        assert!(
            immediate_snapshot_with_claim(&proposal, policy, positively_expired).safe_to_cancel()
        );
    }

    #[test]
    fn external_signing_expiry_status_rejects_missing_pczt_or_exact_transaction() {
        let policy_fingerprint = validated_policy().fingerprint();
        let (_, evidence) = immediate_evidence();
        let (_, staged_pczt) = external_signing_pczt();
        let exact_bytes = vec![TEST_TRANSACTION_BYTE];
        let exact_transaction = ExactTransaction {
            artifact_identity: evidence.identity(),
            txid: TxId::from_bytes([TEST_TXID_BYTE; DIGEST_LENGTH]),
            consensus_expiry_height: evidence.expiry_height(),
            digest: ExactTransactionDigest::from_transaction_bytes(&exact_bytes),
            bytes: exact_bytes,
        };

        assert_eq!(
            DeliveryClaim::from_parts(
                evidence.clone(),
                SignerOwnership::External,
                ClaimStatus::ExternalSigningExpiredUnmined,
                None,
                None,
                None,
                None,
                policy_fingerprint,
                None,
            ),
            Err(ClaimValidationError::InvalidExternalSigningState)
        );
        assert_eq!(
            DeliveryClaim::from_parts(
                evidence,
                SignerOwnership::External,
                ClaimStatus::ExternalSigningExpiredUnmined,
                None,
                Some(staged_pczt),
                None,
                Some(exact_transaction),
                policy_fingerprint,
                None,
            ),
            Err(ClaimValidationError::InvalidExactTransaction)
        );
        assert_eq!(
            ClaimStatus::from_stored(ClaimStatus::ExternalSigningExpiredUnmined.as_str()),
            Some(ClaimStatus::ExternalSigningExpiredUnmined)
        );
    }

    #[test]
    fn migration_state_archive_round_trips_every_status_and_transaction_state() {
        let statuses = [
            MigrationStatus::Planning,
            MigrationStatus::Committed,
            MigrationStatus::InProgress,
            MigrationStatus::Complete,
            MigrationStatus::Failed,
        ];
        let transaction_states = [
            MigrationTxState::AwaitingSignature,
            MigrationTxState::Signed,
            MigrationTxState::Proved,
            MigrationTxState::Broadcast {
                txid: TxId::from_bytes([TEST_TXID_BYTE; DIGEST_LENGTH]),
            },
            MigrationTxState::Mined {
                height: BlockHeight::from_u32(TEST_RELEASE_HEIGHT - 1),
            },
        ];

        for status in statuses {
            for transaction_state in transaction_states {
                let state = archive_test_state(status, transaction_state, TEST_ARTIFACT_BYTE);
                let archive = encode_migration_state_archive(&state).unwrap();
                assert_eq!(
                    archive.canonical_bytes()[0],
                    MIGRATION_STATE_ARCHIVE_VERSION
                );
                assert_eq!(archive.fingerprint(), migration_state_fingerprint(&state));
                assert_eq!(
                    decode_migration_state_archive(
                        archive.canonical_bytes(),
                        archive.fingerprint()
                    )
                    .unwrap(),
                    state
                );
            }
        }
    }

    #[test]
    fn migration_state_archive_rejects_future_corrupt_trailing_or_wrong_fingerprint() {
        let state = archive_test_state(
            MigrationStatus::InProgress,
            MigrationTxState::Signed,
            TEST_ARTIFACT_BYTE,
        );
        let archive = encode_migration_state_archive(&state).unwrap();

        let mut future = archive.canonical_bytes().to_vec();
        future[0] = MIGRATION_STATE_ARCHIVE_VERSION + 1;
        let future_fingerprint =
            MigrationStateFingerprint::from_bytes(digest(STATE_PERSONAL, &future));
        assert!(decode_migration_state_archive(&future, future_fingerprint).is_err());

        let corrupt = &archive.canonical_bytes()[..archive.canonical_bytes().len() - 1];
        let corrupt_fingerprint =
            MigrationStateFingerprint::from_bytes(digest(STATE_PERSONAL, corrupt));
        assert!(decode_migration_state_archive(corrupt, corrupt_fingerprint).is_err());

        let mut trailing = archive.canonical_bytes().to_vec();
        trailing.push(UNKNOWN_CODEC_TAG);
        let trailing_fingerprint =
            MigrationStateFingerprint::from_bytes(digest(STATE_PERSONAL, &trailing));
        assert!(decode_migration_state_archive(&trailing, trailing_fingerprint).is_err());

        assert!(
            decode_migration_state_archive(
                archive.canonical_bytes(),
                MigrationStateFingerprint::from_bytes([UNKNOWN_CODEC_TAG; DIGEST_LENGTH]),
            )
            .is_err()
        );
    }

    #[test]
    fn canonical_materialization_transition_is_narrow_and_artifact_bound() {
        let expected = archive_test_state(
            MigrationStatus::Committed,
            MigrationTxState::AwaitingSignature,
            TEST_ARTIFACT_BYTE,
        );
        let signed = archive_test_state(
            MigrationStatus::Committed,
            MigrationTxState::Signed,
            TEST_TRANSACTION_BYTE,
        );
        let identity = DeliveryArtifactIdentity::Scheduled(ScheduledArtifactIdentity::new(
            MigrationTxId::new(0),
            migration_transaction_fingerprint(&expected, &expected.transactions()[0]),
        ));
        assert_eq!(
            migration_transaction_fingerprint(&expected, &expected.transactions()[0]),
            migration_transaction_fingerprint(&signed, &signed.transactions()[0]),
            "signing changes exact PCZT bytes but not the attempt identity"
        );
        let mut released = signed.clone();
        released.transactions[0].lock_owner = None;
        assert_eq!(
            migration_transaction_fingerprint(&signed, &signed.transactions()[0]),
            migration_transaction_fingerprint(&released, &released.transactions()[0]),
            "terminal source release clears reservation ownership without changing attempt identity"
        );
        assert_ne!(
            migration_state_fingerprint(&signed),
            migration_state_fingerprint(&released),
            "the complete canonical archive still records reservation ownership"
        );
        assert_ne!(
            migration_state_fingerprint(&expected),
            migration_state_fingerprint(&signed),
            "the complete canonical state still binds exact lifecycle and PCZT bytes"
        );
        let transition = CanonicalMaterializationTransition::new(
            DeliveryRevision::from_stored(TEST_REVISION).unwrap(),
            MigrationRunIdentity::from_stored([TEST_TOKEN_BYTE; DIGEST_LENGTH]),
            &expected,
            identity,
            ClaimToken::from_stored([TEST_TOKEN_BYTE; DIGEST_LENGTH]),
            PolicyFingerprint::from_bytes([TEST_FINGERPRINT_BYTE; DIGEST_LENGTH]),
            signed.clone(),
        )
        .unwrap();
        assert_eq!(
            transition.purpose(),
            CanonicalMaterializationPurpose::ExternalSignature
        );
        assert_eq!(transition.claim_kind(), ClaimKind::Materialization);
        assert_eq!(transition.artifact_identity(), identity);
        assert_eq!(transition.successor_state(), &signed);

        assert_eq!(
            CanonicalMaterializationTransition::new(
                DeliveryRevision::from_stored(TEST_REVISION).unwrap(),
                MigrationRunIdentity::from_stored([TEST_TOKEN_BYTE; DIGEST_LENGTH]),
                &expected,
                DeliveryArtifactIdentity::Immediate(ImmediateArtifactIdentity::from_stored(
                    [TEST_ARTIFACT_BYTE; DIGEST_LENGTH],
                )),
                ClaimToken::from_stored([TEST_TOKEN_BYTE; DIGEST_LENGTH]),
                PolicyFingerprint::from_bytes([TEST_FINGERPRINT_BYTE; DIGEST_LENGTH]),
                signed.clone(),
            ),
            Err(CanonicalMaterializationTransitionError::InvalidArtifactLane)
        );
        assert_eq!(
            CanonicalMaterializationTransition::new(
                DeliveryRevision::from_stored(TEST_REVISION).unwrap(),
                MigrationRunIdentity::from_stored([TEST_TOKEN_BYTE; DIGEST_LENGTH]),
                &expected,
                DeliveryArtifactIdentity::Scheduled(ScheduledArtifactIdentity::new(
                    MigrationTxId::new(99),
                    migration_transaction_fingerprint(&expected, &expected.transactions()[0]),
                )),
                ClaimToken::from_stored([TEST_TOKEN_BYTE; DIGEST_LENGTH]),
                PolicyFingerprint::from_bytes([TEST_FINGERPRINT_BYTE; DIGEST_LENGTH]),
                signed.clone(),
            ),
            Err(CanonicalMaterializationTransitionError::ArtifactNotFound)
        );
        let invalid_order = archive_test_state(
            MigrationStatus::Committed,
            MigrationTxState::Proved,
            TEST_TRANSACTION_BYTE,
        );
        assert_eq!(
            CanonicalMaterializationTransition::new(
                DeliveryRevision::from_stored(TEST_REVISION).unwrap(),
                MigrationRunIdentity::from_stored([TEST_TOKEN_BYTE; DIGEST_LENGTH]),
                &expected,
                identity,
                ClaimToken::from_stored([TEST_TOKEN_BYTE; DIGEST_LENGTH]),
                PolicyFingerprint::from_bytes([TEST_FINGERPRINT_BYTE; DIGEST_LENGTH]),
                invalid_order,
            ),
            Err(CanonicalMaterializationTransitionError::InvalidTransitionOrdering)
        );
    }

    #[test]
    fn canonical_materialization_receipts_bind_exact_claim_state_and_evidence() {
        let revision = DeliveryRevision::from_stored(TEST_REVISION).unwrap();
        let run_identity = MigrationRunIdentity::from_stored([TEST_TOKEN_BYTE; DIGEST_LENGTH]);
        let reservation_owner =
            SourceReservationOwner::from_stored([TEST_FINGERPRINT_BYTE; DIGEST_LENGTH]);
        let token = ClaimToken::from_stored([TEST_TRANSACTION_BYTE; DIGEST_LENGTH]);
        let policy = validated_policy();
        let (unsigned_bytes, staged_pczt) = external_signing_pczt();
        let signer_returned =
            pczt_with_global_enrichment(&unsigned_bytes, "test-signer", TEST_TRANSACTION_BYTE);
        let signed_pczt = staged_pczt.merge_signed(signer_returned).unwrap();

        let mut awaiting = archive_test_state(
            MigrationStatus::Committed,
            MigrationTxState::AwaitingSignature,
            TEST_ARTIFACT_BYTE,
        );
        awaiting.transactions[0].pczt = unsigned_bytes;
        awaiting.transactions[0].expiry_height = BlockHeight::from_u32(TEST_RELEASE_HEIGHT);
        let mut signed = awaiting.clone();
        signed.transactions[0].pczt = signed_pczt.bytes().to_vec();
        signed.transactions[0].state = MigrationTxState::Signed;
        let identity = DeliveryArtifactIdentity::Scheduled(ScheduledArtifactIdentity::new(
            MigrationTxId::new(0),
            migration_transaction_fingerprint(&awaiting, &awaiting.transactions()[0]),
        ));
        let signing_transition = CanonicalMaterializationTransition::new(
            revision,
            run_identity,
            &awaiting,
            identity,
            token,
            policy.fingerprint(),
            signed.clone(),
        )
        .unwrap();
        let signing_claim = DeliveryClaim::from_parts(
            DeliveryArtifactEvidence::Scheduled(
                scheduled_artifact_evidence(&awaiting, MigrationTxId::new(0)).unwrap(),
            ),
            SignerOwnership::External,
            ClaimStatus::AwaitingExternalSignature,
            Some(
                DeliveryLease::new(
                    ClaimKind::Materialization,
                    token,
                    test_instant(TEST_INSTANT_MILLIS),
                    LeaseDuration::from_millis(TEST_LEASE_MILLIS).unwrap(),
                )
                .unwrap(),
            ),
            Some(staged_pczt),
            Some(signed_pczt),
            None,
            policy.fingerprint(),
            None,
        )
        .unwrap();
        let signed_delivery = DeliverySnapshot::from_parts(
            revision.checked_next().unwrap(),
            run_identity,
            DeliveryRunFingerprint::Scheduled(migration_state_fingerprint(&signed)),
            reservation_owner,
            DeliveryPhase::Active,
            StorageFinality::Active,
            1,
            None,
            Some(policy.clone()),
            None,
            vec![signing_claim],
        )
        .unwrap();
        let signing_receipt = CanonicalMaterializationReceipt::from_committed_parts(
            signing_transition,
            signed_delivery,
        )
        .unwrap();
        assert_eq!(signing_receipt.canonical_state(), &signed);

        let proved_pczt =
            pczt_with_global_enrichment(signed.transactions[0].pczt(), "test-proof", 1);
        let mut proved = signed.clone();
        proved.transactions[0].pczt = proved_pczt;
        proved.transactions[0].state = MigrationTxState::Proved;
        let exact = ExactTransaction::from_transaction(
            identity,
            &empty_v6_transaction(BlockHeight::from_u32(TEST_RELEASE_HEIGHT)),
        )
        .unwrap();
        let proof_transition = CanonicalMaterializationTransition {
            expected_revision: revision,
            run_identity,
            expected_state_fingerprint: migration_state_fingerprint(&signed),
            artifact_identity: identity,
            token,
            purpose: CanonicalMaterializationPurpose::Proof,
            proof_transaction: Some(exact.clone()),
            expected_policy_fingerprint: policy.fingerprint(),
            successor_state: proved.clone(),
        };
        let staged_claim = DeliveryClaim::from_parts(
            DeliveryArtifactEvidence::Scheduled(
                scheduled_artifact_evidence(&proved, MigrationTxId::new(0)).unwrap(),
            ),
            SignerOwnership::Sdk,
            ClaimStatus::Staged,
            None,
            None,
            None,
            Some(exact),
            policy.fingerprint(),
            None,
        )
        .unwrap();
        let proved_delivery = DeliverySnapshot::from_parts(
            revision.checked_next().unwrap(),
            run_identity,
            DeliveryRunFingerprint::Scheduled(migration_state_fingerprint(&proved)),
            reservation_owner,
            DeliveryPhase::Active,
            StorageFinality::Active,
            1,
            None,
            Some(policy.clone()),
            None,
            vec![staged_claim],
        )
        .unwrap();
        let proof_receipt = CanonicalMaterializationReceipt::from_committed_parts(
            proof_transition,
            proved_delivery,
        )
        .unwrap();
        assert_eq!(proof_receipt.canonical_state(), &proved);

        use pczt::roles::creator::Creator;
        let different_global = Creator::new(
            u32::from(BranchId::Nu6_3),
            TEST_RELEASE_HEIGHT,
            134,
            None,
            None,
        )
        .unwrap()
        .build()
        .unwrap()
        .serialize()
        .unwrap();
        let mut redirected = signed.clone();
        redirected.transactions[0].pczt = different_global;
        redirected.transactions[0].state = MigrationTxState::Proved;
        assert_eq!(
            CanonicalMaterializationTransition::new(
                revision,
                run_identity,
                &signed,
                identity,
                token,
                policy.fingerprint(),
                redirected,
            ),
            Err(CanonicalMaterializationTransitionError::InvalidProofEnrichment)
        );
    }

    #[test]
    fn rollover_stamps_one_store_owner_and_receipts_the_exact_canonical_state() {
        let predecessor = archive_test_state(
            MigrationStatus::Complete,
            MigrationTxState::Mined {
                height: BlockHeight::from_u32(TEST_RELEASE_HEIGHT - 1),
            },
            TEST_ARTIFACT_BYTE,
        );
        let mut successor = archive_test_state(
            MigrationStatus::Committed,
            MigrationTxState::Signed,
            TEST_TRANSACTION_BYTE,
        );
        successor.transactions[0].lock_owner = None;
        let revision = DeliveryRevision::from_stored(TEST_REVISION).unwrap();
        let predecessor_run = MigrationRunIdentity::from_stored([TEST_TOKEN_BYTE; DIGEST_LENGTH]);
        let predecessor_owner =
            SourceReservationOwner::from_stored([TEST_FINGERPRINT_BYTE; DIGEST_LENGTH]);
        let request = ReservationRollover::replace_terminal(
            revision,
            predecessor_run,
            predecessor_owner,
            &predecessor,
            successor.clone(),
        )
        .unwrap();
        let canonical =
            request.successor_state_with_lock_owner(LockOwner::new([OTHER_CLOCK_SESSION_BYTE; 32]));
        assert!(canonical.transactions().iter().all(|transaction| {
            transaction.lock_owner() == Some([OTHER_CLOCK_SESSION_BYTE; 32])
        }));
        let snapshot = DeliverySnapshot::from_parts(
            revision.checked_next().unwrap(),
            MigrationRunIdentity::from_stored([TEST_TRANSACTION_BYTE; DIGEST_LENGTH]),
            DeliveryRunFingerprint::Scheduled(migration_state_fingerprint(&canonical)),
            SourceReservationOwner::from_stored([TEST_ARTIFACT_BYTE; DIGEST_LENGTH]),
            DeliveryPhase::Active,
            StorageFinality::Active,
            1,
            None,
            Some(validated_policy()),
            None,
            vec![],
        )
        .unwrap();
        let receipt = ReservationRolloverReceipt::from_committed_parts(
            request.clone(),
            canonical.clone(),
            snapshot,
        )
        .unwrap();
        assert_eq!(receipt.canonical_state(), &canonical);

        assert!(
            ReservationRolloverReceipt::from_committed_parts(
                request.clone(),
                successor.clone(),
                receipt.successor().clone(),
            )
            .is_none()
        );
        let mut preowned = successor;
        preowned.transactions[0].lock_owner = Some([TEST_TOKEN_BYTE; 32]);
        assert_eq!(
            ReservationRollover::replace_terminal(
                revision,
                predecessor_run,
                predecessor_owner,
                &predecessor,
                preowned,
            ),
            Err(ReservationRolloverValidationError::SuccessorAlreadyOwned)
        );
    }

    #[test]
    fn expired_rebuild_stays_in_run_and_changes_only_attempt_identity() {
        let expected = archive_test_state(
            MigrationStatus::InProgress,
            MigrationTxState::Proved,
            TEST_ARTIFACT_BYTE,
        );
        let prior_artifact = ScheduledArtifactIdentity::new(
            MigrationTxId::new(0),
            migration_transaction_fingerprint(&expected, &expected.transactions()[0]),
        );
        let mut successor = expected.clone();
        successor.transactions[0].pczt = vec![TEST_TRANSACTION_BYTE, TEST_TXID_BYTE];
        successor.transactions[0].state = MigrationTxState::Signed;
        successor.transactions[0].scheduled_height =
            BlockHeight::from_u32(TEST_RELEASE_HEIGHT + 10);
        successor.transactions[0].expiry_height = BlockHeight::from_u32(TEST_RELEASE_HEIGHT + 100);
        successor.transactions[0].anchor_boundary =
            Some(BlockHeight::from_u32(TEST_RELEASE_HEIGHT + 1));

        let revision = DeliveryRevision::from_stored(TEST_REVISION).unwrap();
        let run_identity = MigrationRunIdentity::from_stored([TEST_TOKEN_BYTE; DIGEST_LENGTH]);
        let reservation_owner =
            SourceReservationOwner::from_stored([TEST_FINGERPRINT_BYTE; DIGEST_LENGTH]);
        let request = ExpiredTransferRebuild::new(
            revision,
            run_identity,
            reservation_owner,
            &expected,
            prior_artifact,
            SignerOwnership::Sdk,
            RebuiltTransferSuccessor::from_test_parts(
                expected.clone(),
                successor.clone(),
                prior_artifact.transaction_id(),
                false,
            ),
        )
        .unwrap();
        assert_eq!(request.run_identity(), run_identity);
        assert_eq!(request.source_reservation_owner(), reservation_owner);
        assert_eq!(request.prior_artifact(), prior_artifact);
        assert_eq!(request.signer_ownership(), SignerOwnership::Sdk);
        assert_ne!(
            prior_artifact.transaction_fingerprint(),
            migration_transaction_fingerprint(&successor, &successor.transactions()[0])
        );
        assert_eq!(request.successor_state(), &successor);

        let policy = validated_policy();
        let replacement_attempt = request.successor_artifact();
        let materialization_token = ClaimToken::from_stored([TEST_TRANSACTION_BYTE; DIGEST_LENGTH]);
        let claim = DeliveryClaim::from_parts(
            DeliveryArtifactEvidence::Scheduled(
                scheduled_artifact_evidence(&successor, MigrationTxId::new(0)).unwrap(),
            ),
            SignerOwnership::Sdk,
            ClaimStatus::Materializing,
            Some(
                DeliveryLease::new(
                    ClaimKind::Materialization,
                    materialization_token,
                    test_instant(TEST_INSTANT_MILLIS),
                    LeaseDuration::from_millis(TEST_LEASE_MILLIS).unwrap(),
                )
                .unwrap(),
            ),
            None,
            None,
            None,
            policy.fingerprint(),
            None,
        )
        .unwrap();
        let committed = DeliverySnapshot::from_parts(
            revision.checked_next().unwrap(),
            run_identity,
            DeliveryRunFingerprint::Scheduled(migration_state_fingerprint(&successor)),
            reservation_owner,
            DeliveryPhase::Active,
            StorageFinality::Active,
            1,
            None,
            Some(policy),
            None,
            vec![claim],
        )
        .unwrap();
        let receipt =
            ExpiredTransferRebuildReceipt::from_committed_parts(request.clone(), committed)
                .unwrap();
        assert_eq!(receipt.archived_attempt(), prior_artifact);
        assert_eq!(receipt.replacement_attempt(), replacement_attempt);
        assert_eq!(receipt.canonical_state(), &successor);
        assert_eq!(receipt.delivery().run_identity(), run_identity);
        assert_eq!(
            receipt.delivery().source_reservation_owner(),
            reservation_owner
        );

        let mut wrong_successor = successor;
        wrong_successor.note_split = NoteSplitPlan::from_stored_parts(
            vec![],
            Zatoshis::ZERO,
            None,
            Zatoshis::ZERO,
            Zatoshis::ZERO,
            Zatoshis::ZERO,
        )
        .unwrap();
        assert_eq!(
            ExpiredTransferRebuild::new(
                revision,
                run_identity,
                reservation_owner,
                &expected,
                prior_artifact,
                SignerOwnership::Sdk,
                RebuiltTransferSuccessor::from_test_parts(
                    expected.clone(),
                    wrong_successor,
                    prior_artifact.transaction_id(),
                    false,
                ),
            ),
            Err(ExpiredTransferRebuildValidationError::UnrelatedCanonicalMutation)
        );
    }

    #[test]
    fn fixed_width_types_round_trip_and_reject_truncation() {
        let fingerprint = PolicyFingerprint::from_bytes([TEST_FINGERPRINT_BYTE; DIGEST_LENGTH]);
        let mut encoded = Vec::new();
        fingerprint.write(&mut encoded).unwrap();
        assert_eq!(
            PolicyFingerprint::read(encoded.as_slice()).unwrap(),
            fingerprint
        );
        assert!(PolicyFingerprint::read(&encoded[..DIGEST_LENGTH - 1]).is_err());

        let owner = SourceReservationOwner::from_stored([TEST_TOKEN_BYTE; DIGEST_LENGTH]);
        let mut encoded_owner = Vec::new();
        owner.write(&mut encoded_owner).unwrap();
        assert_eq!(encoded_owner.len(), DIGEST_LENGTH);
        assert_eq!(
            SourceReservationOwner::decode(&encoded_owner).unwrap(),
            owner
        );
        encoded_owner.push(UNKNOWN_CODEC_TAG);
        assert!(SourceReservationOwner::decode(&encoded_owner).is_err());
    }
}
