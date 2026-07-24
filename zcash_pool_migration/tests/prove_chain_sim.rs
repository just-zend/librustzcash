//! End-to-end, real-proving chain simulation of a whole migration over a genuine wallet.
//!
//! This drives a real (in-memory) `zcash_client_sqlite` `WalletDb` through the
//! `zcash_client_backend` testing framework, exercising the migration engine's proving path against
//! the wallet's OWN Orchard commitment tree instead of a hand-built one:
//!
//! 1. fund an account with a spendable Orchard note and commit a migration over the
//!    [`WalletMigration`] adapter (so the plan, the prep transactions, and the transfers all come
//!    from the real wallet);
//! 2. prove each PREPARATION transaction against the chain tip (installing the source anchor and its
//!    spends' witnesses through the PCZT `Updater` role), extract it, mine it, and scan it — so its
//!    minted funding notes become genuinely scanned received notes with real tree positions;
//! 3. advance the chain to each TRANSFER's drawn anchor boundary and prove it (resolving the funding
//!    note's witness from the wallet's tree by the nullifier its spend reveals), extract it, and
//!    assert both its Orchard and Ironwood bundles verify.
//!
//! [`WalletMigrationProver`] resolves every spend's tree position from the wallet's own note store
//! (no hand-supplied map), so this test also covers that production lookup path. It keeps each
//! transfer's boundary within `zcash_client_sqlite`'s checkpoint pruning window (100 blocks of the
//! tip), so it needs no migration anchor-checkpoint retention, which is a wallet backend concern
//! out of the migration crate's control.
#![cfg(all(feature = "wallet", feature = "test-dependencies"))]

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::fmt;
use std::rc::Rc;

use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;

use pczt::roles::tx_extractor::TransactionExtractor;

use zcash_client_backend::data_api::testing::{
    AddressType, TestBuilder, TestState, orchard::OrchardPoolTester, pool::ShieldedPoolTester,
};
use zcash_client_backend::data_api::wallet::{
    ConfirmationsPolicy, TargetHeight, decrypt_and_store_transaction, input_selection::LockFilter,
};
use zcash_client_backend::data_api::{Account, InputSource, WalletRead, WalletWrite};
use zcash_client_backend::wallet::{LockOwner, OutputRef};
// The wallet, block cache, DB factory, and Orchard-checkpoint helper come from
// `zcash_client_sqlite`'s own test harness, exposed under its `test-dependencies` feature.
use zcash_client_sqlite::testing::db::{TestDb, TestDbFactory};
use zcash_client_sqlite::testing::{BlockCache, highest_rooted_orchard_checkpoint};
use zcash_keys::keys::UnifiedSpendingKey;

use zcash_primitives::block::BlockHash;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::local_consensus::LocalNetwork;
use zcash_protocol::value::testing::zats;
use zcash_protocol::value::{COIN, Zatoshis};
use zcash_protocol::{PoolType, ShieldedPool};

use zcash_pool_migration::delivery::{ReservationRelease, SourceReservationOwner, StorageFinality};
use zcash_pool_migration::engine::{
    self, MigrationState, MigrationStatus, MigrationTxId, MigrationTxKind, MigrationTxState,
    PoolMigrationRead, PoolMigrationWrite,
};
use zcash_pool_migration::wallet::{
    Error as WalletMigrationError, ExactReceivedOutput, LockedWalletMigration, MigrationCompletion,
    MigrationFinalizationAudit, OrchardReservationAuthorization, PcztLockError,
    PoolMigrationLockStore, ReceivedOutputAvailability, ReceivedOutputAvailabilitySource,
    WalletMigration, WalletMigrationProver, cancel_migration_and_release_locks,
    commit_preparation_locked, finalize_completed_migration, persist_migration_with_locks,
    update_migration_transaction_with_locks, validate_pczt_orchard_locks,
};
use zcash_pool_migration_memory::{MockBackend, regtest_network};

/// Every network upgrade (through NU6.3, which activates the Ironwood pool) is active from this
/// height, so a migration built at or above it is post-NU6.3 and its transfers cross into Ironwood.
const ACTIVATION: u32 = 100_000;
/// The minimum canonical `{1, 2, 5} * 10^k` migration denomination.
const SINGLE_QUANTUM_ZATOSHI: u64 = COIN / 100;
/// Empty blocks scanned after a note is received so its commitment-tree shard completes and an
/// anchor at that height is available.
const SHARD_COMPLETION_BLOCKS: usize = 5;

/// A network with every upgrade through NU6.3 active at [`ACTIVATION`].
fn nu63_network() -> LocalNetwork {
    let h = BlockHeight::from_u32(ACTIVATION);
    LocalNetwork {
        nu6: Some(h),
        nu6_1: Some(h),
        nu6_2: Some(h),
        nu6_3: Some(h),
        ..TestBuilder::<(), ()>::DEFAULT_NETWORK
    }
}

/// A trivial in-memory migration store for the [`WalletMigration`] adapter. The chain simulation
/// drives proving through the engine's free functions (which mutate the in-memory
/// [`MigrationState`] directly), so only `replace_migration` (used by commit) is exercised.
#[derive(Default)]
struct MigrationTestStore {
    state: Option<MigrationState>,
    lock_calls: Vec<LockCall>,
    release_calls: Vec<ReleaseCall>,
    availability: Option<ReceivedOutputAvailability>,
    atomic_availability: Option<ReceivedOutputAvailability>,
    atomic_storage_finality: Option<StorageFinality>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MigrationTestStoreError {
    CanonicalStateMismatch,
    CanonicalOwnerMismatch,
}

impl fmt::Display for MigrationTestStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CanonicalStateMismatch => f.write_str("canonical migration changed"),
            Self::CanonicalOwnerMismatch => f.write_str("canonical owner changed"),
        }
    }
}

impl std::error::Error for MigrationTestStoreError {}

struct LockCall {
    state: MigrationState,
    outputs: Vec<OutputRef>,
    owner: LockOwner,
    expiry: BlockHeight,
}

struct ReleaseCall {
    state: MigrationState,
    owners: BTreeSet<LockOwner>,
}

impl PoolMigrationRead for MigrationTestStore {
    type Error = MigrationTestStoreError;

    fn get_migration(&self) -> Result<Option<MigrationState>, Self::Error> {
        Ok(self.state.clone())
    }
}

impl PoolMigrationWrite for MigrationTestStore {
    fn replace_migration(&mut self, state: &MigrationState) -> Result<(), Self::Error> {
        self.state = Some(state.clone());
        Ok(())
    }

    fn update_transaction(
        &mut self,
        _id: MigrationTxId,
        _state: MigrationTxState,
    ) -> Result<(), Self::Error> {
        panic!("LockedWalletMigration must route updates through atomic whole-state persistence")
    }
}

impl PoolMigrationLockStore for MigrationTestStore {
    fn lock_outputs_and_replace_migration(
        &mut self,
        expected: Option<&MigrationState>,
        state: &MigrationState,
        outputs: &[OutputRef],
        owner: LockOwner,
        lock_expiry_height: BlockHeight,
    ) -> Result<(), Self::Error> {
        if self.state.as_ref() != expected {
            return Err(MigrationTestStoreError::CanonicalStateMismatch);
        }
        self.state = Some(state.clone());
        self.lock_calls.push(LockCall {
            state: state.clone(),
            outputs: outputs.to_vec(),
            owner,
            expiry: lock_expiry_height,
        });
        Ok(())
    }

    fn release_locks_and_replace_migration(
        &mut self,
        expected: &MigrationState,
        state: &MigrationState,
        owners: &BTreeSet<LockOwner>,
    ) -> Result<(), Self::Error> {
        if self.state.as_ref() != Some(expected) {
            return Err(MigrationTestStoreError::CanonicalStateMismatch);
        }
        self.state = Some(state.clone());
        self.release_calls.push(ReleaseCall {
            state: state.clone(),
            owners: owners.clone(),
        });
        Ok(())
    }

    fn finalize_migration_if_outputs_available(
        &mut self,
        expected: &MigrationState,
        finalized: &MigrationState,
        owners: &BTreeSet<LockOwner>,
        outputs: &[(MigrationTxId, ExactReceivedOutput)],
        _target_height: TargetHeight,
        _confirmations_policy: ConfirmationsPolicy,
        _lock_filter: LockFilter<'_>,
    ) -> Result<MigrationFinalizationAudit, Self::Error> {
        if self.state.as_ref() != Some(expected) {
            return Err(MigrationTestStoreError::CanonicalStateMismatch);
        }
        let canonical_owners = expected
            .transactions()
            .iter()
            .filter_map(|transaction| transaction.lock_owner().map(LockOwner::new))
            .collect::<BTreeSet<_>>();
        if canonical_owners != *owners {
            return Err(MigrationTestStoreError::CanonicalOwnerMismatch);
        }
        let availability = self
            .atomic_availability
            .or(self.availability)
            .unwrap_or(ReceivedOutputAvailability::Unknown);
        let storage_finality = self
            .atomic_storage_finality
            .expect("completion tests must choose explicit storage-finality semantics");
        let evidence = outputs
            .iter()
            .map(|(transaction_id, output)| {
                zcash_pool_migration::wallet::MigrationOutputAvailability::new(
                    *transaction_id,
                    *output,
                    availability,
                )
            })
            .collect::<Vec<_>>();
        if evidence.iter().all(|entry| {
            matches!(
                entry.availability(),
                ReceivedOutputAvailability::Spendable | ReceivedOutputAvailability::Spent { .. }
            )
        }) && matches!(storage_finality, StorageFinality::Finalized(_))
            && !owners.is_empty()
        {
            self.state = Some(finalized.clone());
            self.release_calls.push(ReleaseCall {
                state: finalized.clone(),
                owners: owners.clone(),
            });
        }
        Ok(MigrationFinalizationAudit::new(evidence, storage_finality))
    }
}

impl ReceivedOutputAvailabilitySource for MigrationTestStore {
    type Error = MigrationTestStoreError;

    fn received_output_availability(
        &self,
        _output: ExactReceivedOutput,
        _target_height: TargetHeight,
        _confirmations_policy: ConfirmationsPolicy,
        _lock_filter: LockFilter<'_>,
    ) -> Result<ReceivedOutputAvailability, Self::Error> {
        Ok(self
            .availability
            .unwrap_or(ReceivedOutputAvailability::Unknown))
    }
}

/// Cloneable, interior-mutable view of one canonical store, used to model two independently
/// resumed adapters racing with the same snapshot.
#[derive(Clone)]
struct SharedMigrationTestStore(Rc<RefCell<MigrationTestStore>>);

impl SharedMigrationTestStore {
    fn new(store: MigrationTestStore) -> Self {
        Self(Rc::new(RefCell::new(store)))
    }

    fn state(&self) -> Option<MigrationState> {
        self.0.borrow().state.clone()
    }

    fn release_call_count(&self) -> usize {
        self.0.borrow().release_calls.len()
    }

    fn lock_call_count(&self) -> usize {
        self.0.borrow().lock_calls.len()
    }
}

impl PoolMigrationRead for SharedMigrationTestStore {
    type Error = MigrationTestStoreError;

    fn get_migration(&self) -> Result<Option<MigrationState>, Self::Error> {
        self.0.borrow().get_migration()
    }
}

impl PoolMigrationWrite for SharedMigrationTestStore {
    fn replace_migration(&mut self, state: &MigrationState) -> Result<(), Self::Error> {
        self.0.borrow_mut().replace_migration(state)
    }

    fn update_transaction(
        &mut self,
        id: MigrationTxId,
        state: MigrationTxState,
    ) -> Result<(), Self::Error> {
        self.0.borrow_mut().update_transaction(id, state)
    }
}

impl PoolMigrationLockStore for SharedMigrationTestStore {
    fn lock_outputs_and_replace_migration(
        &mut self,
        expected: Option<&MigrationState>,
        state: &MigrationState,
        outputs: &[OutputRef],
        owner: LockOwner,
        lock_expiry_height: BlockHeight,
    ) -> Result<(), Self::Error> {
        self.0.borrow_mut().lock_outputs_and_replace_migration(
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
            .borrow_mut()
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
        self.0.borrow_mut().finalize_migration_if_outputs_available(
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

/// An end-to-end migration proving scenario, built fluently: [`Scenario::funded`] /
/// [`Scenario::funded_notes`] set the source note shape, the `expect_*` setters declare the
/// observable outcomes, and [`Scenario::prove_end_to_end`] funds a real wallet, runs the whole
/// migration, and asserts those outcomes phase by phase. Each new balance or note shape is a new
/// builder in the test below.
struct Scenario {
    label: &'static str,
    funding: Vec<Zatoshis>,
    expected_preparations: usize,
    expected_transfers: usize,
    expected_migrated: Zatoshis,
}

impl Scenario {
    /// Starts a scenario whose account is funded with a single Orchard note worth `funding`.
    fn funded(label: &'static str, funding: Zatoshis) -> Self {
        Self::funded_notes(label, vec![funding])
    }

    /// Starts a scenario whose account is funded with several source Orchard notes (the "exchange" /
    /// dusty shapes whose consolidation drives multi-layer preparation).
    fn funded_notes(label: &'static str, funding: Vec<Zatoshis>) -> Self {
        Self {
            label,
            funding,
            expected_preparations: 0,
            expected_transfers: 0,
            expected_migrated: Zatoshis::ZERO,
        }
    }

    /// Declares the number of preparation transactions the migration should produce.
    fn expect_preparations(mut self, n: usize) -> Self {
        self.expected_preparations = n;
        self
    }

    /// Declares the number of pool-crossing transfers (one per prepared funding note).
    fn expect_transfers(mut self, n: usize) -> Self {
        self.expected_transfers = n;
        self
    }

    /// Declares the total value that should cross into Ironwood (the sum of the crossings).
    fn expect_migrated(mut self, migrated: Zatoshis) -> Self {
        self.expected_migrated = migrated;
        self
    }

    /// Runs the whole migration for this scenario, phase by phase, asserting every declared
    /// expectation as it goes: setup, plan-and-commit, prove-preparations, prove-transfers.
    fn prove_end_to_end(self) {
        let mut run = Run::setup(&self);
        let mut committed = run.plan_and_commit(&self);
        run.prove_preparations(&mut committed, &self);
        run.prove_transfers(&mut committed, &self);
    }
}

/// The running harness of one [`Scenario`]: a funded wallet plus the account identity, carried
/// across the proving phases.
struct Run {
    network: LocalNetwork,
    st: TestState<BlockCache, TestDb, LocalNetwork>,
    account_id: <TestDb as WalletRead>::AccountId,
    usk: UnifiedSpendingKey,
    fvk: <OrchardPoolTester as ShieldedPoolTester>::Fvk,
}

/// The committed migration produced by [`Run::plan_and_commit`] and advanced by the proving phases,
/// with the planned amounts those phases hold the real chain state to.
struct Committed {
    state: MigrationState,
    funding_notes: Vec<Zatoshis>,
    change: u64,
}

impl Run {
    /// Phase 1 (setup): builds an NU6.3 wallet, funds the account with the scenario's source Orchard
    /// notes (one per block), and completes their shards so an anchor is available at the tip.
    fn setup(scenario: &Scenario) -> Self {
        let network = nu63_network();

        let mut st = TestBuilder::new()
            .with_network(network)
            .with_data_store_factory(TestDbFactory::default())
            .with_block_cache(BlockCache::new())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();

        let account = st.test_account().cloned().expect("the test account exists");
        let account_id = account.id();
        let usk = account.usk().clone();
        let fvk = OrchardPoolTester::test_account_fvk(&st);

        for &note in &scenario.funding {
            let (h, _, _) = st.generate_next_block(&fvk, AddressType::DefaultExternal, note);
            st.scan_cached_blocks(h, 1);
        }
        let funded_total: Zatoshis = scenario
            .funding
            .iter()
            .copied()
            .sum::<Option<Zatoshis>>()
            .expect("the funded total is a valid amount");
        // The shared wallet test harness has no balance row until an account has received a note,
        // so the deliberately empty foreign-wallet case below cannot query `get_total_balance`.
        if !scenario.funding.is_empty() {
            assert_eq!(
                st.get_total_balance(account_id),
                funded_total,
                "{}: funded balance",
                scenario.label
            );
        }
        for _ in 0..SHARD_COMPLETION_BLOCKS {
            let (h, _) = st.generate_empty_block();
            st.scan_cached_blocks(h, 1);
        }

        Self {
            network,
            st,
            account_id,
            usk,
            fvk,
        }
    }

    /// Phase 2 (plan and commit): plans and commits the migration over the wallet adapter (its plan,
    /// preparations, and transfers all drawn from the real wallet's notes), checks the planned
    /// funding-note count and migrated value against the scenario, and returns the committed
    /// migration (every transaction Signed, with anchors and witnesses deferred).
    fn plan_and_commit(&mut self, scenario: &Scenario) -> Committed {
        let tip = self
            .st
            .wallet()
            .chain_height()
            .expect("reads the chain height")
            .expect("the wallet has a chain tip");
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        let (state, funding_notes, migrated, change) = {
            let adapter = WalletMigration::new(
                self.st.wallet(),
                self.account_id,
                self.usk.clone(),
                MigrationTestStore::default(),
            );
            let plan = engine::plan_migration(&self.network, &adapter, &mut rng)
                .expect("plans the migration");
            let funding_notes = plan.funding_notes();
            let migrated = plan.note_split().total_migratable();
            let change = plan.note_split().change().map(u64::from).unwrap_or(0);
            let mut adapter = adapter;
            let (state, _) = engine::commit_preparation_with_funding(
                &self.network,
                tip,
                &mut adapter,
                &plan,
                &mut rng,
            )
            .expect("commits the migration");
            (state, funding_notes, migrated, change)
        };

        // The observable amounts match what this balance is expected to migrate: one funding note
        // (and one transfer) per crossing denomination, and the whole value carried into Ironwood.
        assert_eq!(
            funding_notes.len(),
            scenario.expected_transfers,
            "{}: prepared funding notes",
            scenario.label
        );
        assert_eq!(
            migrated, scenario.expected_migrated,
            "{}: total migrated value",
            scenario.label
        );
        for tx in state.transactions() {
            assert!(matches!(tx.state(), MigrationTxState::Signed));
        }

        Committed {
            state,
            funding_notes,
            change,
        }
    }

    /// Phase 3 (prove preparations): proves each preparation against the current tip, extracts it
    /// (asserting it is Orchard-only), then mines and scans it so its minted funding notes become
    /// spendable; finally checks the wallet balance is the funding less the reserved preparation fees.
    fn prove_preparations(&mut self, committed: &mut Committed, scenario: &Scenario) {
        let prep_ids: Vec<MigrationTxId> = committed
            .state
            .transactions()
            .iter()
            .filter(|t| matches!(t.kind(), MigrationTxKind::Preparation { .. }))
            .map(|t| t.id())
            .collect();
        assert_eq!(
            prep_ids.len(),
            scenario.expected_preparations,
            "{}: preparation transactions",
            scenario.label
        );

        for prep_id in prep_ids {
            let tip = self
                .st
                .wallet()
                .chain_height()
                .expect("reads the chain height")
                .expect("the wallet has a chain tip");
            let anchor = highest_rooted_orchard_checkpoint(self.st.wallet_mut(), tip)
                .expect("a rooted Orchard checkpoint exists");
            {
                let mut prover = WalletMigrationProver::new(
                    self.st.wallet_mut(),
                    self.account_id,
                    self.fvk.clone(),
                );
                engine::prove_preparation(&mut prover, &mut committed.state, prep_id, anchor)
                    .expect("proves the preparation transaction");
            }
            let proven = committed
                .state
                .transactions()
                .iter()
                .find(|t| t.id() == prep_id)
                .expect("the preparation transaction is present");
            assert!(matches!(proven.state(), MigrationTxState::Proved));
            let tx = TransactionExtractor::new(
                pczt::Pczt::parse(proven.pczt()).expect("parses the proven preparation PCZT"),
            )
            .extract()
            .expect("extracts and verifies the preparation transaction");
            // A preparation transaction is Orchard-only: no Ironwood bundle.
            assert!(
                tx.orchard_bundle().is_some(),
                "the preparation has an Orchard bundle"
            );
            assert!(
                tx.ironwood_bundle().is_none(),
                "the preparation has no Ironwood bundle"
            );

            let (prep_height, _) = self.st.generate_next_block_from_tx(1, &tx);
            self.st.scan_cached_blocks(prep_height, 1);
        }

        let funding_notes_total: u64 = committed.funding_notes.iter().map(|&v| u64::from(v)).sum();
        assert_eq!(
            self.st.get_total_balance(self.account_id),
            Zatoshis::from_u64(funding_notes_total + committed.change).expect("a valid balance"),
            "{}: balance after preparations",
            scenario.label
        );
    }

    /// Phase 4 (prove transfers): advances the chain to each transfer's drawn anchor boundary (so
    /// that checkpoint is settled and holds the funding note, within the pruning window), proves the
    /// transfer, extracts it, and asserts both its Orchard and Ironwood bundles verify. Finally
    /// checks the destination pool: the migration created exactly one Ironwood note per transfer,
    /// together holding the whole migrated value.
    fn prove_transfers(&mut self, committed: &mut Committed, scenario: &Scenario) {
        let mut transfers: Vec<(MigrationTxId, BlockHeight)> = committed
            .state
            .transactions()
            .iter()
            .filter(|t| matches!(t.kind(), MigrationTxKind::Transfer { .. }))
            .map(|t| {
                (
                    t.id(),
                    t.anchor_boundary()
                        .expect("a transfer carries a drawn boundary"),
                )
            })
            .collect();
        transfers.sort_by_key(|(_, boundary)| *boundary);
        assert_eq!(
            transfers.len(),
            scenario.expected_transfers,
            "{}: transfers",
            scenario.label
        );

        // The Ironwood output note each transfer creates, collected to check the destination pool.
        let mut ironwood_notes: Vec<Zatoshis> = Vec::new();

        for (transfer_id, boundary) in transfers {
            loop {
                let tip = self
                    .st
                    .wallet()
                    .chain_height()
                    .expect("reads the chain height")
                    .expect("the wallet has a chain tip");
                if tip > boundary {
                    break;
                }
                let (h, _) = self.st.generate_empty_block();
                self.st.scan_cached_blocks(h, 1);
            }

            {
                let mut prover = WalletMigrationProver::new(
                    self.st.wallet_mut(),
                    self.account_id,
                    self.fvk.clone(),
                );
                engine::prove_transfer(&mut prover, &mut committed.state, transfer_id)
                    .expect("proves the transfer against its drawn boundary");
            }
            let proven = committed
                .state
                .transactions()
                .iter()
                .find(|t| t.id() == transfer_id)
                .expect("the transfer is present");
            assert!(matches!(proven.state(), MigrationTxState::Proved));
            let tx = TransactionExtractor::new(
                pczt::Pczt::parse(proven.pczt()).expect("parses the proven transfer PCZT"),
            )
            .extract()
            .expect("extracts and verifies the transfer's Orchard and Ironwood proofs");
            assert!(
                tx.orchard_bundle().is_some(),
                "the transfer has an Orchard bundle"
            );
            let ironwood = tx
                .ironwood_bundle()
                .expect("the transfer has an Ironwood bundle");
            // A transfer creates exactly one Ironwood output: the migrated crossing note. Its value
            // is the magnitude of the (output-only) bundle's value balance.
            assert_eq!(
                ironwood.actions().len(),
                1,
                "{}: Ironwood outputs per transfer",
                scenario.label
            );
            ironwood_notes.push(
                Zatoshis::from_u64(i64::from(ironwood.value_balance()).unsigned_abs())
                    .expect("a valid Ironwood note value"),
            );
        }

        // The destination pool holds exactly one Ironwood note per crossing, together carrying the
        // whole migrated value.
        assert_eq!(
            ironwood_notes.len(),
            scenario.expected_transfers,
            "{}: Ironwood notes",
            scenario.label
        );
        let ironwood_total: u64 = ironwood_notes.iter().map(|&v| u64::from(v)).sum();
        assert_eq!(
            Zatoshis::from_u64(ironwood_total).expect("a valid balance"),
            scenario.expected_migrated,
            "{}: Ironwood balance",
            scenario.label
        );
    }
}

fn single_quantum_scenario(label: &'static str) -> Scenario {
    // Match the upstream fee-derived minimal balance instead of freezing a fee constant: one
    // quantum, one transfer buffer, and one padded preparation transaction fee.
    let mut rng = ChaCha8Rng::seed_from_u64(0);
    let probe = MockBackend::new(vec![2 * SINGLE_QUANTUM_ZATOSHI], 2_000_000);
    let probe_plan = engine::plan_migration(&regtest_network(true), &probe, &mut rng)
        .expect("the one-quantum fee probe plans");
    assert_eq!(probe_plan.preparation().transaction_count(), 1);
    let funding = SINGLE_QUANTUM_ZATOSHI
        + u64::from(probe_plan.note_split().note_fee_buffer())
        + u64::from(probe_plan.note_split().prep_fees());
    Scenario::funded(label, zats(funding))
        .expect_preparations(1)
        .expect_transfers(1)
        .expect_migrated(zats(SINGLE_QUANTUM_ZATOSHI))
}

fn minimal_locking_scenario() -> Scenario {
    single_quantum_scenario("locking adapter, one minimum-denomination crossing")
}

fn current_orchard_output_refs(run: &Run) -> Vec<OutputRef> {
    let tip = run
        .st
        .wallet()
        .chain_height()
        .expect("reads chain height")
        .expect("wallet has a chain tip");
    run.st
        .wallet()
        .select_unspent_notes(
            run.account_id,
            &[ShieldedPool::Orchard],
            TargetHeight::from(u32::from(tip) + 1),
            &[],
            LockFilter::Unfiltered,
        )
        .expect("reads unspent Orchard notes")
        .orchard()
        .iter()
        .map(|note| {
            OutputRef::new(
                *note.txid(),
                PoolType::Shielded(ShieldedPool::Orchard),
                u32::from(note.output_index()),
            )
        })
        .collect()
}

fn commit_unlocked(run: &Run, seed: u64) -> (MigrationState, MigrationTestStore) {
    let tip = run
        .st
        .wallet()
        .chain_height()
        .expect("reads chain height")
        .expect("wallet has a chain tip");
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let mut adapter = WalletMigration::new(
        run.st.wallet(),
        run.account_id,
        run.usk.clone(),
        MigrationTestStore::default(),
    );
    let plan = engine::plan_migration(&run.network, &adapter, &mut rng).expect("plans migration");
    let state = engine::commit_preparation(&run.network, tip, &mut adapter, &plan, &mut rng)
        .expect("commits migration");
    (state, adapter.into_store())
}

fn commit_locked(run: &Run, seed: u64, owner: LockOwner) -> (MigrationState, MigrationTestStore) {
    let tip = run
        .st
        .wallet()
        .chain_height()
        .expect("reads chain height")
        .expect("wallet has a chain tip");
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let mut adapter = LockedWalletMigration::new(
        run.st.wallet(),
        run.account_id,
        run.usk.clone(),
        MigrationTestStore::default(),
        owner,
    );
    let plan = engine::plan_migration(&run.network, &adapter, &mut rng).expect("plans migration");
    let state = commit_preparation_locked(&run.network, tip, &mut adapter, &plan, &mut rng)
        .expect("commits locked migration");
    (state, adapter.into_store())
}

/// Every proving scenario, spanning the migration personas exercised across the codebase (the Python
/// integration-test suite and the note-split golden vectors): single small / medium / large
/// balances, the minimum-denomination and buffer-pruned edges, and the many-note "exchange" / dust /
/// whale shapes whose consolidation drives multi-layer preparation.
fn scenarios() -> Vec<Scenario> {
    // 0.02 ZEC dust notes.
    let dust = zats(COIN / 50);
    let dust_heavy: Vec<Zatoshis> = std::iter::once(zats(COIN))
        .chain(std::iter::repeat_n(dust, 12))
        .collect();
    // The migrated total is the balance less the reserved transfer buffers and preparation fees, so
    // it is a multiple of the 0.01-ZEC minimum denomination; expressed here in hundredths of a ZEC.
    let hundredths = COIN / 100;
    vec![
        // Single-note balances.
        Scenario::funded("small holder, 2 ZEC", zats(2 * COIN))
            .expect_preparations(1)
            .expect_transfers(7)
            .expect_migrated(zats(199 * hundredths)),
        Scenario::funded("retail, 15 ZEC", zats(15 * COIN))
            .expect_preparations(1)
            .expect_transfers(9)
            .expect_migrated(zats(1_499 * hundredths)),
        Scenario::funded("denominations, 60 ZEC", zats(60 * COIN))
            .expect_preparations(1)
            .expect_transfers(10)
            .expect_migrated(zats(5_999 * hundredths)),
        Scenario::funded("78 ZEC in a single note", zats(78 * COIN))
            .expect_preparations(1)
            .expect_transfers(10)
            .expect_migrated(zats(7_799 * hundredths)),
        Scenario::funded(
            "Gwen, 0.0152 ZEC (a single minimum-denomination note)",
            zats(1_520_000),
        )
        .expect_preparations(1)
        .expect_transfers(1)
        .expect_migrated(zats(hundredths)),
        Scenario::funded(
            "Priya, 7.1101 ZEC (the buffer prunes the trailing crossing)",
            zats(711_010_000),
        )
        .expect_preparations(1)
        .expect_transfers(3)
        .expect_migrated(zats(710 * hundredths)),
        // Many-note shapes, consolidated across preparation layers.
        Scenario::funded_notes("exchange, ten 5 ZEC notes", vec![zats(5 * COIN); 10])
            .expect_preparations(2)
            .expect_transfers(3)
            .expect_migrated(zats(4_500 * hundredths)),
        Scenario::funded_notes("monotonic, ten 12 ZEC notes", vec![zats(12 * COIN); 10])
            .expect_preparations(5)
            .expect_transfers(11)
            .expect_migrated(zats(11_999 * hundredths)),
        Scenario::funded_notes("dust-heavy, 1 ZEC and twelve 0.02 ZEC notes", dust_heavy)
            .expect_preparations(4)
            .expect_transfers(4)
            .expect_migrated(zats(123 * hundredths)),
        Scenario::funded_notes(
            "whale plus dust, 40 ZEC and a six-note dust tail",
            vec![
                zats(40 * COIN),
                zats(COIN / 50),
                zats(COIN / 50),
                zats(COIN / 20),
                zats(COIN / 20),
                zats(COIN / 10),
                zats(COIN / 10),
            ],
        )
        .expect_preparations(4)
        .expect_transfers(6)
        .expect_migrated(zats(4_033 * hundredths)),
    ]
}

#[test]
fn migration_proves_end_to_end_against_a_funded_wallet() {
    for scenario in scenarios() {
        scenario.prove_end_to_end();
    }
}

/// The upstream minimal prover-backed migration, adapted to the shared real-wallet harness.
/// Zend's lock tests below deliberately reuse this exact fee-derived one-quantum shape.
#[test]
fn single_quantum_migration_proves_end_to_end() {
    let scenario = single_quantum_scenario("one exact quantum plus canonical fees");
    let mut run = Run::setup(&scenario);
    let mut committed = run.plan_and_commit(&scenario);
    assert_eq!(
        committed.change, 0,
        "the exact minimal balance has no change"
    );
    run.prove_preparations(&mut committed, &scenario);
    run.prove_transfers(&mut committed, &scenario);
}

#[test]
fn completion_audit_is_atomic_and_finalized_reorg_bootstraps_one_new_owner() {
    let scenario = single_quantum_scenario("atomic completion and finalized reorg recovery");
    let mut run = Run::setup(&scenario);
    let mut committed = run.plan_and_commit(&scenario);
    let owner = LockOwner::new([0xA8; 32]);

    // Attach the durable owner at the atomic lock/state seam, then prove the exact upstream-shaped
    // one-quantum preparation and transfer against the real wallet.
    let mut store = MigrationTestStore {
        state: Some(committed.state.clone()),
        ..MigrationTestStore::default()
    };
    let expected = committed.state.clone();
    committed.state = persist_migration_with_locks(
        run.st.wallet(),
        run.account_id,
        &run.fvk,
        &mut store,
        owner,
        Some(&expected),
        &committed.state,
    )
    .expect("attaches the completion test owner");
    let persisted_before_proving = committed.state.clone();

    run.prove_preparations(&mut committed, &scenario);
    let prep_ids = committed
        .state
        .transactions()
        .iter()
        .filter(|transaction| matches!(transaction.kind(), MigrationTxKind::Preparation { .. }))
        .map(|transaction| transaction.id())
        .collect::<Vec<_>>();
    for id in prep_ids {
        committed
            .state
            .mark_mined(id, BlockHeight::from_u32(ACTIVATION + 50));
    }
    run.prove_transfers(&mut committed, &scenario);
    let transfer_id = committed
        .state
        .transactions()
        .iter()
        .find(|transaction| matches!(transaction.kind(), MigrationTxKind::Transfer { .. }))
        .expect("the one-quantum transfer exists")
        .id();
    let transfer_txid = TransactionExtractor::new(
        pczt::Pczt::parse(
            committed
                .state
                .transactions()
                .iter()
                .find(|transaction| transaction.id() == transfer_id)
                .expect("the transfer remains present")
                .pczt(),
        )
        .expect("the proved transfer parses"),
    )
    .extract()
    .expect("the proved transfer extracts")
    .txid();
    committed
        .state
        .mark_mined(transfer_id, BlockHeight::from_u32(ACTIVATION + 100));
    assert_eq!(committed.state.status(), MigrationStatus::Complete);

    let completed = persist_migration_with_locks(
        run.st.wallet(),
        run.account_id,
        &run.fvk,
        &mut store,
        owner,
        Some(&persisted_before_proving),
        &committed.state,
    )
    .expect("persists owner-bearing provisional Complete");
    let tip = run
        .st
        .wallet()
        .chain_height()
        .expect("reads chain height")
        .expect("wallet has a chain tip");
    let target_height = TargetHeight::from(u32::from(tip) + 1);

    // A stale pre-transaction read says Spendable, but the storage-atomic snapshot says Unknown.
    // Finalization must use only the latter and leave owner/state/locks untouched.
    store.availability = Some(ReceivedOutputAvailability::Spendable);
    store.atomic_availability = Some(ReceivedOutputAvailability::Unknown);
    let finality_release = ReservationRelease::at(BlockHeight::from_u32(ACTIVATION + 100));
    store.atomic_storage_finality =
        Some(StorageFinality::CompletePendingFinality(finality_release));
    let release_calls = store.release_calls.len();
    let pending = finalize_completed_migration(
        &mut store,
        target_height,
        ConfirmationsPolicy::default(),
        LockFilter::Unfiltered,
    )
    .expect("the atomic audit returns pending evidence");
    assert!(matches!(pending, MigrationCompletion::Pending(ref entries) if entries.len() == 1));
    assert_eq!(store.state, Some(completed.clone()));
    assert_eq!(store.release_calls.len(), release_calls);

    store.atomic_availability = Some(ReceivedOutputAvailability::Spendable);
    let spendable_pending_finality = finalize_completed_migration(
        &mut store,
        target_height,
        ConfirmationsPolicy::default(),
        LockFilter::Unfiltered,
    )
    .expect("spendable output remains pending until storage finality");
    assert!(matches!(
        spendable_pending_finality,
        MigrationCompletion::SpendablePendingFinality(ref entries) if entries.len() == 1
    ));
    assert_eq!(store.state, Some(completed.clone()));
    assert_eq!(store.release_calls.len(), release_calls);

    store.atomic_storage_finality = Some(StorageFinality::Finalized(finality_release));
    let finalized = match finalize_completed_migration(
        &mut store,
        target_height,
        ConfirmationsPolicy::default(),
        LockFilter::Unfiltered,
    )
    .expect("the atomic satisfied audit finalizes")
    {
        MigrationCompletion::Finalized(state) => state,
        MigrationCompletion::Pending(_) => panic!("spendable exact output must finalize"),
        MigrationCompletion::SpendablePendingFinality(_) => {
            panic!("explicit finalized storage state must release the migration")
        }
    };
    assert!(
        finalized
            .transactions()
            .iter()
            .all(|transaction| transaction.lock_owner().is_none())
    );
    assert_eq!(store.release_calls.len(), release_calls + 1);

    // Re-audit is idempotent, and cancellation cannot reactivate an ownerless finalized state.
    assert!(matches!(
        finalize_completed_migration(
            &mut store,
            target_height,
            ConfirmationsPolicy::default(),
            LockFilter::Unfiltered,
        )
        .expect("ownerless finalization re-audits"),
        MigrationCompletion::Finalized(_)
    ));
    assert_eq!(store.release_calls.len(), release_calls + 1);
    let recovery_owner = LockOwner::new([0xB8; 32]);
    let err = cancel_migration_and_release_locks(
        run.st.wallet(),
        run.account_id,
        &run.fvk,
        &mut store,
        recovery_owner,
        &finalized,
    )
    .expect_err("finalized Complete cannot be cancelled/re-locked");
    assert!(matches!(err, WalletMigrationError::MigrationComplete));
    assert_eq!(store.state, Some(finalized.clone()));

    // A chain reorg is an explicit lifecycle rewind. The caller supplies one recovery token; CAS
    // makes that bootstrap deterministic, persists it on every row, and rejects a concurrent
    // second token based on the same ownerless snapshot.
    let reorged = update_migration_transaction_with_locks(
        run.st.wallet(),
        run.account_id,
        &run.fvk,
        &mut store,
        recovery_owner,
        &finalized,
        transfer_id,
        MigrationTxState::Broadcast {
            txid: transfer_txid,
        },
    )
    .expect("the explicit reorg rewind bootstraps its recovery owner");
    assert_eq!(reorged.status(), MigrationStatus::InProgress);
    assert!(
        reorged
            .transactions()
            .iter()
            .all(|transaction| transaction.lock_owner() == Some(*recovery_owner.as_bytes()))
    );
    let err = update_migration_transaction_with_locks(
        run.st.wallet(),
        run.account_id,
        &run.fvk,
        &mut store,
        LockOwner::new([0xC8; 32]),
        &finalized,
        transfer_id,
        MigrationTxState::Broadcast {
            txid: transfer_txid,
        },
    )
    .expect_err("only one recovery owner can win the ownerless-state CAS");
    assert!(matches!(
        err,
        WalletMigrationError::Store(MigrationTestStoreError::CanonicalStateMismatch)
    ));
    assert_eq!(store.state, Some(reorged));
}

#[test]
fn fvk_lock_adapter_resolves_the_pczt_input_not_an_equal_value_sibling() {
    let scenario = minimal_locking_scenario();
    let mut run = Run::setup(&scenario);
    let original = current_orchard_output_refs(&run);
    assert_eq!(original.len(), 1);
    let (state, store) = commit_unlocked(&run, 101);

    // Add an indistinguishable-value sibling after the PCZT has fixed its input. A value- or
    // selection-index-based reservation could now lock the wrong note; nullifier identity cannot.
    let (h, _, _) =
        run.st
            .generate_next_block(&run.fvk, AddressType::DefaultExternal, zats(1_520_000));
    run.st.scan_cached_blocks(h, 1);
    for _ in 0..SHARD_COMPLETION_BLOCKS {
        let (h, _) = run.st.generate_empty_block();
        run.st.scan_cached_blocks(h, 1);
    }
    let now_unspent = current_orchard_output_refs(&run);
    assert_eq!(now_unspent.len(), 2);

    let owner = LockOwner::new([0xA1; 32]);
    let mut store = store;
    let persisted = persist_migration_with_locks(
        run.st.wallet(),
        run.account_id,
        &run.fvk,
        &mut store,
        owner,
        Some(&state),
        &state,
    )
    .expect("the exact committed input resolves with only the viewing key");
    let call = store.lock_calls.last().expect("a lock call was recorded");

    assert_eq!(call.outputs, original);
    assert_eq!(call.owner, owner);
    assert_eq!(call.state, persisted);
    assert_eq!(call.expiry, BlockHeight::from_u32(u32::MAX));
    assert!(
        persisted
            .transactions()
            .iter()
            .all(|transaction| transaction.lock_owner() == Some(*owner.as_bytes()))
    );
}

#[test]
fn locked_adapter_rejects_a_root_input_that_is_absent_from_the_wallet() {
    let first_scenario = minimal_locking_scenario();
    let first = Run::setup(&first_scenario);
    let (state, store) = commit_unlocked(&first, 102);

    // A second wallet has none of the first wallet's outputs. It must not satisfy the root PCZT
    // spend fixed by the first wallet, even though it uses the same backend implementation.
    let second_scenario = Scenario::funded_notes("locking adapter, empty wallet", Vec::new());
    let second = Run::setup(&second_scenario);
    let owner = LockOwner::new([0xA2; 32]);
    let mut store = store;
    let err = persist_migration_with_locks(
        second.st.wallet(),
        second.account_id,
        &second.fvk,
        &mut store,
        owner,
        Some(&state),
        &state,
    )
    .expect_err("an equal value in a different wallet is not the PCZT input");
    assert!(matches!(err, WalletMigrationError::RootInputNotFound(_)));
    assert!(store.lock_calls.is_empty());
}

#[test]
fn locked_adapter_defers_then_refreshes_a_new_preparation_output_lock() {
    let scenario = minimal_locking_scenario();
    let mut run = Run::setup(&scenario);
    let original = current_orchard_output_refs(&run);
    let owner = LockOwner::new([0xA3; 32]);
    let (mut state, store) = commit_locked(&run, 103, owner);
    let canonical_before_preparation = state.clone();
    assert_eq!(store.lock_calls.len(), 1);
    assert_eq!(store.lock_calls[0].outputs, original);

    let prep_id = state
        .transactions()
        .iter()
        .find(|transaction| matches!(transaction.kind(), MigrationTxKind::Preparation { .. }))
        .expect("the minimal migration has a preparation")
        .id();
    let tip = run
        .st
        .wallet()
        .chain_height()
        .expect("reads chain height")
        .expect("wallet has a chain tip");
    let anchor = highest_rooted_orchard_checkpoint(run.st.wallet_mut(), tip)
        .expect("a rooted Orchard checkpoint exists");
    {
        let mut prover =
            WalletMigrationProver::new(run.st.wallet_mut(), run.account_id, run.fvk.clone());
        engine::prove_preparation(&mut prover, &mut state, prep_id, anchor)
            .expect("proves preparation");
    }
    let preparation = state
        .transactions()
        .iter()
        .find(|transaction| transaction.id() == prep_id)
        .expect("preparation remains in state");
    let tx = TransactionExtractor::new(
        pczt::Pczt::parse(preparation.pczt()).expect("parses preparation PCZT"),
    )
    .extract()
    .expect("extracts preparation");
    let (mined_height, _) = run.st.generate_next_block_from_tx(1, &tx);
    run.st.scan_cached_blocks(mined_height, 1);
    state.mark_mined(prep_id, mined_height);
    let after_preparation = current_orchard_output_refs(&run);

    let mut store = store;
    persist_migration_with_locks(
        run.st.wallet(),
        run.account_id,
        &run.fvk,
        &mut store,
        owner,
        Some(&canonical_before_preparation),
        &state,
    )
    .expect("refresh finds the newly scanned funding note");
    assert_eq!(store.lock_calls.len(), 2);
    let refreshed = &store.lock_calls[1].outputs;
    assert_eq!(refreshed.len(), 1);
    assert_ne!(refreshed, &original);
    assert!(after_preparation.contains(&refreshed[0]));
}

#[test]
fn locked_adapter_rejects_owner_mismatch_and_cancel_releases_only_its_owner() {
    let scenario = minimal_locking_scenario();
    let run = Run::setup(&scenario);
    let owner = LockOwner::new([0xA4; 32]);
    let foreign = LockOwner::new([0xB4; 32]);
    let (state, store) = commit_locked(&run, 104, owner);

    let mut store = store;
    let err = persist_migration_with_locks(
        run.st.wallet(),
        run.account_id,
        &run.fvk,
        &mut store,
        foreign,
        Some(&state),
        &state,
    )
    .expect_err("a different owner cannot take over persisted transactions");
    assert!(matches!(err, WalletMigrationError::LockOwnerMismatch(_)));
    assert_eq!(store.lock_calls.len(), 1, "no foreign re-lock occurred");

    let cancelled = cancel_migration_and_release_locks(
        run.st.wallet(),
        run.account_id,
        &run.fvk,
        &mut store,
        owner,
        &state,
    )
    .expect("the owning migration can cancel");
    assert_eq!(cancelled.status(), MigrationStatus::Failed);
    assert!(
        cancelled
            .transactions()
            .iter()
            .all(|transaction| transaction.lock_owner().is_none())
    );
    assert_eq!(store.release_calls.len(), 1);
    assert_eq!(store.release_calls[0].owners, BTreeSet::from([owner]));
    assert_eq!(store.release_calls[0].state, cancelled);
}

#[test]
fn resume_refreshes_exact_locks_and_stale_adapters_cannot_update_or_cancel() {
    let scenario = minimal_locking_scenario();
    let run = Run::setup(&scenario);
    let owner = LockOwner::new([0xA7; 32]);
    let (canonical, store) = commit_locked(&run, 108, owner);
    let transaction_id = canonical.transactions()[0].id();
    let shared = SharedMigrationTestStore::new(store);

    let mut first = LockedWalletMigration::resume(
        run.st.wallet(),
        run.account_id,
        run.usk.clone(),
        shared.clone(),
        owner,
        canonical.clone(),
    )
    .expect("restart refreshes the canonical owner's exact locks before returning");
    let mut stale = LockedWalletMigration::resume(
        run.st.wallet(),
        run.account_id,
        run.usk.clone(),
        shared.clone(),
        owner,
        canonical,
    )
    .expect("a second reader can resume while the canonical snapshot is unchanged");
    assert_eq!(
        shared.lock_call_count(),
        3,
        "initial commit plus one refresh for each independently resumed adapter"
    );

    first
        .update_transaction(transaction_id, MigrationTxState::Proved)
        .expect("the first adapter advances the canonical state");
    let advanced = shared.state().expect("the advanced state is canonical");

    let err = stale
        .update_transaction(transaction_id, MigrationTxState::Proved)
        .expect_err("a stale lifecycle update must fail its expected-state CAS");
    assert!(matches!(
        err,
        WalletMigrationError::Store(MigrationTestStoreError::CanonicalStateMismatch)
    ));
    assert_eq!(shared.state(), Some(advanced.clone()));

    let release_calls = shared.release_call_count();
    let err = stale
        .cancel_and_release()
        .expect_err("a stale cancellation must fail its expected-state CAS");
    assert!(matches!(
        err,
        WalletMigrationError::Store(MigrationTestStoreError::CanonicalStateMismatch)
    ));
    assert_eq!(shared.state(), Some(advanced));
    assert_eq!(shared.release_call_count(), release_calls);
}

#[test]
fn locked_adapter_transaction_updates_retain_owner_at_provisional_complete() {
    let scenario = minimal_locking_scenario();
    let run = Run::setup(&scenario);
    let owner = LockOwner::new([0xA5; 32]);
    let (state, store) = commit_locked(&run, 105, owner);
    let ids: Vec<_> = state
        .transactions()
        .iter()
        .map(|transaction| transaction.id())
        .collect();
    let mut store = store;
    let mut expected = state;

    for (offset, id) in ids.into_iter().enumerate() {
        expected = update_migration_transaction_with_locks(
            run.st.wallet(),
            run.account_id,
            &run.fvk,
            &mut store,
            owner,
            &expected,
            id,
            MigrationTxState::Mined {
                height: BlockHeight::from_u32(ACTIVATION + 100 + offset as u32),
            },
        )
        .expect("transaction update uses whole-state persistence");
    }

    let completed = store.state.expect("completed state is persisted");
    assert_eq!(completed.status(), MigrationStatus::Complete);
    assert!(
        completed
            .transactions()
            .iter()
            .all(|transaction| transaction.lock_owner() == Some(*owner.as_bytes()))
    );
    assert!(
        store.release_calls.is_empty(),
        "all-mined is provisional until exact Ironwood outputs pass finalization"
    );
}

#[test]
fn stale_pczt_is_rejected_by_lock_then_by_active_spend_while_exact_retry_passes() {
    let scenario = minimal_locking_scenario();
    let mut run = Run::setup(&scenario);
    let outputs = current_orchard_output_refs(&run);
    assert_eq!(outputs.len(), 1);

    // Build two different fully-authorized artifacts over the same note before either reserves it:
    // `stale` models an ordinary transaction, and `winning` models the migration transaction that
    // acquires the lock and is ingested first.
    let (mut stale, _) = commit_unlocked(&run, 106);
    let (mut winning, _) = commit_unlocked(&run, 107);
    let root_id = |state: &MigrationState| {
        state
            .transactions()
            .iter()
            .find(|transaction| transaction.depends_on().is_empty())
            .expect("the minimal migration has a root transaction")
            .id()
    };
    let tip = run
        .st
        .wallet()
        .chain_height()
        .expect("reads chain height")
        .expect("wallet has a chain tip");
    let anchor = highest_rooted_orchard_checkpoint(run.st.wallet_mut(), tip)
        .expect("a rooted Orchard checkpoint exists");
    for state in [&mut stale, &mut winning] {
        let id = root_id(state);
        let mut prover =
            WalletMigrationProver::new(run.st.wallet_mut(), run.account_id, run.fvk.clone());
        engine::prove_preparation(&mut prover, state, id, anchor)
            .expect("proves the root preparation");
    }
    let root_pczt = |state: &MigrationState| {
        pczt::Pczt::parse(
            state
                .transactions()
                .iter()
                .find(|transaction| transaction.depends_on().is_empty())
                .expect("root transaction exists")
                .pczt(),
        )
        .expect("root PCZT parses")
    };
    let stale_pczt = root_pczt(&stale);
    let winning_pczt = root_pczt(&winning);
    let stale_txid = TransactionExtractor::new(stale_pczt.clone())
        .extract()
        .expect("extract stale PCZT")
        .txid();
    let winning_tx = TransactionExtractor::new(winning_pczt.clone())
        .extract()
        .expect("extract winning PCZT");
    let winning_txid = winning_tx.txid();
    assert_ne!(stale_txid, winning_txid);

    let owner = LockOwner::new([0xA6; 32]);
    run.st
        .wallet_mut()
        .lock_outputs(&outputs, owner, BlockHeight::from_u32(ACTIVATION + 10_000))
        .expect("migration acquires its input lock after the PCZT was built");

    let err = validate_pczt_orchard_locks(
        run.st.wallet().db(),
        &stale_pczt,
        OrchardReservationAuthorization::ORDINARY,
    )
    .expect_err("ordinary finalization recognizes no migration lock owner");
    assert!(matches!(
        err,
        PcztLockError::InputLocked(output) if output == outputs[0]
    ));

    let foreign = LockOwner::new([0xB6; 32]);
    let reservation_owner = SourceReservationOwner::random(&mut ChaCha8Rng::seed_from_u64(0xB6));
    assert!(matches!(
        validate_pczt_orchard_locks(
            run.st.wallet().db(),
            &stale_pczt,
            OrchardReservationAuthorization::delivery(reservation_owner, foreign),
        ),
        Err(PcztLockError::InputLocked(output)) if output == outputs[0]
    ));

    validate_pczt_orchard_locks(
        run.st.wallet().db(),
        &winning_pczt,
        OrchardReservationAuthorization::delivery(reservation_owner, owner),
    )
    .expect("migration delivery may recognize exactly its durable owner");

    // Ingestion records the winning spend. Its delivery flow then releases the completed owner's
    // advisory locks in one owner-scoped operation. The stale artifact must still fail against the
    // active spend claim, while an exact retry of the already-stored candidate txid remains
    // idempotently valid.
    let network = *run.st.network();
    decrypt_and_store_transaction(&network, run.st.wallet_mut(), &winning_tx, None)
        .expect("ingests winning migration transaction");
    assert!(
        run.st
            .wallet_mut()
            .unlock_output(&outputs[0], owner)
            .expect("releases only the delivered migration's exact lock")
    );
    let err = validate_pczt_orchard_locks(
        run.st.wallet().db(),
        &stale_pczt,
        OrchardReservationAuthorization::ORDINARY,
    )
    .expect_err("a different active spender protects the now-unlocked input");
    assert!(
        matches!(
            &err,
            PcztLockError::InputAlreadySpent {
                output,
                spender_txid,
            } if *output == outputs[0] && *spender_txid == winning_txid
        ),
        "unexpected validator result: {err:?}"
    );
    validate_pczt_orchard_locks(
        run.st.wallet().db(),
        &winning_pczt,
        OrchardReservationAuthorization::ORDINARY,
    )
    .expect("same-txid retry is idempotently valid");
}
