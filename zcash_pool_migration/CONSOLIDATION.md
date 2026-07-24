# Ironwood migration capability consolidation

Status: working review note, refreshed 2026-07-24. The live comparison baseline is
`zcash/librustzcash` `main` at `df1d8d5508d563b52b08899bd92c2007555b5a22`,
merged against Zend PR #1's pre-refresh head
`1d63c9c07b0b40b3de633c8396008ff543464a01`. This note records capability
decisions; the Rust and downstream SDK pull requests remain the review authority.
Retired standalone repositories are historical evidence, not rebase sources or
active implementation guidance.

## Retirement boundary (historical context)

`just-zend/ZODLIronwoodMigrationRust` is no longer the migration engine of record.
The Chlup repository from which it was forked is likewise no longer a Zend runtime
dependency. After the Zend Swift SDK and app have removed their exact-revision
pins and the replacement chain has passed funded-wallet validation, both repositories
should be made read-only historical references (and the Chlup owner asked to archive
their copy if appropriate). Preserve their tags, reports, and history; do not carry
their crate, lockfile, or `ext_ironwood_migration_*` schema into a second engine.

The engine of record is the in-tree `zcash_pool_migration`, with canonical
persistence in `zcash_client_sqlite` and a minimal Zend delta maintained on top of
`zcash/librustzcash`.

## Current capability decision

The 2026-07-24 reassessment found no newly merged upstream replacement for Zend's
delivery, immediate-reservation, storage-finality, or legacy-cutover capabilities.
The new upstream delta through `df1d8d55` is adopted exactly: PR
[#2754](https://github.com/zcash/librustzcash/pull/2754) releases the
`zcash_history` / `zcash_encoding` no-std work, and PR
[#2757](https://github.com/zcash/librustzcash/pull/2757) expands the public
`propose_send_max_transfer` contract. Neither changes migration runtime semantics
or the canonical migration schema.

The exact upstream capability set retained as the base is:

- planning, denomination, preparation, scheduling, and lifecycle from PR
  [#2663](https://github.com/zcash/librustzcash/pull/2663) (`fce025199c`),
  the 144-block interval from PR
  [#2729](https://github.com/zcash/librustzcash/pull/2729) (`8d14d03e00`),
  and expiry/rebuild from PR
  [#2723](https://github.com/zcash/librustzcash/pull/2723) (`6bfd0fe154`);
- PCZT proving from PR
  [#2710](https://github.com/zcash/librustzcash/pull/2710) (`56195ed25e`),
  note locking from PRs
  [#2716](https://github.com/zcash/librustzcash/pull/2716) (`beec9b595f`)
  and [#2726](https://github.com/zcash/librustzcash/pull/2726) (`b2f8dce83d`),
  and retained checkpoints from PR
  [#2728](https://github.com/zcash/librustzcash/pull/2728) (`d212c548dd`);
- normalized `orchard_ironwood_migration[s]_*` persistence from PR
  [#2713](https://github.com/zcash/librustzcash/pull/2713) (`a41e941f8e`),
  the exact crate rename from PR
  [#2744](https://github.com/zcash/librustzcash/pull/2744) (`b96925d6d2`),
  and exact `BundlePadding` API from PR
  [#2745](https://github.com/zcash/librustzcash/pull/2745) (`850cb32b44`).

Zend remains additive on that base because upstream still has no durable delivery
CAS/lease/exact-artifact protocol, reservation-before-exposure immediate lane,
unknown-outcome recovery, spendable-destination plus deep-rewind finality boundary,
ordinary-spend/account-deletion authorization, or strict legacy quarantine. Upstream
`MigrationStatus::Complete` still means that every canonical migration transaction
is mined; it does not establish that the exact Ironwood destination is scanned,
spendable, and beyond the source-release horizon. The detailed retained-capability
section below documents how each additive boundary preserves upstream types, schema,
and control flow.

## Upstream implementation and schema adopted unchanged

- ZIP 318 denomination planning uses the canonical `{1, 2, 5} * 10^k` crossings,
  canonical transaction-shape fees, a self-funding fee buffer, and Orchard residual
  handling from `note_splitting`, `preparation`, and the merged engine series.
- Preparation graphs, per-crossing release, randomized ordering, shifted-exponential
  block scheduling, boundary selection, rolling expiry, and run estimates remain the
  upstream implementations. Zend does not retain its separate cadence, anchor-bucket,
  expiry, or denomination algorithms in Rust.
- PCZT construction, deferred anchors and witnesses, software and external-signing
  seams, proving, the expired-transfer rebuild API and control flow, and the canonical
  `MigrationState` lifecycle remain upstream. Zend's stricter exact-note resolution is
  documented below. Relevant merged work includes librustzcash PRs
  [#2663](https://github.com/zcash/librustzcash/pull/2663),
  [#2695](https://github.com/zcash/librustzcash/pull/2695),
  [#2710](https://github.com/zcash/librustzcash/pull/2710), and
  [#2723](https://github.com/zcash/librustzcash/pull/2723).
- The standalone fork's spend-paired dummy-output privacy requirement is no longer a fork-only
  capability. The exact Orchard revision selected by upstream librustzcash (`3bd2b736`) and the
  SDK's released Orchard 0.15.4 dependency both randomize the zero-valued paired output ciphertext
  for external-scope spends. Zend therefore keeps the upstream dependency and behavior instead of
  carrying the former ValarGroup Orchard fork or a second ciphertext patch.
- Merged upstream [PR #2744](https://github.com/zcash/librustzcash/pull/2744) renamed the
  unreleased `zcash_pool_migration_backend` crate to `zcash_pool_migration` and published
  `0.1.0-alpha.1`. This branch adopts that exact upstream merge, including the workspace path,
  package name, imports, release metadata, and downstream SDK dependency name.
- Merged upstream [PR #2745](https://github.com/zcash/librustzcash/pull/2745) replaced the
  per-pool transaction-builder flags with canonical `BundlePadding`. The migration preparation
  and transfer builders use that exact API and its upstream padding choices; Zend carries no
  parallel bundle-shape configuration.
- The canonical database is the normalized, account-scoped
  `orchard_ironwood_migration[s]_*` schema registered through
  `zcash_client_sqlite` migrations. It replaces the standalone crate's application-owned
  `ext_ironwood_migration_*` schema; the two schemas must not be treated as mirrors.
- Cross-pool `OutputRef`, `LockOwner`, lock expiry, owner-aware input-selection policy,
  balance classification, and lock conflict behavior are the upstream wallet APIs from
  the note-locking work, including PRs
  [#2716](https://github.com/zcash/librustzcash/pull/2716) and
  [#2726](https://github.com/zcash/librustzcash/pull/2726).
  The unmerged structural follow-up
  [#2742](https://github.com/zcash/librustzcash/pull/2742) proposes moving that same
  vocabulary into `data_api::locking` and extracting `OutputLockStore`. It is not
  early-carried here: the Zend delta stays on upstream `main` and should take the
  mechanical module/trait migration if and when that PR lands, without retaining a
  parallel locking abstraction.
- Merged upstream PR [#2751](https://github.com/zcash/librustzcash/pull/2751) is a release-only
  version/metadata update for `zcash_primitives` 0.30.0, `zcash_proofs` 0.30.0, and `pczt` 0.8.0.
  This branch includes that exact upstream merge; it changes no migration capability or schema.

## Zend improvements retained on top

The Zend delta deliberately leaves planning, scheduling, canonical PCZT/state types, and
the normalized upstream schema unchanged. It adds wallet locking and a separate, versioned
delivery-control layer rather than forking those implementations:

- `LockedWalletMigration` resolves each real, deferred-witness Orchard spend in an
  already-built PCZT by nullifier to its exact wallet `OutputRef`. It never substitutes
  an equal-value note or a result-set index.
- `PoolMigrationLockStore` makes exact-output reservation and owner-bearing canonical
  state replacement one transaction. SQLite rollback tests cover a later batch conflict
  and a failure serializing canonical state. Terminal or cancelled persistence releases
  only that migration owner's locks and clears stale owner tokens.
- Re-persisting after synchronization acquires newly materialized preparation outputs
  under the same durable owner. `migration_lock_owners` supplies the exact owner set for
  an owner-scoped `LockedInputPolicy`; foreign locks remain ineligible.
- Expired-transfer rebuild keeps the upstream rebuild API and lifecycle, but resolves the
  real source note by matching each stored PCZT action nullifier against same-denomination
  wallet candidates and requiring one exact match. This is necessary after proving fills
  witnesses: the upstream `witness().is_none()` heuristic no longer uniquely identifies
  the real input in an already-proved transaction.
- FVK-only persistence, update, and cancellation adapters expose that same atomic
  boundary to external signers without requiring a `UnifiedSpendingKey`.
- `validate_pczt_orchard_locks` closes the advisory-lock time-of-check/time-of-use gap:
  immediately before finalization it rejects an Orchard PCZT whose exact wallet input is
  now locked, unless the caller supplies that migration's recovered owner. An ordinary
  finalizer supplies no owners; migration delivery supplies exactly its durable owner.
- `MigrationState::transfer_amount(&MigrationTransaction) -> Option<Zatoshis>` exposes
  the canonical crossing denomination to SDKs without reimplementing schema/index logic.
- The backend crate now owns the typed delivery protocol: non-zero CAS revisions, Rust-random
  run/artifact/claim identities, signer ownership, immutable unsigned and signed PCZT evidence,
  exact transaction bytes, bounded versioned policy requests, explicit submission outcomes,
  storage-finality evidence, and recovery reasons. The SDK adapts these domain types; it does not
  maintain a second delivery state machine.
- `zcash_client_sqlite` persists that protocol in versioned additive
  `orchard_ironwood_delivery_*` tables. Exact DDL, indexes, triggers, foreign keys, and schema
  version are provenance-checked before use. Canonical `orchard_ironwood_migration_*` tables and
  `MigrationState` remain the exact upstream implementation.
- Delivery mutations use SQLite `IMMEDIATE` transactions and compare-and-swap the canonical state,
  delivery revision, run identity, policy fingerprint, artifact identity, and live claim. Rust owns
  the monotonic clock session and lease sampling, so an FFI caller cannot extend or backdate a
  claim by supplying wall-clock values.
- Scheduled delivery re-derives every claim from current canonical state and binds the canonical
  PCZT, transaction fingerprint, materialized txid, exact bytes, expiry, and signer path. A restart
  can resume an owned lease or reconcile an unknown submission outcome without inventing a second
  canonical transaction.
- Immediate migration is a separate lane but uses the same run, source-reservation, artifact,
  policy, submission, and finality vocabulary. The store first derives and reserves an
  account-scoped intent from wallet state under a Rust-generated owner; only then may it expose a
  typed proposal or PCZT. The only caller-supplied amount is a maximum gross authorization; the
  SQLite store re-derives the exact selected Orchard input total from the canonical proposal and
  rejects an over-limit proposal before any run, reservation, lock, or claim write in that same
  wallet transaction. Callers cannot inject arbitrary sources, exact amounts, dependencies, or
  expiry. Unsigned and signed PCZT bytes are durable and never overwrite each other, including
  across an external-signature relaunch.
- The user's maximum gross authorization is a versioned companion record committed in the same
  SQLite transaction as the immediate run and source locks. The published v1 wallet migration is
  frozen to its original schema fingerprint; its v2 successor rebuilds the immediate table under
  corrected lifecycle constraints and never fabricates authorization for legacy rows. A legacy row
  at a forward-exposure boundary is unavailable as `MissingSpendAuthorization`; exposed, outcome,
  and terminal states retain their non-exposing reconciliation paths. An exact unexposed
  `materialization_failed` state may be explicitly reauthorized. The retry transaction atomically
  inserts authorization and advances the claim/revision, or rolls back all three.
- A known-unsent immediate materialization failure may reacquire only a fresh bounded claim for the
  same account, run, artifact, signer, policy, proposal, and reservations. Rust requires an active
  run with no lease, PCZT, exact transaction, txid, or exposure history; it never derives a second
  proposal. Ambiguous or externally exposed artifacts remain fail-closed.
- Submission policy distinguishes direct canonical public-DNS TLS, public-DNS TLS through an
  isolated Tor proxy, canonical v3 onion service transport, and explicit loopback development
  transport. Literal IP and legacy numeric-IP spellings fail closed rather than bypassing the
  public-endpoint class. A public LWD host is never mislabeled as an onion service or silently
  downgraded to direct transport when Tor was requested.
- Source reservations remain an independent wallet-selection exclusion through network ambiguity
  and the fixed storage-finality horizon. A unique active-source index prevents the same Orchard
  output from backing two runs. Finalized exact destination evidence is archived before release so
  a later deep rewind fails closed and reacquires exclusion instead of silently spending the source.
- `OrdinarySpendAuthorization` is an account-explicit Rust capability. The SQLite producer audits
  delivery schema provenance, legacy state, active/recovery runs, and reservations atomically; an
  all-account producer evaluates every wallet account in the same read transaction. Ordinary spend
  proposal/finalization paths consume this result rather than relying on SDK timing.
- Account deletion is refused while delivery authority is active or in recovery. Only explicitly
  terminal finalized/abandoned runs may cascade, so unresolved exact bytes cannot be forgotten.
- Exact legacy standalone objects are quarantined by case-sensitive name and schema fingerprint.
  This includes both historical prefixes and the exact ZcashLC table
  `ext_zcashlc_orchard_ironwood_migration_invalid_marks`, which predates those prefixes. Both
  direct runtime status checks and migration-time quarantine discovery now recognize that table;
  no legacy plan, PCZT, lock, or runtime row is auto-imported into canonical state.

These changes follow librustzcash's established patterns: domain-typed capability traits,
the optional wallet adapter boundary, exact output identity, normalized canonical state,
owner-scoped advisory locks, and atomic multi-write operations with rollback tests.

## Standalone capabilities intentionally dropped as obsolete

- The duplicate `MigrationContext`, hand-written six/15-phase projection, private
  denomination/preparation/scheduling engine, `ReservedInputSource`, and separate
  rusqlite store are replaced by the canonical engine, wallet traits, and schema.
- The standalone `refresh_stale_transfers` proof-refresh path is replaced by upstream's
  deferred-anchor proving immediately before broadcast; an actually expired transfer is
  rebuilt through the canonical typed rebuild API.
- The old valargroup/alternate-librustzcash dependency graph, unstable cfg, private
  consensus pins, hand-rolled canonical-type encodings, and duplicate proof/sign pipeline
  are dropped. Zend follows the exact dependency graph and types of its up-to-date
  librustzcash fork.
- Platform transport and broadcasting remain outside the synchronous, network-free Rust
  engine. TLS, endpoint selection, Tor, background workers, and UI projection belong in
  the SDK/app integration rather than a second consensus engine.

## Capabilities deliberately outside the Rust consolidation

- Upstream boundary proving and durable checkpoint retention are preserved unchanged: the
  canonical wallet proves at the drawn boundary and retains every 144th-block checkpoint from
  NU6.3 activation. [Issue #2700](https://github.com/zcash/librustzcash/issues/2700) remains open
  as the upstream validation tracker even though the implementation landed through PRs #2710 and
  #2728. Funded public-testnet validation remains a release gate; it is not a reason to restore the
  standalone anchor implementation.
- Upstream `Complete` continues to mean every canonical migration transaction is mined; Zend does
  not change that upstream state enum. The additive Rust finality audit requires each exact
  resulting Ironwood output to be present on the active chain, fully scanned, and spendable under
  wallet rules, then retains source reservations for the fixed reorg horizon. The SDK may project
  this result for UI, but completion safety is no longer an SDK-owned predicate.
- An expired preparation invalidates its dependent pre-signed subtree. The canonical
  engine explicitly marks rebuilding that subtree as follow-up work; only expired
  transfers have the typed rebuild API today.
- Network I/O stays outside the synchronous Rust store. Endpoint selection, TLS/Tor, retries,
  process scheduling, and UI remain SDK/app responsibilities. The Rust protocol supplies a bounded
  validated submission policy and exact claim/outcome callbacks; it does not perform transport.
- The upstream master tracker is
  [issue #2630](https://github.com/zcash/librustzcash/issues/2630), review follow-ups are
  collected in [issue #2701](https://github.com/zcash/librustzcash/issues/2701), and the
  seeded minimal proving path remains open as
  [PR #2718](https://github.com/zcash/librustzcash/pull/2718). Any new Zend carry should
  be checked against those live references before implementation.

## Future upstream adoption triggers

These were live at the 2026-07-24 checkpoint. Their heads are audit evidence, not
pins; recheck upstream state before carrying anything.

- [PR #2742](https://github.com/zcash/librustzcash/pull/2742), observed at
  `b92ebf8d99203d76fdf6830a959494603753e8e7`, extracts `OutputLockStore` and
  moves locking vocabulary. If merged, adopt its exact trait/module layout; keep Zend's
  atomic migration-lock transaction only as an additive implementation of that upstream boundary.
- Draft [PR #2333](https://github.com/zcash/librustzcash/pull/2333), observed at
  `efb348e4a4163ff4c460ae6f57858c00fb37b134`, redesigns spendability schema and
  anchor priority. If merged, migrate Zend's exact-output completion SQL to its exact
  schema/helper. It does not by itself replace migration storage finality.
- Draft [PR #2738](https://github.com/zcash/librustzcash/pull/2738), observed at
  `008a36a053129f8b966524d3aaa672751ceaf540`, moves and threads `TargetHeight`.
  If merged, take the mechanical type/API migration without retaining a parallel Zend
  target-height abstraction.
- [PR #2659](https://github.com/zcash/librustzcash/pull/2659), observed at
  `552130e7bd8b6c472d9e878fb5183913c7c0f685`, adds a backend-agnostic
  privacy/network layer. If merged, SDK transport may delegate to it where contracts
  align; Rust's network-free durable delivery authority remains separate unless upstream
  supplies the same exact outcome and recovery semantics.
- Closed draft [PR #2705](https://github.com/zcash/librustzcash/pull/2705), branch
  `31c3cd180821244fe2a8ef7469b692410627f147` (implementation
  `4b1ce8d6530cb29d2267ff84ec7d9ed2225e2acd`), is not carried. The accepted
  upstream migration schema is normalized and uses no structured blobs except the opaque
  PCZT; Zend's separately versioned delivery/finality evidence is not a competing
  canonical migration-state codec.

## Candidate upstream proposals after Zend review

Keep these as small, independently reviewable proposals rather than proposing the retired engine:

- exact-output lock resolution and atomic owner-bearing migration persistence;
- pre-finalization PCZT lock validation for ordinary and migration-owned spends;
- the minimal transfer-amount accessor needed by typed SDK projections;
- generic typed delivery identities, CAS/lease semantics, exact-artifact evidence, and
  submission-outcome recovery, without Zend-specific transport or UI policy;
- account-scoped immediate reservation-before-proposal, atomic maximum-gross authorization,
  exact known-unsent claim reacquisition, and ordinary-spend authorization;
- wallet-backed output finality evidence and finalized deep-rewind recovery.

Each proposal must first be rechecked against current `zcash/librustzcash` issues, pull requests,
branches, and ZIP work. The implementation should be split where upstream can accept a general
primitive without accepting Zend's entire additive runtime schema.

## Downstream cutover rule

The Swift SDK should bind directly to the Zend librustzcash revision and translate its FFI/runtime
model to the canonical state plus Rust-owned delivery protocol. Remove the standalone crate pin and
SDK-owned `ext_ironwood_migration_*` runtime only after all of these gates pass:

1. Every supported legacy database is either demonstrably fresh or enters an explicit, tested
   recovery workflow; retirement never silently discards old rows or possibly exposed bytes.
2. The rebuilt binary artifact records and CI-verifies the exact Zend librustzcash source revision,
   toolchain, features, checksums, and supported platform slices.
3. Rust and Swift tests cover scheduled and immediate reservation-before-exposure, software and
   external signing, relaunch/lease expiry, unknown outcomes, reorg recovery, ordinary-spend
   exclusion, account deletion, and finalized deep rewind.
4. A funded public-testnet wallet proves the complete engine -> rebuilt/provenance-locked SDK -> app
   path, including a spendable Ironwood destination and post-finality source release.
5. The iOS integration is folded into the branch derived from the designated PR #132 tip and passes
   app build/test validation. Retirement does not authorize making that PR ready, merging it,
   deploying TestFlight, or enabling production migration cadence.
