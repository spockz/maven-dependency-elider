<!-- WHY: Records the revised Maven resolver work package and measured lifecycle constraints from RQ-0006. -->
# Work Package Handover: WP-RESOLVE-01 Maven Lifecycle & Dependency Graph Consistency

* **Status**: Slices 3.2c–3.2d implemented and independently reviewed; package gates pass
* **Owning Thread / Session**: Primary Coordinating Session
* **Date**: 2026-10-27
* **Target Branch / Base**: `main`
* **Related Research Question**: [RQ-0006](../research/RQ-0006-maven-artifact-view-consistency-and-early-resolution-hooks.md)
* **Related Architecture Decision**: [ADR-0002](../adr/0002-in-memory-artifact-mutation-for-downstream-packaging-transparency.md)

---

## 1. Executive Summary & Non-Negotiable Invariants

### 1.1 Objective and measured boundary

Determine how Maven's separate direct dependency and resolved classpath views behave during lifecycle re-resolution, then support exact replacement paths for retained trimmed JARs without mutating Maven's project artifact cache. This work package no longer assumes that a `ProjectDependenciesResolver` decorator controls all Maven resolution paths.

The real Maven 3.9.11 fixture establishes that a priority-indexed `ProjectDependenciesResolver` decorator is selected for `dependency:tree`, while live lifecycle TEST requests bypass it. A test-only `RepositorySessionDecorator` does receive those requests and can substitute an exact retained JAR path after an initialize-phase plan is written to repository session data. The prior direct-plus-resolved mutation diagnostic also shows that later lifecycle resolution can load the retained artifact again from its original repository path.

The current production slice publishes validated retained-JAR GAVCE-to-path mappings and applies those exact mappings through a copied repository session with a wrapping `WorkspaceReader`. An isolated Maven 3.9.11 consumer proves test-seeded first-request activation and, after the production `elide` Mojo publishes a plan, a test helper directly invokes `ProjectDependenciesResolver.resolve` with a TEST filter using the same project and session. This is a distinct resolver call, not a second Maven `MojoExecutor` lifecycle request; EventSpy does not capture it as a lifecycle request. The resolver decorator observes its graph transformation: with the extension, the result contains root→keep; without it, the result contains root→drop+keep. Direct dependency membership stays unchanged in both cases. This does not establish `dependency:tree` behavior or broader Maven compatibility.

The production `elide` goal now binds the raw inventory to a unique compatible graph capture, computes an effective decision, trims retained JARs using the effective per-artifact roots, and stages reports and replacements before publishing the resolver plan last. A distinct direct `ProjectDependenciesResolver.resolve` call with a TEST filter, using the same project and session, proves the production decorator projects the returned graph from root→drop+keep to root→keep. Direct artifact membership remains unchanged; retained artifact file pointers use the validated output. This fixture does not prove `dependency:tree` behavior.

### 1.2 Current invariants and open requirements

1. Keep Maven Resolver objects and live Maven artifacts out of session data. Store detached maps, lists, strings, and integer schema versions only, because plugin and core-extension realms may load project classes separately.
2. A missing project plan or empty replacement map returns the original repository session. A malformed plan, missing replacement file, or changed expected SHA-256 digest fails explicitly.
3. Replace only exact retained JAR GAVCE matches and delegate all other workspace lookups.
4. Forward Maven's `MavenWorkspaceReader.findModel` API to an existing Maven workspace reader. Same-GAV reactor behavior still requires a real integration test.
5. Keep direct artifact membership and the POM model unchanged. Apply only node-ID removals approved by the effective graph policy, and validate the predicted projection against a distinct direct TEST resolver call before publishing the plan.
6. Production activation, goal publication, and the direct TEST resolver projection are proven in one Maven 3.9.11 single-project fixture. This does not prove another lifecycle Mojo request, `dependency:tree`, reactor isolation, concurrent writers, or other Maven versions.
7. Output/report/view/plan publication uses synchronous staged rollback; process crashes and concurrent goal executions are outside the guarantee.
8. Keep `dependency:tree` claims separate from binary-resolving lifecycle requests. A tree-only POM collection does not prove that a missing JAR is unused.

---

## 2. Track Decomposition & Directed Acyclic Graph (DAG)

The graph below records the original proposal. Tracks 2–5 are now gated by the measured lifecycle boundary above; they are not authorization to prune dependency subtrees or claim general resolver consistency.

```text
┌────────────────────────────────────────────────────────┐
│ Track 1: Re-Resolution Diagnostic Harness & Spying    │
└──────────────────────────┬─────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│ Track 2: Core Graph & Resolution Result Pruning Engine │
└──────────────────────────┬─────────────────────────────┘
                           │
             ┌─────────────┴─────────────┐
             ▼                           ▼
┌──────────────────────────┐┌──────────────────────────┐
│ Track 3: Path-Aware      ││ Track 4: Post-Download   │
│ Mediated Graph Capture   ││ Resolver Decorator Hook  │
└────────────┬─────────────┘└────────────┬─────────────┘
             │                           │
             └─────────────┬─────────────┘
                           ▼
┌────────────────────────────────────────────────────────┐
│ Track 5: Fixtures, Tree Verification & End-to-End Gates│
└────────────────────────────────────────────────────────┘
```

---

## 3. Track Specifications & Committable Slices

### Track 1: Re-Resolution Diagnostic Harness & Spying

**Goal**: Build a deterministic diagnostic test harness that captures the internal Maven lifecycle state and reproduces the exact conditions causing `DependencyContext` cache invalidation and re-resolution.

* **Slice 1.1: Lifecycle Context Spy & State Recording**
  * Implement test utilities in `dependency-elider-maven-plugin/src/test/java/...` to monitor `MavenProject.getArtifacts()`, `MavenProject.getDependencyArtifacts()`, and `DependencyContext`.
  * Record artifact object identity, collection size, and backing file paths across lifecycle phases.
* **Slice 1.2: Re-Resolution Reproduction Test**
  * Codify the failure mode where setting `project.setDependencyArtifacts(retainedDirect)` causes a subsequent dependency-resolving mojo (e.g. `prepare-package` probe) to revert `getArtifacts()` to untrimmed JARs.
  * Establish baseline assertions that any proposed solution must satisfy.

---

### Track 2: Core Graph & Resolution Result Pruning Engine (`elider-core`)

**Goal**: Preserve the measured direct-tree resolver feasibility result and define safe graph policy before any production graph transformation.

* **Slice 2.1: Retained JAR Session Plan**
  * Publish detached exact retained-JAR path mappings only after trim outputs and reports validate.
  * Apply matching paths from `RepositorySessionDecorator` through a copied session and `WorkspaceReader`.
  * Do not prune whole-artifact graph nodes until a mediated graph and retained-descendant policy are defined and tested.
* **Slice 2.2: Packaged Component Activation**
  * Verify the indexed production component in an isolated consumer core-extension realm against a no-production-extension control.
  * Seed only a classloader-neutral JDK payload from test support before the first resolver request; assert exact resulting path/hash plus unchanged repository originals.
  * Keep test-only seeder classes outside the production artifact; constrain claims to Maven 3.9.11 and one sequential project.
  * This proves first-request activation/substitution. A fresh later TEST resolution after production Mojo publication is a separate gate.

---

### Track 3: Path-Aware Mediated Graph Capture (`elider-core` & `dependency-elider-maven-plugin`)

**Goal**: Capture the mediated graph and define a conservative effective-artifact policy before any production filtering or artifact-view mutation.

* **Slice 3.1: Post-Mediation Capture-Only Prototype**
  * Add a separate indexed `RepositorySessionDecorator` that copies the session, chains the existing `DependencyGraphTransformer`, calls it exactly once, snapshots its returned root, and returns that same root. Delegate exceptions propagate.
  * Store project-scoped snapshots as immutable JDK-only maps/lists. Use traversal identity IDs and ordered edges so equal-coordinate nodes, repeated references, diamonds, and cycles remain distinct. Preserve dependency coordinates, effective dependency scope/optionality, exclusions, managed bits, aliases/relocations, and conflict winner/original-scope/original-optionality metadata. Represent winners outside reachable child edges as metadata-only nodes.
  * Keep the structural graph fingerprint independent of plan provenance. Record decoration-time plan presence/fingerprint/generation and a separate capture generation; absent and present-empty plans remain distinct. Append each resolver invocation with session-data compare-and-set, including repeated graph/provenance captures.
  * Prove the packaged decorator in the existing Maven 3.9.11 consumer: initial unplanned capture contains both fixture dependencies; later capture has published-plan provenance and leaves the original row unchanged. Keep this slice capture-only: no node filtering, direct-view changes, result-list adaptation, tree rendering, or report persistence.
* **Slice 3.2a: Pure Effective-Graph Policy**
  * Atomically capture the graph before and after Maven's transformer within one resolver call, with shared request token, project identity, plan provenance, and structural inventory.
  * Accept only a unique plan-absent pair whose post-transform artifact GAVCE+scope inventory exactly matches the caller's raw decision; otherwise retain every raw elision.
  * Promote all occurrences of a retained GAVCE and repeatedly retain every ancestor occurrence until stable. Protect identity groups with conflicting path scope/optionality/exclusions, pre-mediation competing versions, winner references, unknown edges, or ambiguous raw outcomes.
  * Keep this pure: no `MavenProject`, report, file, session-plan, dependency tree, or artifact mutation. Pair selection here does not prove TEST scope or match artifact paths/hashes to the actual `ElideMojo` inventory; later integration must establish a unique context match or fail closed.
* **3.2a review follow-up**: explicit null-child edges in either pre- or post-mediation snapshots now trigger global fail-closed protection for raw-elided candidates and disable direct-leaf advice. The focused suite passes 27/27: 2 inventory-protection tests, 15 pure policy cases, 4 decorator tests, and 6 store tests. Full `make check` passes with 149 core and 140 plugin tests, formatting, Checkstyle, PMD, SpotBugs, and Markdown lint.
* **Slice 3.2b: Prepare/Finish and Bytecode Closure**
  * `prepare` fingerprints resolved artifact paths and bytes before scanning, verifies them after scanning and graph binding, and binds only a unique plan-absent pair whose post graph GAVCE/scope inventory exactly matches the Maven inventory in an explicit TEST context. Unsupported artifact-type projection, including Maven `test-jar` mapped to resolver extension `jar` but not scanned by the current analyzer, fails closed to zero effective drops.
  * `finishAnalysis` runs an analysis-only fixed point over strict bytecode roots and graph ancestor promotion. It seeds unchanged retained/configured pass-through/dynamic-root artifacts against the complete scanned inventory, analyzes newly reached dropped JARs as program inputs, and repeats ancestor promotion until stable. A→raw-drop B→C, raw-retained B method→C, distinct ancestor re-closure, trim-disabled dynamic-root promotion, and input-digest changes are covered.
  * This method returns advisory in-memory analyses only. It writes no trimmed JARs/cache manifests and changes no MavenProject, session, reports, artifact views, or resolver graph. The existing output-producing `finish(prepared)` remains on the raw decision and does not consume discovered roots. Direct declarations remain untouched; this slice does not establish output consistency.
  * Focused analysis/binding suite passed 38/38. Log: `/tmp/wp-resolve-3.2b-focused.log`, copied to `dependency-elider-maven-plugin/target/wp-resolve-3.2b-focused.log` (SHA-256 `fe686f4270a83bda927256e61f7809230fa6689bd2f9855f2f411b69793d81a7`). Full `make check` passed with 149 core and 159 plugin tests, all Java lint/static checks clean, and Markdown lint at 0 issues. Log: `/tmp/wp-resolve-3.2b-make-check.log`, copied to `dependency-elider-maven-plugin/target/wp-resolve-3.2b-make-check.log` (SHA-256 `befd00378e66056cd0532221dd4125fd834e7147e7f3ba7f2413a526fef87776`).
  * The binding regression represents retained Maven `test-jar` (`tests` classifier, resolver extension `jar`) as the parent of raw-dropped `drop-library`; because the current analyzer scans only Maven type `jar`, pair matching fails closed and returns zero effective removals.
* **Slice 3.2c: Output-Producing Trim Integration (historical milestone)**
  * Implement an isolated effective-output engine that consumes immutable `EffectiveAnalysis` once; the live `finish(prepared)` path remains on the legacy raw decision until Slice 3.2d can coordinate views and resolver publication.
  * Bind output/cache identity to source inventory and digests, effective per-artifact roots and pass-throughs, bytecode references, production output content, and compiler/JDK context. Require exact candidate roots and both SHA-256/SHA-1 output hashes on cache hits; classless retained JARs pass through byte-identically.
  * Stage complete output generations and the manifest before switching the commit marker. Roll back failed pre-commit replacement and preserve the prior generation; recognize a move-then-throw as committed only when the staged manifest disappeared and the committed digest matches.
  * Focused tests pass 13/13. `make lint-java` and full `make check` pass; full checks report 149 core and 177 plugin tests and Markdown linting 35 files with 0 issues. Exact logs and hashes are recorded below.
  * At the 3.2c milestone, normal goal publication was not yet wired to this engine. Slice 3.2d below records the completed integration.
* **Slice 3.2d: Resolver Views and Later-Resolution Proof (implemented)**
  * Slices 3.2c and 3.2d are committed together because an effective-output engine cannot safely become the production `finish` path while reporting and resolver publication still consume only the raw decision. The combined integration binds one finalized effective analysis across outputs, reports, resolved views, and plan activation.
  * Apply exact effective graph node IDs only after source fingerprint validation, then verify the projected fingerprint. A distinct direct TEST resolver call supplies the observed later graph; mismatch fails before mutation.
  * Keep direct artifact membership and the POM model unchanged. Stage reports, outputs, and reversible Maven views before activating the resolver plan last. Synchronous rollback is tested; process crashes and concurrent executions are not atomic.
  * Independent review approved the implementation after the semantic and rollback fixes. `make lint-java` is clean; `make test-plugin` and `make check` pass 149 core and 198 plugin tests. The full-check log reports `Linting: 35 files` and `Summary: 0 issues in 0 files` at lines 469–470. Log `/tmp/wp-resolve-3.2d-make-check-final2.log` (SHA-256 `7ef1be42b99b76a546a1a042aa9742ccba1fcf1f770560179fed3cc25f328fd3`), copied byte-for-byte to `dependency-elider-maven-plugin/target/wp-resolve-3.2d-make-check-final2.log`.
  * `make test-examples` passes Basic, Spring Boot, CVE unused, and CVE safe-class fixtures; core 149/149 and plugin 198/198. Graphless fixtures intentionally assert zero whole-artifact removals; the packaged extension lifecycle fixture proves the positive graph-removal case. Log `/tmp/wp-resolve-3.2d-test-examples-final6.log` (SHA-256 `21385ca8bbaeb896d8395aac7062b3944a74ab9db05be504c53d838fc481f0d2`), copied byte-for-byte to `dependency-elider-maven-plugin/target/wp-resolve-3.2d-test-examples-final6.log`.
* **Slice 3.3: Path-Aware Elision Report Extension**
  * Persist the captured mediated graph plus raw candidate, effective disposition, and protection reason in `dependency-elider-report.json`.
  * Derive deterministic dependency paths from that snapshot for effective whole-artifact removals. Keep graph node IDs and edge metadata so repeated coordinates and differing scopes remain distinct.
  * Cover diamonds, repeated-coordinate occurrences, conflict-protected nodes, direct and transitive drops, and stable path ordering. This is an audit report over captured graph evidence, not a claim about the standard `dependency:tree` goal.
* **Slice 3.4: Report Goal Tree Rendering**
  * Let `dependency-elider:report` render the persisted mediated graph snapshot with retained/effective-drop status and dependency paths.
  * Do not invoke or claim to alter `maven-dependency-plugin:tree`; this goal renders saved graph evidence only and fails clearly when no compatible graph snapshot is persisted.

#### Slice 3.1 implementation evidence

* `EliderMediatedGraphCaptureDecorator` is a separate indexed production `RepositorySessionDecorator`. It copies the session, invokes the prior `DependencyGraphTransformer` exactly once with the original transformation context, captures its returned root, and returns that same node. Exceptions propagate. The artifact-path decorator's no-plan identity behavior is unchanged.
* `ResolverArtifactGraphSnapshot` traverses by object identity with ordered edge records, preserving equal-coordinate nodes, repeated edges, diamonds, cycles, null child slots, and metadata-only conflict winners outside child reachability. It detaches coordinates, dependencies, scopes, optionality, exclusions, managed bits, aliases, ordered relocation sequences, and conflict metadata. Structural fingerprints exclude plan state, plan generation, and capture generation.
* Schema v2 keeps plan observations and graph snapshots in repository-session data. CAS makes observations session-scoped and appends captures atomically; independent sessions for the same project have independent plan generations. Capture generation follows append order, while plan generation records decoration order and may be out of capture-completion order.
* Snapshot construction recursively freezes JDK-only maps/lists. Loading validates exact nested fields and types, project keys, root/node/edge/winner references, actual reachability, structural fingerprints, and capture-generation consistency. Unsupported original scope/optionality values fail explicitly instead of using arbitrary `toString()` output.
* Focused unit tests pass 23/23 across `ResolverArtifactGraphSnapshotTest`, `ResolverArtifactGraphSnapshotStoreTest`, `EliderMediatedGraphCaptureDecoratorTest`, `ResolverArtifactGraphSnapshotRoundTripTest`, and `ResolverArtifactGraphTopologyValidationTest`. They cover null root, nullable optionality, nested validation, winner encodings, child-edge consistency, deep freezing, and concurrent distinct captures. The packaged Maven 3.9.11 `DependencyContextLifecycleIntegrationTest` passes 4/4. Positive fixture evidence is under `dependency-elider-maven-plugin/target/production-mojo-evidence/mojo-positive/reports/graph-{initial,later}.tsv`; the negative control's later graph report has `missing=true` because it does not load the production extension.
* Historical 3.1 capture assertion: the initial graph was consumer/drop/keep at `n0` with edges `n0→n1,n2`, and a test helper removed a direct leaf to trigger another capture. Slice 3.2d supersedes that helper path with a fresh TEST resolver call that preserves direct membership and exercises production graph projection.
* Review-fix validation passed: `make check` reported 149 core and 123 plugin tests, with formatting, Checkstyle, PMD, SpotBugs, and Markdown lint clean. The worktree used the cached Markdown linter via `MARKDOWNLINT=../../tools/node_modules/.bin/markdownlint-cli2` because `.scratch/tools` is not provisioned in this linked checkout. Log: `dependency-elider-maven-plugin/target/wp-resolve-3.1-review-fix-null-and-validator-make-check.log`. The two remaining PMD LawOfDemeter suppressions are method-scoped in test fixture helpers for MavenProject identity access and RepositorySystemSession payload access.
* Historical 3.1 boundary: capture alone did not filter graph nodes, change views, or persist reports. Slice 3.2d below records the later production projection and publication boundary. Path-aware reporting remains Slice 3.3; `dependency:tree`, reactor, concurrent-writer, and other-Maven-version guarantees remain open.

#### Slice 3.2a policy evidence and limits

* `ResolverArtifactGraphCapturePair` stores pre/post snapshots from the same transformer invocation with one token and consistent project/plan provenance. One session-data compare-and-set appends both snapshots and the pair with the same capture generation.
* `EffectiveGraphPolicy` selects a unique planless pair only when its post graph has the same GAVCE+scope inventory as the raw `ElisionDecision`; missing, duplicate, plan-present, unknown, or unmatched cases return zero removals. This is a pure selector API and does not claim to bind the pair to the Mojo's TEST request, paths, or file hashes.
* `EffectiveGraphClosure` promotes all occurrences of a required artifact identity, then recomputes reverse ancestor closure until stable. A repeated artifact can therefore promote a second parent on another path. Protected raw-elided nodes remain in results as `PROTECTED` with their reason. Protection preserves identities with different scope/optional/exclusion path metadata, pre-mediation competing versions even without a winner marker, explicit mapped/external winner references, and incomplete inventories. Any explicit null-child edge in either snapshot is globally incomplete conflict visibility, protects all raw-elided candidates, and disables direct-leaf advice.
* Focused command passed 27 tests: `EffectiveGraphInventoryProtectionTest` (2), `EffectiveGraphPolicyRetentionTest` (5), `EffectiveGraphPolicySafetyTest` (10), `EliderMediatedGraphCaptureDecoratorTest` (4), and `ResolverArtifactGraphSnapshotStoreTest` (6). Log: `/tmp/wp-resolve-3.2a-null-edge-review-fix-focused.log` and `dependency-elider-maven-plugin/target/wp-resolve-3.2a-null-edge-review-fix-focused.log` (SHA-256 `1c11db0c9a4928b6d5deb33e218c9db78cb8e5024cfbf5f43a3772bb7190bf1a`).
* Full `make check` passed with 149 core and 140 plugin tests plus formatting, Checkstyle, PMD, SpotBugs, and Markdown lint. Log: `/tmp/wp-resolve-3.2a-null-edge-review-fix-make-check.log` and `dependency-elider-maven-plugin/target/wp-resolve-3.2a-null-edge-review-fix-make-check.log` (SHA-256 `bae77946211488287b0250eff79b8ee95b32b0403f74d19f3230b10c8fd0c4e4`).
* This slice cannot prove graph-policy selection for the actual Mojo inventory/context. It does not mutate nodes or views, compute bytecode pass-through closure, produce reports, prove a later dependency tree, or establish safe direct-view mutation. Keep raw effective policy advisory until the later context/path binding and re-resolution gates pass.

#### Slice 3.2c output engine evidence (historical milestone)

* At the 3.2c milestone, `MavenDependencyTrimmer.trimEffectiveOutputs(EffectiveAnalysis)` was an isolated effective-output entry point, while normal `finish(prepared)` still used the raw decision. Slice 3.2d supersedes that wiring gap: normal goal execution now consumes the finalized effective analysis for output, reports, resolved-view removals, and plan publication.
* Effective cache identity includes ordered artifact inventory and source digests, per-artifact roots/pass-through state, bytecode reference results, production-output content digest, trim options, compiler release, and JDK platform identity. Cache hits require exact roots/retained/reachable metadata and re-hash both output digests. A classless retained resource JAR remains in inventory/cache context but is excluded from ProGuard candidate analysis and preserved byte-identically.
* Publication stages outputs and a manifest, then switches the manifest commit marker. A failed pre-switch publication restores the prior generation; a move that succeeds and then throws is recognized as committed only if the staged manifest is gone and the target digest matches. Staging lives beside `.generations` so generation enumeration includes committed generations only. This is synchronous rollback, not crash- or concurrent-writer atomicity.
* Focused effective-output suite passes 13/13: `MavenElisionServiceEffectiveOutputTest` (6) and `MavenElisionServiceEffectiveOutputTransactionTest` (7). Logs: `/tmp/wp-resolve-3.2c-focused-final.log` and `dependency-elider-maven-plugin/target/wp-resolve-3.2c-focused-final.log`; SHA-256 `29b510bd71ce896bab67af680479d6818891677bbdcdc02193961d21838c0a00`.
* `make lint-java` passes with Checkstyle 0, PMD 0, and SpotBugs 0. Logs: `/tmp/wp-resolve-3.2c-lint-current.log` and `dependency-elider-maven-plugin/target/wp-resolve-3.2c-lint-current.log`; SHA-256 `8e812ea666cb7d91f70b072be79a822a3de73f38e71c4bbaa24e7849dd63c806`.
* Full `make check` passes with 149 core and 177 plugin tests, clean Checkstyle/PMD/SpotBugs, and Markdown linting 35 files with 0 issues. Logs: `/tmp/wp-resolve-3.2c-make-check-final.log` and `dependency-elider-maven-plugin/target/wp-resolve-3.2c-make-check-final.log`; SHA-256 `4b8a75de0c7ad11a6c6c8394f8a2473b18d9018d248111cfb74b9ffe9822dfa5`.
* The output generation/cache and synchronous rollback behavior remain as described above. Process crashes and concurrent writers are outside the rollback guarantee.

#### Slice 3.2d resolver views and publication evidence

* `ElideMojo` carries raw and effective decisions separately. Only effective safe removals change the resolved view; direct artifact membership and the POM model remain unchanged. Reports persist raw candidate drops separately from effective drops, and the output engine consumes the same finalized effective analysis used by the goal.
* The later TEST proof is a distinct direct `ProjectDependenciesResolver.resolve` call from the post-elide fixture Mojo, using the same project and repository session. It records `DependencyResolutionResult.getResolvedDependencies()` independently from EventSpy lifecycle events. With the production extension, the transformed graph is root→keep and the exact resolved keep artifact uses trimmed bytes; without the extension, the graph retains root→drop+keep and both resolved dependencies use original repository bytes.
* Graph projection checks the source fingerprint before mutation and validates the projected fingerprint afterward. A mismatch leaves the source graph unchanged, including child-list object references. Equal-coordinate occurrences, shared descendants, and conflict-winner references are covered directly.
* Publication stages outputs and all report files, validates targets and replacement mappings, applies reversible Maven views, and activates the resolver plan last. Injected report, view, plan, output-generation, and rollback failures verify restoration of prior report bytes, view membership/file paths, and session payload. Rollback is synchronous and best-effort; process crashes and concurrent goal executions are not atomic.
* Retained file-pointer updates preserve direct object membership. This evidence does not establish `dependency:tree` output or broader Maven-version/reactor behavior.
* The final review and gate receipt is maintained above; it supersedes the earlier pre-final package counts and logs.

---

### Track 4: Post-Download `ProjectDependenciesResolver` Decorator & Core Extension Packaging

**Goal**: Package and activate the validated session-plan decorator in the appropriate Maven core-extension realm; retain the resolver/tree decorator only as a separately scoped tree feasibility path.

* **Slice 4.1: Production `RepositorySessionDecorator`**
  * Add a uniquely named indexed decorator and verify packaged discovery from `.mvn/extensions.xml` in an isolated Maven 3.9.11 consumer.
  * Publish only the detached per-project plan from `elide` after outputs and project views validate; the production Mojo-to-consumer handoff is still open.
  * Return the original session when no plan exists; copy and wrap the existing workspace reader for exact planned artifacts.
* **Slice 4.2: Core Extension Packaging and Boundaries**
  * Prove reactor isolation and supported Maven versions before claiming those guarantees.

---

### Track 5: Fixtures, Tree Verification & End-to-End Gates

**Goal**: Validate replacement-path behavior in a real binary consumer; defer effective-tree and whole-artifact graph claims until graph policy is complete.

* **Slice 5.1: Binary Consumer Replacement Test**
  * **5.1a complete**: a real consumer loads the packaged production extension and consumes a test-seeded plan on its first TEST request; an otherwise identical consumer without the production extension retains original paths/hashes.
  * **5.1b complete for one Maven 3.9.11 project**: an initial TEST resolution observes original JARs; the production `elide` Mojo trims keep-library and publishes a plan; a test helper then directly invokes `ProjectDependenciesResolver.resolve` with a TEST filter using the same project/session. The packaged production decorator projects that distinct result from root→drop+keep to root→keep. A negative control without the production extension returns both graph children. Direct dependency membership remains unchanged, while retained file pointers use the trimmed JAR. This is not a second lifecycle request and makes no `dependency:tree` claim.
  * The helper's explicit TEST resolver result is checked separately from EventSpy lifecycle request events. It proves one post-publication direct resolver call under the same project/session, not a second `MojoExecutor` lifecycle request. Parsed JSON confirms the consumer identity, effective whole-artifact drop, one pruned class, the trimmed SBOM SHA-256, and the original SHA-256 in its pedigree ancestor. The explicit result list also records artifact paths and SHA-256 values. Logs, snapshots, reports, and repository: `dependency-elider-maven-plugin/target/production-mojo-evidence/`.
* **Slice 5.2: Effective Graph Policy and Tree Verification**
  * Define mediated graph treatment for retained descendants before testing omitted tree nodes.
  * Assert each tree output independently; do not infer unused artifacts from tree-only artifact absence.
* **Slice 5.3: Path-Aware Audit Report Verification**
  * Verify `mvn dependency-elider:report` outputs exact dependency paths for all dropped artifacts in `example-basic-app` and `example-spring-boot-app`.
* **Slice 5.4: Full Repository Gate Sweep**
  * Run `make check` and `make test-examples` to verify that all 149+ core tests, plugin tests, Checkstyle, PMD, SpotBugs, and Markdownlint gates pass cleanly.

---

## 4. Verification Protocol

1. Run the plan store/decorator focused unit tests and assert no-plan session identity, project-key isolation, detached JDK-only payload values, exact GAVCE replacement, and delegated nonmatches.
2. Run `make check` for formatting, static analysis, and repository tests.
3. Packaged production extension activation and first-request test-seeded substitution are verified under Maven 3.9.11. The actual production Mojo handoff is verified by a distinct direct `ProjectDependenciesResolver.resolve` TEST call from a test helper after Mojo publication; this is not a second lifecycle request. The observed resolver graph is root→keep with the extension and root→drop+keep without it. `dependency:tree`, reactor, and additional Maven versions remain separate checkpoints.
4. Keep dependency-tree, direct artifact membership, and binary package assertions separate. Do not assert whole-artifact omissions until a mediated graph and retained-descendant policy is in place.
