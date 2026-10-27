<!-- WHY: Records the revised Maven resolver work package and measured lifecycle constraints from RQ-0006. -->
# Work Package Handover: WP-RESOLVE-01 Maven Lifecycle & Dependency Graph Consistency

* **Status**: In progress; design revision required
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

The current production slice publishes validated retained-JAR GAVCE-to-path mappings and applies those exact mappings through a copied repository session with a wrapping `WorkspaceReader`. An isolated Maven 3.9.11 A/B consumer proves both test-seeded first-request activation and the production `elide` Mojo handoff to a distinct later TEST request. With the extension, the later resolved view uses the trimmed JAR; without it, Maven resolves the original repository JAR while the direct artifact keeps its transformed file pointer. This does not establish production direct-view consistency, remove whole artifacts from the graph, or prune graph nodes.

A separate capture-only component now chains the existing Aether graph transformer and stores detached mediated-graph snapshots in repository session data. The packaged fixture proves an initial absent-plan snapshot contains both fixture dependencies and a later present-plan snapshot preserves the original capture. This does not choose or filter an effective graph.

### 1.2 Current invariants and open requirements

1. Keep Maven Resolver objects and live Maven artifacts out of session data. Store detached maps, lists, strings, and integer schema versions only, because plugin and core-extension realms may load project classes separately.
2. A missing project plan or empty replacement map returns the original repository session. A malformed plan, missing replacement file, or changed expected SHA-256 digest fails explicitly.
3. Replace only exact retained JAR GAVCE matches and delegate all other workspace lookups.
4. Forward Maven's `MavenWorkspaceReader.findModel` API to an existing Maven workspace reader. Same-GAV reactor behavior still requires a real integration test.
5. Keep the existing direct/resolved project-view behavior and do not prune graph nodes in this slice. A graph node cannot be dropped with its subtree while a retained descendant may still be needed.
6. Production component activation and actual Mojo publication followed by a distinct TEST request are proven for one Maven 3.9.11 consumer. Broader end-to-end behavior still requires graph, package, reactor, and compatibility evidence.
7. Test package consumers, graph/list/error consistency, reactor isolation, concurrency, and supported Maven versions before expanding the behavior.
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

**Goal**: Capture the full pre-elision dependency graph from the delegate resolver so `dependency-elider:report` can render complete path justifications for why each artifact was originally pulled into the project.

* **Slice 3.1: Post-Mediation Capture-Only Prototype**
  * Add a separate indexed `RepositorySessionDecorator` that copies the session, chains the existing `DependencyGraphTransformer`, calls it exactly once, snapshots its returned root, and returns that same root. Delegate exceptions propagate.
  * Store project-scoped snapshots as immutable JDK-only maps/lists. Use traversal identity IDs and ordered edges so equal-coordinate nodes, repeated references, diamonds, and cycles remain distinct. Preserve dependency coordinates, effective dependency scope/optionality, exclusions, managed bits, aliases/relocations, and conflict winner/original-scope/original-optionality metadata. Represent winners outside reachable child edges as metadata-only nodes.
  * Keep the structural graph fingerprint independent of plan provenance. Record decoration-time plan presence/fingerprint/generation and a separate capture generation; absent and present-empty plans remain distinct. Append with session-data compare-and-set and deduplicate identical project/graph/provenance captures.
  * Prove the packaged decorator in the existing Maven 3.9.11 consumer: initial unplanned capture contains both fixture dependencies; later capture has published-plan provenance and leaves the original row unchanged. Keep this slice capture-only: no node filtering, direct-view changes, result-list adaptation, tree rendering, or report persistence.
* **Slice 3.2: Path-Aware Elision Report Extension**
  * Update `MavenElisionReportSnapshot` and `MavenElisionReportWriter`:
    * Persist `MediatedDependencyGraph` into `dependency-elider-report.json`.
    * For each elided or trimmed artifact, record the shortest dependency path from project root (e.g., `example-spring-boot-app -> spring-boot-starter-web -> spring-webmvc`).
  * Block report-path conclusions on a later policy slice that defines source/ancestor retention and handles external conflict winners; Slice 3.1 only proves detached capture.
* **Slice 3.3: Report Goal Tree Rendering**
  * Update `dependency-elider:report` Mojo to format and print the tree of elided vs. retained artifacts with their dependency chains.

#### Slice 3.1 implementation evidence

* `EliderMediatedGraphCaptureDecorator` is a separate indexed production `RepositorySessionDecorator`. It copies the session, invokes the prior `DependencyGraphTransformer` exactly once with the original transformation context, captures its returned root, and returns that same node. Exceptions propagate. The artifact-path decorator's no-plan identity behavior is unchanged.
* `ResolverArtifactGraphSnapshot` traverses by object identity with ordered edge records, preserving equal-coordinate nodes, repeated edges, diamonds, cycles, null child slots, and metadata-only conflict winners outside child reachability. It detaches coordinates, dependencies, scopes, optionality, exclusions, managed bits, aliases, ordered relocation sequences, and conflict metadata. Structural fingerprints exclude plan state, plan generation, and capture generation.
* Schema v2 keeps plan observations and graph snapshots in repository-session data. CAS makes observations session-scoped and appends captures atomically; independent sessions for the same project have independent plan generations. Capture generation follows append order, while plan generation records decoration order and may be out of capture-completion order.
* Snapshot construction recursively freezes JDK-only maps/lists. Loading validates exact nested fields and types, project keys, root/node/edge/winner references, actual reachability, structural fingerprints, and capture-generation consistency. Unsupported original scope/optionality values fail explicitly instead of using arbitrary `toString()` output.
* Focused unit tests pass 23/23 across `ResolverArtifactGraphSnapshotTest`, `ResolverArtifactGraphSnapshotStoreTest`, `EliderMediatedGraphCaptureDecoratorTest`, `ResolverArtifactGraphSnapshotRoundTripTest`, and `ResolverArtifactGraphTopologyValidationTest`. They cover null root, nullable optionality, nested validation, winner encodings, child-edge consistency, deep freezing, and concurrent distinct captures. The packaged Maven 3.9.11 `DependencyContextLifecycleIntegrationTest` passes 4/4. Positive fixture evidence is under `dependency-elider-maven-plugin/target/production-mojo-evidence/mojo-positive/reports/graph-{initial,later}.tsv`; the negative control's later graph report has `missing=true` because it does not load the production extension.
* The packaged assertion checks exact topology: initial capture is consumer/drop/keep at `n0` with edges `n0→n1,n2`; later capture preserves the first row and is consumer/keep at `n0` with edge `n0→n1`. The test-only helper removes the known direct drop leaf solely to trigger a second request; no production graph filtering occurs.
* Review-fix validation passed: `make check` reported 149 core and 123 plugin tests, with formatting, Checkstyle, PMD, SpotBugs, and Markdown lint clean. The worktree used the cached Markdown linter via `MARKDOWNLINT=../../tools/node_modules/.bin/markdownlint-cli2` because `.scratch/tools` is not provisioned in this linked checkout. Log: `dependency-elider-maven-plugin/target/wp-resolve-3.1-review-fix-null-and-validator-make-check.log`. The two remaining PMD LawOfDemeter suppressions are method-scoped in test fixture helpers for MavenProject identity access and RepositorySystemSession payload access.
* Open: no graph node filtering, direct-view change, report persistence, path selection, descendant policy, general dependency-tree consistency, or reactor/concurrency/other-Maven-version guarantee is included. Never drop a node subtree without proving retained descendants remain reachable.

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
  * **5.1b complete for one Maven 3.9.11 project**: a TEST request first resolves the original JAR, the actual production `elide` Mojo trims keep-library and publishes a session plan, and a later TEST request sees that plan. With the production core extension, the resolved view has the trimmed path/hash; without it, the resolved view returns the original repository path/hash while the direct artifact pointer remains trimmed. Original repository bytes are unchanged. A test-only helper removes exactly one synthetic direct drop leaf to trigger the later request; this does not prove production direct-view consistency or graph policy.
  * The isolated fixture asserts two distinct EventSpy request identity tokens: request 1 has no plan before the goal, request 2 has the plan after the elision summary. Parsed JSON confirms the consumer identity, one whole-artifact drop, one pruned class, the trimmed SBOM SHA-256, and the original SHA-256 in its pedigree ancestor. Logs, snapshots, reports, and repository: `dependency-elider-maven-plugin/target/production-mojo-evidence/`.
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
3. Packaged production extension activation and first-request test-seeded substitution are verified under Maven 3.9.11. The actual production Mojo handoff is also verified: initial original-path request, Mojo plan publication, and replacement consumption by a distinct later TEST request in the same process. General graph and package behavior remain separate checkpoints.
4. Keep dependency-tree, direct artifact membership, and binary package assertions separate. Do not assert whole-artifact omissions until a mediated graph and retained-descendant policy is in place.
