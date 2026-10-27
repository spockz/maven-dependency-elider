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

The current production slice publishes validated retained-JAR GAVCE-to-path mappings and applies those exact mappings through a copied repository session with a wrapping `WorkspaceReader`. An isolated Maven 3.9.11 A/B consumer proves the packaged production decorator is loaded and substitutes a retained JAR on the first TEST-resolution request when a test-only EventSpy seeds its JDK payload. This does not prove a fresh re-resolution after `ElideMojo` publishes the plan; actual Mojo-to-later-request handoff remains open. It does not remove whole artifacts or prune dependency graph nodes.

### 1.2 Current invariants and open requirements

1. Keep Maven Resolver objects and live Maven artifacts out of session data. Store detached maps, lists, strings, and integer schema versions only, because plugin and core-extension realms may load project classes separately.
2. A missing project plan or empty replacement map returns the original repository session. A malformed plan, missing replacement file, or changed expected SHA-256 digest fails explicitly.
3. Replace only exact retained JAR GAVCE matches and delegate all other workspace lookups.
4. Forward Maven's `MavenWorkspaceReader.findModel` API to an existing Maven workspace reader. Same-GAV reactor behavior still requires a real integration test.
5. Keep the existing direct/resolved project-view behavior and do not prune graph nodes in this slice. A graph node cannot be dropped with its subtree while a retained descendant may still be needed.
6. Production component activation and first-request test-seeded retained-JAR replacement are proven for one Maven 3.9.11 consumer; verify that the production `elide` Mojo publishes a plan after initial resolution and that a later TEST request consumes it before claiming end-to-end goal support.
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

* **Slice 3.1: Pre-Filter Graph Snapshot Model**
  * Create immutable model `io.github.spockz.elider.model.MediatedDependencyGraph`:
    * Records root nodes, parent-child edges, scope transitions, and conflict selections.
  * Extract the graph directly from delegate resolver's `DependencyResolutionResult.getDependencyGraph()` before pruning occurs.
* **Slice 3.2: Path-Aware Elision Report Extension**
  * Update `MavenElisionReportSnapshot` and `MavenElisionReportWriter`:
    * Persist `MediatedDependencyGraph` into `dependency-elider-report.json`.
    * For each elided or trimmed artifact, record the shortest dependency path from project root (e.g., `example-spring-boot-app -> spring-boot-starter-web -> spring-webmvc`).
* **Slice 3.3: Report Goal Tree Rendering**
  * Update `dependency-elider:report` Mojo to format and print the tree of elided vs. retained artifacts with their dependency chains.

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
  * **5.1b open**: preserve an initial original-path resolution, have the production `elide` Mojo publish the plan, then trigger a separate TEST request and assert the replacement path/hash plus unchanged repository originals.
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
3. Packaged production extension activation and first-request substitution with a test-seeded plan are verified under Maven 3.9.11. Before claiming end-to-end `elide` lifecycle support, assert an initial original-path resolution, Mojo publication, and replacement consumption by a separate later TEST request in that same consumer process.
4. Keep dependency-tree, direct artifact membership, and binary package assertions separate. Do not assert whole-artifact omissions until a mediated graph and retained-descendant policy is in place.
