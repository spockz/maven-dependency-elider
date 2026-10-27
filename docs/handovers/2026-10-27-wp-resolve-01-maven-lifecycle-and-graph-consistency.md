<!-- WHY: Defines the work package specification, track decomposition, and committable slices for resolving Maven lifecycle re-resolution and dependency graph consistency (RQ-0006). -->
# Work Package Handover: WP-RESOLVE-01 Maven Lifecycle & Dependency Graph Consistency

* **Status**: Ready for Implementation
* **Owning Thread / Session**: Primary Coordinating Session
* **Date**: 2026-10-27
* **Target Branch / Base**: `main`
* **Related Research Question**: [RQ-0006](../research/RQ-0006-maven-artifact-view-consistency-and-early-resolution-hooks.md)
* **Related Architecture Decision**: [ADR-0002](../adr/0002-in-memory-artifact-mutation-for-downstream-packaging-transparency.md)

---

## 1. Executive Summary & Non-Negotiable Invariants

### 1.1 Objective

Resolve the architectural asymmetry between Maven's direct dependency view (`project.getDependencyArtifacts()`) and resolved classpath view (`project.getArtifacts()`), and solve the `DependencyContext` cache-invalidation trap in Maven 3.9+.

The primary goals are:

1. **Unified Effective Graph**: Ensure that `mvn dependency:tree` and other dependency-inspection goals reflect the genuine post-elision effective graph rather than declared POM bloat.
2. **Re-Resolution Immunity**: Guarantee that downstream goals declaring `@RequiresDependencyResolution` do not invalidate the resolver cache and re-populate untrimmed original artifacts from `~/.m2/repository`.
3. **Path-Aware Audit Trail**: Capture the pre-filter Maven-mediated dependency tree (including scopes, conflict resolution, and parent-child edges) in `dependency-elider:report` so engineers can inspect the exact path that introduced each dropped or trimmed library.
4. **Clean Maven 3.9 & Forward Compatibility**: Implement integration using supported Eclipse Aether / Maven Resolver extension points (`DependencyGraphTransformer` / `RepositorySessionDecorator`), with graceful fallback for standard plugin invocations.

### 1.2 Non-Negotiable Invariants

1. **Zero Re-Resolution Regressions**: No downstream goal or phase transition may trigger re-resolution that silently restores elided dependencies or untrimmed original JARs into packaging.
2. **Effective Graph Fidelity**: When elision is active, `mvn dependency:tree` must omit completely elided dependencies while displaying retained transitive dependencies with valid parentage.
3. **Pre-Elision Path Attribution**: The pre-elision Maven-mediated dependency graph must be preserved in the elision report snapshot (`dependency-elider-report.json`) to explain *why* an artifact was on the classpath and *why* it was elided or trimmed.
4. **Reactor Isolation**: Graph transformations and session state must be strictly scoped to each reactor project and must not leak across project boundaries or reactor iterations.
5. **Fail-Closed Safety**: If trace files or configuration inputs are corrupt or invalid, resolution must fail closed or execute in an explicit pass-through mode without corrupting the Maven session.
6. **Backward Compatibility**: If the early resolver extension is not installed (e.g. standard standalone plugin execution), the plugin must fall back to the existing `INITIALIZE` in-memory mutation with documented boundaries.
7. **Verification Gates**: Every slice must pass `make check` (formatting, Spotless, Checkstyle, PMD, SpotBugs, Markdownlint, tests) and `make test-examples` across all fixtures.

---

## 2. Track Decomposition & Directed Acyclic Graph (DAG)

```text
┌────────────────────────────────────────────────────────┐
│ Track 1: Re-Resolution Diagnostic Harness & Spying    │
└──────────────────────────┬─────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│ Track 2: Eclipse Aether DependencyGraphTransformer     │
└──────────────────────────┬─────────────────────────────┘
                           │
             ┌─────────────┴─────────────┐
             ▼                           ▼
┌──────────────────────────┐┌──────────────────────────┐
│ Track 3: Path-Aware      ││ Track 4: Resolver Session│
│ Mediated Graph Capture   ││ Lifecycle Hook Injection │
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

### Track 2: Eclipse Aether `DependencyGraphTransformer`

**Goal**: Implement a custom Aether `DependencyGraphTransformer` that operates during dependency collection to prune unneeded nodes from the `DependencyNode` graph before Maven caches the resolved project.

* **Slice 2.1: Core Node Transformation Engine (`elider-core`)**
  * Create `io.github.spockz.elider.resolver.ElisionDependencyGraphTransformer` implementing `org.eclipse.aether.collection.DependencyGraphTransformer`.
  * Ingest the elision decision and trace evidence.
  * Prune unobserved dependency subtrees while preserving transitive ancestors of retained nodes.
  * Unit tests validating graph trimming with complex multi-level diamond and conflicting transitive dependencies.
* **Slice 2.2: Aether Context & Metadata Preservation**
  * Ensure that pruned `DependencyNode` trees preserve conflict resolution winner metadata, scope derivations, and optional flags for surviving nodes.
  * Verify that surviving nodes preserve standard Maven artifact coordinates.

---

### Track 3: Path-Aware Mediated Graph Capture (`elider-core` & `dependency-elider-maven-plugin`)

**Goal**: Capture the full pre-elision dependency graph so `dependency-elider:report` can render complete path justifications for why each artifact was originally pulled into the project.

* **Slice 3.1: Pre-Filter Graph Snapshot Model**
  * Create immutable model `io.github.spockz.elider.model.MediatedDependencyGraph`:
    * Records root nodes, parent-child edges, scope transitions, and conflict selections.
  * Extract the graph directly from Aether's root `DependencyNode` before pruning occurs.
* **Slice 3.2: Path-Aware Elision Report Extension**
  * Update `MavenElisionReportSnapshot` and `MavenElisionReportWriter`:
    * Persist `MediatedDependencyGraph` into `dependency-elider-report.json`.
    * For each elided or trimmed artifact, record the shortest dependency path from project root (e.g., `example-spring-boot-app -> spring-boot-starter-web -> spring-webmvc`).
* **Slice 3.3: Report Goal Tree Rendering**
  * Update `dependency-elider:report` Mojo to format and print the tree of elided vs. retained artifacts with their dependency chains.

---

### Track 4: Resolver Session Lifecycle Hook Injection

**Goal**: Inject the `ElisionDependencyGraphTransformer` into Maven's resolver session using standard, supported extension points.

* **Slice 4.1: Repository Session Decorator Implementation**
  * Implement `io.github.spockz.elider.plugin.EliderRepositorySessionDecorator` using `org.apache.maven.project.RepositorySessionDecorator` (Maven 3.9.4+ / Plexus component).
  * Wrap the existing `ChainedDependencyGraphTransformer` with `ElisionDependencyGraphTransformer`.
* **Slice 4.2: Core / Build Extension Packaging**
  * Configure the extension descriptor (`META-INF/plexus/components.xml` or Sisu `@Named`).
  * Support loading via `.mvn/extensions.xml` for whole-session graph governance.
* **Slice 4.3: Graceful Standalone Fallback**
  * If the core extension is absent, `ElideMojo` continues operating at `INITIALIZE` via `MavenArtifactViewUpdater` with an informative warning regarding `dependency:tree` diagnostic limitations.

---

### Track 5: Fixtures, Tree Verification & End-to-End Gates

**Goal**: Validate the integrated resolver and graph consistency across all reference applications and CLI commands.

* **Slice 5.1: `dependency:tree` Verification Test**
  * Verify that running `mvn dependency:tree` on `example-basic-app` with elision active omits `commons-codec:commons-codec`.
  * Verify that on `example-spring-boot-app`, unused starters (e.g. `commons-codec`, `snakeyaml`) are completely omitted from the tree, while `spring-webmvc` is retained.
* **Slice 5.2: Re-Resolution Immunity Verification**
  * Execute full packaging lifecycles (Shade, Spring Boot repackage) after running `dependency:tree` in the same Maven invocation.
  * Assert that packages strictly contain trimmed JARs and that no original untrimmed JAR is reintroduced.
* **Slice 5.3: Path-Aware Audit Report Verification**
  * Verify `mvn dependency-elider:report` outputs exact dependency paths for all dropped artifacts in `example-basic-app` and `example-spring-boot-app`.
* **Slice 5.4: Full Repository Gate Sweep**
  * Run `make check` and `make test-examples` to verify that all 149+ core tests, plugin tests, Checkstyle, PMD, SpotBugs, and Markdownlint gates pass cleanly.

---

## 4. Verification Protocol

1. **Diagnostic Verification**:

   ```sh
   ./mvnw -pl dependency-elider-maven-plugin test -Dtest=DependencyContextReResolutionTest
   ```

2. **Effective Tree Verification**:

   ```sh
   ./mvnw -f examples/example-basic-app/pom.xml \
     -Delide.mode=elision \
     -Delide.traceFiles=target/classes.log \
     dependency:tree
   ```

   *Assert*: `commons-codec` must NOT appear in output.

3. **Packaging Integrity Verification**:

   ```sh
   make test-examples
   ```

   *Assert*: All four example fixtures build, package, trim, and pass runtime assertions without regression.

4. **Final Gate Sweep**:

   ```sh
   make check
   ```
