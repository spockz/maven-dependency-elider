<!-- WHY: Defines the work package specification, track decomposition, and committable slices for resolving Maven lifecycle re-resolution and dependency graph consistency (RQ-0006) via post-download ProjectDependenciesResolver decoration. -->
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

Rather than intercepting dependency collection before physical JARs are downloaded (which creates chicken-and-egg inspection dilemmas on cold builds), this work package decorates Maven's **`ProjectDependenciesResolver`** immediately **after** standard artifact resolution and download completes.

The primary goals are:

1. **Zero Download Friction**: Maven downloads and resolves dependency JARs to `~/.m2/repository` exactly how, when, and where users expect.
2. **Unified Effective Graph**: Intercept `DependencyResolutionResult` to prune unobserved `DependencyNode`s directly from the graph, ensuring `mvn dependency:tree` reflects true post-elision topology without declared bloat.
3. **Re-Resolution Immunity**: Because the transformed artifacts and graph originate from the resolver itself, Maven's internal `DependencyContext` marks the cached resolution clean, preventing subsequent `@RequiresDependencyResolution` plugins (Shade, Spring Boot) from triggering POM re-resolution.
4. **Path-Aware Audit Trail**: Capture the raw pre-elision dependency tree from the delegate resolver before filtering, persisting it to `target/dependency-elider-report.json` so `dependency-elider:report` can render exact dependency chain justifications.
5. **Authoritative Core Extension Model**: Deliver integration via `.mvn/extensions.xml` as a first-class Maven Core Extension.

### 1.2 Non-Negotiable Invariants & Architectural Consensus

1. **Post-Download Resolution Hook**: The Core Extension decorates `ProjectDependenciesResolver`. Maven's native `DefaultProjectDependenciesResolver` executes first to resolve and download all candidate JARs naturally.
2. **Authoritative Single Model**: The extension is registered via `.mvn/extensions.xml`, eliminating divergent plugin-only fallback modes.
3. **Direct Root Pruning**: Completely unobserved direct dependencies are pruned directly from `rootNode.getChildren()` in the resolved graph, ensuring `getDependencyArtifacts()` and `getArtifacts()` naturally omit them from the start.
4. **Pre-Elision Path Attribution & Session Handoff**: The raw unpruned graph from the delegate resolver is cached in `session.getRequest().getData()` and persisted to `target/dependency-elider-report.json` to provide full path justifications for `dependency-elider:report`.
5. **Informative Pass-Through on Missing Traces**: If no trace files are supplied (or `-Delide.skip=true`), the extension operates as an efficient pass-through ($< 0.1\text{ ms}$ overhead) and logs an informative notice explaining that elision is inactive.
6. **Per-Module Reactor Scoping with Shared Fallback**: In multi-module reactors, each submodule evaluates its own dependencies against module-specific trace files if defined, falling back to reactor-root aggregate trace files.
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

**Goal**: Implement the graph and artifact collection transformation logic operating on `DependencyResolutionResult` after Maven downloads candidate JARs.

* **Slice 2.1: Post-Download Result Pruner**
  * Create `io.github.spockz.elider.resolver.ElisionResolutionResultTransformer`:
    * Operates on `org.eclipse.aether.graph.DependencyNode` and `Set<Artifact>`.
    * Inspects downloaded JARs via `JarIndexScanner`.
    * Matches against `TraceData` to compute whole-artifact and intra-JAR trimming decisions.
    * Prunes unobserved direct dependencies from `rootNode.getChildren()` and drops unobserved transitive subtrees.
    * Filters the artifact set and updates file pointers to `target/elided-artifacts/` for trimmed JARs.
* **Slice 2.2: Aether Context & Metadata Preservation**
  * Ensure that pruned `DependencyNode` trees preserve conflict resolution winner metadata, scope derivations, and optional flags for surviving nodes.
  * Unit tests validating graph trimming with complex multi-level diamond and conflicting transitive dependencies.

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

**Goal**: Intercept Maven's dependency resolution by decorating `ProjectDependenciesResolver` as a high-priority Sisu component packaged in `.mvn/extensions.xml`.

* **Slice 4.1: `EliderProjectDependenciesResolver` Implementation**
  * Create `io.github.spockz.elider.plugin.EliderProjectDependenciesResolver` implementing `org.apache.maven.project.ProjectDependenciesResolver`.
  * Inject `DefaultProjectDependenciesResolver` as the delegate.
  * In `resolve(request)`:
    1. Call `delegate.resolve(request)` to let Maven naturally download and resolve all candidate JARs.
    2. Check for active trace files; if absent or `-Delide.skip=true`, log an informative notice and return delegate result unchanged.
    3. Snapshot raw pre-elision graph to `session.getRequest().getData()`.
    4. Execute `ElisionResolutionResultTransformer` to prune nodes and update file pointers.
    5. Return the transformed `DependencyResolutionResult`.
* **Slice 4.2: Sisu & Core Extension Configuration**
  * Annotate with `@Named @Priority(10)` (or Plexus component descriptor) to override default resolver.
  * Configure `.mvn/extensions.xml` packaging in reference projects.
  * Support per-module trace resolution with fallback to reactor-root traces.

---

### Track 5: Fixtures, Tree Verification & End-to-End Gates

**Goal**: Validate the integrated resolver decorator and graph consistency across all reference applications and CLI commands.

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
