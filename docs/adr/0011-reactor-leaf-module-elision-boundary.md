<!-- WHY: Records the architectural decision to support reactor leaf module elision (elide.leafOnly) so multi-module builds skip intermediate libraries and perform definitive elision only at the deployment boundary (RQ-0012). -->
# ADR-0011: Reactor Leaf Module Elision Boundary

* **Status**: Accepted
* **Date**: 2026-10-30
* **Role**: architecture
* **Scope**: reactor-lifecycle
* **Area**: plugin-core
* **Related**:
  * [ADR-0001: Runtime Telemetry-Driven Dependency Elision at Maven INITIALIZE Phase](0001-runtime-telemetry-driven-dependency-elision-at-maven-initialize-phase.md)
  * [ADR-0002: In-Memory Artifact Mutation for Downstream Packaging Transparency](0002-in-memory-artifact-mutation-for-downstream-packaging-transparency.md)
  * [RQ-0012: Multi-Module Reactor Elision and Concurrency](../research/RQ-0012-multi-module-reactor-elision-and-concurrency.md)

---

## 1. Context

In a multi-module Maven reactor (`pom` packaging aggregator with child submodules), projects are organized into layered tiers:

* Root aggregator POM (`packaging="pom"`).
* Intermediate internal library modules (`core`, `service`, `common`, `domain`, `api`).
* Leaf application modules (`app`, `cli`, `web`, packaging fat JARs, WARs, container images, or Native Images).

Under the baseline configuration, every module declaring `dependency-elider:elide` runs full dependency analysis, ProGuard link-closure, dynamic-root scanning, and in-memory artifact mutation. In multi-module builds, this creates several challenges:

1. **Incomplete Reachability in Intermediate Tiers**:
   Intermediate modules only have partial visibility (typically their own unit tests). They lack the complete application trace, dynamic roots, and closed-world entry points available only to the final application module. Trimming intermediate dependencies either prunes classes needed downstream by consumer applications or forces conservative over-retention.
2. **Redundant Build Latency**:
   Intermediate modules produce internal artifacts that are consumed by downstream sibling modules during the build and are not deployed as independent units. Running link closure and archive rewriting across every intermediate library adds cumulative latency to both sequential builds and parallel reactor builds (`mvn -T`).
3. **Reactor Classpath Inconsistencies**:
   Mutating dependency graphs in intermediate modules alters transitive dependency sets, creating potential divergence for downstream sibling compilation and testing.

---

## 2. Decision

We introduce **Reactor Leaf Module Elision (`elide.leafOnly`)**:

1. **Configuration Parameter**:
   * Both `ElideMojo` and `AnalyzeMojo` expose `@Parameter(property = "elide.leafOnly", defaultValue = "true") private boolean leafOnly = true;`.
   * When `leafOnly=true` (default), dependency elision and intra-JAR trimming execute **only on leaf modules** in a multi-module Maven reactor.
   * When `leafOnly=false`, each module independently evaluates and trims its dependencies, preserving module-local reports for every reactor submodule.

2. **Topological Leaf Detection (`ReactorLeafModuleDetector`)**:
   * The plugin evaluates the Maven reactor DAG using `session.getProjectDependencyGraph()`.
   * In a multi-module reactor (`graph != null && graph.getAllProjects().size() > 1`):
     * If `project.getPackaging().equalsIgnoreCase("pom")`, the project is an aggregator or parent POM, not a deployment leaf; elision is skipped.
     * If `graph.getDownstreamProjects(project, false)` is not empty, downstream sibling modules in the reactor depend on this module; it is an intermediate library module; elision is skipped.
     * If `graph.getDownstreamProjects(project, false)` is empty, no other module in the reactor depends on this module; it is topologically a **leaf module**; elision executes.
   * In a standalone/single-project build (`graph == null` or `graph.getAllProjects().size() <= 1`), the project is standalone and executes elision regardless of the `leafOnly` flag.
   * Targeted partial builds (`mvn -pl :submodule -am`): Maven restricts the active project graph to the requested projects and their upstream prerequisites. Intermediate modules with downstream targets in the active graph skip elision; the targeted endpoint executes elision.

3. **Skipping Semantics**:
   * When an intermediate module is skipped:
     * The plugin logs an informational message: `[INFO] Skipping dependency elision on intermediate reactor module: ${project.artifactId}`.
     * The plugin calls `publishEmptyPlan()`, publishing an empty retained-artifact plan so downstream Maven consumers and resolver hooks observe unmodified dependencies.
     * The plugin immediately terminates Mojo execution without reading JMODs, scanning dynamic roots, or staging transformed outputs.

---

## 3. Consequences

* **Positive**:
  * **Unified Application Reachability**: The leaf packaging module evaluates all dependencies (including transitive dependencies declared by intermediate submodules) against the complete application telemetry trace and dynamic roots.
  * **Drastic Latency Reduction in Multi-Module Builds**: Eliminates repeated ProGuard pool construction, JMOD parsing, and archive rewriting across intermediate submodules.
  * **Clean Reactor Dependency Propagation**: Internal reactor libraries compile and test against standard, un-mutated dependencies.
  * **Zero-Configuration Topology**: Leaf modules are discovered automatically from Maven's project dependency graph without requiring manual module-by-module property overrides.

* **Negative / Trade-offs**:
  * If an intermediate library module is intentionally published as a standalone, elided/trimmed artifact to an external Maven repository, `elide.leafOnly` must be set to `false` for that specific module.
  * Multi-module fixtures or builds that assert module-local reports for every reactor submodule must explicitly configure `<elide.leafOnly>false</elide.leafOnly>`.
