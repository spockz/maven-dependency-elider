<!-- WHY: Investigates supporting projects with source-generation lifecycles (MapStruct, OpenAPI, Protobuf, Lombok, ANTLR) without failing closed or pinning all compile dependencies. -->
# RQ-0017: Source-Generation Lifecycle Integration and Deferred Source-Root Completeness

## Status

Open

## Date

2026-10-30

## Category

Maven Lifecycle & Source-Generation Integration

## 1. Context & Current Boundary

[ADR-0001](../adr/0001-runtime-telemetry-driven-dependency-elision-at-maven-initialize-phase.md) binds `dependency-elider:elide` to the Maven `INITIALIZE` lifecycle phase with `requiresDependencyResolution = ResolutionScope.TEST`. Executing at `INITIALIZE` ensures that Maven resolves the dependency graph before compilation and testing, allowing elided dependencies to be removed from compile and test classpaths.

However, executing at `INITIALIZE` creates a fundamental conflict with projects that generate Java source code during the build:

1. **The Lifecycle Reality**:
   * Maven executes lifecycle phases in fixed sequence:
     $$\text{validate} \longrightarrow \text{initialize} \longrightarrow \text{generate-sources} \longrightarrow \text{process-sources} \longrightarrow \text{generate-resources} \longrightarrow \text{compile}$$
   * At `INITIALIZE`, no source generation has occurred. Tooling such as MapStruct, OpenAPI Generator, Protobuf / gRPC compiler, Apache Avro, ANTLR, Lombok, and JAXB have not yet generated their `.java` files into `target/generated-sources/*`.
2. **The Current `sourceRootsComplete` Contract**:
   To prevent removing dependencies that might be needed by ungenerated code, the plugin introduced `elide.sourceRootsComplete`, defaulting to `false`:
   * **Mode A (`elide.sourceRootsComplete=false`, default)**:
     * The plugin skips source attribution and conservatively pins **all effective compile-classpath JARs and all their indexed classes**.
     * Consequence: Compile-scoped dependencies cannot be dropped as whole artifacts. If the project lacks runtime telemetry matching or intra-JAR trimming, `analyze` reports **zero savings and zero CVE reductions**.
   * **Mode B (`elide.sourceRootsComplete=true`)**:
     * The user explicitly asserts that all source roots are present before `INITIALIZE` and no later phase generates code.
     * To enforce this assertion, [`MavenPreconditionGenerationGuard.java`](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenPreconditionGenerationGuard.java) inspects the POM's build plugins and executions.
     * Consequence: If the project configures *any* plugin execution bound to `generate-sources` or uses unknown compiler processors, the guard strictly **fails closed**:

       ```text
       Dependency analysis failed closed: Unsupported lifecycle execution in phase generate-sources
       ```

### The Catch-22

Enterprise projects that use modern Java frameworks almost universally rely on source generation (e.g. MapStruct mappers, OpenAPI client stubs, Protobuf DTOs, Lombok). For these projects:

* Setting `elide.sourceRootsComplete=true` crashes the build (`MavenPreconditionGenerationGuard`).
* Setting `elide.sourceRootsComplete=false` suppresses dependency elision (0 savings, 0 avoided CVEs).

---

## 2. Core Architectural Dynamics & Potential Solutions

### Option 1: Two-Stage Lifecycle Split (Graph Mediation at `INITIALIZE`, Slicing at `PROCESS-SOURCES`)

* **Concept**: Split the elider's responsibilities across two lifecycle hooks:
  1. *Early Phase (`INITIALIZE`)*: Hook repository session resolution and record baseline graph structure.
  2. *Post-Generation Phase (`PROCESS-SOURCES` or `PROCESS-CLASSES`)*: Execute source attribution after `target/generated-sources` are populated by Maven lifecycle plugins.
* **Challenge**: Can Maven compile classpaths be safely mutated *after* `INITIALIZE` without triggering the re-resolution cache invalidation problems documented in [RQ-0006](RQ-0006-maven-artifact-view-consistency-and-early-resolution-hooks.md) and [ADR-0002](../adr/0002-in-memory-artifact-mutation-for-downstream-packaging-transparency.md)?

### Option 2: Pre-Execution Generator Dry-Run / Warmup

* **Concept**: During the `INITIALIZE` phase, the plugin detects configured generator plugins in the POM (e.g. `openapi-generator-maven-plugin`, `protobuf-maven-plugin`) and triggers a targeted, in-process execution of their generator goals before source scanning begins.
* **Challenge**: Invoking sibling plugins out-of-band within the Maven session can have unintended side effects on project state, file timestamps, and plugin descriptors.

### Option 3: Persistent Compiled Bytecode Baseline (`target/classes` or Compiler Evidence Cache)

* **Concept**: Instead of parsing raw `.java` source code at `INITIALIZE`, the elider utilizes the output of the compiler from a warm build or previous run (`target/classes`).
  * If `target/classes` exists and is up to date, the elider inspects the actual compiled class files (which already incorporate all generated sources and annotation processor outputs).
  * Static bytecode scanning of `target/classes` is faster and more accurate than parsing uncompiled source text with regular expressions or lightweight Java AST parsers.
* **Challenge**: Requires a baseline build or clean-compile cycle before elision can activate.

### Option 4: Known-Generator Modeling in `MavenPreconditionGenerationGuard`

* **Concept**: Rather than treating all executions in `generate-sources` as hostile, expand `MavenPreconditionGenerationGuard` to recognize standard code generators and register their target output directories (e.g. `target/generated-sources/annotations`, `target/generated-sources/openapi`) as known dynamic sources.

---

## 3. Research Questions

1. **Resolution Hook Timing**:
   * What is the latest lifecycle phase where Maven allows transparent in-memory mutation of `project.getArtifacts()` and `project.setArtifactFilter()` without downstream plugins (like `maven-compiler-plugin`) reverting to the un-elided repository artifacts?
   * If elision runs at `process-sources`, does `maven-compiler-plugin` see the trimmed/elided compile classpath?
2. **Annotation Processor Discovery**:
   * How should annotation processors configured inside `<annotationProcessorPaths>` in `maven-compiler-plugin` be handled? Can their processor classes be treated as compile-time dependencies without forcing their transitive libraries into runtime packaging?
3. **Ergonomic Workarounds for Today**:
   * What configuration advice should be given to users whose builds fail due to `generate-sources`? Can they bind the elider to a profile or run a two-pass build (`mvn compile && mvn dependency-elider:analyze`)?

---

## 4. Evidence Gates

* **MapStruct / OpenAPI Reference Fixture**:
  * Create a standalone example fixture utilizing `generate-sources` (e.g., MapStruct or OpenAPI generator).
  * Demonstrate successful dependency elision without failing closed in `MavenPreconditionGenerationGuard`.
* **Zero Compilation Regressions**:
  * Verify that generated source code compiles cleanly against the elided classpath.
* **Static Analysis**:
  * Pass `make check` cleanly.
