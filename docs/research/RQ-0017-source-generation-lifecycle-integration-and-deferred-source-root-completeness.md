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

## 2. The Primary Architectural Proposal: Programmatic Double-Pass Compilation

To preserve the project's unique selling proposition (USP)—**guaranteeing that code compiles cleanly against the elided classpath in a single Maven run**—while supporting all code generators and annotation processors without hardcoded heuristics, the leading proposal introduces a **Programmatic Double-Pass Compilation Pattern**:

### 2.1 The Execution Workflow

```text
Pass 1: Full Discovery & Generation (Full Classpath)
├── 1. [generate-sources]  (OpenAPI, Protobuf, Avro generate .java files)
└── 2. [compile]           (javac + MapStruct/Lombok compile into target/classes)

Elision & Verification Hook
├── 3. [process-classes]   <=== DEPENDENCY-ELIDER RUNS HERE!
│      ├── Reads compiled bytecode in target/classes (human + generated)
│      ├── Performs link-closure dependency analysis
│      ├── Mutates project.getArtifacts() & sets artifact filters in memory
│      ├── Atomically clears target/classes
│      └── Programmatically re-invokes compiler:compile on ELIDED classpath!
│          └── If javac succeeds -> USP IS PROVEN! All code compiles without dropped JARs!

Downstream Lifecycle Continues (Elided Classpath)
├── 4. [test-compile]      (Compiles tests against elided classpath)
├── 5. [test]              (Surefire runs against elided classpath)
└── 6. [package]           (Packages elided/trimmed artifacts)
```

### 2.2 Orchestration Trade-Offs: Programmatic Invocation vs. POM XML Settings

| Dimension | Programmatic (`BuildPluginManager.executeMojo`) | POM Settings (`<executions>` in `pom.xml`) |
| :--- | :--- | :--- |
| **Developer Ergonomics** | **Zero configuration.** The user just adds Dependency Elider. Everything happens automatically in `mvn clean verify`. | **High friction.** Every project must modify its POM, duplicate compiler executions, and maintain boilerplate XML. |
| **Compiler Settings Parity** | **Guaranteed zero drift.** Elider inspects the project's existing `maven-compiler-plugin` execution and clones its exact configuration (`release`, `compilerArgs`, etc.). | **Risk of configuration drift.** If a developer updates compiler flags in one execution but forgets the other, the two passes diverge. |
| **Atomic State Control** | **Total control.** Elider wipes `target/classes`, swaps the artifact pointers in memory, and immediately triggers `javac` before any other plugin can see a dirty state. | **Fragile lifecycle ordering.** Other plugins bound to `process-classes` might run between executions or see inconsistent states. |
| **IDE Compatibility** | **Completely transparent.** IntelliJ, Eclipse, and VSCode import the POM as a normal single-compiler build without confusion. | **IDE confusion.** IDEs often struggle with duplicate compiler plugin executions in the same build, triggering duplicate incremental compilation cycles. |
| **Incremental Compilation Safety** | Clears `target/classes` or sets `compiler.forceJavacCompilerUse = true` so `javac` does not skip the second pass. | Same issue: `javac` skips compilation unless `target/classes` is cleared. |

### 2.3 Why This Solves the Annotation Processor Problem

* **Zero Knowledge of Processors**: Elider never needs to know what MapStruct, Lombok, or Dagger do. `javac` runs them during Round 1.
* **Ground-Truth Bytecode**: In `target/classes`, all generated mapper classes, builder classes, and protobuf stubs exist as compiled JVM bytecode with explicit constant pool references and method invocations.
* **Fail-Fast Safety**: If an annotation processor generated code that references a dropped dependency, Round 2 fails immediately at compile time.

---

## 3. Alternative Architectural Dynamics & Considerations

### Option 1: Two-Stage Lifecycle Split (Graph Mediation at `INITIALIZE`, Slicing at `PROCESS-SOURCES`)

* **Concept**: Split the elider's responsibilities across two lifecycle hooks:
  1. *Early Phase (`INITIALIZE`)*: Hook repository session resolution and record baseline graph structure.
  2. *Post-Generation Phase (`PROCESS-SOURCES`)*: Execute source attribution after `target/generated-sources` are populated by Maven lifecycle plugins, but before `javac` compiles.
* **Scope**: Solves file-based code generators (OpenAPI, Protobuf), but does not cover annotation processors running inside `javac` (MapStruct, Lombok).

### Option 2: Pre-Execution Generator Dry-Run / Warmup

* **Concept**: During the `INITIALIZE` phase, the plugin detects configured generator plugins in the POM (e.g. `openapi-generator-maven-plugin`, `protobuf-maven-plugin`) and triggers a targeted, in-process execution of their generator goals before source scanning begins.
* **Challenge**: Invoking sibling plugins out-of-band within the Maven session can have unintended side effects on project state, file timestamps, and plugin descriptors.

### Option 3: User-Trust Opt-In (`elide.trustSourceGenerators=true`)

* **Concept**: Rather than treating all executions in `generate-sources` as hostile, allow users to assert that their generators/processors only map between project entities. The plugin scans explicit source types in `src/main/java`, prunes dependencies, and lets `javac` compile in a single pass. If a generator needed a dropped dependency, `javac` fails cleanly.

---

## 4. Research Questions

1. **`BuildPluginManager` Programmatic Invocation**:
   * How cleanly does `BuildPluginManager.executeMojo` re-execute `maven-compiler-plugin:compile` across Maven 3.9 and Maven 4?
   * How should incremental compilation (`useIncrementalCompilation`) be disabled on the verification pass to guarantee `javac` actually runs?
2. **Re-resolution Cache Behavior**:
   * Does mutating `project.getArtifacts()` at `process-classes` persist reliably through `test-compile`, Surefire, and packaging without Maven's `DependencyContext` triggering graph re-resolution?
3. **Compilation Overhead Benchmarks**:
   * What is the wall-clock overhead of the second `javac` pass on representative mid-size and large enterprise projects?

---

## 5. Evidence Gates

* **MapStruct / OpenAPI Reference Fixture**:
  * Create a standalone example fixture utilizing `generate-sources` (e.g., MapStruct or OpenAPI generator).
  * Demonstrate successful dependency elision without failing closed in `MavenPreconditionGenerationGuard`.
* **Zero Compilation Regressions**:
  * Verify that generated source code compiles cleanly against the elided classpath.
* **Static Analysis**:
  * Pass `make check` cleanly.
