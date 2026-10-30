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

## 2. The Primary Architectural Solution: Single-Pass `process-classes` Execution

Rather than attempting to predict what annotation processors will generate from uncompiled source text, or introducing an over-engineered double-compilation pass, the definitive architectural solution is **binding dependency elision to `process-classes` in a single, high-speed build pass**:

### 2.1 The Execution Workflow

```text
1. [compile]         javac compiles src/main/java + generated-sources + annotation processors
                     └── Produces the 100% complete bytecode truth in target/classes

2. [process-classes] dependency-elider executes:
                     ├── Inspects target/classes (ground-truth bytecode, zero guessing)
                     ├── Performs link-closure analysis against dependencies
                     └── Mutates project artifacts in-memory (drops dead JARs, trims retained JARs)

3. [test-compile]    javac compiles test classes against the ELIDED compile classpath!
                     └── If an elided dependency was mistakenly dropped, test-compile FAILS here!

4. [test]            Surefire runs tests on the ELIDED runtime classpath!
                     └── If a dynamic/reflection path was broken, tests FAIL here!

5. [package]         Shade / Spring Boot packages the ELIDED artifacts into the final JAR/WAR/image.
```

### 2.2 Why This Preserves Safety & The Compile-Time Gate

* **The Test-Compile Gate**: `test-compile` runs immediately after `process-classes`. It compiles the project's unit and integration tests against `project.getCompileClasspathElements()`, which has now been pruned by the elider. If production code or test code relies on a dropped dependency, `test-compile` fails immediately at compile time.
* **The Surefire Runtime Gate**: Surefire runs test suites against the elided and trimmed JARs. If any runtime reflection or SPI path was broken, tests fail before packaging or publication.
* **100% Complete Bytecode Truth**: In `target/classes`, all code generated by MapStruct, Lombok, OpenAPI, Protobuf, Avro, ANTLR, and Kotlin physically exists as compiled JVM bytecode. Bytecode analysis (`ProGuard Core` / ASM) inspects exact constant pool entries, opcodes, and descriptors with zero heuristic guessing.
* **Zero Ecosystem Special-Casing**: The plugin does not need to know about `@Mapper`, `@Builder`, `@Introspected`, or any custom enterprise annotation processor.

---

## 3. Analysis of the Rejected "Double Javac Pass" Alternative

During research, an alternative was analyzed: having the plugin trigger a second `javac` compilation pass inside the build. While conceptually appealing on paper, detailed analysis proved it to be an over-engineered anti-pattern:

1. **The "Wiped Resources" Hazard**: `process-resources` runs before `compile`. Wiping `target/classes` to force recompilation accidentally destroys copied and filtered application resources (`application.properties`, XML schemas).
2. **Annotation Processor Loops & `FilerException`**: Running `javac` twice causes annotation processors to run twice, risking `javax.annotation.processing.FilerException: Attempt to recreate a file for type ...` on existing generated sources unless `-proc:none` is artificially injected.
3. **Reactor Concurrency Starvation (`mvn -T`)**: Under parallel reactor builds, sibling modules read `target/classes` directly from disk. Clearing or swapping classes mid-build creates fatal race conditions across threads.
4. **Redundant Work**: Bytecode analysis of `target/classes` is already mathematically more rigorous and complete than `javac`. Forcing `javac` to recompile adds 3–5 seconds of build latency solely to rubber-stamp what link-closure analysis already verified.

---

## 4. Research Questions

1. **Maven Lifecycle Re-Resolution Boundaries**:
   * Does mutating `project.getArtifacts()` at `process-classes` persist reliably through `test-compile`, Surefire, and packaging without Maven's internal `DependencyContext` cache triggering graph re-resolution?
   * How should the core extension (`EliderGraphTransformer` / `EliderEventSpy`) intercept resolution sessions when elision is bound to `process-classes`?
2. **Test-Scoped Dependency Elision**:
   * When whole-artifact elision runs at `process-classes`, should test-scoped dependencies (`scope = test`) also be evaluated and pruned for Surefire, or should elision remain strictly focused on compile/runtime dependencies destined for packaging?
3. **Ergonomic Profile / Configuration**:
   * Should the lifecycle binding phase be configurable via `@Parameter(property = "elide.phase", defaultValue = "process-classes")` to allow backwards-compatibility with projects using `initialize`?

* **MapStruct / OpenAPI Reference Fixture**:
  * Create a standalone example fixture utilizing `generate-sources` (e.g., MapStruct or OpenAPI generator).
  * Demonstrate successful dependency elision without failing closed in `MavenPreconditionGenerationGuard`.
* **Zero Compilation Regressions**:
  * Verify that generated source code compiles cleanly against the elided classpath.
* **Static Analysis**:
  * Pass `make check` cleanly.
