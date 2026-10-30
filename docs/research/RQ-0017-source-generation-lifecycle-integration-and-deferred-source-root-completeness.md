<!-- WHY: Investigates supporting projects with source-generation lifecycles (MapStruct, OpenAPI, Protobuf, Lombok, ANTLR) without failing closed or pinning all compile dependencies. -->
# RQ-0017: Source-Generation Lifecycle Integration and Post-Compile Bytecode Completeness

## Status

Resolved (see [ADR-0010](../adr/0010-process-classes-lifecycle-and-bytecode-completeness.md))

## Date

2026-10-30

## Category

Maven Lifecycle & Source-Generation Integration

## 1. Context & Current Boundary

[ADR-0001](../adr/0001-runtime-telemetry-driven-dependency-elision-at-maven-initialize-phase.md) binds `dependency-elider:elide` by default to the Maven `INITIALIZE` lifecycle phase with `requiresDependencyResolution = ResolutionScope.TEST`. Executing at `INITIALIZE` resolves the dependency graph before compilation and testing, allowing elided dependencies to be removed before `compile`.

However, executing at `INITIALIZE` creates a fundamental conflict with projects that generate Java source code or bytecode during the build:

1. **The Lifecycle Reality**:
   * Maven executes lifecycle phases in fixed sequence:
     $$\text{validate} \longrightarrow \text{initialize} \longrightarrow \text{generate-sources} \longrightarrow \text{process-sources} \longrightarrow \text{generate-resources} \longrightarrow \text{process-resources} \longrightarrow \text{compile} \longrightarrow \text{process-classes}$$
   * At `INITIALIZE`, no source generation or annotation processing has occurred. Tooling such as MapStruct, OpenAPI Generator, Protobuf / gRPC, Apache Avro, ANTLR, Lombok, and JAXB have not yet generated their `.java` or `.class` files.
2. **The Current `sourceRootsComplete` Contract in `MavenElisionService`**:
   To prevent removing dependencies that might be needed by ungenerated code at `INITIALIZE`, [`MavenElisionService.compilerInputs`](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenElisionService.java) only supports two modes via `elide.sourceRootsComplete` (default `false`):
   * **Mode A (`elide.sourceRootsComplete=false`, default)**:
     * `MavenElisionService.compilerInputs` skips source attribution and conservatively pins **all effective compile-visible JARs (`compile`, `provided`, `system`) and all their indexed classes**.
     * Crucially, even if `elide.productionOutput` (`target/classes`) is provided and scanned by `ProductionBytecodeReferenceScanner`, `compilerInputs` currently ignores `bytecodeScan` when `sourceRootsComplete=false` and still pins 100% of compile-visible JARs and classes.
     * Consequence: Compile-scoped dependencies cannot be dropped as whole artifacts or trimmed, causing `analyze` and `elide` to report **zero compile-scope savings and zero CVE reductions**.
   * **Mode B (`elide.sourceRootsComplete=true`)**:
     * The user asserts that all production and generated source roots exist before `INITIALIZE` and no later lifecycle phase generates code.
     * To enforce this assertion, [`MavenElisionService.verifySourceRootsComplete`](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenElisionService.java) calls `hasUnknownSourceGeneration(project)` to inspect the POM's build plugins.
     * Consequence 1: If the project configures any plugin execution bound to `generate-sources`..`compile` (outside a narrow built-in list), `MavenElisionService` strictly **fails closed**:

       ```text
       Dependency analysis failed closed: elide.sourceRootsComplete=true conflicts with a source-generation lifecycle execution
       ```

     * Consequence 2: `MavenElisionService.isKnownNonGeneratingExecution` unconditionally allowlists `maven-compiler-plugin` (`compile`, `testCompile`) without inspecting `<annotationProcessorPaths>` or `<proc>`. If a project uses MapStruct or Lombok solely via `maven-compiler-plugin`, `verifySourceRootsComplete` does not catch it; instead, `JavaSourceReferenceScanner` runs `JavacTask.analyze()` without annotation processors on ungenerated sources, failing to resolve generated types or silently missing processor-generated dependency references.
     * Consequence 3: If `elide.preconditionClassPathComplete=true` is enabled for VEX generation, [`MavenPreconditionGenerationGuard`](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenPreconditionGenerationGuard.java) and [`MavenCompilerGenerationGuard`](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenCompilerGenerationGuard.java) reject `generate-sources` plugins, reject `maven.compiler.annotationProcessorPaths`, and require `maven.compiler.proc=none`, downgrading the VEX precondition inventory to `INCOMPLETE`.

### The Catch-22

Enterprise projects that use modern Java frameworks almost universally rely on source generation or annotation processing (MapStruct, OpenAPI, Protobuf, Lombok). For these projects:

* Setting `elide.sourceRootsComplete=true` fails closed in `MavenElisionService.verifySourceRootsComplete` (or misanalyzes ungenerated annotation-processor types).
* Setting `elide.sourceRootsComplete=false` pins all compile-scoped dependencies in `MavenElisionService.compilerInputs`, yielding 0 savings and 0 avoided CVEs even when `target/classes` is already compiled.

---

## 2. The Architectural Solution: Post-Compile `process-classes` Execution & Bytecode Completeness

Rather than attempting to predict what code generators or annotation processors will emit from uncompiled source text, or introducing a fragile double-compilation pass, the solution is a **post-compile `process-classes` lifecycle mode backed by first-class Production Bytecode Completeness (`elide.productionClassesComplete=true`)**:

### 2.1 The Execution Workflow

```text
1. [generate-sources .. process-resources]
                     OpenAPI / Protobuf / Avro / ANTLR generate .java sources;
                     resources are copied to target/classes.

2. [compile]         javac compiles src/main/java + generated-sources + annotation processors
                     (MapStruct, Lombok, Immutables) in a single standard pass.
                     └── Produces 100% complete production bytecode in target/classes.

3. [process-classes] dependency-elider:elide executes:
                     ├── Scans target/classes via ProductionBytecodeReferenceScanner
                     ├── Unpins compile-scoped JARs in compilerInputs using bytecodeScan
                     ├── Computes fixed-point bytecode link-closure across dependency JARs
                     │   (MavenElisionService.finishAnalysis promotes any transitive owner)
                     └── Mutates project artifact views in-memory (drops dead JARs, trims retained JARs)

4. [test-compile]    javac compiles src/test/java against the post-elision classpath.

5. [test]            Surefire runs tests against the elided and trimmed runtime classpath.

6. [package]         Shade / Spring Boot / JAR plugin packages the elided artifacts.
```

### 2.2 Four Required Codebase Capabilities

To make this workflow mathematically sound and compatible with Maven's execution model, four plugin subsystems must be updated together:

1. **First-Class Bytecode-Complete Mode in `MavenElisionService.compilerInputs`**:
   * Introduce `elide.productionClassesComplete` (`@Parameter(property = "elide.productionClassesComplete", defaultValue = "false")`) on `ElideMojo` and `AnalyzeMojo`, and automatically enable it when `ElideMojo` runs in the `process-classes` lifecycle phase (with `sourceRootsComplete=false`).
   * When `productionClassesComplete=true`, default `productionOutput` to `${project.build.outputDirectory}` (`target/classes`) if not explicitly set, and require that `target/classes` exists and contains at least one compiled `.class` file.
   * In `MavenElisionService.prepare`, run `productionBytecodeInputs(productionOutput)` before `compilerInputs`. When `productionClassesComplete=true`, `compilerInputs` derives:
     * `requiredClasses` = `bytecodeScan.referencedClasses()`
     * `compileVisibleCoordinates` = only those `compileVisibleArtifacts` whose indexed classes intersect `bytecodeScan.referencedClasses()`
     * `declaredClasses` = `classNamesInOutput(bytecodeScan.scope())`
   * **Link-Closure Guarantee**: Static linkage of `target/classes` method bodies is **not** delegated to `test-compile` (which only inspects class signatures referenced by tests, not method bodies inside `target/classes`). Instead, static linkage is guaranteed by the existing fixed-point bytecode reachability loop in [`MavenElisionService.finishAnalysis`](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenElisionService.java) (`newlyReachedDrops` $\rightarrow$ `promoteForBytecode`), which promotes any dependency reachable from `bytecodeScan.referencedClasses()`.
2. **Lifecycle Binding & Dynamic Phase Rebinding via `EliderLifecycleParticipant`**:
   * In Maven, a Mojo `@Parameter` cannot change `@Mojo(defaultPhase = ...)` because `DefaultLifecycleExecutionPlanCalculator` computes the execution plan from `META-INF/maven/plugin.xml` and POM `<execution><phase>` before Mojo instantiation.
   * Keep `ElideMojo`'s default annotation at `LifecyclePhase.INITIALIZE` so existing `initialize`-bound builds and integration suites remain 100% backwards-compatible.
   * Support `<phase>process-classes</phase>` in POM `<execution>`, **and** enhance [`EliderLifecycleParticipant.afterProjectsRead`](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/EliderLifecycleParticipant.java) so that when `elide.productionClassesComplete=true` is set (via POM `<configuration>`, project `<properties>`, or CLI `-Delide.productionClassesComplete=true`), any active `elide` execution with phase `null` or `initialize` is dynamically rebound to `process-classes` before Maven calculates the lifecycle execution plan.
3. **Phase-Aware `mvn dependency:tree` Preparation (`EliderTreePreparation`)**:
   * Update [`EliderPluginConfiguration`](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/EliderPluginConfiguration.java) and [`EliderGoalOrder`](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/EliderGoalOrder.java) to accept `elide` executions bound to either `initialize` or `process-classes`.
   * When `elide` is bound to `process-classes` and the user invokes standalone `mvn dependency:tree` without an earlier `process-classes` (or later) lifecycle phase in the CLI request, `EliderTreePreparation` injects `process-classes` before `dependency:tree` (so Maven executes `generate-sources` $\rightarrow$ `compile` $\rightarrow$ `process-classes (elide)` $\rightarrow$ `dependency:tree`).
4. **Phase-Relative Precondition Guards (`MavenPreconditionGenerationGuard` & `MavenCompilerGenerationGuard`)**:
   * When `elide.preconditionClassPathComplete=true` is evaluated in `productionClassesComplete` mode at `process-classes`, phases `generate-sources` through `compile` have **already executed** and their outputs in `target/classes` are directly hashed by `MavenPreconditionProviderRoots.capture`.
   * Update `MavenPreconditionGenerationGuard` and `MavenCompilerGenerationGuard` so that post-`compile` capture at `process-classes` permits pre-capture source generators (`generate-sources`..`process-resources`) and compiler annotation processors (`annotationProcessorPaths`, default `proc` during `compile`), while continuing to reject unmodeled class-generating executions in phases *after* `process-classes`.
   * Also fix the blind spot in `MavenElisionService.hasUnknownSourceGeneration` when running at `initialize` (`sourceRootsComplete=true`) so that `maven-compiler-plugin` configurations with `<annotationProcessorPaths>`, `<annotationProcessors>`, or `<proc>only|full</proc>` are recognized as source generators and rejected with a clear message directing the user to `elide.productionClassesComplete=true` / `process-classes`.

### 2.3 Test-Only References to Compile-Scoped Dependencies

When `elide` runs at `process-classes` and prunes `compile`-scoped dependencies based on `target/classes` + runtime traces, a test class in `src/test/java` might reference a `compile`-scoped dependency (or a class inside a retained JAR) that production code in `target/classes` never used:

* When traces are collected by running the test suite (`mvn test`), test-used classes are present in `traceFiles` and retained automatically.
* When traces are collected from production/staging (or only subset tests), `test-compile` will fail if `src/test/java` directly imports a dropped `compile`-scoped dependency—surfacing that the dependency is unused by production and should be declared in `<scope>test</scope>` (or retained via `elide.excludedArtifacts` / `elide.trimRoots`).

---

## 3. Analysis of the Rejected "Double Javac Pass" Alternative

During research, an alternative was evaluated: having the plugin trigger a second `javac` compilation pass inside the build (`generate-sources` $\rightarrow$ `compile` $\rightarrow$ `elide` $\rightarrow$ `compile` again). Detailed analysis showed this to be an anti-pattern:

1. **The "Wiped Resources" Hazard**: `process-resources` runs before `compile`. Wiping `target/classes` to force recompilation destroys copied and filtered application resources (`application.properties`, XML schemas, META-INF descriptors).
2. **Annotation Processor Loops & `FilerException`**: Running `javac` twice causes annotation processors to execute twice, risking `javax.annotation.processing.FilerException: Attempt to recreate a file for type ...` on existing generated sources unless `-proc:none` is injected by mutating compiler plugin state.
3. **Reactor Concurrency Races (`mvn -T`)**: Under parallel reactor builds, sibling modules read `target/classes` or packaged artifacts across threads. Deleting and recreating `.class` files mid-build introduces race conditions.
4. **Redundant Work**: `ProductionBytecodeReferenceScanner` + `MavenElisionService.finishAnalysis` already computes the exact transitive bytecode link closure over `target/classes` and all dependency JARs. Re-running `javac` adds 3–5 seconds of build latency without adding soundness.

---

## 4. Research Questions & Answers

1. **Maven Lifecycle Re-Resolution Boundaries**:
   * *Question*: Does mutating `project.getArtifacts()` at `process-classes` persist reliably through `test-compile`, Surefire, and packaging without Maven's internal `DependencyContext` cache triggering graph re-resolution?
   * *Answer*: Yes. `ElideMojo` already declares `requiresDependencyResolution = ResolutionScope.TEST`. When `ElideMojo` executes at `process-classes`, Maven has already resolved the `TEST` scope inventory; `MavenArtifactViewUpdater` and `ResolverArtifactPlanPublisher` update both `project.getArtifacts()` / `project.setResolvedArtifacts()` and the `EliderRepositorySessionDecorator` session plan, which intercepts any subsequent plugin resolution request in `test-compile`, `test`, or `package`.
2. **Ergonomic Phase Configuration**:
   * *Question*: How can users activate post-compile elision via a property (`-Delide.productionClassesComplete=true`) when Maven computes lifecycle phases before Mojo `@Parameter` injection?
   * *Answer*: Because `@Mojo(defaultPhase)` is static in `plugin.xml`, `EliderLifecycleParticipant.afterProjectsRead(MavenSession)` inspects effective project/user properties and plugin `<configuration>` before `DefaultLifecycleExecutionPlanCalculator` runs, dynamically rebinding the `elide` execution's phase to `process-classes` whenever `elide.productionClassesComplete=true` is enabled.

---

## 5. Evidence Gates

* **Source-Generation / Annotation-Processor Tests**:
  * Verify that a project with a `generate-sources` execution and/or `maven-compiler-plugin` `annotationProcessorPaths` succeeds with `elide.productionClassesComplete=true` at `process-classes`, dropping unused compile-scoped JARs and retaining dependencies referenced only by generated classes.
  * Verify that `elide.sourceRootsComplete=true` fails closed when `maven-compiler-plugin` configures `annotationProcessorPaths` or `annotationProcessors`, with an actionable message pointing to `elide.productionClassesComplete=true`.
* **CLI `analyze` and `dependency:tree` Integration**:
  * Verify `mvn compile dependency-elider:analyze -Delide.productionClassesComplete=true` reports accurate artifact savings and CVE reductions using `target/classes`.
  * Verify `mvn dependency:tree` with `elide` bound to `process-classes` (or `-Delide.productionClassesComplete=true`) schedules `process-classes` before `dependency:tree` via `EliderTreePreparation`.
* **Static Analysis & Regression Gate**:
  * Pass `make check` cleanly with zero regressions across existing `initialize`-bound tests.

## 6. Implementation Evidence and Limits

The implementation now separates the output-completeness assertion from the trusted capture context. The latter is propagated only when the Mojo execution reports `MojoExecution.Source.LIFECYCLE` and the exact phase `process-classes`. Direct CLI goal invocations can use explicitly supplied compiled output for static attribution, but they do not relax provider-generation guards. Same-phase and later unknown writers remain rejected; compile executions explicitly bound after `process-classes` are also rejected.

`MavenCompilerSettings.platformReleaseOptions` resolves only supported release/source/target settings for trimming and rejects compiler arguments that override platform or output selection. A mixed source root retains all regular members: Java files contribute parsed declarations and other files become digest-bound resource providers. Source-like files in languages the scanner cannot parse (`.scala`, `.kt`, `.kts`, `.groovy`) are captured before the inventory is rejected as incomplete.

The real Maven lifecycle test `extensionRebindsElideAfterGeneratedBytecodeExists` generates a Java class with the AntRun `generate-sources` execution, checks that the produced class references the retained dependency, enables the extension property, and runs a post-elision `dependency:tree` request. Unit tests cover compiled-bytecode attribution, missing class output, source-root resource members, and process-classes writer ordering. The Maven Compiler Plugin `testCompile` safeguard remains active even when `skipTests` is true because that flag does not skip test compilation.

Remaining boundary: trusted VEX inventory requires the packaged Maven extension and a real lifecycle-sourced `process-classes` execution. Direct Mojo invocation, a missing lifecycle phase, and other phases remain conservative. The process-classes mode also takes effect only after production compilation; it cannot remove dependencies from that compile invocation.
