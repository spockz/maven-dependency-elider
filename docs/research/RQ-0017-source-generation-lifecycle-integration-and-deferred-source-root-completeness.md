<!-- WHY: Investigates supporting projects with source-generation lifecycles (MapStruct, OpenAPI, Protobuf, Lombok, ANTLR) without failing closed or pinning all compile dependencies. -->
# RQ-0017: Source-Generation Lifecycle Integration and Post-Compile Bytecode Completeness

## Status

Resolved for source-generation lifecycle integration (implementation and inlined-constant follow-up accepted in [ADR-0010](../adr/0010-process-classes-lifecycle-and-bytecode-completeness.md)); the ADR-0016 resource-view follow-up in §21 is open.

## Date

2026-10-30

Last updated: 2026-11-23

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
* When traces are collected from production/staging (or only subset tests), `test-compile` will fail if `src/test/java` directly imports a dropped `compile`-scoped dependency—surfacing that the dependency is unused by production and should be declared in `<scope>test</scope>` (or retained via `elide.retainedArtifacts` / `elide.trimRoots`).

### 2.4 Inlined Compile-Time Constants and Non-Emitted Symbols

When `javac` compiles code that references `public static final` primitive or `String` constants defined in a dependency library:

```java
// Dependency library constant:
public class ConfigConstants {
    public static final String API_URL = "https://api.example.com";
}

// Application code:
String url = ConfigConstants.API_URL;
```

The Java compiler performs compile-time constant folding:

1. It inlines the literal value directly into the application bytecode stream.
2. It does not emit an entry for the constant-defining class (`ConfigConstants`) in the constant pool of the consuming `.class` file.
3. At `process-classes`, `ProductionBytecodeReferenceScanner` inspects only `target/classes` and finds zero references to `ConfigConstants`.

If that dependency is not otherwise invoked at runtime (and thus absent from runtime telemetry), `dependency-elider` concludes the dependency is completely dead and drops it as a whole artifact or trims the constant class:

* **Downstream `test-compile` Breakage**: `test-compile` executes immediately after `process-classes`. If any test in `src/test/java` references `ConfigConstants` (e.g. `assertEquals(ConfigConstants.API_URL, client.getUrl())`), compilation fails with `cannot find symbol ConfigConstants` because the library was removed from the compile classpath.
* **Consumer Reactor Breakage**: In multi-module builds, if an upstream library module undergoes post-compile elision, downstream sibling modules compiling against it lose access to the constant class unless protected by the leaf-only boundary ([ADR-0011](../adr/0011-reactor-leaf-module-elision-boundary.md)).
* **Incremental Recompilation & IDEs**: Incremental compilers and IDE workspaces that reuse the mutated post-elision classpath cannot recompile edits referencing members of the pruned library.

---

## 3. Analysis of the Rejected "Double Javac Pass" Alternative

During research, an alternative was evaluated: having the plugin trigger a second `javac` compilation pass inside the build (`generate-sources` $\rightarrow$ `compile` $\rightarrow$ `elide` $\rightarrow$ `compile` again). Detailed analysis showed this to be an anti-pattern:

1. **The "Wiped Resources" Hazard**: `process-resources` runs before `compile`. Wiping `target/classes` to force recompilation destroys copied and filtered application resources (`application.properties`, XML schemas, META-INF descriptors).
2. **Annotation Processor Loops & `FilerException`**: Running `javac` twice causes annotation processors to execute twice, risking `javax.annotation.processing.FilerException: Attempt to recreate a file for type ...` on existing generated sources unless `-proc:none` is injected by mutating compiler plugin state.
3. **Reactor Concurrency Races (`mvn -T`)**: Under parallel reactor builds, sibling modules read `target/classes` or packaged artifacts across threads. Deleting and recreating `.class` files mid-build introduces race conditions.
4. **Redundant Work**: `ProductionBytecodeReferenceScanner` + `MavenElisionService.finishAnalysis` computes the bytecode link closure over `target/classes` and dependency JARs. A second compilation that generates output or runs processors would duplicate work and introduce lifecycle hazards. The accepted follow-up uses only javac semantic attribution with output generation and processors disabled; its build-time overhead has not been measured.

---

## 4. Research Questions & Answers

1. **Maven Lifecycle Re-Resolution Boundaries**:
   * *Question*: Does mutating `project.getArtifacts()` at `process-classes` persist reliably through `test-compile`, Surefire, and packaging without Maven's internal `DependencyContext` cache triggering graph re-resolution?
   * *Answer*: Yes. `ElideMojo` already declares `requiresDependencyResolution = ResolutionScope.TEST`. When `ElideMojo` executes at `process-classes`, Maven has already resolved the `TEST` scope inventory; `MavenArtifactViewUpdater` and `ResolverArtifactPlanPublisher` update both `project.getArtifacts()` / `project.setResolvedArtifacts()` and the `EliderRepositorySessionDecorator` session plan, which intercepts any subsequent plugin resolution request in `test-compile`, `test`, or `package`.
2. **Ergonomic Phase Configuration**:
   * *Question*: How can users activate post-compile elision via a property (`-Delide.productionClassesComplete=true`) when Maven computes lifecycle phases before Mojo `@Parameter` injection?
   * *Answer*: Because `@Mojo(defaultPhase)` is static in `plugin.xml`, `EliderLifecycleParticipant.afterProjectsRead(MavenSession)` inspects effective project/user properties and plugin `<configuration>` before `DefaultLifecycleExecutionPlanCalculator` runs, dynamically rebinding the `elide` execution's phase to `process-classes` whenever `elide.productionClassesComplete=true` is enabled.
3. **Inlined Constants and Non-Emitted Symbols in Post-Compile Slicing**:
   * *Question*: How can `process-classes` elision prevent pruning dependencies that contributed inlined `static final` constants or compile-only types without re-running a slow second `javac` attribution pass?
   * *Investigated Solutions*:
     * **Option A: Hybrid Post-Compile Source + Bytecode Union (Accepted)**:
       `sourceRootsComplete` and `productionClassesComplete` remain mutually exclusive assertions. In the latter mode, once `compile` and generation have completed, the analyzer computes:
       $$\text{Required Roots} = \text{BytecodeReferences}(\text{target/classes}) \ \cup \ \text{AttributedSourceReferences}(\text{CompileSourceRoots})$$
       The source attribution uses the compiled output and compile dependencies on its classpath, forces `-proc:none`, and does not pass arbitrary compiler arguments or invoke processors. It preserves owners referenced only through inlined constants while keeping generated members and classes resolvable when the compiler emitted them.
     * **Option B: Lightweight Syntactic Import & Identifier Token Scanner (Not Selected)**:
       The accepted implementation uses `JavacTask.analyze()` only for semantic attribution, with processors disabled and no generated output. Its overhead is unmeasured. A syntax-only scanner could be considered later, but it would over-retain names without symbol resolution.
     * **Option C: Preserving Inlined Constants via Annotation/Configuration Overrides**:
       Allow developers to retain constant-defining libraries explicitly using `elide.trimRoots` or `<retainedArtifacts>`, while surfacing diagnostic warnings during `dependency-elider:report` when a dropped library matches an imported class name from source files.

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
  * Prove a dependency referenced only through a compile-time-inlined constant remains in artifact-only and JAR-trimming analysis; prove source attribution failure selects conservative retention rather than bytecode-only pruning.

## 6. Implementation Evidence and Limits

The implementation now separates the output-completeness assertion from the trusted capture context. The latter is propagated only when the Mojo execution reports `MojoExecution.Source.LIFECYCLE` and the exact phase `process-classes`. Direct CLI goal invocations can use explicitly supplied compiled output for static attribution, but they do not relax provider-generation guards. Same-phase and later unknown writers remain rejected; compile executions explicitly bound after `process-classes` are also rejected.

`MavenCompilerSettings.platformReleaseOptions` resolves only supported release/source/target settings for trimming and rejects compiler arguments that override platform or output selection. A mixed source root retains all regular members: Java files contribute parsed declarations and other files become digest-bound resource providers. Source-like files in languages the scanner cannot parse (`.scala`, `.kt`, `.kts`, `.groovy`) are captured before the inventory is rejected as incomplete.

The real Maven lifecycle test `extensionRebindsElideAfterGeneratedBytecodeExists` generates a Java class with the AntRun `generate-sources` execution, checks that the produced class references the retained dependency, enables the extension property, and runs a post-elision `dependency:tree` request. Unit tests cover compiled-bytecode attribution, missing class output, source-root resource members, process-classes writer ordering, constant-only source references, trimming roots, and conservative fallback after failed attribution. Compiler-generation checks protect production `compile`; test-only output is excluded when isolated, so test compiler processing does not need to be disabled.

The source union feeds compile artifact pruning and class-trimming roots, but remains separate from `BytecodeReferenceScan`, class-use categories, and runtime telemetry. Class-use reports continue to label only bytecode and runtime evidence; CVE/VEX claims are still bounded by their existing trim and precondition evidence. The source supplement can retain source-only unused types, and it does not guarantee dependencies referenced only by test sources. Missing/empty source roots, unsupported source forms or compiler/platform modes, and javac attribution errors produce a visible conservative fallback that retains every compile-visible coordinate and all indexed classes it provides.

Remaining boundary: trusted VEX inventory requires the packaged Maven extension and a real lifecycle-sourced `process-classes` execution. Direct Mojo invocation, a missing lifecycle phase, and other phases remain conservative. The process-classes mode takes effect only after production compilation; it cannot remove dependencies from that compile invocation.

## 7. Dated verification: 2026-11-06

The source-attribution and automatic inlined-constant preservation described earlier in this record
are historical: the dated amendment to [ADR-0010](../adr/0010-process-classes-lifecycle-and-bytecode-completeness.md)
and [ADR-0013](../adr/0013-compiler-decoupling-multi-jdk-portability-and-report-driven-liveness.md)
supersede them with production bytecode attribution and explicit retention for dependencies used only
through inlined constants.

A real Spring Boot example was verified using the existing extension-driven `process-classes`
rebind. Production compile preceded elide, three tests passed in a separate `clean test` run, and a
`clean package` run produced a JAR whose HTTP endpoint returned the expected response. A standalone
`dependency:tree` caused the extension to run compile and elide first, while `clean compile` alone did
not invoke elide. A valid source-free JAR project failed because no compiled class output existed.

The phase move did not resolve the Logback/Janino prerequisite assessment: with the mapping and
completeness opt-in supplied, the guard rejected Spring Boot's later `repackage` execution. It also
did so for a request ending at `process-classes`, where that execution did not run. The common report
did not surface the guard reason. The concrete setup, outcomes and limitations are recorded in
[RQ-0020](RQ-0020-advisory-source-coverage-and-scanner-finding-projections.md) and its
[verification snapshot](data/rq-0020/2026-11-06-process-classes-verification.json). Changing the
default phase would need a separate compatibility decision and updates to phase inference, goal
preparation, supported output boundaries, examples, and regression tests; the existing accepted
`initialize` default has not changed.

## 8. Dated implementation update: 2026-11-08

The wholesale-purge work package supersedes the 2026-11-06 checkpoint above: `elide` now defaults
to `process-classes`, after production compilation has emitted `target/classes`. The old
`elide.sourceRootsComplete=true` path is rejected with migration guidance; the lifecycle no longer
uses source-root scanning as a substitute for compiled output. Source-free modules are supported
when their configured production output is valid, while missing or empty output is handled as an
explicit lifecycle case rather than treated as proof that dependencies are unused.

## 9. Dated Boundary Update: 2026-11-09

Lifecycle provenance is not proof authority. Direct `elide` and `analyze` goals may capture physical runtime inputs when `elide.productionClassesComplete=true` explicitly asserts that compiled production output is complete. With `elide.preconditionClassPathComplete=true`, Analyze may prove prerequisite absence in that current inventory even when no removal is planned; only removals that exist solely in its plan remain forecasts. Analyze records the proof but does not modify artifacts or publish VEX files. The provider scan covers production class/resource roots and non-test-scoped effective dependency archives, excluding isolated test output and test-scoped archives. These scope filters apply only to proof; resolved dependency-scope rows remain in decisions and SBOMs. Normal `testCompile` and `testResources` may run. Custom test compiler arguments or output settings that can redirect into production remain guarded. Unmodeled production writers remain unsupported. The Spring example
and lifecycle integration tests exercise the extension-driven phase rebind, later `dependency:tree`
preparation, and final package behavior. See [ADR-0010](../adr/0010-process-classes-lifecycle-and-bytecode-completeness.md)
for the accepted lifecycle contract and [RQ-0020](RQ-0020-advisory-source-coverage-and-scanner-finding-projections.md)
for the real-package evidence and its limits.

## 10. Historical test-only dependency-view proposal: 2026-11-21

At this point [ADR-0016](../adr/0016-test-compilation-and-isolated-test-runtime-views.md) proposed revisiting the historical test-only guidance in §2.3: compile tests against allowed original mediated inputs, then analyze test bytecode and supply needed additions only to the test runtime. Production trimming, package resolution and production evidence would remain separate. The ADR recorded the Maven source investigation, two candidate compiler-view integrations and the lifecycle proof required to select one. In Maven 3.9.9 the compiler Mojo is configured before `MojoExecutionListener.beforeMojoExecution`, so that callback alone cannot change its already injected test classpath. The proposal had not yet been implemented; the experiment below verified only a narrow simulation. The later real-Elider implementation and its limits are recorded in §§12–16. Track resolver-view findings in [RQ-0006](RQ-0006-maven-artifact-view-consistency-and-early-resolution-hooks.md) and module-path issues in [RQ-0018](RQ-0018-jpms-module-awareness-and-assisted-modularization.md).

## 11. Local Maven view experiment: 2026-11-21

An isolated experiment tested the execution-listener route proposed in [ADR-0016](../adr/0016-test-compilation-and-isolated-test-runtime-views.md). These are observations from a **test-only simulation**, not implementation of Elider or completion of its lifecycle gate. The complete fixture source, observed logs, original command file and component descriptor are preserved in this checkout's ignored `.scratch/adr0016-maven-view-proof/`; the executed working copy was `/tmp/maven-view-proof/`. The `.scratch` copy and the original local Maven cache are environment-local and are not a published test fixture.

The run used Maven 3.9.11, JDK 21.0.12, Maven Compiler Plugin 3.13.0, Surefire 3.5.2 and Shade 3.6.0. Those versions describe this observation, not a required JDK vendor, patch or general compatibility guarantee. The fixture declares a real compile-scope `fixture:lib:1` and a test-scope JUnit dependency. `original.jar` contains `demo.Client`, `demo.Builder` and `demo.Helper`; `trimmed.jar` contains only `Client`; `overlay.jar` contains `Builder` and `Helper`. The app calls `Client`; the JUnit test calls `Builder`, which calls `Helper`, and checks the actual code-source URLs for the retained production and overlay classes.

The experimental extension, loaded using `-Dmaven.ext.class.path`, registers an `AbstractMavenLifecycleParticipant` using a Plexus component descriptor. Its `afterSessionStart` chains the session's existing execution listener. After production compilation succeeds it simulates elision by changing the resolved library artifact file to `trimmed.jar`. On `mojoStarted` for `maven-compiler-plugin:testCompile`, it temporarily changes that file to `original.jar`; on `mojoSucceeded` and `mojoFailed` for that compiler goal, it restores `trimmed.jar`. On `mojoStarted` for `maven-surefire-plugin:test`, it appends `overlay.jar` to the selected `MojoExecution`'s `additionalClasspathElements` configuration. The extension logs each transition and delegates to Maven's previous listener. The proxy, hard-coded goal checks and paths are probe code, not a proposed production API.

| Run | Actual observation |
| :--- | :--- |
| `clean test` with `-Dprobe.disabled=true` | Expected build failure: `testCompile` sees `trimmed.jar` and cannot find `Builder`. |
| `clean package` with both switches | Build succeeds; one JUnit test passes and verifies `Client` came from `trimmed.jar` and `Builder` from `overlay.jar`. Shade receives `trimmed.jar`; inspection of the resulting application JAR finds `demo/App.class` and `demo/Client.class`, but not `Builder` or `Helper`. |
| `clean test` with `-Dprobe.noOverlay=true` | Test compilation succeeds against `original.jar`, then Surefire fails with `NoClassDefFoundError: demo/Builder`. |
| `clean test` with a deliberate unrelated invalid test source | Test compilation fails after the original switch and the listener logs restoration of `trimmed.jar` on `mojoFailed`. |
| `clean package dependency:build-classpath` and a separate `clean package dependency:tree` | Later plugin execution logs show the trimmed project artifact; `build-classpath` contains the trimmed path and the tree lists the original compile coordinate. These observations do **not** establish an independently fresh resolver request. |

The observed command setup and exact invocations are in `.scratch/adr0016-maven-view-proof/commands.txt`; the six corresponding logs are `baseline.log`, `success.log`, `no-overlay.log`, `compiler-failure.log`, `resolution.log` and `tree.log` in the same directory. `classpath.txt` preserves the later dependency-plugin classpath, and `shaded-jar-contents.txt` preserves the inspected package entry list. The original working copy's `build.sh` is specific to `/tmp/maven-view-proof`, a local JDK/Maven installation and a cached repository; reproducing elsewhere requires choosing a compliant local JDK, Maven installation and seeded local repository, then adapting those paths. Seeded plugins and JUnit allowed the experiment to run Maven with `-o`; no live external service was needed. The fixture's app POM, extension source and service descriptor are preserved with the logs so an implementor can port the probe into the repository's real Maven integration harness.

The original working directory already contained the Plexus descriptor. The preserved `build.sh` does **not** create it, so a fresh reconstruction must copy the descriptor into the compiled extension's output directory before running that script; otherwise the JAR will not register the extension. With the preserved fixture copied to `/tmp/maven-view-proof` and a local repository prepared, run:

```sh
mkdir -p /tmp/maven-view-proof/extclasses/META-INF/plexus
cp .scratch/adr0016-maven-view-proof/components.xml \
  /tmp/maven-view-proof/extclasses/META-INF/plexus/components.xml
/tmp/maven-view-proof/build.sh
```

The existing `build.sh` hardcodes the observed JDK and Maven installation paths; update its local working copy for another installation. Confirm that Maven logs `PROBE registered` before interpreting any result.

For example, after preparing the working copy, extension JAR and seeded local repository as described in that command file, the following reproduce the two principal cases; `probe_maven` is the chosen Maven executable and `JAVA_HOME` points to the chosen JDK:

```sh
"$probe_maven" -o -f /tmp/maven-view-proof/app/pom.xml \
  -Dmaven.repo.local=/tmp/maven-view-proof/repo \
  -Dmaven.ext.class.path=/tmp/maven-view-proof/hook.jar \
  -Dprobe.disabled=true clean test

"$probe_maven" -o -f /tmp/maven-view-proof/app/pom.xml \
  -Dmaven.repo.local=/tmp/maven-view-proof/repo \
  -Dmaven.ext.class.path=/tmp/maven-view-proof/hook.jar clean package
```

The first command is expected to exit nonzero at test compilation; the second is expected to exit zero. The fixture is seeded by compiling the probe against Maven's `lib/*`, registering it under `META-INF/plexus/components.xml`, compiling `Client`, `Builder` and `Helper`, writing three JARs as described above, and placing the original dependency and its POM in the local repository. The preserved `build.sh`, `components.xml`, `extsrc`, `libsrc` and `app` directory show those exact inputs. Verify the post-test shaded JAR with `jar tf` and the class-origin assertions, not just Maven's exit status.

### Follow-up work package

1. Turn the simulation into a failing real-Elider test using the staged builder, helper and a second wholly dropped test-only artifact in `DependencyContextLifecycleIT` or a focused `ADR0016TestViewIT`. Run actual `process-classes` trimming, not the probe's simulated `compile` callback; verify the selected builder is physically absent from the retained production JAR.
2. Port only the proven listener timing into the lifecycle extension after deciding a supported registration and listener-chaining approach. Reuse the actual post-mediation, post-ban original inventory. Verify callback behavior before Mojo injection and restoration for success, checked failure, partial/direct goals, multiple executions and user listener coexistence. Preserve both Maven artifact sets and the detached production resolver projection.
3. Replace the hand-built overlay with existing test-root graph and fixed-point closure analysis; assert that a method body in `Builder` reaches `Helper` and the second artifact. Inject the generated paths into the actual Surefire execution before it is configured, preserve user-specified entries and test multiple Surefire executions. Handle dynamic roots and unsupported archive semantics as specified in ADR-0016.
4. Prove packaging and resolver isolation with the **real** `ResolverArtifactPlanPublisher`, `EliderRepositorySessionDecorator` and a genuinely separate `ProjectDependenciesResolver.resolve` request after test execution. Start with the existing `PostElideProbeMojo`, ensure the request uses the live production session and reaches the decorator, and assert paths, digests, coordinates, graph topology and final Shade entries. The dependency-plugin result above is useful evidence but is not that proof. Compare separate clean `maven.test.skip`, `skipTests` and test-running builds, and retain existing production SBOM/VEX and ban semantics.
5. Add cache and stale-output tests, ordinary user test dependencies, duplicate identities, test processor/generated output, direct goals, failure and skip paths, reactor scope and applicable module/multi-release boundaries. Record which cases are supported; report unsupported configurations instead of silently exposing original dependencies to packaging. Follow the exact TDD and verification steps in ADR-0016 and only then update user documentation, FAQ and reproducible examples.

After the real-Elider isolation proof and before production integration, record the selected hook, activation and extension requirements, supported Maven/compiler/runner versions, unsupported and direct-invocation behavior, test-report persistence/replay and fallback boundaries in ADR-0016. The local probe does not decide those implementation contracts.

Still unverified by this probe: Elider's actual resolver decorator and graph, an independent fresh resolution request, multiple compiler/Surefire executions, preexisting Surefire entries, mixed/direct/partial goal ordering, process interruption and unchecked failures, Maven or JDK portability, reactor and JPMS behavior, whole-artifact drops, generated or reflective test roots, actual overlay generation, bans and Maven mediation, stale inputs, and test skip settings.

## 12. Real-Elider first-slice proof: 2026-11-21

The new `DependencyContextLifecycleIT.realElider*` cases use the packaged Elider plugin and core extension, not the simulated trim from §11. The isolated `consumer-test-view` fixture compiles `App` against `Client`. Its test compiles against `Builder` and `Marker`; `Builder.build()` calls `Helper`. `test-view-library` and `test-only-library` are both declared compile scope. The real `process-classes` run retained `Client`, pruned `Builder`, `Helper` and `Unused` from the first JAR, and marked the second artifact `EFFECTIVE_DROP`. The unmodified Elider baseline reached Compiler 3.13.0's `testCompile` and failed specifically with missing `Builder` and `Marker`; the outer assertion also inspected the generated retained JAR. Fixture setup failures during the first local attempt (an unseeded Maven Install Plugin and missing trace input) were fixed before counting the baseline.

The selected **fixture hook** is a separate test-only core extension. Its `afterSessionStart` callback replaced the session execution listener with an explicit forwarding listener and logged `chained=true`. It captured original artifact order, identity, scope and file on `MojoStarted(elide)`, after Maven's resolution and before the real plugin publication. `MojoStarted(testCompile)` switched the project artifact objects and paths before compiler configuration; `MojoSucceeded` and `MojoFailed` restored the production set and paths. A deliberate unrelated invalid test source caused checked compilation failure and logged `production-restored outcome=failure` followed by `project-failed-production=true`. A partial run ending at `process-test-resources` never switched views. Direct `compiler:testCompile`, `surefire:test` and an appended `lifecycle-probe:post-elide-probe` succeeded when preceded by `process-classes`. The fixture listener added the hand-built JAR to the selected Surefire `MojoExecution`; the previous user `additionalClasspathElement` stayed usable inside the test. This observation selects the scoped listener as the next production candidate, not a supported integration for arbitrary projects.

The hand-built `test-additions.jar` contains only `Builder`, `Helper` and `Marker`. Without it, compilation succeeds but the test fails with `NoClassDefFoundError: Builder`. With `Builder` and `Marker` but no `Helper`, the test fails with `NoClassDefFoundError: Helper`. With all three, the test passes and checks that `Client` came from the generated trimmed JAR while `Builder` and `Marker` came from `test-additions.jar`. The preserved user classpath resource was also found. A later no-clean `package` used one validated production trim cache hit and passed again. Separate clean `-DskipTests` and `-Dmaven.test.skip=true` packages both excluded test additions; the former compiled `AppTest.class`, the latter did not. A clean package with the test source removed also succeeded without an addition.

After the successful test execution, the existing `PostElideProbeMojo` made an explicit, distinct `ProjectDependenciesResolver.resolve` call using the live repository session and a `COMPILE` filter. The probe marked only that call in session data and cleared the marker afterward. A lower-priority test-only session decorator observed `probeRequest=true`, `planPresent=true` and the input reader `EliderRepositorySessionDecorator$PlannedWorkspaceReader` during the marked call. The resulting filtered dependency list had exactly `io.github.spockz.elider.test:test-view-library:1.0.0:jar:` at the generated trimmed path with its SHA-256; no original JAR or additions path was resolved. The raw graph retained the declared JUnit test subtree even under the compile filter, while the production projection removed `test-only-library`. The graph rows, edges, resolved artifact path and digest are checked separately. Shade consumed the retained trimmed artifact and the final application JAR contained `App` and `Client`, but no `Builder`, `Helper`, `Unused`, `Marker`, original full JAR or test additions.

Retained local logs show original compile files under `/tmp/junit-270332593150420548/repository/io/github/spockz/elider/test/`, including `test-view-library/1.0.0/test-view-library-1.0.0.jar` and `test-only-library/1.0.0/test-only-library-1.0.0.jar`. A separate successful nested package run resolved `/tmp/junit-860533898890080166/lifecycle-probe-fixture/consumer-test-view/target/elided-artifacts/.generations/dd7bddbdd7e341bf5af3e66ecbf7805040d0f71afc2253bb3201364f7ce18957/io.github.spockz.elider.test-test-view-library-1.0.0-trimmed.jar`, SHA-256 `cf9a6760520912953b953920adeaff5417faff6515aa415ba38868c9a0e41ce2`. These `/tmp` paths are local evidence from different runs, not stable fixture paths or runtime requirements.

The final focused command used this host's JDK 21 toolchain and temporary Maven cache:

```sh
env HOME=/tmp/adr0016-home MAVEN_USER_HOME=/tmp/adr0016-home/.m2 MAVEN_OPTS=-Duser.home=/tmp/adr0016-home JAVA_HOME=/workspace/sources/maven-dependency-elider/.scratch/toolchains/graalvm-jdk-21.0.12+7.1 \
  ./mvnw -pl dependency-elider-maven-plugin -Dtest=none -Dsurefire.failIfNoSpecifiedTests=false '-Dit.test=DependencyContextLifecycleIT#realElider*' -Djacoco.skip=true verify --batch-mode --no-transfer-progress
```

The outer command exited 0 with three selected integration tests passing. Its fixture bootstrap first installs the real plugin and core extension, then the local fixture libraries and test-only listener extension. Nested calls use the harness-generated local settings and repository tail. Their goal sequences and observed exits were: `clean test` without listener, nonzero at test compilation; `clean test` with listener but no addition, nonzero at Surefire; `clean test` with incomplete addition, nonzero at Surefire; `clean package` with the full addition, zero; no-clean `package` with the full addition, zero; `clean test` with invalid test source, nonzero at test compilation; `clean process-test-resources`, zero; `clean process-classes compiler:testCompile surefire:test lifecycle-probe:post-elide-probe`, zero; `clean package lifecycle-probe:post-elide-probe -DskipTests`, zero; `clean package -Dmaven.test.skip=true`, zero; and `clean package` without test sources, zero. The focused test asserts the expected failure stage and content for each nonzero run rather than treating any failure as success.

The final `make check` exited 0 with the selected JDK's `bin` directory on `PATH` and the two pinned advisory Git LFS archives hydrated from the local object store. It included formatting, Checkstyle, PMD, SpotBugs, core and plugin tests, 28 plugin integration tests with no failures, documentation checks and transcript verification. The transcript checker reported that configured command transcripts are up to date. The archives were restored to their worktree pointer state after verification.

The proof changes no production code or persisted format. The fixture captures originals before Elider applies bans, so the candidate **cannot** yet be used as the production allowed-input handoff. Unverified: ban-filtered original capture, duplicate identities and mediation conflicts, multiple compiler or Surefire executions, arbitrary user listeners, unchecked failures and interruption, reactor and module path, Maven 4 or other plugin versions, generated test roots and annotation processors, stale test outputs, automatic graph/overlay generation, fallback archive semantics, test report persistence, production SBOM/VEX comparison and precondition-proof configurations. The current production ban, forbidden-code, SBOM and VEX paths were untouched by this fixture-only work; their interaction with a future integrated test view still needs tests.

## 13. Packaged first-slice integration: 2026-11-22

The first production hook was added after §12's fixture proof. The real `EliderLifecycleParticipant` now chains the Maven execution listener in `afterSessionStart`; the real `MavenElideExecution` publishes an ordered, JDK-only original-artifact handoff alongside its production output, and the listener limits the original project view to the compiler callback window. Surefire receives only the supplied, hand-built additions JAR on its selected execution. The production resolver plan and package inputs were not changed. The test-only extension now observes the production listener without switching artifact views itself. Its `registered chained=true`, `compiler-original before-configuration=true`, and `production-restored outcome=success/failure value=true` observations came from real Maven processes. The original experiment's simulated trim remains separate evidence and is not counted as proof of this integration.

The initial new production test was run against the previous implementation and failed at `testCompile` for missing `Builder` and `Marker`, after Elider had generated a retained JAR without `Builder`. After the hook was installed, the first nested package run exposed an incorrect direct mutation of `project.dependencyArtifacts`: Surefire then loaded `Marker` from the original full JAR. Removing that mutation restored the intended class origins and the package test passed. A separate observer run revealed that the listener forwarded `MojoStarted(testCompile)` before switching views; compilation still succeeded, but the chained observer saw the production view. The switch now occurs before forwarding the callback, with rollback if forwarding throws, and the observer and compiler both see original inputs before Mojo configuration.

The verified fixture is the same `consumer-test-view` of §12, now activated with `-Delide.testCompilationView=true` and optionally `-Delide.testAdditionsJar=<hand-built JAR>`. `AppTest` checks that `Client` loads from the generated trimmed production JAR while `Builder` and the wholly dropped artifact's `Marker` load from the additions JAR; `Builder` calls `Helper`. The preexisting user Surefire classpath resource remains visible. A run with no additions JAR compiled tests and failed at Surefire with missing `Builder`; a JAR lacking only `Helper` failed at Surefire with missing `Helper`. The compiler-failure run used an unrelated `UnknownType` source and the observer saw production artifact paths restored before `projectFailed`. Partial `process-test-resources`, direct `compiler:testCompile surefire:test` after `process-classes`, appended probe, `skipTests`, `maven.test.skip`, no test sources and a no-clean trim-cache hit passed. In the successful package run, the explicit post-test `ProjectDependenciesResolver.resolve` request reached the live production decorator and selected only the trimmed retained artifact path and SHA-256; Shade bundled `Client` and excluded `Builder`, `Helper`, `Unused`, `Marker`, original full JARs and additions. The graph and resolved rows are asserted separately, as in §12.

Commands used this host's JDK 21 toolchain and temporary Maven cache:

```sh
env HOME=/tmp/adr0016-home MAVEN_USER_HOME=/tmp/adr0016-home/.m2 MAVEN_OPTS=-Duser.home=/tmp/adr0016-home JAVA_HOME=/workspace/sources/maven-dependency-elider/.scratch/toolchains/graalvm-jdk-21.0.12+7.1 \
  ./mvnw -pl dependency-elider-maven-plugin -am install -DskipTests -Djacoco.skip=true --batch-mode --no-transfer-progress
env HOME=/tmp/adr0016-home MAVEN_USER_HOME=/tmp/adr0016-home/.m2 MAVEN_OPTS=-Duser.home=/tmp/adr0016-home JAVA_HOME=/workspace/sources/maven-dependency-elider/.scratch/toolchains/graalvm-jdk-21.0.12+7.1 \
  ./mvnw -pl dependency-elider-maven-plugin '-Dit.test=DependencyContextLifecycleIT#realElider*+productionTestViewRejectsMissingElideAndUnprovenBanInputs' -Dtest=none -Dsurefire.failIfNoSpecifiedTests=false -Dfailsafe.forkCount=1 -Djacoco.skip=true verify
```

The install exited 0. The current focused command exited 0 with four selected integration tests and no failures on 2026-11-22. Each nested Maven invocation used the packaged plugin and core extension, a copied local fixture repository and real lifecycle goals. The exact temporary artifact paths vary by test run and are checked against the generated production trim and hand-built addition paths rather than hardcoded. The live resolved row includes coordinate, normalized path and SHA-256; the package entry list is inspected from the shaded JAR.

The additional focused case ran `clean compiler:testCompile` with the view enabled but no earlier Elide goal and observed the explicit missing-plan error. It then requested a ban for an unmatched coordinate in the fixture and observed the view's explicit ban-policy rejection before test compilation. A first attempted ban of the direct `test-only-library` dependency failed earlier under Elider's existing direct-ban validation; that result was not counted as evidence for the view guard. The case passed after using the unmatched coordinate to reach the guard. The initial `make check-fast` and `make check` commands both exited 0 with local-socket permission for embedded HTTP fixtures; `make check` ran 30 plugin integration tests with no failures and reported configured transcripts up to date. The two pinned advisory archives were hydrated from local Git LFS objects for the checks and restored to pointer files afterward.

The supported boundary is opt-in, single-project Maven 3.9.11 with Compiler 3.13.0, Surefire 3.5.2 and Shade 3.6.0 in the tested classpath configuration. Elider must succeed earlier in the same invocation. The current capture is before production ban application, so enabling this view when a ban is requested fails closed; it never restores a banned original input. The JAR is supplied by the caller and no test graph, automatic addition, report or persisted format is produced. Maven 4, other compiler/runner versions, multiple executions, reactor or JPMS builds, annotation processors, interruption and unchecked callback failures, policy interaction and production SBOM/VEX comparison remain unverified. The production ban, forbidden-code, SBOM and VEX implementation was left untouched.

## 14. Surefire property review and correction: 2026-11-22

An independent Astra 6 High review found that the first production listener appended a child to `additionalClasspathElements` even when `maven.test.additionalClasspath` supplied a parent value. Maven 3.9.11's array converter uses the parent value and ignores those child entries. The review also found that a second clean package test duplicated the more complete successful package execution. The redundant method was removed; the remaining execution still asserts class origins, user classpath access, the fresh resolver request, graph, artifact paths and digests, original JAR immutability, and Shade entries. With the same JUnit parallel configuration, `DependencyContextLifecycleIT` ran 28 cases in 72.57 seconds before consolidation and 27 cases in 71.84 seconds afterward. This removes one nested Maven build, though the observed wall-time difference is small because other cases run concurrently.

The remaining successful package fixture was changed to supply `-Dmaven.test.additionalClasspath=<user JAR>` without the fixture's XML placeholder property. Against the previous listener, the test compilation succeeded but Surefire failed with `NoClassDefFoundError` for `Builder` and `Marker`. The listener now appends the hand-built additions path to the existing property value, leaving Maven's comma-separated array conversion in place. When the property is absent, it keeps appending an XML child. The changed real Maven run passed: `AppTest` found the user classpath marker, loaded `Client` from the trimmed JAR, and loaded `Builder` and `Marker` from the additions JAR. The XML child path remains exercised by the no-overlay, missing-helper and cached-package runs. The resolver and Shade assertions also passed in the property-based package run. The verification command was:

```sh
env HOME=/tmp/adr0016-home MAVEN_USER_HOME=/tmp/adr0016-home/.m2 MAVEN_OPTS=-Duser.home=/tmp/adr0016-home JAVA_HOME=/workspace/sources/maven-dependency-elider/.scratch/toolchains/graalvm-jdk-21.0.12+7.1 \
  ./mvnw -pl dependency-elider-maven-plugin '-Dit.test=DependencyContextLifecycleIT#realElider*+productionTestViewRejectsMissingElideAndUnprovenBanInputs' -Dtest=none -Dsurefire.failIfNoSpecifiedTests=false -Dfailsafe.forkCount=1 -Djacoco.skip=true verify
```

It exited 0 with four selected real Maven integration tests and no failures. After the correction, `make check-fast` and `make check` both exited 0; the full check ran 29 plugin integration tests with no failures and reported configured command transcripts up to date. The pinned advisory archives were restored to their worktree pointer state afterward. Other Surefire versions, configuration expressions beyond the standard property and XML entry forms, and multiple Surefire executions remain unverified.

## 15. Automatic test additions and reporting: 2026-11-22

The implementation after §14 adds a `prepare-test-view` execution at `process-test-classes` for an opted-in project whose Elide execution is at `initialize` or `process-classes`. `PrepareTestViewMojo` requires successful test compilation in the same invocation, reads the immutable allowed-original handoff, and compares it with the restored effective Maven artifact view. `TestAdditionsAnalyzer` scans compiled test roots, prepares one shared closure context across original JARs and project classes, follows reached classes into other original providers until stable, and selects only classes absent from the effective runtime view. `TestAdditionsArchiveWriter` writes sorted entries with zero timestamps to `target/elider/test-additions.jar`. The production resolver plan, package input and vulnerability evidence are not extended with that JAR.

The automatic writer has a deliberately narrow boundary. The scanner handles direct `Class.forName`, `ClassLoader.loadClass`, `ServiceLoader.load` and `loadInstalled` calls in compiled test classes and reached original classes. Literal class names become roots. If a call cannot be resolved, it seeds all classes missing from the effective view and records `conservativeFallbackUsed=true`; unchanged reached test libraries can trigger this, as the public JUnit example does. The fallback adds classes only to the test JAR. It does not model custom loaders, method handles, resource-driven names or dynamically reached classes outside the scanned closure, so it makes no general dynamic completeness claim. Changed-path contributors with non-metadata resources, and selected signed, sealed, modular or multi-release archives or classpath-relevant manifest fields, fail with a complete-test-view diagnostic. Duplicate original class providers, missing links and a selected runtime provider different from the original provider also fail. A whole-artifact test-only replacement, resource/service overlay and JPMS support are not implemented. A requested forced-absent ban is omitted from the allowed originals; the test compiler then cannot import it. An unmatched ban leaves the mediated original input available. The real Maven integration source asserts both cases, while the old all-bans rejection documented in §13 is historical.

`TestViewFreshness` stores independent schema-1 category digests for test source files, test and production class output, original and effective artifact files, compiler execution configuration, project/user properties and runtime options. A clean invocation records the manifest after successful analysis. Without a clean in the same invocation, preparation checks the saved manifest before analyzing and fails with a `Run Maven clean test` diagnostic for a missing or changed category. The goal removes the prior saved test report before that check, so a failed changed-input run leaves `report` with an explicit `no saved test preparation` result. The focused automatic integration test observed this state after a changed production output and verified the previous addition bytes were not authorized. The goal also checks that compiled test classes still have matching current sources. `maven.test.skip=true` writes an unavailable test report; `skipTests` still reaches compilation and preparation. A second compiler execution invalidates an earlier preparation before Surefire starts.

`TestViewReportSnapshot` and its strict writer/validator use a separate schema-1 JSON file under `target/elider/test-view-report.json`. Prepared rows retain the original-versus-effective test artifact paths and sorted added classes, bound by SHA-256 to the production report and by GAV and canonical base directory to the project. Caller-supplied additions and skipped compilation produce explicit unavailable observations. `ReportMojo` renders the production snapshot first, then replays the matching test observation without scanning classes, dependencies or advisories. An Analyze snapshot, missing test report or digest mismatch prints an unavailable test line; malformed JSON fails explicitly. This keeps test additions out of production omission and vulnerability claims. Because neither test-view persisted format has been released, each remains at version 1 under ADR-0005.

The fixture's new automatic path uses the real packaged Elider plugin and core extension, Compiler 3.13.0, Surefire 3.5.2 and Shade 3.6.0 on Maven 3.9.11. A focused Failsafe run of `realEliderAutomaticallyPreparesTestAdditionsAfterCompilation` passed with one test and no failures in 30.28 seconds (the test method ran for 13.72 seconds). It asserted a clean package with automatic `Builder`, transitive `Helper` and dropped-artifact `Marker` additions, a fresh production resolver request, a production-only Shade package, saved report replay, failed no-clean preparation after changed output, unavailable replay and a clean rebuild. Another focused run passed `realEliderPreservesTwoConfiguredSurefireExecutions` with two distinct user classpath entries (one test, zero failures, 20.80 seconds). A real sequential reactor test passed with one opted-in consumer leaf and original upstream library outputs; its package retained `Client` and omitted `Builder` while the test addition contained it. A focused annotation-processor test also passed: the ordinary compiler generated and compiled a JUnit test, two tests ran, the addition contained `Builder` and `Helper`, and the packaged JAR omitted the generated test class and `Builder`.

A focused three-way policy comparison passed separate clean packages with `-Dmaven.test.skip=true`, `-DskipTests=true`, and tests running. The first had no compiled test class or addition; the second had both but skipped execution; the third ran one test and an isolated packaged `app.App` smoke check. The test compared package entry lists, production SBOM components and dependency graph, VEX statements, and forbidden-code assessments across all three. The mapped `Builder` remained a production `PASS` assessment even when tests received it through an addition. These are structural and semantic comparisons, not a byte-for-byte equality claim for every output file. A focused real Maven `-T2` test passed its refusal assertion before the listener published an original compiler view; parallel reactor execution remains unsupported. Maven 4, multiple opted-in reactor modules, arbitrary reactor topology, arbitrary runners and plugin versions, unchecked listener failures, interruption and module path remain unsupported or unverified.

The new public fixture installed `test-only-library` and `test-view-library` into an isolated local repository, then passed `clean verify -Delide.mode=baseline`. The packaged baseline printed `client-ready` and supplied a class-load trace. With that trace and `-Delide.trimJars=true`, `clean test -Delide.mode=elision` without opt-in exited 1 at `compiler:testCompile` because `Builder` was absent; the error named `Builder`, rather than Maven setup or JUnit. Repeating as `clean verify -Delide.mode=elision -Delide.testCompilationView=true -Delider.verifyElision=true` passed one JUnit test. The direct `report` goal replayed a prepared result with four classes in two additions: `Builder`, `Helper`, `Marker` and conservatively included `Unused`; `conservativeFallbackUsed=true`. Inspection found all four in the test addition and only `Client` in the shaded production JAR. These focused commands used Maven 3.9.11, JDK 21, offline mode and `/tmp/adr0016-home/.m2/repository`. The README transcript was regenerated with the repository's default Maven arguments and records the prepared result.

The full `make test-examples` run first exposed two harness setup problems in this isolated repository. Its default `-T` reached the opted-in standalone fixture through the Maven wrapper's inherited `MAVEN_ARGS`; Elide correctly refused the unsupported parallel invocation. The harness now removes both the argument and inherited variable for that fixture. Its copied runtime-preparation reactor also lacked the `examples` parent POM in a clean local repository; the initial install now includes that reactor parent. On the corrected run, the test-view worker passed its baseline missing-`Builder` check, one JUnit test, test-only archive and report checks, and production Shade entry checks. The full harness result, including other fixtures and the reactor, is recorded in the final verification section below.

## 16. Final ADR-0016 verification: 2026-11-22

The final checks used Maven 3.9.11, the repository wrapper and an isolated local repository. The relevant commands can be reproduced with this environment and command sequence:

```sh
export HOME=/tmp/adr0016-home
export MAVEN_USER_HOME=/tmp/adr0016-home/.m2
export MAVEN_OPTS=-Duser.home=/tmp/adr0016-home
export JAVA_HOME=/workspace/sources/maven-dependency-elider/.scratch/toolchains/graalvm-jdk-21.0.12+7.1
export PATH="$JAVA_HOME/bin:$PATH"
export MARKDOWNLINT=/workspace/sources/maven-dependency-elider/.scratch/tools/node_modules/.bin/markdownlint-cli2
export MAVEN=/home/node/.codex/worktrees/6191/maven-dependency-elider/mvnw
MAVEN_ARGS='--batch-mode --no-transfer-progress -Dmaven.build.cache.enabled=false' make check-fast
MAVEN_ARGS='--batch-mode --no-transfer-progress -Dmaven.build.cache.enabled=false' make test-examples
MAVEN_ARGS='--batch-mode --no-transfer-progress' make update-transcripts
MAVEN_ARGS='--batch-mode --no-transfer-progress' make check
```

Each final command exited 0. `make check-fast` ran the full plugin suite and met the JaCoCo thresholds after two focused `EliderTestCompilationEvidenceTest` cases were added for the session handoff. `make test-examples` reported seven standalone fixtures and the multi-module reactor passed. The test-view fixture compiled and ran one JUnit test, reported the conservative four-class addition, and checked the production Shade archive and input list. The first full harness attempts failed for the inherited `-T` option and absent copied-reactor parent described in §15; those failures were setup failures, not successful feature evidence. The default-argument transcript update generated the new README report block. Full `make check` ran 548 core, 48 native-image, 145 lifecycle and 797 plugin unit tests with two configured plugin skips, plus 35 plugin integration tests, all without failures. Coverage, Java and Markdown static checks, catalog reproducibility and `go run scripts/update-transcripts.go --check` passed; the latter reported configured command transcripts up to date. Logs from this checkout are under `/tmp/adr0016-check-fast-final3.log`, `/tmp/adr0016-test-examples-final3.log` and `/tmp/adr0016-make-check-final.log`.

The second JDK check used the same isolated Maven repository and these focused commands:

```sh
export JAVA_HOME=/workspace/sources/maven-dependency-elider/.scratch/toolchains/graalvm-jdk-25.0.5+1.1
export PATH="$JAVA_HOME/bin:$PATH"
./mvnw --batch-mode --no-transfer-progress -Dmaven.build.cache.enabled=false \
  -pl dependency-elider-maven-plugin -am install -DskipTests -Djacoco.skip=true
./mvnw --batch-mode --no-transfer-progress -Dmaven.build.cache.enabled=false \
  -pl dependency-elider-maven-plugin \
  '-Dit.test=DependencyContextLifecycleIT#realEliderAutomaticallyPreparesTestAdditionsAfterCompilation' \
  -Dtest=none -Dsurefire.failIfNoSpecifiedTests=false -Dfailsafe.forkCount=1 \
  -Djacoco.skip=true verify
```

Both exited 0. The focused test ran the packaged plugin and extension through real Maven on JDK 25 and passed one integration case with no failures. Its log is `/tmp/adr0016-jdk25-it.log`. This is a second compliant JDK release check, not an exact JDK-build dependency. The accepted boundary remains one opted-in project in a sequential Maven 3.9.11 ordinary-classpath build with Compiler 3.13.0 and Surefire 3.5.2. At this point, changed or dropped resource-bearing contributors and unsafe archive splits failed preparation; §20 records the later unchanged-resource case. Custom loaders and other dynamic mechanisms are not proved complete. Maven 4, other plugin versions and test runners, JPMS, multiple opted-in reactor modules, unchecked listener failure and process interruption remain unverified.

## 17. Independent review and regressions: 2026-11-22

One independent `gpt-6-astra` High review ran against the uncommitted implementation with both `cli_daybreak` and `api_key_cyber_access_programs` disabled. Its log is `/tmp/adr0016-astra-review.log`. The review identified three counterexamples; none required changing the production resolver plan or packaging boundary:

1. A compiled test can reference a retained production class whose method body references a helper removed from the trimmed JAR. The test addition originally contained no helper because a root already available at runtime was excluded before closure. A focused `TestAdditionsAnalyzerTest` regression failed with an empty addition. Closure now starts from every referenced original class, including a retained class, while the archive writer still emits only missing classes. The regression expects the removed `Helper` and `Marker` and excludes the already supplied `Client`.
2. A control-flow branch can put either of two string literals on the stack before `Class.forName`. The scanner originally treated the last visited literal as the only name and did not request conservative fallback. An ASM-generated regression failed with `conservativeFallbackUsed=false` and one missing branch class. The scanner now invalidates its pending literal at a label, so the ambiguous call requests the documented conservative fallback.
3. Maven Compiler can produce a valid compiled test class without a `SourceFile` attribute when explicitly configured with `-g:none`. The real Maven clean-build regression failed at preparation with `Stale compiled test class has no current source` despite successful test compilation. The initial correction accepted missing optional metadata while retaining the source-path check when `SourceFile` was present. Clean-build provenance or the saved no-clean fingerprint remained required. The packaged plugin and extension then passed the same real Maven regression, including the assertion that `AppTest.class` lacks `SourceFile`. The follow-up correction in §18 removes the source-path check entirely.

The two focused analyzer tests passed together (22 tests, no failures) after the fixes. The focused real Maven `DependencyContextLifecycleIT#realEliderAutomaticallyPreparesTestAdditionsAfterCompilation` passed (one integration test, no failures) with the `-g:none` fixture. Red and green logs are `/tmp/adr0016-review-unit-red.log`, `/tmp/adr0016-review-unit-green.log`, `/tmp/adr0016-review-debug-red2.log` and `/tmp/adr0016-review-debug-green.log`. This evidence covers the reported counterexamples. It does not make arbitrary reflective calls, custom class loaders, resource overlays, JPMS or other Maven and runner versions supported.

Post-review verification used the §16 JDK 21 environment and these commands:

```sh
MAVEN_ARGS='--batch-mode --no-transfer-progress -Dmaven.build.cache.enabled=false -Dfailsafe.forkCount=1 -Djunit.jupiter.execution.parallel.enabled=false' make check-fast
MAVEN_ARGS='--batch-mode --no-transfer-progress -Dmaven.build.cache.enabled=false' make test-examples
MAKE_JOBS=1 MAVEN_ARGS='--batch-mode --no-transfer-progress -Dfailsafe.forkCount=1 -Djunit.jupiter.execution.parallel.enabled=false' make check
```

All exited 0. The full check ran 548 core, 48 native-image, 145 lifecycle, 799 plugin unit and 35 plugin integration tests without failures; two plugin unit tests were configured skips. The example harness passed seven standalone fixtures and the multi-module reactor. Coverage, static analysis, catalog reproducibility and transcript comparison passed. Logs are `/tmp/adr0016-review-check-fast-serial.log`, `/tmp/adr0016-review-test-examples.log` and `/tmp/adr0016-review-make-check.log`. An initial default-parallel `make check-fast` run failed four integration cases after JVM subprocesses reported `unable to create native thread` and one timed out. The same 35 integration cases passed with one Failsafe fork and disabled JUnit parallel execution; the failed run is recorded in `/tmp/adr0016-review-check-fast2.log` as an environment resource limit, not successful feature evidence.

The §16 JDK 25 packaged-plugin install and focused `DependencyContextLifecycleIT#realEliderAutomaticallyPreparesTestAdditionsAfterCompilation` were repeated after the fixes. Both exited 0; the focused real Maven test passed with the `-g:none` fixture and no failures. Logs are `/tmp/adr0016-review-jdk25-install.log` and `/tmp/adr0016-review-jdk25-it.log`. The supported and unverified boundaries stated above are unchanged.

## 18. Follow-up review of the fixes: 2026-11-22

A second independent `gpt-6-astra` High review ran with `cli_daybreak` and `api_key_cyber_access_programs` disabled. It verified the three §17 fixes and identified three further counterexamples. Its log is `/tmp/adr0016-astra-rereview.log`.

1. A conservative fallback can add `package-info.class` or a class with Unicode in its binary name. Archive creation succeeded, but the saved test report's ASCII class-name validator rejected the observation. A focused report test failed with `Added class name is invalid: a/Café`. Report validation now accepts JVM-style internal class entries, including `package-info` and Unicode, while rejecting empty and path-like invalid names. The report round-trip test passed with both names.
2. Maven Clean reports a successful Mojo even when `-Dmaven.clean.skip=true` leaves output intact. The listener originally marked that callback clean, bypassing the saved freshness fingerprint. A unit test failed because existing production and test output directories were still marked clean. A real Maven fixture then removed its test source and ran `-Dmaven.clean.skip=true clean package`; before the marker correction it unexpectedly succeeded. The marker now requires both output directories to be absent at the clean callback. The same real Maven invocation fails on changed source inputs with `Run Maven clean test` and leaves no saved test-view report.
3. Maven Compiler accepts `src/test/java/AppTest.java` declaring `package app`, even though its class is written to `target/test-classes/app/AppTest.class`. The original `SourceFile` path reconstruction rejected a valid clean package. The relocated-source real Maven fixture failed with `Stale compiled test class has no current source`; after removing that check, it compiled, ran and packaged successfully. Verified clean output deletion or a matching saved fingerprint now establishes freshness independently of optional debug metadata and source directory layout.

The red unit logs are `/tmp/adr0016-rereview-unit-red.log` and `/tmp/adr0016-rereview-report-red.log`. The red real Maven logs are `/tmp/adr0016-rereview-it-red.log` and `/tmp/adr0016-rereview-skipped-clean-red.log`. The focused green report and clean-evidence unit tests passed seven cases in total; the final packaged-plugin `DependencyContextLifecycleIT#realEliderAutomaticallyPreparesTestAdditionsAfterCompilation` passed one real Maven integration case, including the relocated source, debug-free compilation, skipped-clean rejection, fresh production resolver request and production-only Shade assertions. Logs are `/tmp/adr0016-rereview-unit-green.log` and `/tmp/adr0016-rereview-it-green2.log`. Maven Compiler deleted the old test class in the skipped-clean fixture, so that case proves changed-source rejection, not retention of a stale class file; the clean-evidence unit test directly checks the case where output directories remain.

The final follow-up checks used the §16 JDK 21 environment and bounded Failsafe concurrency:

```sh
MAVEN_ARGS='--batch-mode --no-transfer-progress -Dmaven.build.cache.enabled=false -Dfailsafe.forkCount=1 -Djunit.jupiter.execution.parallel.enabled=false' make check-fast
MAKE_JOBS=1 MAVEN_ARGS='--batch-mode --no-transfer-progress -Dfailsafe.forkCount=1 -Djunit.jupiter.execution.parallel.enabled=false' make check
```

Both exited 0. Full `make check` ran 548 core, 48 native-image, 146 lifecycle, 800 plugin unit and 35 plugin integration tests with no failures and two configured plugin unit skips. Coverage, Java and Markdown static checks, catalog reproducibility and command transcripts passed. Logs are `/tmp/adr0016-rereview-check-fast2.log` and `/tmp/adr0016-rereview-make-check.log`. The §16 JDK 25 packaged-plugin install and focused real Maven integration were also repeated after these fixes; both exited 0 and the focused case passed with no failures. Their logs are `/tmp/adr0016-rereview-jdk25-install.log` and `/tmp/adr0016-rereview-jdk25-it.log`. No example fixture changed in this follow-up; the prior seven-fixture example harness result in §17 remains the last full example run. The supported Maven 3 ordinary-classpath boundary and unresolved cases remain as stated in §16.

## 19. Dual-JDK verification: 2026-11-22

The follow-up request required the complete repository tests on JDK 21 and 25. The §18 full JDK 21 `make check` had passed on the unchanged Java implementation. The first full JDK 25 `make check` passed the Java, integration, static and catalog phases but failed `check-transcripts`: generated Maven output used runtime release 25 instead of 21, emitted Maven/Guice `sun.misc.Unsafe` warnings, and reported that the configured compiler target 21 was not covered by the supplied JDK 25 runtime release. That transcript drift was a documentation reproducibility failure, not a failing Java test or a changed test-view package. Its log is `/tmp/adr0016-jdk25-full-check.log`.

A new Go transcript-normalization test fed both the JDK-specific warning lines and runtime release values. It first failed because the generated lines still carried them; after the change it passed while preserving the configured target release and an independent policy warning. The normalization now uses `<RUNTIME_RELEASE>` for the analyzed runtime release and omits only the identified Maven/Guice and compiler-runtime coverage warnings from generated examples. The warning remains in live JDK 25 Maven output, and normalization makes no claim that JDK 25 runtime analysis covers target release 21. `make update-transcripts` on JDK 21 regenerated six README lines and one plugin-usage line containing the placeholder. `make check-transcripts` then passed independently on JDK 21 and JDK 25. The fixture scripts' missing-`JAVA_HOME` diagnostics now state the supported JDK 21-or-newer floor without naming a particular vendor or patch. Logs are `/tmp/adr0016-dualjdk-update-transcripts.log`, `/tmp/adr0016-jdk21-transcripts-check.log` and `/tmp/adr0016-jdk25-transcripts-check.log`.

The final JDK 25 verification used this host's JDK 25 toolchain, the isolated Maven cache and one Failsafe fork:

```sh
JAVA_HOME=/workspace/sources/maven-dependency-elider/.scratch/toolchains/graalvm-jdk-25.0.5+1.1 \
  MAVEN_ARGS='--batch-mode --no-transfer-progress -Dfailsafe.forkCount=1 -Djunit.jupiter.execution.parallel.enabled=false' \
  MAKE_JOBS=1 make check
JAVA_HOME=/workspace/sources/maven-dependency-elider/.scratch/toolchains/graalvm-jdk-25.0.5+1.1 \
  make test-examples
```

The selected JDK's `bin` directory was also first on `PATH`, and `HOME` and `MAVEN_USER_HOME` pointed to the isolated cache. Both commands exited 0. Full `make check` ran 548 core, 48 native-image, 146 lifecycle, 800 plugin unit and 35 plugin integration tests with no failures and two configured plugin unit skips. Formatting, Checkstyle, PMD, SpotBugs, coverage, catalog reproducibility and command transcripts passed. The example harness passed seven standalone fixtures and its sequential and threaded reactor cases, including the automatic test view. Logs are `/tmp/adr0016-jdk25-full-check-final.log` and `/tmp/adr0016-jdk25-test-examples.log`. These observations cover JDK 21 and 25 with Maven 3.9.11 on this host. Other JDK distributions, Maven 4 and the unsupported lifecycle and class-loading boundaries in §16 remain unverified.

A fresh full JDK 21 `make check` on the final transcript change also exited 0 with the same test counts and configured skips, static and coverage checks, catalog reproducibility and command transcripts. It used the same bounded-concurrency arguments with the JDK 21 toolchain; its log is `/tmp/adr0016-jdk21-full-check-final.log`. An initial sandboxed attempt stopped in tests using embedded HTTP servers because local socket creation was denied. The rerun with local socket access passed; that sandbox refusal is not a product-test failure.

A repeated JDK 21 `make test-examples` run exposed a harness repeatability issue: Maven Build Cache restored a previous result for the runtime-preparation fixture and skipped `dependency-elider:elide`, so the fixture's expected `1 validated hit(s)` observation was absent. The test-view fixture itself compiled, ran and packaged successfully in that run. A rerun with `-Dmaven.build.cache.enabled=false` passed all seven fixtures and the reactor. The harness now adds that property to each Maven invocation so its lifecycle assertions always observe real plugin execution. Standard `make test-examples` without a caller-supplied cache flag then passed on both JDK 21 and JDK 25, including the sequential and threaded reactor checks. Final logs are `/tmp/adr0016-jdk21-test-examples-standard.log` and `/tmp/adr0016-jdk25-test-examples-final.log`. This changes verification execution only; the packaged plugin's runtime and resolver behavior are unchanged.

## 20. Class-only additions and production resource reuse: 2026-11-23

The desired test runtime is the effective production JARs plus a JAR containing only extra classes. Production trimming already preserves ordinary resources in retained JARs. The first class-only analyzer instead rejected any original JAR with a resource once its path changed, even if the trimmed production JAR contained identical resource bytes. A focused test added the same `config/test.properties` entry to original and effective JARs while `Builder` was absent from the effective one. It failed with `Changed-path test artifact has a resource requiring a complete test view`; log `/tmp/adr0016-resource-red.log`.

The analyzer now compares non-metadata resource names and bytes in changed-path JARs. Identical resources remain supplied by the production JAR, and the class-only writer emits only the missing classes. A missing or changed resource still fails; the existing service-descriptor case also fails when a known provider named by an unchanged descriptor is absent from the effective classpath and the addition. The analyzer's 23 focused tests passed; log `/tmp/adr0016-resource-unit-green2.log`. This is a resource-view check, not a resource overlay or a test-only replacement of the production JAR.

The packaged-plugin `DependencyContextLifecycleIT#realEliderAutomaticallyPreparesTestAdditionsAfterCompilation` ran one real Maven integration case successfully after the fix; final log `/tmp/adr0016-resource-real-it-final.log`. The fixture library contains `fixture/test-view-resource.txt`; its JUnit test verifies the resource URL points to the trimmed production JAR and reads its bytes. The integration assertions verify that the trimmed JAR and Shade package contain the resource, while the test addition omits it. The same run still verifies class origins, a fresh production resolver request and production-only package entries. The initial outer invocation of this test stopped in unrelated socket-using unit tests under the sandbox; the focused rerun selected the analyzer unit class and used local socket access. It passed 23 unit tests and one real Maven integration test.

Production's archive sanitizer writes complete per-artifact trimmed outputs with resource and manifest handling. The test additions writer has a different byte contract: it must emit only missing classes and keep the effective production artifacts on the test runtime classpath. This is why it does not call the production sanitizer to make a replacement JAR. True module-path execution is still outside both this class-only test-view proof and the verified ordinary-classpath production boundary. A class-only JAR appended to Surefire's classpath cannot establish named-module membership or readability; those cases continue to fail or remain unsupported rather than widening the test artifact to an original full JAR.

After the archive-check refactor, JDK 21 `make check-fast` passed formatting, Checkstyle, PMD, SpotBugs, coverage, 801 plugin unit tests (two configured skips) and all 35 real Maven integration tests; log `/tmp/adr0016-resource-check-fast-final.log`. On JDK 25, the packaged-plugin install and focused verification passed all 23 analyzer unit tests and the real Maven integration case; logs `/tmp/adr0016-resource-jdk25-install.log` and `/tmp/adr0016-resource-jdk25-final.log`. Markdown lint, site-link verification, fixture scheduling, format behavior and the SBOM comparison test passed; logs `/tmp/adr0016-resource-other-checks.log`, `/tmp/adr0016-resource-other-checks-final.log` and `/tmp/adr0016-resource-sbom-test-final.log`. `make check-transcripts` passed with default Maven arguments; log `/tmp/adr0016-resource-transcripts-final.log`. An initial transcript check with an extra cache-disabling flag found expected output drift caused by that flag, not a source change. Both JDKs exercised the same class-only addition and production resource reuse. The earlier full `make check` and example-harness results in §§16 and 19 precede this resource-view change; the current change has the focused and fast-gate evidence stated here.

## 21. Open question: resource semantics across production and test views

**Question:** Can the test runtime reuse the production resource view whenever it adds only missing classes, and where do production resource transformations leave a test-only requirement that a class-only addition cannot satisfy?

The verified case is a retained production JAR with unchanged ordinary resources: its trimmed JAR supplies those resources to both production and tests. Production archive writing also filters service-provider and auto-configuration metadata when classes are removed, and dropping a whole dependency removes its resources. The current test preparation compares original and effective resource names and bytes and rejects a changed or missing resource; this is conservative even when no test uses that resource. Production has a related question for resource lookups that its existing reachability and dynamic-root evidence does not identify. Do not treat the passing unchanged-resource fixture as proof for those cases.

Research the boundary using the existing production resource and provider rules: which transformed resources are observable to tests; whether test bytecode, service configuration or other supported inputs can establish that a changed or missing resource is irrelevant; and which cases must remain unsupported under [ADR-0016](../adr/0016-test-compilation-and-isolated-test-runtime-views.md)'s class-only additions contract. Exercise retained JARs, filtered descriptors, and wholly dropped dependencies with both used and unused resources in real Maven tests. Check resource origins during tests and verify that the live production resolver and packaged artifact still contain only the production view. Record any production-side gap separately from a test-only need, and do not restore an original full JAR or copy resources into the additions JAR to make a fixture pass.
