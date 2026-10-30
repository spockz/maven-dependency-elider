<!-- WHY: Records the architectural decision to support post-compile elision at process-classes and production bytecode completeness for projects with source generation or annotation processing (RQ-0017). -->
# ADR-0010: Post-Compile `process-classes` Lifecycle Execution and Production Bytecode Completeness

* **Status**: Accepted
* **Date**: 2026-10-30
* **Role**: architecture
* **Scope**: build-lifecycle
* **Area**: plugin-core
* **Related**:
  * [ADR-0001: Runtime Telemetry-Driven Dependency Elision at Maven INITIALIZE Phase](0001-runtime-telemetry-driven-dependency-elision-at-maven-initialize-phase.md)
  * [ADR-0008: Evidence-Bounded Precondition-Gated VEX Attestations](0008-precondition-gated-vex-attestations.md)
  * [RQ-0017: Source-Generation Lifecycle Integration and Post-Compile Bytecode Completeness](../research/RQ-0017-source-generation-lifecycle-integration-and-deferred-source-root-completeness.md)

---

## 1. Context

[ADR-0001](0001-runtime-telemetry-driven-dependency-elision-at-maven-initialize-phase.md) bound `dependency-elider:elide` to Maven's `initialize` phase and introduced `elide.sourceRootsComplete` (default `false`) to guard against ungenerated sources. Under that contract:

* When `elide.sourceRootsComplete=false`, `MavenElisionService.compilerInputs` conservatively pins all `compile`, `provided`, and `system` scope JARs and all their indexed classes—even when `elide.productionOutput` (`target/classes`) is present and scanned.
* When `elide.sourceRootsComplete=true`, `MavenElisionService.verifySourceRootsComplete` rejects any project with `generate-sources`..`compile` code-generation executions, while failing to detect `maven-compiler-plugin` annotation processors (`annotationProcessorPaths`).

Modern Java applications routinely rely on source generators and annotation processors (MapStruct, Lombok, OpenAPI Generator, Protobuf/gRPC, Avro, ANTLR). For these projects, `initialize`-phase source scanning either fails closed or suppresses all compile-scope dependency elision and CVE reductions.

---

## 2. Decision

We introduce **Post-Compile Production Bytecode Completeness (`elide.productionClassesComplete`)** and first-class **`process-classes` lifecycle execution**:

1. **Production Bytecode Attribution (`elide.productionClassesComplete=true`)**:
   * Both `ElideMojo` and `AnalyzeMojo` expose `@Parameter(property = "elide.productionClassesComplete", defaultValue = "false")`.
   * When `ElideMojo` executes in the `process-classes` lifecycle phase (and `sourceRootsComplete=false`), `productionClassesComplete` is automatically enabled.
   * `productionClassesComplete=true` and `sourceRootsComplete=true` are mutually exclusive; setting both fails closed.
   * When `productionClassesComplete=true` and `productionOutput` is not explicitly configured, `productionOutput` defaults to `${project.build.outputDirectory}` (`target/classes`). The directory must exist and contain at least one compiled `.class` file (`scannedClassFileCount() > 0`).
   * In `MavenElisionService.prepare`, `productionBytecodeInputs(productionOutput)` is evaluated before `compilerInputs`. When `productionClassesComplete=true`, `compilerInputs` uses the `BytecodeReferenceScan` of `target/classes` in place of source scanning or full compile-scope pinning:
     * `requiredClasses` = `bytecodeScan.referencedClasses()`
     * `compileVisibleCoordinates` = `compileVisibleArtifacts` whose indexed classes intersect `bytecodeScan.referencedClasses()`
     * `declaredClasses` = `classNamesInOutput(bytecodeScan.scope())`
   * Static link-closure across `target/classes` and retained dependency JARs is enforced by the fixed-point bytecode reachability loop in `MavenElisionService.finishAnalysis` (`newlyReachedDrops` $\rightarrow$ `promoteForBytecode`).

2. **Lifecycle Binding & Dynamic Phase Rebinding (`EliderLifecycleParticipant`)**:
   * `ElideMojo` retains `defaultPhase = LifecyclePhase.INITIALIZE` in `plugin.xml` for backwards compatibility with existing `initialize`-bound builds.
   * Users may bind `dependency-elider:elide` explicitly to `<phase>process-classes</phase>` in `pom.xml`, or set `elide.productionClassesComplete=true` (via POM `<configuration>`, project `<properties>`, or CLI `-Delide.productionClassesComplete=true`).
   * Because Maven computes lifecycle execution plans before Mojo parameter injection, `EliderLifecycleParticipant.afterProjectsRead(MavenSession)` inspects effective properties and plugin configuration; when `elide.productionClassesComplete=true` is active, any `elide` execution with phase `null` or `initialize` is dynamically rebound to `process-classes`.

3. **Phase-Aware `mvn dependency:tree` Preparation (`EliderTreePreparation`)**:
   * `EliderPluginConfiguration` and `EliderGoalOrder` accept `elide` executions bound to either `initialize` or `process-classes`.
   * When `elide` is bound to `process-classes` and a standalone `dependency:tree` goal is requested without a preceding `process-classes` (or later) phase after the last `clean`, `EliderTreePreparation` injects `process-classes` before `dependency:tree`.

4. **Phase-Relative Precondition Guards (`MavenPreconditionGenerationGuard` & `MavenCompilerGenerationGuard`)**:
   * When `elide.preconditionClassPathComplete=true` is evaluated with `productionClassesComplete=true` (at `process-classes`), lifecycle phases `generate-sources` through `compile` have already completed and their emitted `.class` files in `target/classes` are directly hashed by `MavenPreconditionProviderRoots.capture`.
   * Pre-capture source generators (`generate-sources`..`process-resources`) and `maven-compiler-plugin` annotation processor settings for `compile` are permitted when `productionClassesComplete=true`, while unmodeled provider-generating executions in phases after `process-classes` remain rejected.
   * Conversely, at `initialize` (`sourceRootsComplete=true`), `MavenElisionService.hasUnknownSourceGeneration` is tightened to also reject `maven-compiler-plugin` configurations that declare `annotationProcessorPaths`, `annotationProcessors`, or `proc` values other than `none`, with an error message directing the user to `elide.productionClassesComplete=true` / `process-classes`.
   * The class-output assertion and lifecycle provenance are separate values. Only a Mojo execution whose source is `MojoExecution.Source.LIFECYCLE` and whose exact phase is `process-classes` gets the trusted precondition-capture context. A direct CLI goal or a missing/other phase may use an explicitly supplied bytecode-completeness assertion for attribution, but keeps the existing conservative provider-generation guards.
   * Only configured writers in phases strictly before `process-classes` can be accepted as pre-capture writers. Unknown writers at the capture phase or later are rejected, including later-bound compiler executions. `skipTests` does not skip `testCompile`; its processor safeguards remain active.

5. **Complete Root-Member Capture and Platform Options**:
   * Every declared source-root member remains part of the provider inventory and its digest. `.java` members are parsed for declarations; other regular files in a mixed source root are captured as resource providers. Known source forms the Java scanner cannot parse, including `.scala`, `.kt`, `.kts`, and `.groovy`, keep the inventory incomplete after capture. No root member is filtered out.
   * Trimming resolves the target Java platform from release/source/target settings without using arbitrary compiler arguments. Processor arguments may be present, but arguments that override release, target, preview, system/boot class path, modules, or output locations are rejected. Explicit `fork=false` and `enablePreview=false` are accepted; selected toolchains and non-javac compilers remain unsupported.

---

## 3. Consequences

* **Positive**:
  * Projects using MapStruct, Lombok, OpenAPI, Protobuf, Avro, or ANTLR achieve full compile-scope dependency elision, intra-JAR trimming, and CVE mitigation in a single standard `javac` pass without special-casing individual code generators.
  * Existing `initialize`-bound projects and test suites remain 100% compatible.
* **Negative / Trade-offs**:
  * When `elide` runs at `process-classes`, `compile` executes against the un-elided compile classpath; elision and trimming take effect immediately after `compile` for `test-compile`, `test`, `package`, SBOM/VEX generation, and `dependency:tree`.
  * The trusted capture behavior depends on the Maven extension and its lifecycle source metadata; direct CLI goal invocations cannot claim a post-compile provider inventory.
