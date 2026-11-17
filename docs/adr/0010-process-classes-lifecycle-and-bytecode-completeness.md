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
  * [ADR-0012: Dual-Layer Ban Policy and Retention Naming](0012-dual-layer-ban-policy-and-retention-naming.md)
  * [RQ-0017: Source-Generation Lifecycle Integration and Post-Compile Bytecode Completeness](../research/RQ-0017-source-generation-lifecycle-integration-and-deferred-source-root-completeness.md)

---

## 1. Context

[ADR-0001](0001-runtime-telemetry-driven-dependency-elision-at-maven-initialize-phase.md) bound `dependency-elider:elide` to Maven's `initialize` phase and introduced `elide.sourceRootsComplete` (default `false`) to guard against ungenerated sources. Under that contract:

* When `elide.sourceRootsComplete=false`, `MavenElisionService.compilerInputs` conservatively pins all `compile`, `provided`, and `system` scope JARs and all their indexed classes—even when `elide.productionOutput` (`target/classes`) is present and scanned.
* When `elide.sourceRootsComplete=true`, `MavenElisionService.verifySourceRootsComplete` rejects any project with `generate-sources`..`compile` code-generation executions, while failing to detect `maven-compiler-plugin` annotation processors (`annotationProcessorPaths`).

Modern Java applications routinely rely on source generators and annotation processors (MapStruct, Lombok, OpenAPI Generator, Protobuf/gRPC, Avro, ANTLR). For these projects, `initialize`-phase source scanning either fails closed or suppresses all compile-scope dependency elision and CVE reductions.

---

## 2. Decision

We introduce **Post-Compile Production Bytecode Completeness (`elide.productionClassesComplete`)** and default **`process-classes` lifecycle execution**:

1. **Production Bytecode Attribution (`elide.productionClassesComplete=true`)**:
   * Both `ElideMojo` and `AnalyzeMojo` expose `@Parameter(property = "elide.productionClassesComplete", defaultValue = "false")`.
   * `ElideMojo` defaults to `LifecyclePhase.PROCESS_CLASSES`. When `ElideMojo` runs in `process-classes` (and `productionClassesComplete` is not explicitly set), `productionClassesComplete` is automatically enabled.
   * `sourceRootsComplete=true` is rejected; compiler-coupled source attribution (`PostCompileSourceAttribution`) has been removed per [ADR-0013](0013-compiler-decoupling-multi-jdk-portability-and-report-driven-liveness.md).
   * When `productionClassesComplete=true` and `productionOutput` is not explicitly configured, `productionOutput` defaults to `${project.build.outputDirectory}` (`target/classes`). The directory must exist and contain at least one class or resource file (`scannedClassFileCount() > 0` or `scannedResourceFileCount() > 0`), so source-free / resource-only modules pass when their configured output directory is valid.
   * `MavenElisionService.prepare` scans compiled production bytecode (`productionBytecodeInputs(productionOutput)`) and unions it with explicit `elide.retainedArtifacts` (`ADR-0013`) and runtime telemetry / framework evaluators rather than invoking `javac`.
   * Static link-closure across `target/classes` and retained dependency JARs is enforced by the fixed-point bytecode reachability loop in `MavenElisionService.finishAnalysis` (`newlyReachedDrops` $\rightarrow$ `promoteForBytecode`).

2. **Lifecycle Binding (`EliderLifecycleParticipant`)**:
   * `ElideMojo` declares `defaultPhase = LifecyclePhase.PROCESS_CLASSES` in `plugin.xml`.
   * Users may also bind `dependency-elider:elide` explicitly or set `elide.productionClassesComplete=true` (via POM `<configuration>`, project `<properties>`, or CLI `-Delide.productionClassesComplete=true`).
   * `EliderLifecycleParticipant.afterProjectsRead(MavenSession)` inspects effective properties and plugin configuration; when `elide.productionClassesComplete=true` is active, any `elide` execution with phase `null` or `initialize` is dynamically rebound to `process-classes`.

3. **Phase-Aware `mvn dependency:tree` Preparation (`EliderTreePreparation`)**:
   * `EliderPluginConfiguration` and `EliderGoalOrder` accept `elide` executions bound to either `initialize` or `process-classes`.
   * When `elide` is bound to `process-classes` and a standalone `dependency:tree` goal is requested without a preceding `process-classes` (or later) phase after the last `clean`, `EliderTreePreparation` injects `process-classes` before `dependency:tree`.

4. **Phase-Relative Precondition Guards (`MavenPreconditionGenerationGuard` & `MavenCompilerGenerationGuard`)**:
   * When `elide.preconditionClassPathComplete=true` is evaluated with `productionClassesComplete=true` (at `process-classes`), lifecycle phases `generate-sources` through `compile` have already completed and their emitted `.class` files in `target/classes` are directly hashed by `MavenPreconditionProviderRoots.capture`.
   * Pre-capture source generators (`generate-sources`..`process-resources`) and `maven-compiler-plugin` annotation processor settings for `compile` are permitted when `productionClassesComplete=true`, while unmodeled provider-generating executions in phases after `process-classes` remain rejected.
   * Conversely, at `initialize` (`sourceRootsComplete=true`), `MavenElisionService.hasUnknownSourceGeneration` is tightened to also reject `maven-compiler-plugin` configurations that declare `annotationProcessorPaths`, `annotationProcessors`, or `proc` values other than `none`, with an error message directing the user to `elide.productionClassesComplete=true` / `process-classes`.
   * The lifecycle phase supports post-compile attribution and phase-sensitive writer checks, but lifecycle origin does not grant proof authority. Direct `elide` and `analyze` goals may capture a complete physical runtime inventory when `elide.productionClassesComplete=true` is explicit. With `elide.preconditionClassPathComplete=true`, Analyze can prove prerequisite absence in the current inventory; planned removals remain predictions until their output is inspected.
   * Unknown production writers that can change captured output remain rejected. Test-only output is excluded when separate from production roots, and test-scoped dependency archives are excluded from the runtime provider inventory. Ordinary `testCompile` and `testResources` do not block proof. Custom test output redirection is rejected, and `skipTests=true` prevents tests from changing production output after capture.

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
  * The extension provides convenient post-compile lifecycle ordering; a direct `elide` goal can also capture completed output when explicitly asserted and physically inspected.
  * The source supplement can retain dependencies referenced only by source and not by emitted bytecode. If semantic attribution fails (including sources that rely on compiler-generated members such as Lombok accessors), the post-compile fallback retains all compile-visible artifacts and their indexed classes. Test-only references are outside this production-root guarantee.

---

## 4. Dated Amendment: 2026-11-02 Narrowing to Emitted Bytecode (ADR-0013 / WP-PLATFORM-01)

Under [ADR-0013](0013-compiler-decoupling-multi-jdk-portability-and-report-driven-liveness.md) and [WP-PLATFORM-01](../handovers/2026-11-02-wp-platform-01-compiler-decoupling-and-live-proof-pivot.md), in-process AST source scanning (`PostCompileSourceAttribution`) is decommissioned. Post-compile analysis is intentionally narrowed to emitted production bytecode (`target/classes`), Spring AOT generated assets, and declared runtime evidence sources. Dependencies referenced exclusively through compile-time inlined primitive or `String` constants (with zero remaining bytecode references in `target/classes`) are retained explicitly via `<retainedArtifacts><retainedArtifact>groupId:artifactId</retainedArtifact></retainedArtifacts>` rather than through redundant in-process `javac` source passes.

## 5. Dated Amendment: 2026-11-08 Default Phase and Provider Boundary

This amendment supersedes the original opt-in description and the 2026-11-02 statement that
existing `initialize`-bound projects remain the default. The Mojo, lifecycle phase inference,
standalone `dependency:tree` preparation, and ban activation now agree on `process-classes` as the
default. The phase is reached after production compilation and before `test-compile`, tests and
packaging. Consequently, production compile itself uses the original dependencies; subsequent
goals consume the validated effective Maven view.

`elide.sourceRootsComplete=true` is rejected with migration guidance because source roots are not
the post-compile proof inventory. A module with no production source can pass this boundary when
its configured class/resource output is valid; missing output and empty class output are handled
explicitly. Direct `elide` and `analyze` goals can capture physical runtime providers when
`elide.productionClassesComplete=true` explicitly asserts complete compiled production output and
the goal inspects those bytes; runtime inventory scoping, isolated test-output exclusions, and
precondition-proof gating follow [ADR-0008](0008-precondition-gated-vex-attestations.md). See
the 2026-11-08 implementation evidence in
[RQ-0017](../research/RQ-0017-source-generation-lifecycle-integration-and-deferred-source-root-completeness.md).
