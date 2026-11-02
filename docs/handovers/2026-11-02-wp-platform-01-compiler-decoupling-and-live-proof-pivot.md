<!-- WHY: Defines the unified work package to decouple the build and runtime from pinned JDK/compiler digests, integrate Spring AOT and JPMS module boundaries, and pivot to report-driven live proof data. -->
# Work Package Handover: WP-PLATFORM-01 Multi-JDK Decoupling, Spring AOT Coherence, and Live Proof Pivot

* **Status**: Proposed
* **Date**: 2026-11-02
* **Scope**: Removing hard dependencies on proprietary/pinned JDK compiler images, enforcing multi-JDK 21+ portability across all features, deprecating in-process `javac` source reproduction, integrating Spring AOT condition evaluation and descriptor trimming (subsuming WP-SPRING-01), implementing JPMS module awareness (classpath-only derivatives and SPI roots), and supporting downstream JVM packaging workflows (advisory `jdeps` module suggestions and post-packaging CDS compatibility).
* **Subsumes**: [WP-SPRING-01: Spring AOT Evidence and Descriptor Coherence](2026-10-31-wp-spring-01-spring-autoconfigure-condition-evaluation-and-descriptor-trimming.md)
* **Related Work Packages**:
  * [WP-POLICY-01: Dependency Banishment and Explicit Retention](2026-10-31-wp-policy-01-global-dependency-exclusions-and-retained-artifacts-flip.md)
  * [WP-LIFECYCLE-01: Process-Classes and Bytecode Completeness](2026-10-30-wp-lifecycle-01-process-classes-and-bytecode-completeness.md)
  * [WP-VEX-02: Precondition-Gated VEX Generation](2026-10-29-wp-vex-02-precondition-gated-vex-generation.md)
* **Related Research**:
  * [RQ-0002: Runtime Sensor Fidelity and Framework Auto-Configuration Quiescence](../research/RQ-0002-runtime-sensor-fidelity-and-framework-autoconfiguration-quiescence.md)
  * [RQ-0005: Spring Bean Request Evidence and Auto-Configuration Recommendations](../research/RQ-0005-spring-bean-request-evidence-and-autoconfiguration-recommendations.md)
  * [RQ-0008: OSV SBOM Comparison and VEX Evidence](../research/RQ-0008-osv-sbom-comparison-and-vex-evidence.md)
  * [RQ-0010: Third-Party SBOM Plugin Integration and Liveness Enrichment](../research/RQ-0010-third-party-sbom-plugin-integration-and-liveness-enrichment.md)
  * [RQ-0013: Precondition-Gated VEX and Multi-Artifact Exploitability](../research/RQ-0013-precondition-gated-vex-and-multi-artifact-exploitability.md)
  * [RQ-0016: Native Image Metadata Ingestion](../research/RQ-0016-graalvm-native-image-metadata-ingestion-and-permissive-argument-taxonomy.md)
  * [RQ-0017: Source Generation Lifecycle Integration](../research/RQ-0017-source-generation-lifecycle-integration-and-deferred-source-root-completeness.md)
  * [RQ-0018: JPMS Mechanics, Spring AOT & CDS Integration, and `jlink` JRE Reduction](../research/RQ-0018-jpms-module-awareness-and-assisted-modularization.md)
* **Related Decisions**:
  * [Contributor Decision Register: JDK runtime and compiler decoupling](../contributor-decisions-and-faq.md#decision-register)
  * [ADR-0006: Dual-Source Vulnerability Advisory Ingestion](../adr/0006-dual-source-vulnerability-advisory-ingestion-from-cvelist-v5-and-osv-maven.md)
  * [ADR-0008: Precondition-Gated VEX Attestations](../adr/0008-precondition-gated-vex-attestations.md)
  * [ADR-0010: Process-Classes Lifecycle and Bytecode Completeness](../adr/0010-process-classes-lifecycle-and-bytecode-completeness.md)
  * [ADR-0013: Compiler Decoupling, Multi-JDK Portability, and Report-Driven Liveness Attestation](../adr/0013-compiler-decoupling-multi-jdk-portability-and-report-driven-liveness.md)

---

## 1. Executive Summary & Root Cause Analysis

### 1.1 The Issue

When building and testing `maven-dependency-elider` on any JDK other than our local GraalVM JDK 21 development image (e.g. standard OpenJDK 21, Eclipse Temurin 21, GraalVM 25, or OpenJDK 27), users encounter extensive test failures:

* **`elider-core`**: 16 failures and 6 errors (10 failures in `SourceReproductionEngineTest`, `SourceReproductionInvocationCacheTest`, `SourceUnitIdentityValidatorTest`, `LiveStructuredSourceBoundaryTest`, and `JavacPluginServiceIsolationTest`; 2 errors in `SourceJdkIdentityTest`).
* **`dependency-elider-maven-plugin`**: 75 failures and 88 errors across Mojo execution, source attribution, and compiler platform tests.

### 1.2 Root Cause

The failures stem from tight, hardcoded coupling to our development JDK image:

1. **Pinned Digest Allowlist in [`SourceJdkIdentity.java`](../../elider-core/src/main/java/io/github/spockz/elider/correspondence/SourceJdkIdentity.java)**:
   The source correspondence engine explicitly pins:
   * `SUPPORTED_FEATURE = 21`
   * `SUPPORTED_RUNTIME = "21.0.12+7-LTS-jvmci-23.1-b96"`
   * Exact SHA-256 digests for `JavacTool.class`, `jdk.compiler.jmod`, `lib/modules`, and `lib/ct.sym`.
   On any other JDK build, `SourceJdkIdentity.current()` returns `Resolution.unavailable("Source reproduction requires the JDK 21 jdk.compiler module")`. Tests asserting successful compilation or completed proofs fail immediately with `AssertionError: Expecting actual: Abstained[...] to be an instance of: ... Completed`.

2. **`lib/ct.sym` Signature Table in [`PlatformArchiveInspector.java`](../../elider-core/src/main/java/io/github/spockz/elider/trimmer/PlatformArchiveInspector.java) & [`JdkPlatformContext.java`](../../elider-core/src/main/java/io/github/spockz/elider/trimmer/JdkPlatformContext.java)**:
   `lib/ct.sym` is a private, internal OpenJDK archive used by `javac` for compile-time signature checks. Historical `ct.sym` release code indexing (`8`, `9`, `A`..`L` for JDK 21) breaks or produces unexpected class counts when run under newer JDK releases (Java 25/27) where directory layouts or platform symbols differ. Because compilation has already completed by `process-classes`, ProGuard Core trimming does not need private compiler symbol tables: it only requires standard runtime platform hierarchies (`java.lang.Object`, `String`, etc.), which are portably provided by standard Java SE `jrt:/` system modules.

3. **In-Process AST Source Scanning in Plugin**:
   [`JavaSourceReferenceScanner`](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/JavaSourceReferenceScanner.java), [`PostCompileSourceAttribution`](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/PostCompileSourceAttribution.java), and [`MavenCompilerSettings`](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenCompilerSettings.java) attempt to parse compile options and invoke `com.sun.source.util` Trees against compiler settings that vary across JDK versions.

---

## 2. Core Architectural Invariants

### 2.1 Zero JDK Coupling Invariant

> [!IMPORTANT]
> **Zero JDK Coupling Invariant**: No feature implemented in this project may ever depend on, require, or assume that users run our exact JDK version, patch release, or vendor build. All features, Mojo executions, and test suites must build, test, and function on standard, compliant JDK 21+ installations. Platform inspection must rely exclusively on standard Java Platform specifications and modular APIs (`java.lang.module`) or graceful feature detection, never proprietary internal digests or fixed vendor versions.

### 2.2 Primacy of Post-Compile Bytecode Link-Closure & Live Proof Data

Rather than attempting to reproduce compiler runs in-process from upstream Java source code:

1. **Operate at `process-classes`**: Elision runs after `maven-compiler-plugin` has already compiled project sources into `target/classes`.
2. **Bytecode Link-Closure**: [`ProductionBytecodeAnalysis`](../../elider-core/src/main/java/io/github/spockz/elider/scanner/ProductionBytecodeAnalysis.java) and ASM-based [`ClassReferenceScanner`](../../elider-core/src/main/java/io/github/spockz/elider/scanner/ClassReferenceScanner.java) inspect `.class` files directly, discovering all type, method, field, and constant pool references across application bytecode and dependencies.
3. **Standard Java SE Platform Introspection**: The active runtime's system module descriptors and class declarations are read through standard Java SE module APIs, eliminating internal dependencies on `lib/ct.sym`, JMOD layouts, and vendor-specific runtime images. Snapshot identity sorts module and class-resource names, hashes descriptor identity and each class resource's name, length, and bytes, and ASM-parses each class from the same transient bytes. The snapshot retains compact module identities and parsed templates, not raw runtime bytes or archive paths; analyses materialize isolated JDK class tables from those templates. This replaces the archive-path and `ct.sym`/JMOD design described historically in ADR-0004. The active platform is not a historical superset and does not validate target-release API availability; accurate target extraction and target/runtime report fields remain the separate P03/S1b requirement. Unresolved platform references remain explicit failures.
4. **Live Telemetry & Closed-World Evaluators**: Liveness and reachability are informed by scoped runtime telemetry: class-loading events recorded during workload execution (CDS `-XX:DumpLoadedClassList`, JFR `jdk.ClassLoad`), instruction execution coverage from tests (JaCoCo `jacoco.exec`), and closed-world framework models (Spring AOT generated bean definitions, GraalVM reachability metadata). Telemetry establishes non-observation during recorded workloads rather than an unconstrained claim of universal non-execution.

### 2.3 Target-Platform Semantics and Why `lib/ct.sym` is Obsolete

A critical architectural clarification concerns why `lib/ct.sym` was originally introduced and why it is wholly unnecessary for post-compile dependency elision:

#### What `lib/ct.sym` Is and Why It Was Introduced

`lib/ct.sym` is an internal, non-standard symbol archive used by OpenJDK's `javac` compiler when invoked with the `--release <N>` flag (JEP 247). It contains stripped stub class signatures (`.sig` files) for historical Java platform releases (e.g. 8, 9, 11, 17, 21), stripping out method bytecodes, constants, and private members. Its purpose is strictly compile-time gatekeeping: preventing a developer's source code from invoking platform APIs that did not exist in target release $N$.

Earlier elider iterations introduced `CtSymClassPoolReader`, `PlatformArchiveInspector`, and `JdkPlatformContext` to parse `lib/ct.sym` using character codes (`(char) ('A' + release - 10)`) to populate ProGuard Core's `libraryClassPool` with the stub classes for `--release N`.

#### Why `lib/ct.sym` is Unnecessary for Dependency Elision

1. **Compilation Has Already Completed**: Dependency elision executes at the Maven `process-classes` phase, strictly after `maven-compiler-plugin` has finished compiling application sources. The compiler has already enforced target-platform API compliance against `--release N`. Elider is not a compiler, does not parse Java source, and does not perform compile-time API gatekeeping.
2. **ProGuard Library Pool Purpose**: ProGuard Core's `libraryClassPool` is used during whole-program analysis strictly to resolve type hierarchies (identifying superclasses and interfaces) and verify member descriptors referenced by compiled bytecode in application classes and third-party dependencies.
3. **Active-Runtime Resolution Boundary**: Standard module APIs expose the platform classes of the JVM running Maven. They do not reconstruct the API surface of an earlier target, and this work package makes no universal historical-equivalence claim. The compiler remains responsible for target-release API checking; if later bytecode analysis references a platform type or member absent from the active runtime, the reference remains unresolved and analysis must fail explicitly.
4. **Internal Brittleness**: `lib/ct.sym` and JMOD file layouts are implementation details. Reading system modules through standard Java module APIs avoids parsing those private layouts and avoids assumptions about their presence or encoding.

#### Determination and Representation of Target-Platform Semantics

To ensure complete correctness when Maven runs on a newer JDK than the project's compilation target (e.g., Maven running on JDK 25 while compiling with `--release 17`):

* **Target Release Determination**: The target release is extracted from Maven compiler plugin configuration (`<release>`, `<target>`, or `maven.compiler.release` property) via `MavenCompilerSettings`. If not explicitly configured, it defaults to the runtime JVM's feature version (`Runtime.version().feature()`).
* **Preserved Target-Release Responsibilities**:
  * **Multi-Release JAR Selection (MR-JAR)**: Target release determines the effective bytecode variant selected from `META-INF/versions/{N}/` inside modular dependency archives. Class variants with $N \le \text{targetRelease}$ are selected, matching what the target JVM executes at runtime.
  * **Downstream Advisory `jdeps` Module Analysis**: When generating advisory module lists (`target/dependency-elider-jdk-modules.txt`) for custom `jlink` runtimes, the target release is forwarded to `jdeps --multi-release <targetRelease>`.
  * **Audit Telemetry & Provenance**: Both `targetRelease` (intended deployment baseline) and `runtimeRelease` (active Maven execution environment) are recorded in `elision-report.json` under execution environment metadata for full audit fidelity.
* **Platform Resolution Contract Change**: ProGuard Core's platform `libraryClassPool` is populated from the active JVM's standard system modules via `ModuleFinder.ofSystem()`, replacing the historical `ct.sym` stub parser. This supplies the active runtime's hierarchy and member declarations through standard APIs; it is not a historical API emulator. Compilation remains responsible for target-release compliance, and analysis must report unresolved references when the active platform lacks a referenced symbol.

### 2.4 Execution Environment Pragmatism: Single-Writer, Developer-Machine Assumptions & Anti-Overengineering

A recurring design defect in earlier iterations was defensive over-engineering against theoretical multi-tenant filesystem attacks, symlink race conditions, and concurrent file modifications.

To ensure clean, maintainable, and high-performance implementation:

1. **Follow KISS (Keep It Simple, Stupid)**:
   * Prefer the simplest possible designs, standard Java APIs, and straightforward code paths.
   * Avoid speculative abstractions, unnecessary configuration toggles, and defensive over-engineering.
2. **Developer-Machine & Single-Writer Assumption**:
   * The plugin runs during a Maven build on a developer workstation or a standard CI runner.
   * Execution is single-process and single-writer within the project `target/` directory and Maven reactor.
   * We explicitly assume there are **no concurrent processes** mutating files in `target/classes`, `target/elided-artifacts`, or `~/.m2/repository` during an active plugin execution phase.
3. **Symlinks Are Out of Scope for Standard Compiler Directories**:
   * Standard compiler and build directories (`target/classes`, `target/generated-sources`, `target/spring-aot`) and local repository cache files do not contain malicious symlinks or adversarial filesystem escapes.
   * Eliminate defensive over-engineering around symlink rejection (e.g. `LinkOption.NOFOLLOW_LINKS`, symlink traversal guards, and escape detection). Standard `java.nio.file` operations (`Files.walk`, `Files.copy`, `Files.newInputStream`, `Files.readAllBytes`) must be used directly.
4. **Elimination of Redundant Double-Hashing (TOCTOU Defense)**:
   * Remove paranoid check-then-act double-hashing patterns (e.g. hashing an archive before reading, reading it, and hashing it again to confirm it did not change during reading).
   * Read or hash once. Single-pass processing eliminates redundant disk I/O and simplifies scanner and trimmer logic.
5. **Pragmatic File Writing & No Complex Atomic Lock Managers**:
   * Standard sequential streaming or basic atomic replacement into `target/elided-artifacts/` or `target/` is sufficient.
   * Avoid complex file-locking protocols, multi-stage transaction managers, or atomic copy fallback gymnastics designed for untrusted multi-tenant shared filesystems.

---

## 3. Explicit Capability Loss Analysis

> [!WARNING]
> **Explicit Capability Losses: Automated In-Process Source Reproduction and Application Source-Only Constant Retention.**

### 3.1 Loss of Automated In-Process Source-to-Binary Reproduction for Third-Party CNAs

* **What was lost**: Under [ADR-0006](../adr/0006-dual-source-vulnerability-advisory-ingestion-from-cvelist-v5-and-osv-maven.md) and [ADR-0008](../adr/0008-precondition-gated-vex-attestations.md), `SourceReproductionEngine` and `SourceUnitCompiler` attempted to download dependency `-sources.jar` files and recompile them in-process to verify byte-identical `.class` generation for raw CVE v5 `programFiles`/`programRoutines` claims.
* **Why abandoned**: Byte-for-byte identical compilation of arbitrary third-party libraries requires knowing and running the exact compiler version, patch release, internal flags, annotation processors, and line-separator normalizations that the upstream maintainer used at release time. Pinning *our own* local GraalVM 21 compiler was unsound: it only matched libraries coincidentally built on that exact image, while breaking the project for all users not running that exact JDK.

### 3.2 Loss of Application Source-Only Compile Reference Retention (Inlined Constants)

* **What was lost**: Under [ADR-0010 §2](../adr/0010-process-classes-lifecycle-and-bytecode-completeness.md), `PostCompileSourceAttribution` ran `JavaSourceReferenceScanner` against application compile roots to detect dependencies referenced solely through compile-time inlined primitive/`String` constants or source-only type references that do not appear in emitted `target/classes` bytecode.
* **Why narrowed**: Running `com.sun.source.util` Trees in-process at `process-classes` duplicates compiler execution, parses compiler options that vary across environments, and introduces severe build latency. In alignment with having zero backwards-compatibility constraints, post-compile analysis is intentionally narrowed to **emitted production bytecode (`target/classes`), Spring AOT generated classes/metadata, and declared runtime evidence sources**.
* **How constant-only dependencies are preserved**: If an application references an external library solely for compile-time inlined constants (with zero remaining bytecode references in `target/classes`), the dependency can be retained by declaring it explicitly in `<retainedArtifacts><retainedArtifact>groupId:artifactId</retainedArtifact></retainedArtifacts>` (or via dependency scope).

### 3.3 What Replaces Them

By pivoting back to emitted bytecode, live proof data, and explicit advisory evidence:

* **Explicit Advisory Evidence (Primary Path)**: Vulnerabilities are mapped via typed OSV advisory indexes or explicit POM preconditions ([`PreconditionVex`](../../elider-core/src/main/java/io/github/spockz/elider/model/PreconditionVex.java)), where the affected binary class/method signatures are explicitly declared.
* **Deterministic Bytecode Attribution via Standard JLS Layout (Heuristic Path)**:
  * Under standard Java compiler conventions ([JLS §7.6](https://docs.oracle.com/javase/specs/jls/se21/html/jls-7.html#jls-7.6)), a public top-level class `p.X` in file `p/X.class` is required by standard compilers to originate from source file `p/X.java`.
  * When `elide.assumeConventionalJavaSourceLayout=true` (the default), `programFiles` claims matching `.../p/X.java` map directly to public class `p/X.class` and its inner class family (`p/X$*.class` via `InnerClasses`), even if the optional `SourceFile` attribute has been stripped.
  * When `elide.assumeConventionalJavaSourceLayout=false` (or for secondary non-public sibling classes where source-file identity cannot be proven from bytecode alone):
    * The engine **fails closed** and abstains from automated VEX generation.
    * The advisory is retained as a **conservative review lead** in the persisted audit report (`SourceReviewFinding`).
    * The user can verify the mapping on their side and configure an explicit, verified POM mapping (`<vulnerableClasses>` / `PreconditionVex`). Once declared, physical omission verification runs against the trimmed JAR and emits the VEX attestation.
* **Direct Binary Omission Verification**: Omission proof checks whether the mapped binary class family is physically removed from the trimmed JAR (and absent across all providers in the declared inventory under ADR-0008), rather than attempting to recompile source files to find out what bytecode they would generate.
* **Live Execution Telemetry**: CDS class-loading traces (`-XX:DumpLoadedClassList`) and JFR `jdk.ClassLoad` logs confirm classes were not observed to be loaded during the recorded workload, while JaCoCo (`jacoco.exec`) establishes instruction-level execution coverage. Telemetry provides workload-scoped evidence, avoiding claims of universal non-execution.

---

## 4. Spring AOT Evidence Integration & Condition Evaluation (Subsuming WP-SPRING-01)

### 4.1 Delegating Condition Evaluation to Spring AOT

Use Spring's own AOT processing to obtain its selected bean model. Do not implement `OnClassCondition`, `AutoConfigurationSorter`, or an enclosing-class condition evaluator inside Elider:

* [`SpringMetadataRoots`](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/SpringMetadataRoots.java) roots imports, metadata owners, class-valued conditions, and ordering targets conservatively. That can retain dormant capabilities, but some class-presence checks preserve observable behavior. It is not sound to remove every conditional target.
* The current production scanner can read generated classes copied into `target/classes`, but adjacent AOT resources are not automatically ingested by that scan. Directory-aware hint/resource handling is a concrete integration gap.
* Generated AOT registrations are stronger evidence than a startup trace, but do not express application demand. Ordinary lazy and prototype beans generally remain. AOT preparation can instantiate infrastructure and exclude processor beans from generated registrations.
* Registration omission does not remove original methods or their bytecode references. Class-level trimming may therefore retain an optional dependency even after its bean registration disappears.
* A runtime listener, environment processor, initializer, service provider, or resource lookup can remain necessary outside the generated bean model. An AOT evidence directory cannot authorize disabling all Spring metadata roots.

### 4.2 Input Boundaries, Generated Asset Ingestion, and Test-Slice Isolation

In Spring Boot 3.3.5, `ProcessAotMojo` generates assets into `target/spring-aot/main/{sources,classes,resources}` and copies compiled classes and resources into `target/classes`.

To ensure complete and sound ingestion:

1. **Scan All Generated Classes Without Naming Assumptions**: Scan all generated class files, generated proxies, and initializers in `target/spring-aot/main/classes` through `ProductionBytecodeAnalysis`. Do not depend on `*__BeanDefinitions` or `*__ApplicationContextInitializer` class naming patterns.
2. **Comprehensive Native Image Descriptor Ingestion**: Ingest all descriptors in `META-INF/native-image/**` (not just `reflect-config.json`, but `proxy-config.json`, `serialization-config.json`, `resource-config.json`, and `jni-config.json`) using the parsers established by RQ-0016. Preserve conditional-hint semantics: the current parser conservatively roots condition types rather than evaluating GraalVM reachability.
3. **Cross-Directory Resource Resolution**: Resource hints (`resource-config.json`) can retain resource-only dependencies (e.g. XML schemas, properties, static assets) or service providers located in another JAR. Extend resource resolution across production/generated directories and dependency archives.
4. **Strict Separation of Production vs. Test AOT**: Output from `process-test-aot` (`target/spring-aot/test/**`) contains slice-test configurations (`@WebMvcTest`, `@DataJpaTest`) and mocks. It **must never be merged into or masquerade as the production AOT model**.
5. **Build-Time vs. Runtime AOT Descriptors**: `META-INF/spring/aot.factories` registers build-time AOT code generators and hint registrars; preserve what regeneration requires without confusing those registrations with runtime application initializers loaded by Boot's `SpringApplication`.

### 4.3 Runtime and Evidence Contracts

| Supported use | Treatment of AOT evidence | Spring roots |
| :--- | :--- | :--- |
| **No AOT evidence** | Existing production/trace/metadata inputs. | Preserve conservative defaults. |
| **Ordinary JVM with AOT evidence** | Add generated references and supported hints. | Preserve conservative defaults; no negative inference from the AOT model. |
| **Validated AOT-enabled JVM or native deployment** | Generated assets are executable inputs tied to a specific environment/classpath. | Investigate replacement of proven-superseded discovery contributions only; retain other obligations. |

AOT generation must run against the application's actual chosen inputs, including intentional feature-selection changes. Regenerate and revalidate after a policy change; do not discard contradictory evidence merely to make a ban pass.

### 4.4 The 4-Category Retention State Reporting Model (Provenance Taxonomy)

To prevent misrepresenting conservative guesses as proven runtime requirements or vice versa, the persisted report (`elision-report.json`) must categorize retention into four distinct states:

1. `conservative_metadata`: Retained solely because of discovery metadata (`SpringMetadataRoots`: `AutoConfiguration.imports`, `.ConditionalOn*` lookup properties, ordering targets).
2. `generated_aot_registration`: Retained by explicit Spring AOT generated bean definitions, generated proxies, or runtime hints.
3. `not_observed_in_workload`: Unobserved during recorded workloads (CDS class list `-XX:DumpLoadedClassList`, JFR `jdk.ClassLoad`, JaCoCo execution probes).
4. `bytecode_link_closure`: Retained due to hard bytecode references (e.g., conditional factory methods inside the original `@Configuration` class or transitive bytecode call sites).

> [!IMPORTANT]
> **Complete Root Provenance Invariant**: Labeling an artifact as *"Solely retained by Spring metadata"* requires complete root provenance and transitive closure. If removing a Spring metadata entry leaves behind an AOT-generated reference, resource hint, or hard bytecode link, the report must show the exact blocking constraint rather than suggesting an impossible ban.

### 4.5 The Two-Step User Workflow (Advisory vs. Policy Enforcement)

The intended workflow has two distinct steps:

* **Step 1: Advisory Analysis & Candidate Discovery**: Spring AOT selects registrations from configuration and classpath inputs; ordinary lazy and unrequested beans remain. Workload evidence and retention explanations identify candidates for explicit feature removal.
* **Step 2: Explicit User-Directed Exclusion & Regeneration**:
  1. For an apparently unnecessary capability, recommend an explicit auto-configuration exclusion in application properties (`spring.autoconfigure.exclude`).
  2. Regenerate Spring AOT and rerun workloads.
  3. Only then evaluate removing its starter/dependencies via `<banishedDependencies>` (WP-POLICY-01) and rerun verification, since classpath removal can activate fallback configurations.
  4. Never automatically modify the POM or populate `banishedDependencies` / `retainedArtifacts` without explicit user configuration.

### 4.6 Deterministic Tail Execution at `process-classes` via Priority

`process-aot` at `prepare-package` is too late for Elider's pre-test production analysis. For the same-phase `process-classes` arrangement:

* In Maven's `DefaultLifecycleMappingDelegate`, executions within a phase are sorted using a `TreeMap<Integer, List<MojoExecution>>` keyed by `PluginExecution.getPriority()` ascending (user POM executions default to `0`), and then by plugin declaration order.
* [`EliderLifecycleParticipant.afterProjectsRead`](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/EliderLifecycleParticipant.java) can deterministically guarantee that `dependency-elider:elide` runs **last** in `process-classes` (regardless of POM declaration order) by setting `execution.setPriority(Integer.MAX_VALUE)` and moving `dependency-elider-maven-plugin` and `elide` to the tail of `project.getBuild().getPlugins()` and `plugin.getExecutions()`.
* [`MavenPreconditionGenerationGuard`](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenPreconditionGenerationGuard.java) can then safely accept verified pre-`elide` `process-classes` writers (whose priority is `< elide.getPriority()`) whose outputs are captured and digested before `elide` executes.

### 4.7 Autoconfigure Descriptor Coherence Invariants

When trimming a Spring JAR (such as `spring-boot-autoconfigure.jar`), filter `AutoConfiguration.imports` and autoconfigure metadata only after final retained classes are known:

* **Input-Archive Ownership**: Remove an entry only when its owner belonged to the input archive and was actually removed. Never prune third-party or external configuration classes.
* **Ordering Target Preservation**: Preserve `wasProcessed` lookup integrity for active `.AutoConfigureBefore`/`.AutoConfigureAfter` targets.
* **Properties Formatting Integrity**: Preserve Java `Properties` escaping and multi-line continuation backslashes (`\`). Do not implement a simplistic line filter; parse with Java properties semantics.
* **Factory Key Discrimination**: Treat `spring.factories` registrations by key so non-auto-configuration listeners, initializers, and environment processors are preserved.
* **Archive Writer Parity**: Apply equivalent ownership and descriptor filtering rules in both [`SingleReleaseArchiveWriter`](../../elider-core/src/main/java/io/github/spockz/elider/trimmer/SingleReleaseArchiveWriter.java) and [`MultiReleaseArchiveWriter`](../../elider-core/src/main/java/io/github/spockz/elider/trimmer/MultiReleaseArchiveWriter.java).
* **Hard Bytecode Limitation**: Document that removing metadata does not remove hard bytecode references from retained classes (e.g. `InternalResourceViewResolver` or `RequestMappingHandlerAdapter` in `spring-webmvc`).

### 4.8 Scoped Discovery-Root Replacement Experiment for Validated AOT Deployments

For a validated AOT-enabled deployment (where `spring.aot.enabled=true` is verified), investigate scoped replacement of proven-superseded discovery roots:

1. **Scoped Replacement, Never Wholesale Disabling**: Do not disable `SpringMetadataRoots` wholesale or drop an entire artifact's dynamic roots merely because it contains auto-configuration metadata. Replace only discovery contributions proven superseded by the generated bean model.
2. **Preserve Runtime Infrastructure**: Retain runtime `spring.factories` registrations (listeners, initializers, environment processors); keep ordinary application references, SPI, native-image hints, and resources independent.
3. **Build-Time vs. Runtime Separation**: `aot.factories` describes AOT processing services and must remain available where regeneration needs them; keep this distinct from runtime initializer discovery.
4. **Validation against Clean Classpath**: Generate against a clean candidate classpath, re-ingest all outputs, and verify no required root was lost. Launch the packaged application with `spring.aot.enabled=true` and test representative runtime paths.
5. **Fixture Coverage**: The first successful fixture should remove one structurally separate inactive configuration while retaining an active lazy bean, reflective DTO, and resource-only dependency, while explaining why an inactive method's hard bytecode reference remains.
6. **Revisiting `example-spring-boot-app`**: Revisit the Spring Boot example application without forcing arbitrary artifact/CVE reduction counts. Remaining hard references, modular-JAR pass-through, or broad hints must be reported accurately.

---

## 5. JPMS Module Awareness & Downstream Packaging (RQ-0018 §4, §5)

### 5.1 JPMS Root vs. Versioned `module-info.class` Trimming and Classpath-Only Derivative

Currently, [`TrimPassThroughPlanner`](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/TrimPassThroughPlanner.java) and [`ArchiveSnapshot`](../../elider-core/src/main/java/io/github/spockz/elider/trimmer/ArchiveSnapshot.java) force any dependency with a root `module-info.class` to pass through completely untrimmed (or fail under `-Delide.failOnUnsupportedModuleInfo=true`). This prevents intra-JAR trimming for key modern libraries (e.g. `tomcat-embed-core`, `logback-core`, `jackson-annotations`). In contrast, [`MultiReleaseArchiveWriter`](../../elider-core/src/main/java/io/github/spockz/elider/trimmer/MultiReleaseArchiveWriter.java) omits versioned module descriptors under `vertical-shade`.

Under this work package, we resolve this asymmetry by introducing:

#### Classpath-Only Derivative Output Contract

For standard classpath / Spring Boot deployments running in the unnamed module, strip root `module-info.class` from the trimmed runtime JAR, unblocking intra-JAR class trimming while enforcing strict boundaries:

* **Opt-In Runtime Derivative**: The output artifact is strictly a runtime derivative for classpath execution in the unnamed module.
* **Original Archive Immutability**: Never modify original JARs in the local repository cache (`~/.m2/repository`). Write trimmed artifacts exclusively to `target/elided-artifacts/`.
* **No General-Purpose Modular Publication**: Never publish or deploy the stripped derivative as a general-purpose modular replacement.
* **Preserve Classpath Services and Resources**: Classpath SPI (`META-INF/services/`) and non-class resources must remain fully intact.
* **Cache & Output Identity**: Explicitly record `mrjarStrategy=classpath-only` in the trim cache fingerprint and CycloneDX 1.6 pedigree properties.

### 5.2 Bounded JPMS Signals vs. Closed-World Proofs

* **SPI Discovery via `uses` and `provides`**: Leverage `module-info.class` declared `provides ... with ...` and `uses ...` together with bytecode `ServiceLoader.load(...)` call sites to distinguish active SPI chains from dormant `META-INF/services/` entries (e.g. Jackson's `ObjectCodec` SPI in CVE-2026-68494).
  * *Boundary*: `ServiceLoader` supports classloader and module-layer discovery; unnamed callers, dynamically added layers, and direct provider references must be accounted for before claiming `vulnerable_code_not_present`.
* **Qualified `exports <pkg> to <target>`**: Restricts access for named-module consumers and explains dependency relationships. It does **not** prove that a package is dead when the target is absent, and access restrictions do not apply to the same JAR loaded on the ordinary classpath.
* **Optional Dependency Classification via `requires static`**: Use `requires static` declarations as positive evidence of optional compile-time dependencies during link-closure. Do **not** remove `requires` clauses merely because bytecode does not name a package, and do not treat `requires static` as proof that runtime execution is safe without the target class.

### 5.3 Downstream Packaging Boundaries & Telemetry Ingestion

Clarifying the architectural boundaries between build-time elision and post-packaging JVM acceleration:

* **Build-Time vs. Packaging Boundary**: During `process-classes`, Elider *ingests* loaded class traces (such as `-XX:DumpLoadedClassList` via [`CdsClassListReader`](../../elider-core/src/main/java/io/github/spockz/elider/trace/CdsClassListReader.java)) recorded from prior runs to protect dynamically loaded classes.
* **Extended Class-List Syntax**: `CdsClassListReader` must parse extended HotSpot class-list entries (IDs, classloader identifiers, and source paths), rejecting truncated or malformed records.
* **`spring.context.exit=onRefresh` Bounds**: In Framework 6.1.14 `DefaultLifecycleProcessor`, `spring.context.exit=onRefresh` calls `Runtime.halt(0)` before lifecycle beans start. It is a bounded training run; it does not cover lazy beans, runners, or request handling. The trace recorder must handle timeouts, non-zero exits, and agent shutdown flushing.
* **Post-Packaging CDS Archive Generation**: Building a binary HotSpot CDS archive (`-XX:ArchiveClassesAtExit` or `-Xshare:dump`) requires executing the final packaged artifact (e.g. Boot executable JAR or shaded JAR). Because this artifact is produced at `package` (after `process-classes`), binary archive creation is a downstream operational/containerization step. Trimming dependencies at `process-classes` guarantees that downstream CDS training runs against a lean classpath free of dead classes.

### 5.4 Advisory `jdeps` Module Analysis for `jlink` (`target/dependency-elider-jdk-modules.txt`)

To assist users crafting custom minimal JRE images via `jlink`:

* **Target-Release Alignment**: Forward the configured `--release` / `<target>` release to `jdeps --multi-release <targetRelease>`.
* **Prohibit `--ignore-missing-deps`**: Never use `--ignore-missing-deps`. Masking missing dynamic dependencies leads to broken runtime images (`NoClassDefFoundError` at runtime).
* **Supplement Static Analysis**: Augment static `jdeps` findings with reflection hints, SPI services, cryptographic providers (`java.security`), JDBC/JNDI drivers, and agent requirements.
* **Artifact Path**: Emit the resulting module list to `target/dependency-elider-jdk-modules.txt`.

---

## 6. Obsolete Components Schedule

The following components are marked obsolete and will be deprecated/removed:

| Component | Path | Disposition |
| :--- | :--- | :--- |
| `SourceJdkIdentity` | `elider-core/.../correspondence/SourceJdkIdentity.java` | Remove pinned digest allowlist and vendor checks; replace with generic JDK 21+ detection. |
| `SourceReproductionEngine` | `elider-core/.../correspondence/SourceReproductionEngine.java` | Remove in-process source compilation pipeline. |
| `SourceUnitCompiler` | `elider-core/.../correspondence/SourceUnitCompiler.java` | Remove compiler service invocation. |
| `SourceUnitIdentityValidator` | `elider-core/.../correspondence/SourceUnitIdentityValidator.java` | Remove byte-identical compilation verification. |
| `SourceReproductionInvocationCache` | `elider-core/.../correspondence/SourceReproductionInvocationCache.java` | Remove compiler invocation caching. |
| `JavacPluginServiceIsolation` | `elider-core/.../correspondence/JavacPluginServiceIsolation.java` | Remove in-process javac service loader isolation. |
| `JavaSourceReferenceScanner` | `dependency-elider-maven-plugin/.../plugin/JavaSourceReferenceScanner.java` | Remove in-process AST source scanner; replace with ASM bytecode link-closure at `process-classes`. |
| `PostCompileSourceAttribution` | `dependency-elider-maven-plugin/.../plugin/PostCompileSourceAttribution.java` | Remove application source AST attribution; narrow post-compile analysis to emitted bytecode and declared evidence. |
| `MavenSourceDeclarationScanner` | `dependency-elider-maven-plugin/.../plugin/MavenSourceDeclarationScanner.java` | Remove JavacTask Trees declaration scanning. |
| `MavenCompilerSettings` | `dependency-elider-maven-plugin/.../plugin/MavenCompilerSettings.java` | **Retain target-release (`--release`/`target`) extraction**; obsolete in-process compiler-option verification. |
| `CtSymClassPoolReader` | `elider-core/.../trimmer/CtSymClassPoolReader.java` | Remove private `ct.sym` ZIP parser; replace ProGuard library pool loader with standard `jrt:/` system modules. |
| `PlatformArchiveInspector` (`ct.sym`) | `elider-core/.../trimmer/PlatformArchiveInspector.java` | Remove `ct.sym` character-code indexing; use standard Java SE `jrt:/` for platform class inspection. |

---

## 7. Implementation Methodology: Test-Driven Development (TDD)

Every slice in this work package must be executed following a strict test-driven development (TDD) cycle:

1. **Write Tests First**: Before modifying or creating production implementation code, construct focused unit/integration tests establishing the expected behavior.
2. **Verify Failure & Acceptance Criteria Coverage**: Run the test suite to verify that the new tests fail for the intended reasons (e.g. absent capability, compilation failure, or assertion failure) and confirm that all specified criteria for the slice are completely asserted.
3. **Implement Minimal Code (Follow KISS)**: Write the minimal, straightforward production code required to satisfy the tests. Prefer simple designs and standard APIs over complex abstractions, speculative configurability, or defensive over-engineering. Adhere strictly to the single-writer, developer-machine, and zero-coupling invariants.
4. **Verify & Refactor**: Re-run the tests across the supported toolchain matrix to ensure 0 failures, 0 regressions, and clean assertion coverage diagnostics.

---

## 8. Staged Implementation Slices

### Slice 1: Multi-JDK Test Suite Decoupling & Transitional Abstention (Immediate)

* Wrap remaining `correspondence.*` tests (`SourceReproductionEngineTest`, `SourceReproductionInvocationCacheTest`, `SourceUnitIdentityValidatorTest`, `LiveStructuredSourceBoundaryTest`, `JavacPluginServiceIsolationTest`) with:

  ```java
  org.junit.jupiter.api.Assumptions.assumeTrue(
      SourceJdkIdentity.isSupported(),
      "Skipping source reproduction tests on non-pinned JDK"
  );
  ```

* Update `SourceJdkIdentityTest` so it does not call `.orElseThrow()` on an empty `Resolution.identity()`.
* Ensure `mvn test -pl elider-core` passes with 0 failures on JDK 21, JDK 25, and JDK 27.

### Slice 2: Standard `jrt:/` Platform Context & Root Descriptor Trimming

* **Preserve Target Release Selection**: Keep the configured target release separate from the active runtime release for multi-release selection and reporting; it does not select a historical JDK class table.
* **Eliminate `lib/ct.sym` and JMOD parsing**: Replace `CtSymClassPoolReader` and `PlatformArchiveInspector`'s private archive parsing with standard Java module APIs. The resulting JDK class table supplies active-runtime hierarchy and member declarations. It does not emulate a historical target platform; unresolved active-runtime references remain failures, while compile-time target API checking belongs to the compiler.
* **Classpath-Only Trimming Derivative**: Implement RQ-0018 §5.2 in `TrimPassThroughPlanner`: allow intra-JAR trimming of modular dependencies (`tomcat-embed-core`, `logback-core`, `jackson-annotations`) by stripping root `module-info.class` for classpath deployments while preserving services and resources.

### Slice 3: Additive Spring AOT Evidence & Provenance Ingestion

* Scan all generated class files (`target/spring-aot/main/classes`), proxies, and initializers through `ProductionBytecodeAnalysis` without relying on `*__BeanDefinitions` naming conventions.
* Ingest all generated reflection, proxy, serialization, resource, and JNI descriptors from `META-INF/native-image/**` via `NativeImageScanContext`, preserving conservative condition-type rooting.
* Extend resource resolution across production/generated directories and dependency archives to protect resource-only dependencies.
* Deduplicate copied generated assets by validated identity while preserving declaring input, target/provider, root category, and runtime/generation role.
* Strictly isolate production evidence from test AOT (`target/spring-aot/test/**`), ensuring slice-test configurations (`@WebMvcTest`, `@DataJpaTest`) never enter the production model.
* Keep any newly introduced persisted evidence format at schema version 1 while unreleased.
* Rebind elision deterministically to the tail of `process-classes` via `execution.setPriority(Integer.MAX_VALUE)`.

### Slice 4: Spring Feature-Selection Explanations & Descriptor Coherence

* Categorize retention reasons in `elision-report.json` using the 4-category provenance model: `conservative_metadata`, `generated_aot_registration`, `not_observed_in_workload`, and `bytecode_link_closure`.
* Enforce the full-provenance invariant: do not report an artifact as "solely retained by Spring metadata" if generated code, resource hints, or hard bytecode links still require it.
* Offer the two-step feature-selection workflow: recommend `spring.autoconfigure.exclude`, regenerate AOT, rerun workloads, and only then evaluate `<banishedDependencies>`.
* Filter `AutoConfiguration.imports`, autoconfigure metadata properties, and `spring.factories` only after retained classes are finalized, preserving input-archive ownership, continuations, properties formatting, and external registrations across both `SingleReleaseArchiveWriter` and `MultiReleaseArchiveWriter`.
* Execute the scoped discovery-root replacement experiment for validated AOT deployments, demonstrating removal of a structurally separate inactive configuration while retaining active lazy beans, reflective DTOs, and resource-only dependencies, and explaining hard bytecode references.
* Revisit `example-spring-boot-app`, reporting remaining hard references, modular-JAR pass-through, or broad hints accurately without forcing arbitrary CVE counts.

### Slice 5: Advisory `jdeps` Module Analysis & Downstream Guidance

* Implement advisory `target/dependency-elider-jdk-modules.txt` emission via `jdeps --multi-release <targetRelease>` against final application and retained dependency JARs (RQ-0018 §5.3) without `--ignore-missing-deps`.
* Augment static module candidate sets with reflection hints, SPI services, cryptographic providers (`java.security`), JDBC/JNDI drivers, and agent requirements.
* Document downstream packaging best practices in user documentation, illustrating how downstream builds benefit from training CDS archives (`-XX:ArchiveClassesAtExit`) against trimmed artifacts.

### Slice 6: Multi-JDK CI Matrix Verification & Pipeline Decommissioning

* Completely remove `io.github.spockz.elider.correspondence` and `MavenSourceDeclarationScanner`.
* Remove transitional test abstentions (`assumeTrue`) and verify clean execution of `make check`, `make test-core`, and `make test-plugin` across:
  * Pinned GraalVM JDK 21 (`.scratch/toolchains/graalvm-jdk-21.0.12+7.1`)
  * GraalVM JDK 25 (`.scratch/toolchains/graalvm-jdk-25.0.5+1.1`)
  * System OpenJDK 27 (`/usr/lib/jvm/java-27-openjdk`)
* Confirm zero test failures and zero regressions across all example applications.

---

## 9. Acceptance Criteria and Verification

* [ ] All tests across `elider-core` and `dependency-elider-maven-plugin` pass cleanly on compliant JDK 21, 25, and 27 installations without requiring specific vendor builds or patch releases.
* [ ] The abandoned `correspondence` package and in-process source AST scanners are completely removed, and all retained tests pass without transitional test abstentions.
* [ ] Target platform release semantics (`--release`) are preserved when running Maven on a newer JDK than compilation target, without relying on pinned JDK digests.
* [ ] Post-compile analysis is narrowed to emitted bytecode and declared evidence sources; applications referencing external libraries solely through compile-time inlined constants retain those libraries via `<retainedArtifacts>` without requiring in-process source scanning.
* [ ] Additive Spring AOT ingestion retains generated/proxy/reflection references and resource-only dependencies without weakening conservative defaults for ordinary launches; test-slice outputs (`target/spring-aot/test/**`) are strictly isolated from production models.
* [ ] Deterministic tail execution at `process-classes` via `execution.setPriority(Integer.MAX_VALUE)` guarantees `dependency-elider:elide` runs after all other `process-classes` writers.
* [ ] Classpath-only derivative mode unblocks intra-JAR trimming for dependencies with root `module-info.class` (`tomcat-embed-core`, `logback-core`, `jackson-annotations`) in classpath deployments, preserving upstream repository immutability, SPI services, and non-class resources.
* [ ] The 4-category retention taxonomy (`conservative_metadata`, `generated_aot_registration`, `not_observed_in_workload`, `bytecode_link_closure`) is reported in `elision-report.json`, ensuring artifacts are not labeled as solely retained by metadata when hard bytecode or generated references exist.
* [ ] Positive/missing-class conditions are evaluated by Spring AOT across deliberate feature changes without introducing custom in-process condition evaluators.
* [ ] Autoconfigure descriptor filtering preserves external registrations, Java properties formatting, and non-autoconfiguration `spring.factories` entries across both `SingleReleaseArchiveWriter` and `MultiReleaseArchiveWriter`.
* [ ] Scoped discovery-root replacement experiment in a validated AOT deployment removes one structurally separate inactive configuration while retaining active lazy beans, reflective DTOs, and resource-only dependencies, and explains surviving hard bytecode references.
* [ ] Advisory `target/dependency-elider-jdk-modules.txt` provides actionable, valid platform module lists for `jlink` custom runtime image creation without `--ignore-missing-deps`.
* [ ] File operations, archive reading, and writing use standard Java NIO without paranoid symlink rejection (`NOFOLLOW_LINKS`), redundant double-hashing (TOCTOU checks), or multi-tenant concurrency guards under the single-writer developer-machine model.
* [ ] When fixtures or documented commands change, run `make update-transcripts` and verify with `make check-transcripts` without hand-editing transcript blocks.
