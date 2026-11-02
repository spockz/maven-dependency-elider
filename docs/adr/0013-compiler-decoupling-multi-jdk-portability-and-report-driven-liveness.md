<!-- WHY: Records the architectural decision to decouple the build and runtime from pinned JDK/compiler digests, guarantee multi-JDK portability across JDK 21+, and pivot from in-process source compilation to report-driven live proofs and bytecode link-closure. -->
# ADR-0013: Compiler Decoupling, Multi-JDK Portability, and Report-Driven Liveness Attestation

* **Status**: Accepted
* **Date**: 2026-11-02
* **Role**: architecture
* **Scope**: build-lifecycle
* **Area**: plugin-core
* **Languages**: java
* **Related**:
  * [ADR-0001: Runtime Telemetry-Driven Dependency Elision at Maven INITIALIZE Phase](0001-runtime-telemetry-driven-dependency-elision-at-maven-initialize-phase.md)
  * [ADR-0004: Assume Resolved Inputs Stay Stable During a Maven Invocation](0004-assume-resolved-inputs-stable-during-build.md)
  * [ADR-0006: Dual-Source Vulnerability Advisory Ingestion from CVEList v5 and OSV Maven](0006-dual-source-vulnerability-advisory-ingestion-from-cvelist-v5-and-osv-maven.md)
  * [ADR-0008: Evidence-Bounded Precondition-Gated VEX Attestations](0008-precondition-gated-vex-attestations.md)
  * [ADR-0010: Post-Compile Lifecycle and Production Bytecode Completeness](0010-process-classes-lifecycle-and-bytecode-completeness.md)
  * [RQ-0018: JPMS Mechanics, Spring AOT & CDS Integration, and `jlink` JRE Reduction](../research/RQ-0018-jpms-module-awareness-and-assisted-modularization.md)

---

## 1. Context

In earlier iterations (specifically [ADR-0006](0006-dual-source-vulnerability-advisory-ingestion-from-cvelist-v5-and-osv-maven.md) and [ADR-0008](0008-precondition-gated-vex-attestations.md)), the project introduced an in-process Java source reproduction engine (`SourceReproductionEngine`, `SourceUnitCompiler`) designed to re-compile upstream dependency source code (`-sources.jar`) to prove that unmapped CNA vulnerability claims (`programFiles` and `programRoutines`) compiled into the exact binary `.class` bytes found in original Maven Central JARs.

To prevent compilation drift, the engine bound itself via `SourceJdkIdentity` to an exact compiler identity:

* Feature release `21`.
* Runtime version `"21.0.12+7-LTS-jvmci-23.1-b96"`.
* Exact SHA-256 digests for `JavacTool.class`, `jdk.compiler.jmod`, `lib/modules`, and `lib/ct.sym`.

Additionally, platform introspection relied on a historical `ct.sym` release character mapping (`8`, `9`, `A`..`L`) in `PlatformArchiveInspector`.

### Problem Statement

This coupling created critical operational and architectural defects:

1. **Broken Multi-JDK Compatibility**: Running the test suite or plugin on any compliant modern JDK (standard OpenJDK 21, Eclipse Temurin 21, GraalVM 25, or OpenJDK 27) failed builds with 22+ core test failures and 163+ plugin test failures because `SourceJdkIdentity` rejected the running runtime.
2. **False Equivalence for Upstream Compilation**: Verifying byte-for-byte identical compilation of arbitrary third-party libraries requires reproducing the exact compiler build, flags, annotation processors, and environment used by the original library maintainers when they published the artifact years ago. Pinning *our own* local GraalVM 21 compiler was unsound: it only matched libraries that coincidentally used that exact compiler, while locking users into our specific vendor toolchain.
3. **Violated Project Invariant**: Hardcoding vendor-specific checksums directly violates the repository requirement that users must never be forced to run our exact JDK build.

---

## 2. Decision

We establish **Mandatory Multi-JDK Portability (JDK 21+)**, **Compiler Decoupling**, and a **Complete Pivot to Report-Driven Live Proof Data and Bytecode Link-Closure**:

### 2.1 Multi-JDK Portability Invariant

* **No feature dependency on exact JDK versions**: No feature implemented in this project may ever depend on, require, or assume that users run our exact JDK version, patch release, or vendor build. All features and analysis capabilities must function on standard, compliant JDK 21+ installations.
* No code may embed hardcoded compiler SHA-256 digests, runtime release-string equality checks, or vendor-specific JVM identity checks that cause execution to fail on other standard JDKs.
* Platform module introspection must use standard Java Platform specifications and APIs (`java.lang.module.ModuleFinder.ofSystem()`), replacing legacy `ct.sym` release code parsing for modern JDKs.
* The JDK class table describes the active Maven runtime's system modules. The configured target release remains separate for multi-release dependency selection and reporting; active-runtime inspection does not emulate a historical Java platform or prove that a referenced API existed in the target release. Unresolved JDK references remain explicit analysis failures.
* A platform snapshot sorts system modules and class-resource names, hashes module descriptor identity and each class resource's name, length, and bytes, and ASM-parses each class from the same transient byte array. It retains compact module identities and parsed class templates, not raw runtime bytes or archive paths; each analysis receives an isolated JDK class table. This replaces ADR-0004's former archive-path and `ct.sym`/JMOD design. Accurate configured-target extraction and its report fields remain a separate P03/S1b requirement.

### 2.2 Abandonment of In-Process Source Reproduction for Unmapped CNAs

* The in-process `javac` source reproduction pipeline (`SourceReproductionEngine`, `SourceUnitCompiler`, `SourceReproductionInvocationCache`, `SourceUnitIdentityValidator`, `JavacPluginServiceIsolation`) is **removed**.
* We abandon the attempt to automatically validate raw CNA source filenames against binary byte hashes in-process via compiler re-execution.
* **Deterministic JLS Layout Mapping vs. Review Leads**:
  * Under standard compiler conventions ([JLS §7.6](https://docs.oracle.com/javase/specs/jls/se21/html/jls-7.html#jls-7.6)), a public top-level class `p.X` in file `p/X.class` is required to originate from source file `p/X.java`. When `elide.assumeConventionalJavaSourceLayout=true`, `programFiles` claims for `.../p/X.java` map directly to `p/X.class` (and its `p/X$*.class` inner family), even if debug `SourceFile` attributes are stripped.
  * When `elide.assumeConventionalJavaSourceLayout=false` (or for secondary non-public sibling classes), the mapping is not assumed: the claim remains a **conservative review lead** in the persisted report, and automated VEX is suppressed. The user can verify the claim and configure an explicit, verified POM mapping (`<vulnerableClasses>` / `PreconditionVex`) to authorize VEX emission.

### 2.3 Primacy of Report-Driven Live Proof Data & Bytecode Link-Closure

* In alignment with [ADR-0010](0010-process-classes-lifecycle-and-bytecode-completeness.md) and [RQ-0018](../research/RQ-0018-jpms-module-awareness-and-assisted-modularization.md), elision analysis executes at **`process-classes`** against compiled `target/classes` bytecode.
* **Bytecode Link-Closure**: [`ProductionBytecodeAnalysis`](../../elider-core/src/main/java/io/github/spockz/elider/scanner/ProductionBytecodeAnalysis.java) and [`ClassReferenceScanner`](../../elider-core/src/main/java/io/github/spockz/elider/scanner/ClassReferenceScanner.java) inspect `.class` files directly using ASM, ensuring that all reachable classes, interfaces, methods, fields, and constant pool references across application code and dependency JARs are preserved.
* **Typed Vulnerability Evidence**: Vulnerability mappings must be established via typed evidence:
  1. Typed OSV index mappings and explicit POM preconditions ([`PreconditionVex`](../../elider-core/src/main/java/io/github/spockz/elider/model/PreconditionVex.java)).
  2. Physical omission verification: checking whether the affected binary class/symbol is present or omitted in the trimmed JAR.
* **Live Proof Telemetry**: Non-execution is attested through external JVM reports:
  * HotSpot Class-Data Sharing (CDS) class lists (`-XX:DumpLoadedClassList`).
  * JDK Flight Recorder (JFR) `jdk.ClassLoad` events.
  * JaCoCo execution data (`jacoco.exec`).
  * Closed-world framework evaluators (Spring AOT generated registrations and GraalVM reachability metadata).

---

## 3. Invariants

1. **Zero Feature Dependence on Specific JDK Versions**: No feature implemented in this project shall require or assume that the user or build runs our exact JDK version or vendor build. Every feature, Mojo goal, and test suite must execute cleanly on any compliant JDK 21+ installation.
2. **Graceful Test Abstention**: Any legacy or transitional tests requiring specific compiler internals must use JUnit 5 `Assumptions.assumeTrue(...)` to abstain gracefully on non-matching environments rather than failing the build.
3. **No Unsound Source Compilation**: The plugin shall not attempt to download external source archives and invoke `javax.tools.JavaCompiler` in-process to verify third-party binary provenance.
4. **Bytecode Primacy**: Bytecode link-closure on `target/classes` and dependency JARs is the definitive source of truth for static compile/runtime references.

---

## 4. Consequences

### Positive

* **Broad Environment Compatibility**: Contributors and users can build and test the project on standard Linux, macOS, and Windows distributions using standard OpenJDK 21, 25, or 27 without encountering spurious failures.
* **Clean Toolchain Decoupling**: Eliminates maintenance of fragile SHA-256 allowlists for compiler internal modules across JDK patches and updates.
* **Architectural Coherence**: Returns the project to its core strength: static bytecode analysis enriched with runtime telemetry (CDS/JFR/JaCoCo) and framework AOT evaluators.

### Negative / Lost Capabilities

* **Loss of Automated Live Source-to-Binary Reproduction**: The tool no longer attempts to automatically validate unmapped CVE v5 `programFiles` / `programRoutines` source claims against binary bytecode without a typed advisory or explicit POM mapping. Such claims remain descriptive review leads in the audit report.
