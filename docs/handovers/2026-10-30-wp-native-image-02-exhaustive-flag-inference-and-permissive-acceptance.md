<!-- WHY: Defines the work package specification for exhaustive GraalVM native-image flag inference, full descriptor metadata ingestion, and permissive acceptance of non-class compiler parameters. -->
# Work Package Handover: WP-NATIVE-02 Exhaustive Native-Image Flag Inference & Permissive Argument Acceptance

* **Status**: Ready for Implementation
* **Owning Thread / Session**: Primary Coordinating Session
* **Date**: 2026-10-30
* **Target Branch / Base**: `main`
* **Related Research Questions**:
  * [RQ-0016: GraalVM Native-Image Metadata Ingestion and Permissive Argument Taxonomy](../research/RQ-0016-graalvm-native-image-metadata-ingestion-and-permissive-argument-taxonomy.md)
* **Related Architecture Decisions**:
  * [ADR-0009: Permissive GraalVM Native-Image Argument Ingestion and Name-Only Allowed Lists](../adr/0009-permissive-graalvm-native-image-metadata-ingestion.md)

---

## 1. Executive Summary & Motivation

### 1.1 Context & Problem

In `WP-NATIVE-01`, `maven-dependency-elider` introduced quote stripping, recognized common flags (`-H:±AddAllCharsets`, `--report-unsupported-elements-at-runtime`, `--enable-http[s]`, `--initialize-at-run-time=`), and provided a name-only allowlist (`elide.allowedNativeImageArgs`).

However, real-world libraries across the Java ecosystem (e.g., Netty, OkHttp, Jackson, BouncyCastle, Spring Boot, Quarkus) employ a wide array of GraalVM compiler switches, VM tuning flags, and reachability descriptors. Under the previous strict fail-closed contract:

1. Any unmodeled compiler flag (such as `-H:EnableURLProtocols`, `-H:+AllowVMInspection`, `--no-fallback`, `-O3`, or architecture options) stops analysis or forces the containing JAR into un-trimmed pass-through.
2. Several class-bearing options (such as `-H:Class=`, dynamic proxy configs, serialization configs, and JNI configs) were not parsed as dynamic roots, creating reachability blind spots.

### 1.2 Objectives

1. **Exhaustive Class-Bearing Flag Inference**: Identify every native-image CLI option that declares live classes, packages, or configuration files, and ingest them as dynamic roots.
2. **Complete Descriptor Ingestion**: Ingest all native-image JSON descriptor schemas (`reflect-config.json`, `jni-config.json`, `proxy-config.json`, `serialization-config.json`, `predefined-classes-config.json`, and unified `reachability-metadata.json`).
3. **Permissive Acceptance of Non-Class Compiler Parameters**: Accept any other native-image argument (compiler optimization, VM capability, diagnostic, protocol, GC flag) without failing closed or disabling trimming.
4. **Preserve Syntactic & Structural Validation**: Continue to fail explicitly on malformed syntax (unclosed quotes, empty tokens, modeled options missing values, invalid binary class names).

---

## 2. Invariants & Guardrails

1. **Zero Dynamic Root Omission**: Every class or package referenced by class-bearing arguments, feature declarations, or reachability JSON descriptors must be extracted and retained as a trimming root.
2. **Non-Class Compiler Parameter Tolerance**: Compiler flags that do not declare code references must never abort the build or disqualify a dependency from trimming.
3. **Strict Syntax & Malformed Input Handling**: Syntactic defects (missing values on root flags, unmatched quotes, corrupt JSON) must fail closed with clear diagnostics.
4. **Code Quality & Zero Suppression Policy**: No `@SuppressWarnings("PMD...")` or Checkstyle suppressions may be introduced. Methods must remain modular, cohesive, and within complexity bounds.
5. **Language & Tooling Boundary (AGENTS.md)**: Strictly Java, Bash, or Go. No Python or Node.js.

---

## 3. Technical Specification

### 3.1 Taxonomy of Native-Image Arguments

```text
┌────────────────────────────────────────────────────────────────────────┐
│                      Native-Image Argument Taxonomy                    │
├────────────────────────────────┬───────────────────────────────────────┤
│ Tier 1: Class-Bearing Roots    │ Live classes/packages/features        │
│ Tier 2: Configuration Pointers │ JSON descriptors declaring classes    │
│ Tier 3: Resource Patterns      │ Regex patterns & non-class assets     │
│ Tier 4: Compiler / JVM Flags   │ Benign build/runtime options (no code)│
└────────────────────────────────┴───────────────────────────────────────┘
```

#### Tier 1: Direct Class & Package Roots (Inferred as Live)

* `--features=<classes>`: Comma-separated FQCNs of `Feature` implementations.
* `--initialize-at-build-time=<classes|packages>`: Classes/packages initialized at build time.
* `--initialize-at-run-time=<classes|packages>`: Classes/packages initialized at runtime.
* `-H:Class=<class>`, `--main-class=<class>`: Executable entry-point class.
* `--trace-class-initialization=<classes>`, `-H:TraceClassInitialization=<classes>`: Class names tracked for initialization.
* `--trace-object-instantiation=<classes>`, `-H:TraceObjectInstantiation=<classes>`: Class names tracked for heap allocation.
* `-H:IncludeResourceBundles=<bundles>`: Resource bundle base names; if they match valid binary class names, retain as roots.

#### Tier 2: Configuration Resource Pointers (JSON Descriptors Inferred as Live)

* `-H:ReflectionConfigurationResources=<paths>` / `-H:ReflectionConfigurationFiles=<paths>`: `reflect-config.json`.
* `-H:JNIConfigurationResources=<paths>` / `-H:JNIConfigurationFiles=<paths>`: `jni-config.json` (reflection schema).
* `-H:DynamicProxyConfigurationResources=<paths>` / `-H:DynamicProxyConfigurationFiles=<paths>`: `proxy-config.json` (`interfaces` arrays).
* `-H:SerializationConfigurationResources=<paths>` / `-H:SerializationConfigurationFiles=<paths>`: `serialization-config.json` (`types` arrays).
* `-H:PredefinedClassesConfigurationResources=<paths>` / `-H:PredefinedClassesConfigurationFiles=<paths>`: `predefined-classes-config.json` (`classes[].nameInfo`).

#### Tier 3: Resource Pattern Flags

* `-H:ResourceConfigurationResources=<paths>`: Ingested via `NativeImageResourceConfig`.
* `-H:IncludeResources=<patterns>`, `-H:ExcludeResources=<patterns>`: Non-class resource regex patterns.

#### Tier 4: Compiler, VM, Protocol, and Optimization Flags (Accepted Permissively)

All parameters not in Tiers 1–3 are accepted safely without declaring class roots (returning `false`):

* Protocol & Security: `--enable-http`, `--enable-https`, `--enable-all-security-services`, `--enable-url-protocols=...`, `-H:EnableURLProtocols=...`.
* Charsets & Locales: `-H:±AddAllCharsets`, `-H:±AddAllLocales`, `-H:±AddAllFileSystemProviders`.
* Diagnostics & Error Handling: `--report-unsupported-elements-at-runtime`, `-H:±ReportUnsupportedElementsAtRuntime`, `--report-exception-stack-traces`, `--allow-incomplete-classpath`, `-H:±AllowIncompleteClasspath`, `--verbose`, `--diagnostics-mode`, `-H:±PrintAnalysisCallTree`.
* Linkage & Runtime: `--no-fallback`, `--force-fallback`, `--auto-fallback`, `--install-exit-handlers`, `--static`, `--shared`, `--libc=...`.
* Optimizations: `-O0` to `-O3`, `-Os`, `-Ob`, `-march=...`, `--pgo`, `--pgo-instrument`, `--gc=...`, `-H:±SpawnIsolates`, `-H:MaxHeapSize=...`, `-H:Name=...`.
* Monitoring: `--enable-monitoring=...`, `--enable-sbom`, `--enable-preview`.
* Pass-Through Properties: `-D<prop>=<val>`, `-J<flag>`, `-R:<option>`, `-H:±<booleanOption>`.

---

### 3.2 Parser Ingestion Matrix

| Argument / Descriptor | Target Type | Action |
| :--- | :--- | :--- |
| `--features=<classes>` | Live Class | Extract comma-separated FQCNs; seed each as dynamic root. |
| `--initialize-at-build-time=<targets>` | Live Class/Package | Extract classes and package prefixes; seed matched classes. |
| `--initialize-at-run-time=<targets>` | Live Class/Package | Extract classes and package prefixes; seed matched classes. |
| `-H:Class=<class>`, `--main-class=<class>` | Live Class | Extract entry-point class; seed as dynamic root. |
| `--trace-class-initialization=<classes>` | Live Class | Extract comma-separated class names; seed as dynamic roots. |
| `--trace-object-instantiation=<classes>` | Live Class | Extract comma-separated class names; seed as dynamic roots. |
| `-H:IncludeResourceBundles=<bundles>` | Potential Class | If token is valid binary class name, seed as root. |
| `-H:ReflectionConfigurationResources=` | JSON Resource | Parse classes in `name`/`type` and `typeReachable`/`typeReached`. |
| `-H:JNIConfigurationResources=` | JSON Resource | Parse classes in `name`/`type` and `typeReachable`/`typeReached`. |
| `-H:DynamicProxyConfigurationResources=` | JSON Resource | Parse interface arrays (`interfaces: [...]`) and conditions. |
| `-H:SerializationConfigurationResources=` | JSON Resource | Parse `types: [{ "name": "..." }]` and conditions. |
| `-H:PredefinedClassesConfigurationResources=` | JSON Resource | Parse `classes: [{ "nameInfo": "..." }]`. |
| Standalone `META-INF/native-image/**` files | JSON Files | Ingest `reflect-config.json`, `jni-config.json`, `proxy-config.json`, `serialization-config.json`, `predefined-classes-config.json`, and `reachability-metadata.json`. |
| Any other valid parameter | Compiler/VM Flag | Accept without declaring roots (return `false`). |
| Modeled root option missing value | Malformed Token | Fail closed with descriptive error. |
| Unmatched quote / empty token | Malformed Syntax | Fail closed with descriptive error. |

---

## 4. Track Decomposition & Committable Slices

### Slice 1: Descriptor Ingestion Expansion in `NativeImageClassConfig`

* Update `isNativeImageClassConfig` to recognize `jni-config.json`, `serialization-config.json`, and `predefined-classes-config.json`.
* Implement parsing for `serialization-config.json` (`types` array with `name` and condition).
* Implement parsing for `predefined-classes-config.json` (`classes` array with `nameInfo`).
* Ensure `jni-config.json` routes through reflection element parsing.

### Slice 2: Argument Parsing Expansion in `NativeImageDynamicRoots`

* Add support for class options: `-H:Class=`, `--main-class=`, `--trace-class-initialization=`, `--trace-object-instantiation=`, `-H:TraceClassInitialization=`, `-H:TraceObjectInstantiation=`, `-H:IncludeResourceBundles=`.
* Add support for resource pointer options: `-H:JNIConfigurationResources=`, `-H:DynamicProxyConfigurationResources=`, `-H:SerializationConfigurationResources=`, `-H:PredefinedClassesConfigurationResources=`.
* Update default argument dispatch: return `false` for unmodeled parameters instead of throwing `UnknownNativeImageArgument`.
* Retain explicit validation on missing values for root options (`-H:Class`, `--features`, etc.).

### Slice 3: Verification & Test Updates

* Unit tests in `DependencyDynamicRootsTest`:
  * Verify each newly modeled class argument extracts expected roots.
  * Verify each JSON descriptor format (`jni-config`, `serialization-config`, `predefined-classes-config`) extracts roots.
  * Verify that unmodeled compiler flags (e.g. `-H:EnableURLProtocols=http`, `--no-fallback`, `-O3`) are accepted cleanly without errors or pass-through tagging.
  * Verify malformed root arguments continue to fail closed.
* Integration tests in `ElideMojoTest` and `AnalyzeMojoTest`:
  * Ensure dependencies containing diverse compiler flags trim effectively rather than falling back to un-trimmed pass-through.

### Slice 4: Documentation & ADR Alignment

* Update [ADR-0009](../adr/0009-permissive-graalvm-native-image-metadata-ingestion.md) and [RQ-0016](../research/RQ-0016-graalvm-native-image-metadata-ingestion-and-permissive-argument-taxonomy.md) to record the transition from fail-closed unmodeled arguments to permissive compiler flag acceptance and exhaustive root extraction.
* Refresh user documentation (`usage.md`, `README.md`) if configuration options or default behaviors are adjusted.

---

## 5. Verification & Acceptance Gates

Execute the full repository verification suite:

```bash
JAVA_HOME=$(pwd)/.scratch/toolchains/graalvm-jdk-21.0.12+7.1 make fmt lint-java test-plugin test-core
```

Invariants:

* 0 Spotless violations.
* 0 Checkstyle violations.
* 0 PMD violations (no suppressions).
* 0 SpotBugs warnings.
* All unit and integration tests passing.
