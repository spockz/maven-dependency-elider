<!-- WHY: Defines the work package specification, track decomposition, and committable slices for permissive native-image metadata ingestion, allowed argument configuration, and bounded pass-through fallback (RQ-0016, ADR-0009). -->
# Work Package Handover: WP-NATIVE-01 Permissive GraalVM Native-Image Argument Ingestion & Configurable Allowed Properties

* **Status**: Ready for Implementation
* **Owning Thread / Session**: Primary Coordinating Session
* **Date**: 2026-10-30
* **Target Branch / Base**: `main`
* **Related Research Questions**:
  * [RQ-0016: GraalVM Native-Image Metadata Ingestion and Permissive Argument Taxonomy](../research/RQ-0016-graalvm-native-image-metadata-ingestion-and-permissive-argument-taxonomy.md)
* **Related Architecture Decisions**:
  * [ADR-0009: Permissive GraalVM Native-Image Argument Ingestion and Name-Only Allowed Lists](../adr/0009-permissive-graalvm-native-image-metadata-ingestion.md)
  * [ADR-0003: ProGuard Core-Driven Intra-JAR Trimming and CycloneDX Pedigree](../adr/0003-proguard-core-intra-jar-trimming-and-cyclonedx-pedigree.md)

---

## 1. Executive Summary & Non-Negotiable Invariants

### 1.1 Objective

Prevent build failures when analyzing popular third-party dependencies that bundle GraalVM reachability metadata (`META-INF/native-image/**/native-image.properties`, such as `com.squareup.okhttp3:okhttp-jvm:5.3.2`).

Specifically:

1. **Name-Only Allowed Argument Configuration (`elide.allowedNativeImageArgs`)**: Allow users to specify recognized or benign native-image argument names via POM configuration `<allowedNativeImageArgs>` or CLI `-Delide.allowedNativeImageArgs=<names>`. Argument values are ignored so users only configure the flag name (e.g. `-H:+AddAllCharsets` or `-H:EnableURLProtocols`).
2. **Default Fail-Closed with Actionable Diagnostics**: Keep `elide.failOnUnsupportedNativeImageArgs=true` as the default. When an unrecognized argument is encountered, fail with an actionable error message directing the developer to inspect the property in the dependency archive and providing the exact snippet to add its name to `allowedNativeImageArgs`.
3. **Configurable Permissive Fallback (`elide.failOnUnsupportedNativeImageArgs=false`)**: When configured to `false`, an unrecognized argument does not abort the build; instead, the single offending dependency JAR passes through conservatively (preserved byte-identically without trimming), while all other dependencies remain eligible for elision and trimming.
4. **Tokenization and Quote Stripping**: Cleanly handle single quotes, double quotes, and multi-line properties without rejecting valid property values.
5. **Built-in Recognition of Standard Compiler Flags**: Out-of-the-box support for common non-class GraalVM compiler flags (e.g., `-H:+AddAllCharsets`, `-H:-AddAllCharsets`, `--report-unsupported-elements-at-runtime`).

### 1.2 Non-Negotiable Invariants

1. **Zero Dynamic Root Omission**: If an argument defines dynamic class or feature roots (e.g. `--features=`, `--initialize-at-build-time=`, `-H:ReflectionConfigurationResources=`), it must be parsed and seeded as a retention root.
2. **Fail-Closed by Default**: Without explicit user configuration in `allowedNativeImageArgs` or `failOnUnsupportedNativeImageArgs=false`, unmodeled arguments must fail closed with actionable diagnostics.
3. **Artifact-Level Containment on Fallback**: When `failOnUnsupportedNativeImageArgs=false`, the failure boundary is contained strictly to the offending dependency archive (it is pinned as a pass-through). It must never silently prune classes from an archive with unknown reflection instructions.
4. **Tooling & Language Policy (AGENTS.md)**: Strictly Java, shell, or Go. No Python or Node.js.
5. **Clean Verification Gates**: All slices must pass `make check` (Checkstyle, PMD 7.28.0, SpotBugs, Markdownlint) and all tests cleanly.

---

## 2. Architecture & Design Specification

### 2.1 Argument Name Extraction & Matching Contract

When parsing `Args = ...` from `native-image.properties`:

* The string is split into individual argument tokens, respecting or stripping enclosing quotes (`"..."`, `'...'`).
* For each argument token:
  1. Determine its **argument name**:
     * If the token contains `=`, the argument name is the substring before `=`:
       $$\text{argument} = \text{"-H:EnableURLProtocols=http,https"} \implies \text{name} = \text{"-H:EnableURLProtocols"}$$
     * If the token contains no `=`, the argument name is the entire token:
       $$\text{argument} = \text{"-H:+AddAllCharsets"} \implies \text{name} = \text{"-H:+AddAllCharsets"}$$
  2. If `name` matches any entry in `allowedNativeImageArgs`, the argument is considered allowed (and if it is non-class, it is safely skipped).
  3. Built-in known arguments are evaluated:
     * Dynamic class/feature roots: `--features=`, `--initialize-at-build-time=`, `-H:ReflectionConfigurationResources=`.
     * Dynamic resources: `-H:ResourceConfigurationResources=`.
     * Known benign compiler flags: `--enable-http`, `--enable-https`, `-H:+AddAllCharsets`, `-H:-AddAllCharsets`, `--report-unsupported-elements-at-runtime`.
  4. If the argument is neither built-in nor in `allowedNativeImageArgs`:
     * If `failOnUnsupportedNativeImageArgs == true`: throw an informative `IOException` detailing the exact argument name, archive entry path, and configuration snippet.
     * If `failOnUnsupportedNativeImageArgs == false`: mark the scanning result as requiring pass-through retention for the containing archive and log an informative warning.

### 2.2 Mojo Configuration Properties

In `ElideMojo.java` and `AnalyzeMojo.java`:

```java
@Parameter(property = "elide.allowedNativeImageArgs")
private List<String> allowedNativeImageArgs;

@Parameter(property = "elide.failOnUnsupportedNativeImageArgs", defaultValue = DEFAULT_TRUE)
private boolean failOnUnsupportedNativeImageArgs;
```

---

## 3. Track Decomposition & Directed Acyclic Graph (DAG)

```text
┌────────────────────────────────────────────────────────┐
│ Track 1: Architecture Decision Record (ADR-0009)       │
└──────────────────────────┬─────────────────────────────┘
                           │
             ┌─────────────┴─────────────┐
             ▼                           ▼
┌──────────────────────────┐┌──────────────────────────┐
│ Track 2: Core Tokenizer  ││ Track 3: Mojo Parameters │
│ & Argument Parser        ││ & Options Wiring         │
└────────────┬─────────────┘└────────────┬─────────────┘
             │                           │
             └─────────────┬─────────────┘
                           ▼
┌────────────────────────────────────────────────────────┐
│ Track 4: Actionable Error Diagnostics & Pass-Through   │
└──────────────────────────┬─────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│ Track 5: Fixture Validation & Regression Tests         │
└────────────────────────────────────────────────────────┘
```

---

## 4. Track Specifications & Committable Slices

### Track 1: Architecture Decision Record (ADR-0009) & Documentation

* **Slice 1.1: Author ADR-0009**
  * Create `docs/adr/0009-permissive-graalvm-native-image-metadata-ingestion.md`.
  * Detail the argument taxonomy, name-only matching contract, fail-closed diagnostic design, and pass-through fallback.
  * Update `docs/adr/README.md` to index ADR-0009.
* **Slice 1.2: Update RQ-0016**
  * Ensure `docs/research/RQ-0016-graalvm-native-image-metadata-ingestion-and-permissive-argument-taxonomy.md` references ADR-0009.

---

### Track 2: Core Tokenizer & Argument Parser (`NativeImageDynamicRoots.java`)

* **Slice 2.1: Quoting & Argument Name Extraction**
  * Update `NativeImageDynamicRoots.readNativeImageProperties`:
    * Implement robust whitespace and quote-stripping tokenization (stripping surrounding single or double quotes from individual arguments).
  * Implement `extractArgumentName(String argument)`:
    * Returns the argument name before `=` (or full token if no `=`).
* **Slice 2.2: Permissive Matching and Built-in Compiler Flags**
  * Add built-in recognition for:
    * `-H:+AddAllCharsets`
    * `-H:-AddAllCharsets`
    * `--report-unsupported-elements-at-runtime`
  * Accept `Set<String> allowedNativeImageArgs` parameter in `readNativeImageProperties`.
  * If `allowedNativeImageArgs.contains(extractArgumentName(argument))`, mark as allowed and proceed.

---

### Track 3: Mojo Parameters & Options Wiring (`dependency-elider-maven-plugin`)

* **Slice 3.1: Add Parameters to `ElideMojo` and `AnalyzeMojo`**
  * Add `@Parameter(property = "elide.allowedNativeImageArgs") private List<String> allowedNativeImageArgs;`
  * Add `@Parameter(property = "elide.failOnUnsupportedNativeImageArgs", defaultValue = "true") private boolean failOnUnsupportedNativeImageArgs;`
* **Slice 3.2: Wire Options into `MavenElisionService.AnalysisOptions`**
  * Update `AnalysisOptions` to include `List<String> allowedNativeImageArgs` and `boolean failOnUnsupportedNativeImageArgs`.
  * Pass options through to `DependencyDynamicRoots.scan(...)`.

---

### Track 4: Actionable Error Diagnostics & Pass-Through Fallback

* **Slice 4.1: Formatted Diagnostic Error Message**
  * In `NativeImageDynamicRoots.readNativeImageArgument`:
    * When an unsupported argument is rejected, construct an explicit, multi-line error message:

      ```text
      Unsupported native-image argument '<name>' in <entryPath> (full argument: '<argument>').
      Inspect the property in the dependency archive. If this argument does not declare dynamic class roots,
      you can allow it by adding its name to <allowedNativeImageArgs> in pom.xml:
        <configuration>
          <allowedNativeImageArgs>
            <allowedNativeImageArg><name></allowedNativeImageArg>
          </allowedNativeImageArgs>
        </configuration>
      Or via CLI: -Delide.allowedNativeImageArgs=<name>
      ```

* **Slice 4.2: Bounded Pass-Through Fallback**
  * When `failOnUnsupportedNativeImageArgs == false`:
    * Record that the dependency archive contains unmodeled native-image metadata.
    * In `MavenDependencyTrimmer`, treat that archive as an explicit pass-through (ineligible for intra-JAR trimming, original bytes preserved).
    * Emit an `[INFO]` log describing the pass-through retention.

---

### Track 5: Fixtures, Unit Tests & Regression Verification

* **Slice 5.1: Unit Tests in `NativeImageDynamicRootsTest` / `DependencyDynamicRootsTest`**
  * Test OkHttp `native-image.properties` content:
    `Args = -H:+AddAllCharsets --enable-http --enable-https --features=okhttp3.internal.graal.OkHttpFeature --report-unsupported-elements-at-runtime`
    Assert `OkHttpFeature` is retained as a dynamic root and no exception is thrown.
  * Test quote stripping: `Args = "-H:ReflectionConfigurationResources=..." '--enable-http'`
  * Test name-only matching: `allowedNativeImageArgs = Set.of("-H:CustomFlag")` allows `-H:CustomFlag=someValue`.
  * Test fail-closed diagnostic message: Verify exception message contains the exact name, entry path, and configuration snippet.
  * Test pass-through fallback: When `failOnUnsupportedNativeImageArgs=false`, verify JAR is marked pass-through.
* **Slice 5.2: Verification & Quality Gate**
  * Run `mvn test -pl dependency-elider-maven-plugin`.
  * Run `make check`.

---

## 5. Verification Matrix & Acceptance Criteria

```bash
# 1. Plugin tests
mvn test -pl dependency-elider-maven-plugin

# 2. Full quality and lint gate
make check

# 3. Example lifecycle verification
make test-examples
```

### Acceptance Criteria

1. **OkHttp Support**: `NativeImageDynamicRoots` parses `okhttp-jvm:5.3.2`'s `native-image.properties` without error, extracting `okhttp3.internal.graal.OkHttpFeature`.
2. **Name-Only Semantics**: Specifying `-H:CustomFlag` in `allowedNativeImageArgs` permits `-H:CustomFlag=foo,bar` without requiring the value.
3. **Actionable Diagnostics**: When an unmodeled argument fails closed, the error message clearly points to the offending flag name and shows the exact POM snippet to allow it.
4. **Pass-Through Fallback**: When `failOnUnsupportedNativeImageArgs=false`, unmodeled native-image arguments preserve the containing JAR byte-identically without aborting the Maven build.
5. **Zero Regressions**: Passes `make check` and `make test-examples` cleanly.
