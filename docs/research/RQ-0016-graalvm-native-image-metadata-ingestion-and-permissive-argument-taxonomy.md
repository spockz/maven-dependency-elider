<!-- WHY: Investigates GraalVM native-image.properties argument taxonomy, quoting syntax, and bounded fallback policies to prevent fail-closed build aborts on standard libraries like OkHttp. -->
# RQ-0016: GraalVM Native-Image Metadata Ingestion and Permissive Argument Taxonomy

## Status

Open

## Date

2026-10-30

## Category

Dynamic Reachability & Native-Image Integration

## 1. Context & Current Boundary

To safeguard applications compiled into GraalVM native images (or using libraries designed for ahead-of-time compilation), `maven-dependency-elider` inspects dependency JARs for embedded GraalVM reachability metadata under `META-INF/native-image/**`. Dynamic class roots and reflection targets identified in this metadata are seeded as retention roots so intra-JAR trimming does not purge classes needed by runtime reflection or native image features.

Before WP-NATIVE-01, [`NativeImageDynamicRoots.java`](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/NativeImageDynamicRoots.java) parsed `native-image.properties` under a strict fail-closed contract that rejected any quote in Args:

```java
// NativeImageDynamicRoots.java
if (args.isEmpty() || args.contains("\"") || args.contains("'")) {
  throw new IOException("Unsupported native-image Args in " + propertiesEntry.getName());
}
```

And in `readNativeImageArgument`:

* It recognizes only **six explicit arguments**:
  * `-H:ReflectionConfigurationResources=`
  * `-H:ResourceConfigurationResources=`
  * `--enable-http`
  * `--enable-https`
  * `--initialize-at-build-time=`
  * `--features=`
* **Any other argument** triggers:

  ```java
  throw new IOException("Unsupported native-image Args in " + propertiesEntry.getName());
  ```

### The Concrete Real-World Failure

In production workloads importing widely-used libraries such as `com.squareup.okhttp3:okhttp-jvm:5.3.2`, the embedded `META-INF/native-image/okhttp/okhttp/native-image.properties` contains:

```properties
Args = -H:+AddAllCharsets --enable-http --enable-https --features=okhttp3.internal.graal.OkHttpFeature --report-unsupported-elements-at-runtime
```

1. **`-H:+AddAllCharsets`**: Instructs the GraalVM native image compiler to package all JDK `java.nio.charset` charsets. It does not introduce any application- or dependency-level dynamic class roots.
2. **`--report-unsupported-elements-at-runtime`**: Instructs the native-image static analysis engine not to abort build-time compilation when encountering unsupported bytecodes in uncalled methods, reporting errors only if executed at runtime. It does not introduce any dynamic class roots.
3. **`--features=okhttp3.internal.graal.OkHttpFeature`**: Declares a native feature class (already supported by the elider).

Because `-H:+AddAllCharsets` and `--report-unsupported-elements-at-runtime` are not on the 6-option whitelist, the plugin immediately aborts dependency analysis:

```text
[ERROR] Failed to execute goal io.github.spockz:dependency-elider-maven-plugin:0.1.0-SNAPSHOT:analyze (default-cli) on project my-service:
Dependency analysis failed closed: Unsupported native-image Args in META-INF/native-image/okhttp/okhttp/native-image.properties
```

The entire Maven build fails closed on a standard HTTP client library.

---

## 2. Core Architectural Questions & Argument Taxonomy

### 2.1 Taxonomy of Native-Image Arguments

Native-image options specified in `Args` fall into three distinct functional categories:

| Category | Description | Examples | Impact on Bytecode Link Closure | Required Elider Action |
| :--- | :--- | :--- | :--- | :--- |
| **Tier 1: Dynamic Class & Feature Roots** | Options that explicitly name Java classes or features to be loaded dynamically. | `--features=<FQCN>`, `--initialize-at-build-time=<FQCNs>`, `-H:ReflectionConfigurationResources=<path>`, `-H:DynamicProxyConfigurationResources=<path>`, `-H:SerializationConfigurationResources=<path>`, `-H:JNIConfigurationResources=<path>` | High. Missing roots cause runtime `ClassNotFoundException` or reflection failures. | **Must parse and seed class names** as retention roots. |
| **Tier 2: Resource Configuration** | Options pointing to non-class resources (bundles, patterns). | `-H:ResourceConfigurationResources=<path>`, `-H:IncludeResources=<pattern>` | None on Java bytecode classes; affects resource retention in JARs. | Parse and preserve referenced resources; do not abort class analysis. |
| **Tier 3: Compiler Flags & JVM Capabilities** | Options tuning the ahead-of-time compiler, code generation, diagnostics, or standard platform modules. | `-H:±AddAllCharsets`, `--report-unsupported-elements-at-runtime`, `--enable-http`, `--enable-https`, `--no-fallback`, `-H:EnableURLProtocols=<protocols>`, `-H:±AllowVMInspection`, `-H:±PrintAnalysisCallTree` | **Zero**. These flags configure the GraalVM compiler environment, not application class references. | **Safely ignore**. They contain no class roots to retain. |

### 2.2 Quoting and Whitespace Escaping

`native-image.properties` follows standard Java properties format, but argument values frequently enclose parameters or regex patterns in quotes (e.g. `-H:IncludeResources=".*\\.properties"` or `--initialize-at-build-time='com.foo.Bar'`). The pre-WP check:

```java
if (args.contains("\"") || args.contains("'")) { ... throw ... }
```

indiscriminately rejects legitimate configuration files. A standards-compliant tokenizer should strip outer quotes rather than failing closed.

### 2.3 Failure Boundary and User-Configurable Policy

To balance safety and ergonomics, the parser adopts a two-pronged configuration model:

#### 1. Configurable Allowed Argument Names (`elide.allowedNativeImageArgs`)

* Users can specify known-safe argument names via `<allowedNativeImageArgs>` in the POM or `-Delide.allowedNativeImageArgs=<names>`.
* **Name-Only Semantics**: The configuration takes **only the argument name**, not the value (e.g. `-H:+AddAllCharsets`, `--report-unsupported-elements-at-runtime`, or `-H:EnableURLProtocols` rather than `-H:EnableURLProtocols=http,https`). If an argument contains an `=` separator, only the prefix before `=` is matched.
* When an argument's name matches an entry in `allowedNativeImageArgs`, the parser ignores it and proceeds without error.

#### 2. Default Fail-Closed with Actionable Diagnostics

* Setting: `@Parameter(property = "elide.failOnUnsupportedNativeImageArgs", defaultValue = "true")`.
* **Default Behavior (`true`, Fail Closed)**:
  * When an unmodeled argument is encountered and not listed in `allowedNativeImageArgs`, the plugin aborts the build with an actionable error message:

    ```text
    [ERROR] Unsupported native-image argument '-H:+AddAllCharsets' in META-INF/native-image/okhttp/okhttp/native-image.properties.
    [ERROR] Inspect the property in the dependency archive. If this argument does not declare dynamic class roots,
    [ERROR] you can allow it by adding its name to <allowedNativeImageArgs> in pom.xml:
    [ERROR]   <configuration>
    [ERROR]     <allowedNativeImageArgs>
    [ERROR]       <allowedNativeImageArg>-H:+AddAllCharsets</allowedNativeImageArg>
    [ERROR]     </allowedNativeImageArgs>
    [ERROR]   </configuration>
    [ERROR] Or via CLI: -Delide.allowedNativeImageArgs=-H:+AddAllCharsets
    ```

* **Permissive Fallback Mode (`false`, Artifact Pass-Through)**:
  * If `elide.failOnUnsupportedNativeImageArgs=false`, the build does not abort.
  * Instead, it logs the warning and marks the single offending dependency JAR as a pass-through (ineligible for trimming, preserved byte-identically), while all other dependencies remain eligible for elision and intra-JAR trimming.

---

## 3. Implementation Findings (WP-NATIVE-01)

The accepted policy is implemented in [ADR-0009](../adr/0009-permissive-graalvm-native-image-metadata-ingestion.md). `Properties.load(InputStream)` remains the properties reader; Args tokens are scanned by whitespace outside quote delimiters, with syntactic quotes removed and backslashes preserved. Unmatched quotes and empty tokens fail explicitly. Feature, initialization, and reflection/resource configuration options are parsed before name-only allowlist matching, so allowlisting a modeled option cannot suppress its roots or validation. The built-in non-root set remains the three ADR-approved flags plus `--enable-http` and `--enable-https`.

`allowedNativeImageArgs` is validated as nonblank names without `=` and canonicalized in sorted, deduplicated order. With strict mode enabled, diagnostics include the argument name, full token, archive entry, POM snippet, and CLI form. With strict mode disabled, the scanner marks only the containing artifact; it is retained before whole-artifact pruning, skipped in both trim engines, and analyzed as unchanged link input. Other artifacts remain independently eligible for trimming and elision. Policy inputs participate in graph and trim-cache identity.

Evidence is in [`NativeImageDynamicRoots`](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/NativeImageDynamicRoots.java), [`DependencyDynamicRootsTest`](../../dependency-elider-maven-plugin/src/test/java/io/github/spockz/elider/plugin/DependencyDynamicRootsTest.java), [`ElideMojoTest`](../../dependency-elider-maven-plugin/src/test/java/io/github/spockz/elider/plugin/ElideMojoTest.java), and [`MavenElisionServiceEffectiveAnalysisTest`](../../dependency-elider-maven-plugin/src/test/java/io/github/spockz/elider/plugin/MavenElisionServiceEffectiveAnalysisTest.java). Tests cover the exact OkHttp Args sequence and feature root, Java-properties continuation, quoted resource/value parsing, a modeled reflection root despite allowlisting its option name, strict CLI diagnostics, cross-archive closure, byte-identical fallback, sibling class trimming, unused-artifact elision, and a fallback-to-allowlist cache-policy switch.

## 4. Remaining Research Questions

1. **Comprehensive Whitelist of Non-Class Compiler Flags**:
   * What is the exhaustive set of standard GraalVM compiler flags used across popular Java libraries (Netty, OkHttp, Jackson, BouncyCastle, Quarkus, Micronaut, Spring)?
   * Can flags prefixed with `--enable-`, `--report-`, or standard `-H:±` boolean toggles be automatically categorized as Tier 3 compiler flags?
2. **Additional Dynamic Root Resources**:
   * Which additional JSON resource formats should be parsed? Specifically:
     * `-H:DynamicProxyConfigurationResources=` (`proxy-config.json`)
     * `-H:SerializationConfigurationResources=` (`serialization-config.json`)
     * `-H:JNIConfigurationResources=` (`jni-config.json`)
3. **Bounded Containment Contract**:
   * How should the configuration and build logs report an archive that drops from candidate trimming to pass-through due to unknown native-image options?
   * Should this be gated by an opt-in/opt-out flag (e.g., `elide.failOnUnknownNativeImageArgs=false`)?

---

## 5. Evidence Gates

* **OkHttp Fixture Verification**:
  * Build a test case using `com.squareup.okhttp3:okhttp-jvm:5.3.2`.
  * Verify that `NativeImageDynamicRoots` successfully parses `OkHttpFeature` without throwing on `-H:+AddAllCharsets` or `--report-unsupported-elements-at-runtime`.
* **Quoting & Spacing Tests**:
  * Verify parser handles single quotes, double quotes, and multi-line properties cleanly.
* **Static Analysis**:
  * Comply with Checkstyle, PMD 7.28.0, and SpotBugs.
