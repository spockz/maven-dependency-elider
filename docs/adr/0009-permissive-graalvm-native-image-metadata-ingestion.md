<!-- WHY: Defines the argument ingestion taxonomy, name-only allowed list semantics, and fail-closed diagnostic design for GraalVM native-image.properties. -->
# ADR-0009: Permissive GraalVM Native-Image Argument Ingestion and Name-Only Allowed Lists

* **Status**: Accepted
* **Date**: 2026-10-30

<!-- semedit-adr-metadata:v1 keys=summary,description,role,scope,area,languages; do not change key names or order. -->
| Key | Value |
| :--- | :--- |
| summary | Ingest GraalVM native-image properties with name-only allowed argument matching, built-in non-class flag recognition, and actionable fail-closed diagnostics. |
| description | Recognize benign GraalVM compiler flags without aborting build analysis; provide `elide.allowedNativeImageArgs` matching argument names before `=` to let developers allow unmodeled non-class flags, while defaulting to fail-closed with actionable diagnostics. |
| role | architecture |
| scope | dynamic-reachability |
| area | plugin-core |
| languages | java |

## Context

To protect applications compiled into GraalVM native images from runtime reflection failures, `maven-dependency-elider` scans dependency archives for `META-INF/native-image/**/native-image.properties`. Dynamic class roots and reflection targets declared in these descriptors are extracted and retained during intra-JAR trimming.

Previously, `NativeImageDynamicRoots.java` enforced an extreme, brittle fail-closed policy:

1. It rejected any property string containing single or double quotes.
2. It whitelisted only six explicit arguments (`--features=`, `--initialize-at-build-time=`, `-H:ReflectionConfigurationResources=`, `-H:ResourceConfigurationResources=`, `--enable-http`, `--enable-https`).
3. Encountering *any* other argument caused an immediate `IOException`, terminating the entire Maven build.

In real-world projects importing widely-used libraries such as `com.squareup.okhttp3:okhttp-jvm:5.3.2`, `native-image.properties` contains arguments like:

```properties
Args = -H:+AddAllCharsets --enable-http --enable-https --features=okhttp3.internal.graal.OkHttpFeature --report-unsupported-elements-at-runtime
```

Flags like `-H:+AddAllCharsets` (instructing native-image to include JDK charsets) and `--report-unsupported-elements-at-runtime` (deferring compile-time errors for uncalled bytecodes) tune the ahead-of-time compiler and declare **zero** dependency class roots. Aborting the entire build when encountering standard compiler flags renders the elider unusable on standard libraries.

## Decision

The project adopts a permissive, name-only argument ingestion policy with built-in non-class flag recognition, user-configurable allowed lists, and actionable fail-closed diagnostics.

### 1. Built-in Recognition of Common Non-Class Compiler Flags

The core parser in `NativeImageDynamicRoots` recognizes standard GraalVM compiler and platform flags that do not define class or resource roots:

* `-H:+AddAllCharsets` and `-H:-AddAllCharsets`
* `--report-unsupported-elements-at-runtime`
* `--enable-http` and `--enable-https`

These flags are safely consumed without error and without declaring dynamic roots.

### 2. Name-Only Allowed Arguments (`elide.allowedNativeImageArgs`)

The plugin introduces a user-configurable property:

* Parameter: `@Parameter(property = "elide.allowedNativeImageArgs") private List<String> allowedNativeImageArgs;`
* **Name-Only Matching**: The configuration matches **only the argument name**, ignoring any value:
  * For flags with values (`-H:EnableURLProtocols=http,https`), the parser extracts the name before `=` (`-H:EnableURLProtocols`) and checks for presence in `allowedNativeImageArgs`.
  * For flags without values (`--no-fallback`), the exact flag name is matched.
* This avoids requiring users to replicate complex, version-specific argument values in their POM.

### 3. Actionable Fail-Closed Default with Configurable Pass-Through Fallback

To preserve the project's safety invariants:

* Parameter: `@Parameter(property = "elide.failOnUnsupportedNativeImageArgs", defaultValue = "true") private boolean failOnUnsupportedNativeImageArgs;`
* **Default Mode (`true`, Fail-Closed)**:
  * If an unmodeled argument is encountered and not present in `allowedNativeImageArgs`, the build halts with an actionable diagnostic message:

    ```text
    [ERROR] Unsupported native-image argument '<name>' in <entryPath> (full argument: '<argument>').
    [ERROR] Inspect the property in the dependency archive. If this argument does not declare dynamic class roots,
    [ERROR] you can allow it by adding its name to <allowedNativeImageArgs> in pom.xml:
    [ERROR]   <configuration>
    [ERROR]     <allowedNativeImageArgs>
    [ERROR]       <allowedNativeImageArg><name></allowedNativeImageArg>
    [ERROR]     </allowedNativeImageArgs>
    [ERROR]   </configuration>
    [ERROR] Or via CLI: -Delide.allowedNativeImageArgs=<name>
    ```

* **Permissive Mode (`false`, Artifact Pass-Through)**:
  * If `failOnUnsupportedNativeImageArgs=false`, the build logs the warning and marks the containing dependency JAR as a pass-through (ineligible for trimming, original bytes preserved), while allowing all other project dependencies to be elided and trimmed.

### 4. Robust Tokenization and Quote Stripping

The parser strips enclosing single (`'...'`) and double (`"..."`) quotes from individual argument tokens rather than rejecting them.

## Invariants

* Arguments that declare dynamic class or feature roots (`--features=`, `--initialize-at-build-time=`, `-H:ReflectionConfigurationResources=`) must always be parsed and retained as roots.
* Unrecognized arguments fail closed by default unless explicitly allowed via `allowedNativeImageArgs` or `failOnUnsupportedNativeImageArgs=false`.
* When fallback mode is active, the failure boundary is strictly bounded to the offending archive (pass-through retention). The engine never strips classes from an archive with unknown reflection instructions.

## Consequences

* Resolves immediate build failures on popular libraries like OkHttp, Netty, and BouncyCastle without sacrificing safety.
* Developers have a simple, one-line escape hatch (`allowedNativeImageArgs`) using flag names when upgrading dependencies that introduce new GraalVM compiler options.
