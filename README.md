<!-- WHY: Introduces the project, its core value proposition, quick start, and architectural model. -->
# Maven Dependency Elider

[![Build](https://github.com/spockz/maven-dependency-elider/actions/workflows/check.yml/badge.svg)](https://github.com/spockz/maven-dependency-elider/actions/workflows/check.yml)
[![Documentation](https://img.shields.io/badge/docs-GitHub%20Pages-blue.svg)](https://spockz.github.io/maven-dependency-elider/)
[![Java 21](https://img.shields.io/badge/Java-21-blue.svg)](https://openjdk.org/projects/jdk/21/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

Maven Dependency Elider is an experimental Maven plugin for reducing dependency artifacts and classes using supplied runtime evidence, source references, and supported dynamic roots. Its examples exercise compilation, tests, and selected packaging paths; they do not establish zero regressions for every application or workload. The plugin emits CycloneDX trim pedigree, but does not map CVEs to classes or generate VEX statements.

```text
  Runtime Evidence                 Maven Build Lifecycle               Lean Distribution
┌──────────────────┐           ┌────────────────────────────┐         ┌───────────────────┐
│ CDS / JFR / JaCoCo│          │   compile and test          │         │ Smaller tested   │
│ Class-load logs   │ ───────> │   package (Shade / Boot)   │ ──────> │ packages         │
│ Explicit roots    │          └────────────────────────────┘         │ CycloneDX pedigree│
└──────────────────┘                         ▲                        └───────────────────┘
                                             │
                                    In-Memory Redirection
                                  (Transparent to Packagers)
```

## Why Maven Dependency Elider?

* **Use Runtime Evidence**: Reads supported telemetry such as CDS class lists, class-loading logs (`-Xlog:class+load`), JFR recordings (`jdk.ClassLoad`), JaCoCo execution data, and supported GraalVM configuration.
* **Exercise the Reduced Classpath**: The `elide` goal updates Maven artifact views at `INITIALIZE`; the example lifecycle runs tests and packaging against those views for the covered fixtures.
* **Two-Tier Reduction**:
  * **Whole-Artifact Elision**: Removes eligible artifacts without runtime evidence, while requiring at least one supplied dependency class to match runtime evidence before pruning.
  * **Intra-JAR Trimming**: Slices unreferenced classes from retained JARs using ProGuard Core link closure, preserving required bytecode metadata, resources, and JAR boundaries.
* **Packaging Integration**: The repository fixtures verify Shade and Spring Boot nested-JAR paths without a custom packager.
* **SBOM Provenance**: Emits schema-valid CycloneDX 1.6 pedigree for trimmed components. CVE-to-class mapping and VEX generation are outside the current implementation.

The work package is incomplete against its original performance acceptance: the latest exact-content warm-cache measurement is about 93 ms, above the <10 ms target, and the per-artifact <1.5 ms target remains unmet. The project is not ready for production dependency removal. See the [work-package closeout](docs/handovers/2026-10-25-intra-jar-trimming-work-package-closeout.md).

## Quick Start

### 1. Install Plugin

```sh
git clone https://github.com/spockz/maven-dependency-elider.git
cd maven-dependency-elider
./mvnw -pl dependency-elider-maven-plugin -am install
```

### 2. Capture Runtime Telemetry

Run your application with standard JVM class-loading logs:

```sh
java -Xlog:class+load=info:file=target/classes.log -jar target/my-app.jar
```

### 3. Analyze Dependencies

Run the non-mutating `analyze` goal to inspect bloat and trimming potential:

```sh
./mvnw io.github.spockz:dependency-elider-maven-plugin:0.1.0-SNAPSHOT:analyze \
  -Delide.traceFiles=target/classes.log
```

### 4. Build with Elision

Activate the `elide` goal to compile, test, and package against the reduced classpath:

```sh
./mvnw package \
  -Delide.skip=false \
  -Delide.traceFiles=target/classes.log
```

For complete configuration options and multi-source telemetry merging, see [Plugin Usage](dependency-elider-maven-plugin/src/site/markdown/usage.md).

## Vulnerability findings and code evidence

Software Composition Analysis (SCA) suffers from a severe **four-tier granularity mismatch**:

1. **Product-Level CPE Over-Matching**: Scanners flag every `io.netty:netty-*` module for an issue present only in `netty-codec-http2`.
2. **Artifact-Level Coarseness**: A single dormant utility class inside an artifact marks the entire JAR vulnerable.
3. **Compound Exploitability**: Most gadget chains require secondary companion libraries and specific deserialization settings.
4. **Class & Method Execution Reality**: The JVM loads classes individually; massive portions of imported libraries never load.

An SBOM or vulnerability scanner can continue to report a coordinate-level finding after artifact or class trimming. A scanner may compare the post-elision CycloneDX inventory, but a class-specific `vulnerable_code_not_present` statement requires vulnerability data that maps the finding to omitted code with sufficient precision. An unused artifact or removed class alone is not that proof. The plugin currently performs no OSV-Scanner integration, CVE-to-class mapping, or VEX generation; see [RQ-0008](docs/research/RQ-0008-osv-sbom-comparison-and-vex-evidence.md).

## How Elision Works

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        Whole-Artifact Elision                          │
│                                                                        │
│   Unused Transitive JAR ───[ No Roots Observed ]───> DROPPED ENTIRELY  │
└────────────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────────────┐
│                        Intra-JAR Link Closure                          │
│                                                                        │
│   Retained JAR ───┬───[ Observed Root Classes ]──────> KEPT            │
│                   ├───[ Transitive Link Closure ]────> KEPT            │
│                   └───[ Unreferenced Classes ]───────> ELIDED          │
│                                                                        │
│   Output: Separate sanitized JAR in target/elided-artifacts/          │
│   Preserves: META-INF/services, licenses, resources, manifest digests  │
└────────────────────────────────────────────────────────────────────────┘
```

1. **Whole-Artifact Elision**: Eligible dependencies without runtime evidence can be removed from the Maven artifact views used by the verified example consumers. The direct dependency-artifact set is preserved in the supported Maven 3 context to avoid triggering a second resolution, so not every Maven view reflects the same decision.
2. **Intra-JAR Trimming**: For retained dependencies, ProGuard Core computes the transitive link closure of all required internal types, superclasses, interfaces, and annotations. Unreferenced classes are purged while preserving resource files, licenses, and SPI service providers.
3. **In-Memory Redirection**: Retained dependencies are redirected in-memory (`artifact.setFile(trimmedJar)`), allowing standard packagers to assemble the trimmed JARs without bespoke glue code.

## Source roots and support limits

The `elide.sourceRootsComplete` setting defaults to `false`. In that mode, all effective compile-classpath JARs and their classes are conservatively retained for class trimming. Setting it to `true` asserts that all production and generated sources exist before `INITIALIZE` and that no later processor or generator adds compile references. Detectable unsupported compiler settings still fail closed. Source scanning covers compile-time references that may not appear in class files, including inlined constants, source-retained annotations, and generic bounds. The independent runtime-evidence match remains required before whole-artifact pruning.

Trimming also uses runtime and production-bytecode references, supported services and Spring or native-image metadata, and explicit roots. Unknown metadata, unresolved references in candidate JARs, and unsupported archive layouts fail closed. Retained multi-release JARs with implementation classes and retained root-module-info JARs pass through unchanged by default; the analysis covers classpath behavior for the current runtime feature, not JPMS module-path linkage. Set `elide.failOnUnsupportedMultiRelease=true` or `elide.failOnUnsupportedModuleInfo=true` to fail on those layouts. `elide.trimSkipArtifacts` explicitly keeps named JARs unchanged and analyzes their classes as roots; unresolved external references from unchanged pass-through code are tolerated.

The examples verify the Basic Shade and Spring Boot nested-JAR paths. Maven's direct dependency-artifact set is preserved in the supported Maven 3 context to avoid triggering a second resolution; resolved/project views and matching artifact file pointers are updated. Other downstream mojos and Maven 4 remain unverified. See [ADR-0002](docs/adr/0002-in-memory-artifact-mutation-for-downstream-packaging-transparency.md) and [RQ-0006](docs/research/RQ-0006-maven-artifact-view-consistency-and-early-resolution-hooks.md).

## Provenance: CycloneDX 1.6

Pruning dependencies and trimming classes must never break supply chain provenance or scanner transparency.

### CycloneDX 1.6 Pedigree

Trimmed components record their actual on-disk SHA-256 while preserving upstream coordinate ancestry:

```json
{
  "type": "library",
  "group": "org.apache.commons",
  "name": "commons-compress",
  "version": "1.21",
  "hashes": [{ "alg": "SHA-256", "content": "<sha256-of-trimmed-jar>" }],
  "pedigree": {
    "ancestors": [{
      "type": "library",
      "group": "org.apache.commons",
      "name": "commons-compress",
      "version": "1.21",
      "hashes": [{ "alg": "SHA-256", "content": "<original-input-sha256>" }]
    }],
    "patches": [{
      "type": "unofficial",
      "description": "Trimmed unreferenced classes using ProGuard Core link closure"
    }]
  },
  "properties": [
    { "name": "elider:status", "value": "trimmed" },
    { "name": "elider:retainedClasses", "value": "18" },
    { "name": "elider:totalClasses", "value": "160" }
  ]
}
```

## Reference Fixtures

The repository includes end-to-end integration fixtures under `examples/`:

| Fixture | Architecture | Target Demonstration |
| :--- | :--- | :--- |
| **`example-basic-app`** | Plain Java + Shade | Elides unused `commons-codec`; produces a shrunken shaded JAR. |
| **`example-spring-boot-app`** | Spring Boot 3 Web | Removes unused Commons Codec and SnakeYAML, trims Spring MVC under `BOOT-INF/lib`, preserves mail JAR bytes, and tests the HTTP endpoint. |
| **`example-cve-unused-app`** | Standalone CVE test | Removes its unused Logback and Janino tree; package inventory can then be scanned separately. |
| **`example-cve-safe-class-app`** | Standalone CVE test | Retains Logback while removing Janino; demonstrates that a package-version finding may remain after one exploit prerequisite is removed. |

Run the full end-to-end verification suite across all fixtures:

```sh
make test-examples
```

The example script uses the Maven Wrapper, a JDK 21 toolchain, Bash, and `timeout`. It places temporary traces, logs, and verification staging under the repository `.scratch/` directory. It does not run OSV-Scanner or generate VEX. The Spring fixture checks trimmed `spring-webmvc` bytes and class entries and verifies the packaged HTTP endpoint; its runtime-only mail classification is evidence, not an explanation of why Spring loaded those classes.

### Sample elision report output

`make test-examples` invokes `dependency-elider:report` after each successful elision build. The report counts whole artifacts removed using original on-disk JAR sizes and classes removed using uncompressed `.class` entry sizes; class metrics exclude module descriptors and archive sanitation metadata. These representative summaries came from one captured run; timestamps vary between runs:

```text
example-basic-app
[INFO] Project: io.github.spockz:example-basic-app:0.1.0-SNAPSHOT
[INFO] Snapshot: last successful elide run at 2026-10-26T16:35:10.573567220Z
[INFO] Whole artifacts dropped: 1 (original JAR file bytes: 365.93 KiB)
[INFO] Program classes pruned from retained JARs: 535 (uncompressed omitted .class payload bytes: 1.93 MiB; excludes module descriptors and archive metadata)

example-spring-boot-app
[INFO] Project: io.github.spockz:example-spring-boot-app:0.1.0-SNAPSHOT
[INFO] Snapshot: last successful elide run at 2026-10-26T16:35:47.614372810Z
[INFO] Whole artifacts dropped: 2 (original JAR file bytes: 683.41 KiB)
[INFO] Program classes pruned from retained JARs: 3374 (uncompressed omitted .class payload bytes: 8.38 MiB; excludes module descriptors and archive metadata)

example-cve-unused-app
[INFO] Project: io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT
[INFO] Snapshot: last successful elide run at 2026-10-26T16:36:05.417027340Z
[INFO] Whole artifacts dropped: 13 (original JAR file bytes: 6.89 MiB)
[INFO] Program classes pruned from retained JARs: 0 (uncompressed omitted .class payload bytes: 0 B; excludes module descriptors and archive metadata)

example-cve-safe-class-app
[INFO] Project: io.github.spockz:example-cve-safe-class-app:0.1.0-SNAPSHOT
[INFO] Snapshot: last successful elide run at 2026-10-26T16:36:11.688187181Z
[INFO] Whole artifacts dropped: 5 (original JAR file bytes: 1.50 MiB)
[INFO] Program classes pruned from retained JARs: 0 (uncompressed omitted .class payload bytes: 0 B; excludes module descriptors and archive metadata)
```

Example POMs use `-Delide.mode=baseline` or `-Delide.mode=elision` to select the named baseline and elision behaviors. The plugin's internal skip parameter remains `elide.skip`; the mode property activates the example's Maven profile.

Run the standalone CVE fixture baselines with:

```sh
./mvnw -f examples/example-cve-unused-app/pom.xml verify -Delide.mode=baseline
./mvnw -f examples/example-cve-safe-class-app/pom.xml verify -Delide.mode=baseline
```

## Cache benchmarks

The core JMH cache benchmark measures metadata fingerprinting and cache loading, but does not establish the plugin's whole-build overhead. The production trim-cache benchmark uses exact content hashes. Its recorded warm hit is **93.038 ± 0.756 ms/op** on GraalVM JDK 21.0.12, above the <10 ms target; the per-artifact <1.5 ms target remains unmet. See [RQ-0003](docs/research/RQ-0003-sub-10ms-maven-fast-path-invariant-and-benchmarking.md) for method, limitations, and the deferred performance follow-up.

The latest paired example-build medians show about +1.977 s for Basic and +20.417 s for Spring Boot with elision enabled. These measurements include Maven startup, dependency resolution, compilation, tests, elision, and packaging; they are descriptive observations, not a whole-build performance guarantee.

## Analyze summary

The nonmutating, trace-based `analyze` goal qualifies removals as artifacts that would be elided by that analysis and estimates savings using the exact sum of original input JAR file sizes. Final package savings may differ, and `analyze` does not run intra-JAR trimming.

An input class-loading trace may contain lines like this; the source path depends on the local Maven repository and build output:

```text
[0.001s][info][class,load] used.Sample source: file:/.../used.jar
```

For the deterministic two-artifact Mojo fixture, the unused input JAR is 151 bytes:

```text
[INFO] Dependency Elider analysis summary
[INFO]   Artifacts that would be elided by this analysis: 1 / 2 (50.0%)
[INFO]   Estimated original JAR bytes for those artifacts: 151 B (sum of original on-disk input JAR sizes; final package delta may differ)
[INFO]   Cache: unavailable
```

The estimate excludes class-level trimming and may differ from the final package delta. Analyze output has no class, method, or field stage-not-run rows; `elide` keeps its existing summary behavior. See [Maven plugin usage](docs/plugin-usage.md) for supported trace formats and configuration.

## Requirements
The Maven plugin provides a nonmutating, trace-based `analyze` goal. Its summary qualifies removals as artifacts that would be elided by that analysis and gives the exact sum of the original JAR file sizes as an estimate; final package savings may differ, and `analyze` does not run intra-JAR trimming. Install the plugin and its core dependency to the local repository, then run it in the consumer project with an explicit trace:

* **JDK 21** or newer.
* Bash and the `timeout` utility for `make test-examples`.
* Node.js and npm only to install/run the Markdown linter used by `make check`.

The Maven Wrapper is included. The `make test-examples` script uses repository-root-relative paths and stores its temporary files in `.scratch/`.

A class-loading trace may contain lines like this; the source path depends on the local Maven repository and build output:

```text
[0.001s][info][class,load] used.Sample source: file:/.../used.jar
```

The nonmutating `analyze` goal qualifies its result as a prediction and estimates savings from original JAR file sizes. For the deterministic two-artifact Mojo fixture, the unused input JAR is 151 bytes:

```text
[INFO] Dependency Elider analysis summary
[INFO]   Artifacts that would be elided by this analysis: 1 / 2 (50.0%)
[INFO]   Estimated original JAR bytes for those artifacts: 151 B (sum of original on-disk input JAR sizes; final package delta may differ)
[INFO]   Cache: unavailable
```

This estimate does not include class-level trimming and may differ from the final package delta. The `analyze` output has no class, method, or field stage-not-run rows; `elide` keeps its existing summary behavior.

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for local environment setup, build and verification commands, repository layout, and cache benchmark procedures.

## License

This project is licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
