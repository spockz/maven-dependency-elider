<!-- WHY: Introduces the project, its core value proposition, quick start, and architectural model. -->
# Maven Dependency Elider

[![Build](https://github.com/spockz/maven-dependency-elider/actions/workflows/check.yml/badge.svg)](https://github.com/spockz/maven-dependency-elider/actions/workflows/check.yml)
[![Documentation](https://img.shields.io/badge/docs-GitHub%20Pages-blue.svg)](https://spockz.github.io/maven-dependency-elider/)
[![Java 21](https://img.shields.io/badge/Java-21-blue.svg)](https://openjdk.org/projects/jdk/21/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

Software Composition Analysis floods engineering teams with vulnerability alerts because over 97% of reported Java CVEs reside in bloated, dormant code that never executes in production. Maven Dependency Elider eliminates this security impedance mismatch by automatically purging unused transitive libraries and trimming unreferenced classes directly inside your Maven build. By leveraging concrete JVM runtime telemetry (CDS, JFR, JaCoCo) to validate lean classpaths during compile and test phases, it catches regressions before packaging while emitting verifiable CycloneDX 1.6 pedigree provenance to eliminate bloat-driven vulnerability noise.

```text
  Runtime Evidence                 Maven Build Lifecycle               Lean Distribution
┌──────────────────┐           ┌────────────────────────────┐         ┌───────────────────┐
│ CDS Class Lists  │           │   compile                  │         │ Slashed JAR Size  │
│ -Xlog:class+load │ ────────> │   test  (validates elision)│ ──────> │ Zero Bloat CVEs   │
│ JFR ClassLoad    │           │   package (Shade / Boot)   │         │ CycloneDX 1.6 SBOM│
│ JaCoCo & GraalVM │           └────────────────────────────┘         │ Pedigree Provenance│
└──────────────────┘                         ▲                        └───────────────────┘
                                             │
                                    In-Memory Redirection
                                  (Transparent to Packagers)
```

## Why Maven Dependency Elider?

* **Eliminate Runtime Guesswork**: Feeds on concrete JVM telemetry—CDS class lists (`-XX:DumpLoadedClassList`), class-loading logs (`-Xlog:class+load`), JFR recordings (`jdk.ClassLoad`), JaCoCo execution data (`jacoco.exec`), and GraalVM reflection configuration.
* **Catch Regressions Early**: Injects reduced dependency views into Maven at `INITIALIZE`. Your existing `test` and `verify` phases execute against the trimmed classpath, catching any missing-class regressions *before* packaging.
* **Two-Tier Reduction**:
  * **Whole-Artifact Elision**: Removes eligible dependencies without runtime evidence from effective classpaths and terminal packages.
  * **Intra-JAR Trimming**: Slices unreferenced classes from retained JARs using ProGuard Core link closure, preserving required bytecode metadata, resources, and JAR boundaries.
* **Packaging Transparency**: Works seamlessly with `maven-shade-plugin` and `spring-boot-maven-plugin` without requiring bespoke archive packagers.
* **Cryptographic & SBOM Provenance**: Emits schema-valid CycloneDX 1.6 SBOMs with pedigree ancestry for trimmed components. Automated CVE-to-class mapping and VEX generation are tracked in open research ([RQ-0008](docs/research/RQ-0008-osv-sbom-comparison-and-vex-evidence.md)).

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

Run `elide` before the consumer's package lifecycle in the same Maven invocation. Intra-JAR trimming is opt-in; this example enables it:

```sh
./mvnw io.github.spockz:dependency-elider-maven-plugin:0.1.0-SNAPSHOT:elide package \
  -Delide.skip=false \
  -Delide.traceFiles=target/classes.log \
  -Delide.trimJars=true
```

For complete configuration options and multi-source telemetry merging, see [Plugin Usage](dependency-elider-maven-plugin/src/site/markdown/usage.md), the [User FAQ](docs/faq.md), and the [Contributor Decision Register and Engineering FAQ](docs/contributor-decisions-and-faq.md).

## Vulnerability findings and code evidence

Software Composition Analysis (SCA) suffers from a severe **four-tier granularity mismatch**:

1. **Product-Level CPE Over-Matching**: Scanners flag every `io.netty:netty-*` module for an issue present only in `netty-codec-http2`.
2. **Artifact-Level Coarseness**: A single dormant utility class inside an artifact marks the entire JAR vulnerable.
3. **Compound Exploitability**: Most gadget chains require secondary companion libraries and specific deserialization settings.
4. **Class & Method Execution Reality**: The JVM loads classes individually; massive portions of imported libraries never load.

### The 1%–3% vulnerability reality

Empirical research confirms that **only 1% to 3% of reported CVEs are genuinely exploitable** in production:

```text
[Stage 1: Raw Baseline (100%)]
       │
       ▼  Eliminate broad CPE product collisions across modular frameworks (-35% to -55%)
[Stage 2: CPE Disambiguation (45%–65% remaining)]
       │
       ▼  Prune unobserved, completely bloated transitive dependencies (-57% of transitive edges)
[Stage 3: Unused Dependency Pruning (20%–35% remaining)]
       │
       ▼  Verify function and class-level call-graph reachability (-90% to -95%)
[Stage 4: Function & Class Reachability (3%–8% remaining)]
       │
       ▼  Evaluate compound conditions, dormant paths, and configuration flags (-50% to -70%)
[Stage 5: Compound & Runtime Context (1%–3% remaining)]
```

* **57% Transitive Bloat**: Soto-Valero et al. (KTH CASTOR, EMSE 2021) analyzed 723,444 Maven dependency edges and proved that **57% of transitive dependencies and 75.1% of all dependency relationships in Maven are completely bloated** (zero classes loaded).
* **88.8% CPE False Positives**: Ponta et al. (SAP Research, ICSME 2018) proved that **88.8% of findings** for code-covered CVEs were false positives driven by coarse CPE matching.
* **92%–95% Function Unreachability**: Telemetry from Snyk, Endor Labs, and Sonatype demonstrates that over 90% of vulnerability alerts in Java are unreachable at the method level.

For the full academic review and scanner VEX comparison, read the [Project Rationale](dependency-elider-maven-plugin/src/site/markdown/rationale.md).

### Current evidence boundary and SBOM scanning

An SBOM or vulnerability scanner can continue to report a coordinate-level finding after artifact or class trimming. A scanner may compare the post-elision CycloneDX inventory, but a class-specific `vulnerable_code_not_present` statement requires vulnerability data that maps the finding to omitted code with sufficient precision. An unused artifact or removed class alone is not that proof. The plugin currently emits CycloneDX 1.6 trim pedigree; external scanner comparison and evidence-backed VEX generation are investigated in [RQ-0008](docs/research/RQ-0008-osv-sbom-comparison-and-vex-evidence.md).

After `make test-examples`, OSV-Scanner can check the Spring example's generated CycloneDX component inventory against known vulnerability data with `osv-scanner scan source -L examples/example-spring-boot-app/target/dependency-elider-sbom.cdx.json` ([official usage](https://google.github.io/osv-scanner/usage/scan-source)). This repository does not run OSV-Scanner in its example test target, so it makes no scanner-result claim. SBOM inventory scanning matches known findings to components; it does not map CVEs to omitted classes or generate VEX.

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
│   Keeps services, licenses, resources; strips signature/digest metadata│
└────────────────────────────────────────────────────────────────────────┘
```

1. **Whole-Artifact Elision**: Eligible dependencies without runtime evidence can be removed from the Maven artifact views used by the verified example consumers. The direct dependency-artifact set is preserved in the supported Maven 3 context to avoid triggering a second resolution, so not every Maven view reflects the same decision.
2. **Intra-JAR Trimming**: For retained dependencies, ProGuard Core computes the transitive link closure of all required internal types, superclasses, interfaces, and annotations. Unreferenced classes are purged while preserving resource files, licenses, and SPI service providers.
3. **In-Memory Redirection**: Retained dependencies are redirected in-memory (`artifact.setFile(trimmedJar)`), allowing standard packagers to assemble the trimmed JARs without bespoke glue code.

## Source roots and support limits

The `elide.sourceRootsComplete` setting defaults to `false`. In that mode, all effective compile-classpath JARs and their classes are conservatively retained for class trimming. Setting it to `true` asserts that all production and generated sources exist before `INITIALIZE` and that no later processor or generator adds compile references. Detectable unsupported compiler settings still fail closed. Source scanning covers compile-time references that may not appear in class files, including inlined constants, source-retained annotations, and generic bounds. The independent runtime-evidence match remains required before whole-artifact pruning.

Supported service, Spring, and native-image metadata roots also protect their declaring JARs and provider JARs from whole-artifact elision when `elide.trimJars=false`. A uniquely indexed provider is kept by coordinate; if a root has multiple scanned owners, all matching JARs are kept, and if no owner is found, the plugin conservatively keeps the scanned JAR inventory. With trimming enabled, those roots also participate in intra-JAR closure. Unknown metadata, unresolved references in candidate JARs, and unsupported archive layouts fail closed. Retained multi-release JARs with implementation classes and retained root-module-info JARs pass through unchanged by default; the analysis covers classpath behavior for the current runtime feature, not JPMS module-path linkage. Set `elide.failOnUnsupportedMultiRelease=true` or `elide.failOnUnsupportedModuleInfo=true` to fail on those layouts. `elide.trimSkipArtifacts` explicitly keeps named JARs unchanged and analyzes their classes as roots; unresolved external references from unchanged pass-through code are tolerated.

The analysis fingerprints Maven's resolved and direct artifact views, including membership, coordinates, scopes, file paths, and file contents. A change detected while preparation or the analysis-only effective-closure pass is running fails closed. The effective-closure pass is diagnostic and does not write trimmed JARs or change Maven views; wiring its discovered roots into output generation remains a separate work item.

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
      "diff": {
        "text": {
          "contentType": "text/plain",
          "content": "Trimmed unreferenced classes using ProGuard Core link closure"
        }
      }
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
| **`example-basic-app`** | Plain Java + Shade | Keeps whole-artifact candidates when graph evidence is unavailable, trims Commons Compress classes, and packages the committed trimmed generation. |
| **`example-spring-boot-app`** | Spring Boot 3 Web | Keeps whole-artifact candidates without graph evidence, trims supported retained JARs, preserves mail JAR bytes, and tests the HTTP endpoint. |
| **`example-cve-unused-app`** | Standalone CVE test | Reports raw whole-artifact candidates and verifies fail-closed retention when graph evidence is unavailable. |
| **`example-cve-safe-class-app`** | Standalone CVE test | Verifies runtime behavior and fail-closed whole-artifact retention without graph evidence. |

Run the full end-to-end verification suite across all fixtures:

```sh
make test-examples
```

The example script does not load the production core extension, so its reports and archive checks exercise fail-closed whole-artifact retention while still covering supported class trimming. Consumers must load the core extension through `.mvn/extensions.xml` to enable whole-artifact removal from a validated resolver graph. The script uses the Maven Wrapper, a JDK 21 toolchain, Bash, and `timeout`; temporary traces, logs, and verification staging stay under `.scratch/`. It does not run OSV-Scanner or generate VEX. The Spring fixture checks trimmed `spring-webmvc` bytes and class entries and verifies the packaged HTTP endpoint; its runtime-only mail classification is evidence, not an explanation of why Spring loaded those classes.

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

The estimate excludes class-level trimming and may differ from the final package delta. Analyze output has no class, method, or field stage-not-run rows; `elide` keeps its existing summary behavior. See [Maven plugin usage](dependency-elider-maven-plugin/src/site/markdown/usage.md) for supported trace formats and configuration.

## Requirements

* **Java 21** or newer.

Local developer requirements (Bash, Node.js for Markdown linting, and Caddy for local site preview) and JMH benchmark procedures are documented in [CONTRIBUTING.md](CONTRIBUTING.md).

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for local environment setup, build and verification commands, repository layout, and cache benchmark procedures.

## License

This project is licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
