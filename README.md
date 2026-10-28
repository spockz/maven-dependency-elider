<!-- WHY: Introduces the project, its core value proposition, quick start, and architectural model. -->
# Maven Dependency Elider

[![Build](https://github.com/spockz/maven-dependency-elider/actions/workflows/check.yml/badge.svg)](https://github.com/spockz/maven-dependency-elider/actions/workflows/check.yml)
[![Documentation](https://img.shields.io/badge/docs-GitHub%20Pages-blue.svg)](https://spockz.github.io/maven-dependency-elider/)
[![Java 21](https://img.shields.io/badge/Java-21-blue.svg)](https://openjdk.org/projects/jdk/21/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

Software Composition Analysis can surface findings in code that a build never uses. Maven Dependency Elider combines runtime evidence with static closure to identify removable dependencies and trim unreferenced classes in a Maven build. Whole-artifact removal is applied only when a unique compatible mediated-graph capture proves the exact safe nodes; otherwise raw candidates remain retained. Trimmed outputs include CycloneDX 1.6 pedigree provenance.

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

Whole-artifact graph projection also requires the production core extension in the consumer project. After installing the plugin, create `.mvn/extensions.xml` in the consumer:

```xml
<extensions>
  <extension>
    <groupId>io.github.spockz</groupId>
    <artifactId>dependency-elider-maven-plugin</artifactId>
    <version>0.1.0-SNAPSHOT</version>
  </extension>
</extensions>
```

Without this extension, whole-artifact candidates remain in the effective dependency set; retained-JAR trimming can still run.

Before publication commits, a failed goal restores the prior report and output generation. If backup cleanup fails after commit, Maven reports the cleanup error while the newly published outputs remain active.

```sh
./mvnw io.github.spockz:dependency-elider-maven-plugin:0.1.0-SNAPSHOT:elide package \
  -Delide.skip=false \
  -Delide.traceFiles=target/classes.log \
  -Delide.trimJars=true
```

For complete configuration options and multi-source telemetry merging, see [Plugin Usage](dependency-elider-maven-plugin/src/site/markdown/usage.md), the [User FAQ](docs/faq.md), and the [Contributor Decision Register and Engineering FAQ](docs/contributor-decisions-and-faq.md).

The `elide` goal writes two different JSON files because they contain different records: `elide.reportFile` defaults to `target/dependency-elider-class-usage.json` for class-usage analysis evidence, while `elide.summaryFile` defaults to `target/dependency-elider-report.json` for the persisted elision snapshot read by `dependency-elider:report`. The top-level elision report uses schema version 4; schema-v3 and other unsupported reports are rejected with rerun guidance because they do not contain separate dropped-JAR class metrics. These document schema numbers are independent of the plugin version and of the graph-capture and resolver-plan store schemas.

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

1. **Whole-Artifact Elision**: Eligible dependencies without runtime evidence are reported as raw candidates. A unique compatible pre-elision graph capture is required before the effective decision removes exact safe graph nodes and resolved artifacts. If the production core extension or compatible graph evidence is unavailable, whole-artifact removals fail closed to zero. The direct dependency-artifact membership is preserved.
2. **Intra-JAR Trimming**: For retained dependencies, ProGuard Core computes the transitive link closure of all required internal types, superclasses, interfaces, and annotations. Unreferenced classes are purged while preserving resource files, licenses, and SPI service providers.
3. **In-Memory Redirection**: Retained dependencies are redirected in-memory (`artifact.setFile(trimmedJar)`), allowing standard packagers to assemble the trimmed JARs without bespoke glue code.

## Source roots and support limits

The `elide.sourceRootsComplete` setting defaults to `false`. In that mode, all effective compile-classpath JARs and their classes are conservatively retained for class trimming. Setting it to `true` asserts that all production and generated sources exist before `INITIALIZE` and that no later processor or generator adds compile references. Detectable unsupported compiler settings still fail closed. Source scanning covers compile-time references that may not appear in class files, including inlined constants, source-retained annotations, and generic bounds. The independent runtime-evidence match remains required before whole-artifact pruning.

Supported service, Spring, and native-image metadata roots also protect their declaring JARs and provider JARs from whole-artifact elision when `elide.trimJars=false`. A uniquely indexed provider is kept by coordinate; if a root has multiple scanned owners, all matching JARs are kept, and if no owner is found, the plugin conservatively keeps the scanned JAR inventory. With trimming enabled, those roots also participate in intra-JAR closure. Unknown metadata, unresolved references in candidate JARs, and unsupported archive layouts fail closed. Retained multi-release JARs with implementation classes and retained root-module-info JARs are not eligible for whole-artifact removal; module-path linkage is not covered. Set `elide.failOnUnsupportedMultiRelease=true` or `elide.failOnUnsupportedModuleInfo=true` to fail on those layouts. `elide.trimSkipArtifacts` explicitly keeps named JARs unchanged and analyzes their classes as roots; unresolved external references from unchanged pass-through code are tolerated.

The analysis fingerprints Maven's resolved and direct artifact views, including membership, coordinates, scopes, file paths, and file contents. A change detected during preparation or effective closure fails before publication. The `elide` goal stages trimmed outputs and reports, applies effective resolved membership while preserving direct dependency membership, and publishes the resolver plan last. Reports distinguish raw elision candidates from effective whole-artifact drops. A production core extension is required for later resolver graph projection; `dependency:tree` behavior is not currently guaranteed.

The examples verify the Basic Shade and Spring Boot nested-JAR paths. The Maven 3.9.11 packaged fixture verifies exact graph projection through a distinct direct TEST resolver call; it does not establish a second lifecycle request or `dependency:tree` consistency. Other downstream mojos, reactor behavior, and Maven 4 remain unverified. See [ADR-0002](docs/adr/0002-in-memory-artifact-mutation-for-downstream-packaging-transparency.md) and [RQ-0006](docs/research/RQ-0006-maven-artifact-view-consistency-and-early-resolution-hooks.md).

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
| **`example-basic-app`** | Plain Java + Shade | Elides unused `commons-codec`; produces a shrunken shaded JAR. |
| **`example-spring-boot-app`** | Spring Boot 3 Web | Captures the graph, retains whole-artifact candidates when no safe drop is available, trims Spring MVC under `BOOT-INF/lib`, preserves mail JAR bytes, and tests the HTTP endpoint. |
| **`example-cve-unused-app`** | Standalone CVE test | Captures the graph and currently records no raw or effective whole-artifact drops; package inventory can still be scanned separately. |
| **`example-cve-safe-class-app`** | Standalone CVE test | Captures the graph and currently records no raw or effective whole-artifact drops while preserving Logback/Spring behavior. |

Run the full end-to-end verification suite across all fixtures:

```sh
make test-examples
```

Each example project has a `.mvn/extensions.xml` entry for the installed production `dependency-elider-maven-plugin`; the script runs Maven from each fixture directory so Maven loads that core extension. Checks validate graph-backed outcomes, including zero-drop dispositions when no raw candidate is produced. Basic is the positive graph-removal case for Commons Codec. The example script uses the Maven Wrapper, a JDK 21 toolchain, Bash, and `timeout`. It places temporary traces, logs, and verification staging under the repository `.scratch/` directory. It does not run OSV-Scanner or generate VEX. The Spring fixture checks trimmed `spring-webmvc` bytes and class entries and verifies the packaged HTTP endpoint; its runtime-only mail classification is evidence, not an explanation of why Spring loaded those classes.

### Sample elision report output

`make test-examples` invokes `dependency-elider:report` after each successful elision build. The report counts whole artifacts removed using original on-disk JAR sizes and classes removed using uncompressed `.class` entry sizes; class metrics exclude module descriptors and archive sanitation metadata. These summaries and graph rows came from the final schema-v4 run on 2026-10-28; timestamps vary between runs:

```text
example-basic-app
[INFO] Project: io.github.spockz:example-basic-app:0.1.0-SNAPSHOT
[INFO] Snapshot: last successful elide run at 2026-10-28T09:09:55.318015313Z
[INFO] Whole artifacts dropped: 1 (original JAR file bytes: 365.93 KiB)
[INFO] Program classes removed with dropped JARs: 115 (uncompressed .class entry payload bytes: 413.65 KiB; excludes module descriptors and archive sanitation metadata)
[INFO] Program classes pruned from retained JARs: 535 (uncompressed omitted .class payload bytes: 1.93 MiB; excludes module descriptors and archive metadata)
[INFO]   - io.github.spockz:example-basic-app:0.1.0-SNAPSHOT {nodeId=n0} [RETAINED]
[INFO]   - io.github.spockz:example-basic-app:0.1.0-SNAPSHOT -> commons-codec:commons-codec:jar:1.19.0 (compile) {nodeId=n1} [EFFECTIVE_DROP]
[INFO]   - io.github.spockz:example-basic-app:0.1.0-SNAPSHOT -> org.apache.commons:commons-compress:jar:1.28.0 (compile) {nodeId=n2} [RETAINED, CLASS_TRIMMED]

example-spring-boot-app
[INFO] Project: io.github.spockz:example-spring-boot-app:0.1.0-SNAPSHOT
[INFO] Snapshot: last successful elide run at 2026-10-28T09:10:34.336152374Z
[INFO] Whole artifacts dropped: 0 (original JAR file bytes: 0 B)
[INFO] Program classes removed with dropped JARs: 0 (uncompressed .class entry payload bytes: 0 B; excludes module descriptors and archive sanitation metadata)
[INFO] Program classes pruned from retained JARs: 3374 (uncompressed omitted .class payload bytes: 8.38 MiB; excludes module descriptors and archive metadata)
[INFO]   - io.github.spockz:example-spring-boot-app:0.1.0-SNAPSHOT {nodeId=n0} [RETAINED]
[INFO]   - io.github.spockz:example-spring-boot-app:0.1.0-SNAPSHOT -> org.springframework.boot:spring-boot-starter-web:jar:3.3.5 (compile) {nodeId=n1} [RETAINED]
[INFO]   - io.github.spockz:example-spring-boot-app:0.1.0-SNAPSHOT -> org.springframework:spring-context:jar:6.1.14 (compile) {nodeId=n2} [RETAINED, CLASS_TRIMMED]

example-cve-unused-app
[INFO] Project: io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT
[INFO] Snapshot: last successful elide run at 2026-10-28T09:10:58.049477635Z
[INFO] Whole artifacts dropped: 0 (original JAR file bytes: 0 B)
[INFO] Program classes removed with dropped JARs: 0 (uncompressed .class entry payload bytes: 0 B; excludes module descriptors and archive sanitation metadata)
[INFO] Program classes pruned from retained JARs: 0 (uncompressed omitted .class payload bytes: 0 B; excludes module descriptors and archive metadata)

example-cve-safe-class-app
[INFO] Project: io.github.spockz:example-cve-safe-class-app:0.1.0-SNAPSHOT
[INFO] Snapshot: last successful elide run at 2026-10-28T09:11:10.245962217Z
[INFO] Whole artifacts dropped: 0 (original JAR file bytes: 0 B)
[INFO] Program classes removed with dropped JARs: 0 (uncompressed .class entry payload bytes: 0 B; excludes module descriptors and archive sanitation metadata)
[INFO] Program classes pruned from retained JARs: 0 (uncompressed omitted .class payload bytes: 0 B; excludes module descriptors and archive metadata)
```

The report goal reads this persisted schema-v4 snapshot and fails if its mediated TEST graph is unavailable. It reports dropped-JAR class entries separately from class entries pruned from retained JARs; the two totals never overlap, and the report rejects any coordinate listed in both categories. It does not resolve a new graph or call `maven-dependency-plugin:tree`.

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
