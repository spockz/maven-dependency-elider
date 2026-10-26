<!-- WHY: Introduces the project, its core value proposition, quick start, and architectural model. -->
# Maven Dependency Elider

[![Build](https://github.com/spockz/maven-dependency-elider/actions/workflows/check.yml/badge.svg)](https://github.com/spockz/maven-dependency-elider/actions/workflows/check.yml)
[![Documentation](https://img.shields.io/badge/docs-GitHub%20Pages-blue.svg)](https://spockz.github.io/maven-dependency-elider/)
[![Java 21](https://img.shields.io/badge/Java-21-blue.svg)](https://openjdk.org/projects/jdk/21/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

Software Composition Analysis floods engineering teams with vulnerability alerts because over 97% of reported Java CVEs reside in bloated, dormant code that never executes in production. Maven Dependency Elider eliminates this security impedance mismatch by automatically purging unused transitive libraries and trimming unreferenced classes directly inside your Maven build. By leveraging concrete JVM runtime telemetry (CDS, JFR, JaCoCo) to validate lean classpaths during compile and test phases, it guarantees zero-regression packaging while emitting verifiable CycloneDX 1.6 and OpenVEX attestations to decisively silence false-positive alarms.

```text
  Runtime Evidence                 Maven Build Lifecycle               Lean Distribution
┌──────────────────┐           ┌────────────────────────────┐         ┌───────────────────┐
│ CDS Class Lists  │           │   compile                  │         │ Slashed JAR Size  │
│ -Xlog:class+load │ ────────> │   test  (validates elision)│ ──────> │ Zero Bloat CVEs   │
│ JFR ClassLoad    │           │   package (Shade / Boot)   │         │ CycloneDX 1.6 SBOM│
│ JaCoCo & GraalVM │           └────────────────────────────┘         │ OpenVEX Statements│
└──────────────────┘                         ▲                        └───────────────────┘
                                             │
                                    In-Memory Redirection
                                  (Transparent to Packagers)
```

## Why Maven Dependency Elider?

* **Eliminate Runtime Guesswork**: Feeds on concrete JVM telemetry—CDS class lists (`-XX:DumpLoadedClassList`), class-loading logs (`-Xlog:class+load`), JFR recordings (`jdk.ClassLoad`), JaCoCo execution data (`jacoco.exec`), and GraalVM reflection configuration.
* **Catch Regressions Early**: Injects reduced dependency views into Maven at `INITIALIZE`. Your existing `test` and `verify` phases execute against the trimmed classpath, catching any missing-class regressions *before* packaging.
* **Two-Tier Reduction**:
  * **Whole-Artifact Elision**: Completely purges 100% unused dependencies from effective classpaths and terminal packages.
  * **Intra-JAR Trimming**: Slices unreferenced classes from retained JARs using ProGuard Core link closure, preserving required bytecode metadata, resources, and JAR boundaries.
* **Packaging Transparency**: Works seamlessly with `maven-shade-plugin` and `spring-boot-maven-plugin` without requiring bespoke archive packagers.
* **Cryptographic & SBOM Provenance**: Emits schema-valid CycloneDX 1.6 SBOMs with pedigree ancestry and OpenVEX `vulnerable_code_not_present` attestations.

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

## The 1%–3% Vulnerability Reality

Software Composition Analysis (SCA) suffers from a severe **four-tier granularity mismatch**:

1. **Product-Level CPE Over-Matching**: Scanners flag every `io.netty:netty-*` module for an issue present only in `netty-codec-http2`.
2. **Artifact-Level Coarseness**: A single dormant utility class inside an artifact marks the entire JAR vulnerable.
3. **Compound Exploitability**: Most gadget chains require secondary companion libraries and specific deserialization settings.
4. **Class & Method Execution Reality**: The JVM loads classes individually; massive portions of imported libraries never load.

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

1. **Whole-Artifact Elision**: If no class in a dependency is referenced by sources or observed by runtime traces, the dependency is excluded from Maven's in-memory model. Downstream plugins (compiler, surefire, shade, spring-boot) never see it.
2. **Intra-JAR Trimming**: For retained dependencies, ProGuard Core computes the transitive link closure of all required internal types, superclasses, interfaces, and annotations. Unreferenced classes are purged while preserving resource files, licenses, and SPI service providers.
3. **In-Memory Redirection**: Retained dependencies are redirected in-memory (`artifact.setFile(trimmedJar)`), allowing standard packagers to assemble the trimmed JARs without bespoke glue code.

## Provenance: CycloneDX 1.6 & OpenVEX

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
      "hashes": [{ "alg": "SHA-256", "content": "<original-central-sha256>" }]
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

### OpenVEX Machine-Readable Justifications

When a vulnerable class is eliminated during trimming, OpenVEX emits an evidence-backed statement:

```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "urn:uuid:6b541525-45a8-4eb8-a7df-a0bc7c77ef5a",
  "author": "io.github.spockz:dependency-elider-maven-plugin",
  "timestamp": "2026-10-26T20:00:00Z",
  "version": 1,
  "statements": [{
    "vulnerability": { "name": "CVE-2025-11226" },
    "products": [{ "@id": "pkg:maven/ch.qos.logback/logback-core@1.5.18" }],
    "status": "not_affected",
    "justification": "vulnerable_code_not_present",
    "impact_statement": "The vulnerable class was purged during intra-JAR link closure trimming."
  }]
}
```

## Reference Fixtures

The repository includes end-to-end integration fixtures under `examples/`:

| Fixture | Architecture | Target Demonstration |
| :--- | :--- | :--- |
| **`example-basic-app`** | Plain Java + Shade | Elides unused `commons-codec`; produces a shrunken shaded JAR. |
| **`example-spring-boot-app`** | Spring Boot 3 Web | Elides unused starter dependencies from `BOOT-INF/lib`; tests HTTP endpoint. |
| **`example-cve-unused-app`** | Standalone CVE test | Removes entire Logback + Janino tree, clearing CVE-2025-11226 from vulnerability scans. |
| **`example-cve-safe-class-app`** | Standalone CVE test | Retains Logback while purging Janino; demonstrates the boundary between CVE flags and exploit prerequisites. |

Run the full end-to-end verification suite across all fixtures:

```sh
make test-examples
```

## Requirements

* **Java 21** or newer.

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for local environment setup, build and verification commands, repository layout, and cache benchmark procedures.

## License

This project is licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
