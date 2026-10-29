<!-- WHY: Introduces the project, its core value proposition, quick start, and architectural model. -->
# Maven Dependency Elider

[![Build](https://github.com/spockz/maven-dependency-elider/actions/workflows/check.yml/badge.svg)](https://github.com/spockz/maven-dependency-elider/actions/workflows/check.yml)
[![Documentation](https://img.shields.io/badge/docs-GitHub%20Pages-blue.svg)](https://spockz.github.io/maven-dependency-elider/)
[![Java 21](https://img.shields.io/badge/Java-21-blue.svg)](https://openjdk.org/projects/jdk/21/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

Software Composition Analysis (SCA) frequently surfaces vulnerabilities in dependencies that an application never actually executes. **Maven Dependency Elider** combines runtime JVM telemetry with static bytecode reachability to safely drop unused dependencies and slice unreferenced classes during your Maven build.

Whole-artifact removal runs only when a compatible mediated graph proves the exact safe nodes to elide; otherwise candidates are safely retained. Trimmed outputs include schema-valid CycloneDX 1.6 SBOMs with pedigree provenance.

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

* **Concrete Runtime Telemetry**: Drives decisions using verifiable JVM execution data: CDS lists (`-XX:DumpLoadedClassList`), class-loading logs (`-Xlog:class+load`), JFR events (`jdk.ClassLoad`), JaCoCo coverage (`jacoco.exec`), and GraalVM reflection configs.
* **Early Regression Detection**: Injects trimmed dependency views into Maven at `INITIALIZE`. Your standard `test` and `verify` phases execute against the trimmed classpath, catching regressions *before* packaging.
* **Two-Tier Size Reduction**:
  * **Whole-Artifact Elision**: Removes unused dependencies from effective classpaths and packaged archives.
  * **Intra-JAR Trimming**: Slices unreferenced classes from retained JARs using ProGuard Core link closure, preserving required resources, SPI providers, and licenses.
* **Transparent Packaging**: Functions out-of-the-box with `maven-shade-plugin` and `spring-boot-maven-plugin` without custom archive wrappers.
* **Verifiable Provenance**: Emits schema-valid CycloneDX 1.6 SBOMs recording trimmed component SHA-256 hashes and ancestral pedigree.

---

## Quick Start

### 1. Install the Plugin

Build and install the plugin and core engine into your local repository:

```sh
git clone https://github.com/spockz/maven-dependency-elider.git
cd maven-dependency-elider
./mvnw -pl dependency-elider-maven-plugin -am install
```

### 2. Configure the Core Extension

To enable whole-artifact dependency pruning, register the core extension in your consumer project's `.mvn/extensions.xml`:

```xml
<extensions>
  <extension>
    <groupId>io.github.spockz</groupId>
    <artifactId>dependency-elider-maven-plugin</artifactId>
    <version>0.1.0-SNAPSHOT</version>
  </extension>
</extensions>
```

> **Note**: Without this extension, whole-artifact candidates are retained, though intra-JAR trimming still functions.

### 3. Capture Runtime Telemetry

Run your application with class-loading logging enabled to produce a trace file:

```sh
cd examples/example-basic-app
../../mvnw clean package -Delide.mode=baseline
java -Xlog:class+load=info:file=target/classes.log \
  -jar target/example-basic-app-0.1.0-SNAPSHOT.jar
```

### 4. Run Dry-Run Analysis (`analyze`)

Execute `analyze` to preview removable dependencies and estimated byte savings without modifying the build:

```sh
../../mvnw io.github.spockz:dependency-elider-maven-plugin:0.1.0-SNAPSHOT:analyze \
  -Delide.traceFiles=target/classes.log \
  -Delide.sourceRootsComplete=true \
  -Dmaven.compiler.proc=none \
  -Delide.excludedArtifacts=commons-io:commons-io,org.apache.commons:commons-lang3
```

On this Basic fixture, `analyze` identifies two whole-artifact candidates out of thirteen (942.11 KiB of original JAR bytes, removing `CVE-2014-3577` from inventory).

### 5. Build with Elision (`elide`)

Run `elide` alongside your packaging goals to trim dependencies and generate sanitized outputs:

```sh
../../mvnw io.github.spockz:dependency-elider-maven-plugin:0.1.0-SNAPSHOT:elide package \
  -Delide.skip=false \
  -Delide.traceFiles=target/classes.log \
  -Delide.trimJars=true \
  -Delide.sourceRootsComplete=true \
  -Dmaven.compiler.proc=none \
  -Delide.excludedArtifacts=commons-io:commons-io,org.apache.commons:commons-lang3
```

This run drops `httpclient` (420 classes) and `commons-codec` (115 classes), and trims 535 unreferenced classes from retained `commons-compress` (saving 535 classes / 1.52 MiB from dropped JARs and 535 classes / 1.93 MiB from retained JARs).

### 6. Inspect the Post-Elision Dependency Tree

Run `dependency:tree` to confirm that Maven sees the trimmed dependency graph:

```sh
../../mvnw -Delide.mode=elision \
  -Delide.traceFiles=target/classes.log \
  -Delide.trimJars=true \
  -Delide.sourceRootsComplete=true \
  -Dmaven.compiler.proc=none \
  -Delide.excludedArtifacts=commons-io:commons-io,org.apache.commons:commons-lang3 \
  dependency:tree
```

The resulting tree omits `org.apache.httpcomponents:httpclient` and `commons-codec:commons-codec`, and retains trimmed `org.apache.commons:commons-compress:1.28.0`.

### 7. Permanent POM Configuration

Add the plugin to `pom.xml` under `<build><plugins>` to automate elision in routine builds:

```xml
<build>
  <plugins>
    <plugin>
      <groupId>io.github.spockz</groupId>
      <artifactId>dependency-elider-maven-plugin</artifactId>
      <version>0.1.0-SNAPSHOT</version>
      <executions>
        <execution>
          <!-- Binds automatically to the initialize lifecycle phase -->
          <goals>
            <goal>elide</goal>
          </goals>
        </execution>
      </executions>
      <configuration>
        <traceFiles>
          <traceFile>target/classes.log</traceFile>
        </traceFiles>
        <trimJars>true</trimJars>
      </configuration>
    </plugin>
  </plugins>
</build>
```

With this configuration:

* Standard commands (`./mvnw clean package`) run elision automatically during `initialize`.
* Diagnostic commands (`./mvnw dependency:tree`) reflect the post-elision dependency graph.
* When telemetry files are absent, elision passes through safely without modifying dependencies.

### Persisted Output Files

The `elide` goal writes two structured JSON records:

* `target/dependency-elider-report.json` (`-Delide.summaryFile`): Persisted snapshot consumed by `dependency-elider:report`.
* `target/dependency-elider-class-usage.json` (`-Delide.reportFile`): Detailed class-usage evidence.

All persisted stores use independent schema version 1. Incompatible pre-release drafts or unsupported schema versions fail fast.

For detailed configuration parameters, see [Plugin Usage](dependency-elider-maven-plugin/src/site/markdown/usage.md), the [User FAQ](docs/faq.md), and [Contributor Decisions and FAQ](docs/contributor-decisions-and-faq.md).

---

## Vulnerability Findings and Code Evidence

Software Composition Analysis (SCA) suffers from a **four-tier granularity mismatch**:

1. **Product-Level CPE Over-Matching**: Scanners flag every `io.netty:netty-*` sub-module for an issue isolated to `netty-codec-http2`.
2. **Artifact-Level Coarseness**: A single dormant utility class inside an artifact marks the entire JAR vulnerable.
3. **Compound Exploitability**: Most gadget chains require companion libraries and specific deserialization settings.
4. **Class & Method Execution Reality**: The JVM loads classes individually; massive portions of imported libraries never execute.

### The 1%–3% Vulnerability Reality

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

* **57% Transitive Bloat**: Soto-Valero et al. (KTH CASTOR, EMSE 2021) showed that **57% of transitive dependencies and 75.1% of all dependency relationships in Maven are completely bloated** (zero classes loaded).
* **88.8% CPE False Positives**: Ponta et al. (SAP Research, ICSME 2018) proved that **88.8% of findings** for code-covered CVEs were false positives driven by coarse CPE matching.
* **92%–95% Function Unreachability**: Telemetry from Snyk, Endor Labs, and Sonatype demonstrates that over 90% of vulnerability alerts in Java are unreachable at the method level.

For complete academic citations and analysis, see the [Project Rationale](dependency-elider-maven-plugin/src/site/markdown/rationale.md).

### Evidence Boundary and SBOM Scanning

Removing an artifact or class removes package bloat, but generating a formal `vulnerable_code_not_present` VEX statement requires precise symbol-to-CVE mapping:

* The plugin currently emits CycloneDX 1.6 trim pedigree; evidence-backed VEX generation is tracked in [RQ-0008](docs/research/RQ-0008-osv-sbom-comparison-and-vex-evidence.md).
* Run `make scan-sbom` to run OSV-Scanner offline against baseline and post-elision SBOMs, producing a hash-backed comparison report in `target/sbom-comparison/`.
* A finding is marked eliminated only when its package component is absent from the post-elision SBOM.

---

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

1. **Whole-Artifact Elision**: Candidates without runtime observations are verified against a unique compatible pre-elision graph capture before safe nodes are removed.
2. **Intra-JAR Link Closure**: For retained dependencies, ProGuard Core computes transitive link closure of all required types, interfaces, and annotations. Unreferenced classes are pruned while preserving resources, licenses, and SPI service providers.
3. **In-Memory Redirection**: Retained artifacts are redirected in-memory (`artifact.setFile(trimmedJar)`), allowing standard packaging plugins to consume the trimmed archives transparently.

---

## Source Roots and Support Limits

### Feature Support and Verification Status

These statuses summarize current evidence in the repository. Fixture and unit-test results are scoped to specific test cases and versions:

| Feature or Environment | Status | Evidence and Boundary |
| :--- | :--- | :--- |
| Single-project Maven elision lifecycle | Fixture verified | Packaged Maven CLI 3.9.11 [integration fixture](dependency-elider-maven-plugin/src/test/java/io/github/spockz/elider/plugin/DependencyContextLifecycleIntegrationTest.java#L446) runs `elide`, trims an unused class, and verifies a distinct direct TEST resolver call. |
| Shade and Spring Boot packaging | Fixture verified | Basic Shade 3.6.0 and Spring Boot 3.3.5 [example builds](examples/run-elision-cycle.sh#L658) verify trimmed packaging and runtime behavior under JDK 21. |
| Resolver extension and mediated artifact graph | Required; fixture verified | Graph-aware decisions require `.mvn/extensions.xml`. Without it, original repository artifacts remain visible. |
| Bare production `dependency:tree` | Example and fixture verified for Maven CLI 3.9.11 and Dependency Plugin 3.8.1 | With `.mvn/extensions.xml` and an active initialize-bound execution, `dependency:tree` automatically runs elision first. See [production lifecycle tests](dependency-elider-maven-plugin/src/test/java/io/github/spockz/elider/plugin/DependencyContextLifecycleIntegrationTest.java#L583) and [tree assertions](examples/run-elision-cycle.sh#L529). |
| Class reachability and safe dependency removal | Unit tested; fixture verified | Covers explicit roots, source references, framework metadata, and graph leaves with retention across ancestors, cycles, and diamonds. |
| Multi-release dependency JARs | Conservative pass-through | Retained multi-release JARs remain byte-identical; multi-release candidate archives are not trimmed. Optional strict mode can reject them. |
| JARs with root `module-info.class` | Conservative pass-through on classpath | Retained JARs with root module descriptors are not trimmed. JPMS module-path linkage is unsupported. |
| Multi-symbol vulnerability interpretation | Strict fail-closed (open design question) | When an advisory maps multiple vulnerable classes across wide version ranges (e.g. Jackson Core `CVE-2026-68494`), all mapped classes must be present in the original JAR for proof of absence. |
| Persisted report and CycloneDX pedigree | Unit tested; fixture verified | Verifies report structure, graph data, class and byte metrics, and example pedigree output. |
| Maven multi-module reactor with active elision | Bare-tree auto-preparation fails fast; active reactor elision unverified | Automatic preparation rejects multi-project reactors before rendering the tree. Concurrent multi-module elision is unverified. |
| Other Maven CLI versions | Unverified | Pinned to Maven CLI 3.9.11. Other Maven 3 versions and Maven 4 are unverified. |
| Java 25 class files | Supported | Pinned ProGuard Core 9.4.0 engine parses and analyzes class files through Java 27. |
| Process crash during publication | Unverified | Covers normal rollback on failure, not crash recovery or concurrent writers. |

### Configuration Rules & Safeguards

* **Source Roots (`elide.sourceRootsComplete`)**: Defaults to `false` (conservatively retains all compile-classpath JARs and classes). Set to `true` only when all production and generated sources exist before `INITIALIZE` with no downstream generation.
* **Framework Metadata Protection**: Service providers (`META-INF/services`), Spring factories, and GraalVM reflection configs automatically protect declaring and provider JARs from whole-artifact removal.
* **Bytecode Sanitization**: Trimmed JARs are written to `target/elided-artifacts/` with original files untouched. JAR digital signatures are removed to avoid signature validation failures.
* **Artifact Fingerprinting**: Maven's resolved and direct artifact views are fingerprinted before mutation. Any unexpected change aborts publication.

### Remaining Verification Work

* Add a parallel reactor integration fixture with two independent consumer modules under `mvn -T2`.
* Extend tree verification beyond single leaf graphs to deep transitive conflict and mediated scope graphs.
* Broaden testing beyond Maven CLI 3.9.11 and JDK 21.

---

## Provenance: CycloneDX 1.6

Trimmed components record their on-disk SHA-256 while preserving upstream coordinate ancestry:

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

---

## Reference Fixtures

The repository includes end-to-end integration fixtures under `examples/`:

| Fixture | Architecture | Target Demonstration |
| :--- | :--- | :--- |
| **`example-basic-app`** | Plain Java + Shade | Elides unused `commons-codec` and `httpclient` (removing `CVE-2014-3577`); produces a shrunken shaded JAR. |
| **`example-spring-boot-app`** | Spring Boot 3 Web | Retains candidates when no safe drop exists, trims Spring MVC under `BOOT-INF/lib`, and verifies HTTP endpoints. |
| **`example-cve-unused-app`** | Standalone CVE test | Trims unused `StringLookup` from `commons-text` to prove `CVE-2022-42889` absent and emits OpenVEX. |
| **`example-cve-safe-class-app`** | Standalone CVE test | Evaluates safe class usage without whole-artifact drops while preserving Logback/Spring runtime behavior. |

Run the full end-to-end verification suite across all fixtures:

```sh
make test-examples
```

Run standalone CVE fixture baselines:

```sh
./mvnw -f examples/example-cve-unused-app/pom.xml verify -Delide.mode=baseline
./mvnw -f examples/example-cve-safe-class-app/pom.xml verify -Delide.mode=baseline
```

### Sample Elision Report Output

`make test-examples` invokes `dependency-elider:report` after each build:

```text
example-basic-app
[INFO] Project: io.github.spockz:example-basic-app:0.1.0-SNAPSHOT
[INFO] Snapshot: last successful elide run at 2026-10-29T09:52:25.434919585Z
[INFO] Whole artifacts dropped: 2 (original JAR file bytes: 942.11 KiB)
[INFO] Program classes removed with dropped JARs: 535 (uncompressed .class entry payload bytes: 1.52 MiB; excludes module descriptors and archive sanitation metadata)
[INFO] Program classes pruned from retained JARs: 535 (uncompressed omitted .class payload bytes: 1.93 MiB; excludes module descriptors and archive metadata)
[INFO] Avoided CVEs (dropped artifacts):
[INFO]   - CVE-2014-3577 org.apache.httpcomponents:httpclient:jar:4.3.4
[INFO] Mitigated CVEs (vulnerable code pruned by trimming): none matched the available vulnerability mappings
[INFO] CVEs inactive due to unmet prerequisite dependencies: none matched the available vulnerability mappings
[INFO] Potentially conservative CVE exclusions: none detected
[INFO] Mediated TEST dependency graph (captured and saved by the elide goal):
[INFO]   - io.github.spockz:example-basic-app:0.1.0-SNAPSHOT {nodeId=n0} [RETAINED]
[INFO]   - io.github.spockz:example-basic-app:0.1.0-SNAPSHOT -> org.apache.commons:commons-compress:jar:1.28.0 (compile) {nodeId=n2} [RETAINED, CLASS_TRIMMED]
[INFO]   - io.github.spockz:example-basic-app:0.1.0-SNAPSHOT -> org.apache.httpcomponents:httpclient:jar:4.3.4 (compile) {nodeId=n1} [EFFECTIVE_DROP]
[INFO]   - io.github.spockz:example-basic-app:0.1.0-SNAPSHOT -> org.apache.commons:commons-compress:jar:1.28.0 (compile) -> commons-codec:commons-codec:jar:1.19.0 (compile) {nodeId=n4} [EFFECTIVE_DROP]
[INFO]   ...

example-spring-boot-app
[INFO] Project: io.github.spockz:example-spring-boot-app:0.1.0-SNAPSHOT
[INFO] Snapshot: last successful elide run at 2026-10-29T09:53:07.220225791Z
[INFO] Whole artifacts dropped: 0 (original JAR file bytes: 0 B)
[INFO] Program classes removed with dropped JARs: 0 (uncompressed .class entry payload bytes: 0 B; excludes module descriptors and archive sanitation metadata)
[INFO] Program classes pruned from retained JARs: 3409 (uncompressed omitted .class payload bytes: 8.49 MiB; excludes module descriptors and archive metadata)
[INFO] Avoided CVEs (dropped artifacts): none matched the available vulnerability mappings
[INFO] Mitigated CVEs (vulnerable code pruned by trimming): none matched the available vulnerability mappings
[INFO] CVEs inactive due to unmet prerequisite dependencies: none matched the available vulnerability mappings
[INFO] Potentially conservative CVE exclusions: none detected
[INFO] Mediated TEST dependency graph (captured and saved by the elide goal):
[INFO]   - io.github.spockz:example-spring-boot-app:0.1.0-SNAPSHOT {nodeId=n0} [RETAINED]
[INFO]   - io.github.spockz:example-spring-boot-app:0.1.0-SNAPSHOT -> org.springframework.boot:spring-boot-starter-web:jar:3.3.5 (compile) {nodeId=n1} [RETAINED]
[INFO]   - io.github.spockz:example-spring-boot-app:0.1.0-SNAPSHOT -> org.springframework:spring-context:jar:6.1.14 (compile) {nodeId=n2} [RETAINED, CLASS_TRIMMED]
[INFO]   ...

example-cve-unused-app
[INFO] Project: io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT
[INFO] Snapshot: last successful elide run at 2026-10-29T09:53:32.915824571Z
[INFO] Whole artifacts dropped: 0 (original JAR file bytes: 0 B)
[INFO] Program classes removed with dropped JARs: 0 (uncompressed .class entry payload bytes: 0 B; excludes module descriptors and archive sanitation metadata)
[INFO] Program classes pruned from retained JARs: 310 (uncompressed omitted .class payload bytes: 985.54 KiB; excludes module descriptors and archive metadata)
[INFO] Avoided CVEs (dropped artifacts): none matched the available vulnerability mappings
[INFO] Mitigated CVEs (vulnerable code pruned by trimming):
[INFO]   - CVE-2022-42889 org.apache.commons:commons-text:jar:1.9
[INFO] CVEs inactive due to unmet prerequisite dependencies: none matched the available vulnerability mappings
[INFO] Potentially conservative CVE exclusions: none detected
[INFO] Mediated TEST dependency graph (captured and saved by the elide goal):
[INFO]   ...

example-cve-safe-class-app
[INFO] Project: io.github.spockz:example-cve-safe-class-app:0.1.0-SNAPSHOT
[INFO] Snapshot: last successful elide run at 2026-10-29T09:53:45.784876234Z
[INFO] Whole artifacts dropped: 0 (original JAR file bytes: 0 B)
[INFO] Program classes removed with dropped JARs: 0 (uncompressed .class entry payload bytes: 0 B; excludes module descriptors and archive sanitation metadata)
[INFO] Program classes pruned from retained JARs: 108 (uncompressed omitted .class payload bytes: 433.66 KiB; excludes module descriptors and archive metadata)
[INFO] Avoided CVEs (dropped artifacts): none matched the available vulnerability mappings
[INFO] Mitigated CVEs (vulnerable code pruned by trimming): none matched the available vulnerability mappings
[INFO] CVEs inactive due to unmet prerequisite dependencies: none matched the available vulnerability mappings
[INFO] Potentially conservative CVE exclusions: none detected
[INFO] Mediated TEST dependency graph (captured and saved by the elide goal):
[INFO]   ...
```

---

## Dry-Run Analysis Output (`analyze`)

The non-mutating `analyze` goal identifies dependencies that would be elided and estimates byte savings:

```text
[INFO] Dependency Elider analysis summary
[INFO]   Artifacts that would be elided by this analysis: 1 / 2 (50.0%)
[INFO]   Estimated original JAR bytes for those artifacts: 151 B (sum of original on-disk input JAR sizes; final package delta may differ)
[INFO]   Program class entries in JARs that would be dropped: 1 (uncompressed .class entry payload bytes: 63 B; excludes module descriptors and archive sanitation metadata)
[INFO]   JAR trim cache: unavailable (trim stage not run)
[INFO]   Avoided CVEs (artifacts that would be dropped): none matched the available vulnerability mappings
[INFO]   Mitigated CVEs (vulnerable code that would be pruned by trimming): none matched the available vulnerability mappings
[INFO]   CVEs that would be inactive due to unmet prerequisite dependencies: none matched the available vulnerability mappings
[INFO]   CVEs that would be excluded due to conservative multi-symbol checks: none detected
```

For configuration options and supported telemetry formats, see [Maven Plugin Usage](dependency-elider-maven-plugin/src/site/markdown/usage.md).

---

## Requirements

* **Java 21** or newer.
* **Maven 3.9+**.

Local contributor requirements (Bash, Markdown linting, Caddy) and JMH benchmark procedures are documented in [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Contributing

Contributions are welcome! Please review [CONTRIBUTING.md](CONTRIBUTING.md) for local environment setup, build commands, and testing procedures.

---

## License

This project is licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
