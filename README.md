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

Internal persisted report and cache formats use independent schema version 1. Their unreleased schemas remain at version 1 and incompatible payloads fail fast. CycloneDX declares `specVersion` 1.6, and OpenVEX uses the 0.2.0 context URL; neither is an internal schema version. Each generated security document's top-level `version` is a document revision counter.

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

Removing an artifact or class removes package bloat, but a formal VEX statement requires precise symbol-to-CVE mapping and proof tied to the resulting artifacts:

* The current omitted-code evidence path is scoped to mapped vulnerable classes proven absent from a retained, trimmed archive. Core CycloneDX/OpenVEX serializers also support exact-class precondition evidence; Maven inventory collection and assessment/publication integration remain pending, so Maven does not emit precondition VEX yet. See [ADR-0008](docs/adr/0008-precondition-gated-vex-attestations.md).
* Precondition VEX requires an exact prerequisite class as well as its coordinate, plus explicit confirmation that the declared Maven build inventory is complete. Maven publication must revalidate inventory-fingerprint freshness; serializers rehash the exact affected component file. The claim does not cover providers added by later packaging or deployment runtime mechanisms. See [RQ-0013](docs/research/RQ-0013-precondition-gated-vex-and-multi-artifact-exploitability.md).
* The current report's inactive-precondition category is based on coordinate absence only. It is a finding for review, not proof that the prerequisite class is absent and not VEX evidence.
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
| Shade and Spring Boot packaging | Fixture verified | Basic Shade 3.6.0 and Spring Boot 3.3.5 [example checks](examples/run-elision-cycle.sh#L947) verify trimmed packaging and runtime behavior under JDK 21. |
| Resolver extension and mediated artifact graph | Required; fixture verified | Graph-aware decisions require `.mvn/extensions.xml`. Without it, original repository artifacts remain visible. |
| Bare production `dependency:tree` | Example and fixture verified for Maven CLI 3.9.11 and Dependency Plugin 3.8.1 | With `.mvn/extensions.xml` and an active initialize-bound execution, `dependency:tree` automatically runs elision first. See [production lifecycle tests](dependency-elider-maven-plugin/src/test/java/io/github/spockz/elider/plugin/DependencyContextLifecycleIntegrationTest.java#L583) and [tree assertions](examples/run-elision-cycle.sh#L808). |
| Class reachability and safe dependency removal | Unit tested; fixture verified | Covers explicit roots, source references, framework metadata, and graph leaves with retention across ancestors, cycles, and diamonds. |
| Multi-release dependency JARs | Conservative pass-through | Retained multi-release JARs remain byte-identical; multi-release candidate archives are not trimmed. Optional strict mode can reject them. |
| JARs with root `module-info.class` | Conservative pass-through on classpath | Retained JARs with root module descriptors are not trimmed. JPMS module-path linkage is unsupported. |
| ServiceLoader SPI roots and conservative exclusion | Supported; positive proof with conservative fallback | Detects constant `ServiceLoader` calls in application bytecode. Unproven SPI roots are retained by default (`<conservativeServiceLoaderRoots>true`); if vulnerable code is kept due to unproven SPI roots, the CVE is reported under conservative exclusions with POM override guidance. |
| Multi-symbol vulnerability interpretation | Strict fail-closed (open design question) | When an advisory maps multiple vulnerable classes across wide version ranges (e.g. Jackson Core `CVE-2026-68494`), all mapped classes must be present in the original JAR for proof of absence. |
| Persisted report and CycloneDX pedigree | Unit tested; fixture verified | Verifies report structure, graph data, class and byte metrics, and example pedigree output. |
| Maven multi-module reactor with active elision | One strict three-module chain verified on Maven CLI 3.9.11 and GraalVM JDK 21.0.12 | Sequential and `-T 4` `clean verify` builds pass with module-local schema-1 reports. The chain has no independent siblings, so broader reactor concurrency remains unverified. |
| Other Maven CLI versions | Unverified | Pinned to Maven CLI 3.9.11. Other Maven 3 versions and Maven 4 are unverified. |
| Java 25 class files | Supported | Pinned ProGuard Core 9.4.0 engine parses and analyzes class files through Java 27. |
| Process crash during publication | Unverified | Covers normal rollback on failure, not crash recovery or concurrent writers. |

### Configuration Rules & Safeguards

* **Source Roots (`elide.sourceRootsComplete`)**: Defaults to `false` (conservatively retains all compile-classpath JARs and classes). Set to `true` only when all production and generated sources exist before `INITIALIZE` with no downstream generation.
* **Conservative ServiceLoader Roots (`elide.conservativeServiceLoaderRoots`)**: Defaults to `true`. Scans application bytecode for constant `ServiceLoader.load` calls. When enabled, unproven SPI providers are retained for runtime safety; any CVE whose vulnerable code is preserved solely by unproven SPI roots is excluded from mitigation and reported under `Potentially conservative CVE exclusions`. Set to `false` (or `-Delide.conservativeServiceLoaderRoots=false`) to prune unproven SPI providers and eliminate dormant vulnerable code.
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
| **`example-basic-app`** | Plain Java + Shade | Elides unused `commons-codec` and `httpclient` (avoiding `CVE-2014-3577`); produces a shrunken shaded JAR. |
| **`example-spring-boot-app`** | Spring Boot 3 Web | Retains candidates when no safe drop exists, trims Spring MVC under `BOOT-INF/lib`, and flags conservative SPI retention (`CVE-2026-68494`). |
| **`example-cve-unused-app`** | Standalone CVE test | Trims unused `StringLookup` from `commons-text` to mitigate `CVE-2022-42889` and emits OpenVEX. |
| **`example-cve-safe-class-app`** | Standalone CVE test | Demonstrates inactive prerequisite dependency handling (`CVE-2025-11226` without Janino) while preserving runtime behavior. |
| **`example-multi-module-reactor`** | Three-module Maven reactor with Shade | Exercises module-local reports and dependency elision for `reactor-common` → `reactor-service` → `reactor-app`, under sequential and `-T 4` builds. |

Run the full end-to-end verification suite across all fixtures:

```sh
make test-examples
```

Run only the multi-module reactor checks:

```sh
make test-reactor-example
```

The multi-module reactor check runs a baseline build, then trace-driven builds with
the single-threaded and `-T 4` Maven builders. It asks the production `report` goal to
validate each child module's separate schema-1 snapshot, compares stable dependency,
class, and byte metrics across the two builds, verifies Shade's same-session classpath
uses the app-local trimmed Commons Compress JAR without Commons Codec, and runs the
shaded application. It also checks the original Compress hash and inventories known
transformed outputs in Maven's configured local repository before and after the builds.
Because its three modules form a strict dependency chain, Maven cannot execute sibling
modules concurrently in this fixture; `-T 4` verifies the threaded-builder path but
does not establish general reactor race safety.

Run standalone CVE fixture baselines:

```sh
./mvnw -f examples/example-cve-unused-app/pom.xml verify -Delide.mode=baseline
./mvnw -f examples/example-cve-safe-class-app/pom.xml verify -Delide.mode=baseline
```

### Sample Elision Report Output

The transcripts below come from configured Maven invocations. Run `make update-transcripts` to refresh them. Report dependency graphs keep the first three rows; an elision count and SHA-256 digest detect changes in omitted rows. Rerun the displayed fixture's full `report` command to inspect its graph without elision.

The CVE findings use only the two mappings in the pinned [transcript fixture](https://github.com/spockz/maven-dependency-elider/blob/main/scripts/fixtures/transcript-vulnerability-cache/README.md); they do not represent complete vulnerability coverage.

example-basic-app
<!-- BEGIN:transcript:report-basic-app -->

```text
$ ./mvnw \
  --batch-mode \
  --no-transfer-progress \
  -f \
  examples/example-basic-app/pom.xml \
  io.github.spockz:dependency-elider-maven-plugin:0.1.0-SNAPSHOT:report
Process exit status: 0
[INFO]
[INFO] -----------------< io.github.spockz:example-basic-app >-----------------
[INFO] Building Example: Basic Maven Application 0.1.0-SNAPSHOT
[INFO]   from pom.xml
[INFO] --------------------------------[ jar ]---------------------------------
[INFO]
[INFO] --- dependency-elider:0.1.0-SNAPSHOT:report (default-cli) @ example-basic-app ---
[INFO] Dependency Elider report
[INFO] Project: io.github.spockz:example-basic-app:0.1.0-SNAPSHOT
[INFO] Snapshot: last successful elide run at <TIMESTAMP>
[INFO] The snapshot does not revalidate changed inputs when this goal runs.
[INFO] Whole artifacts dropped: 2 (original JAR file bytes: 942.11 KiB)
[INFO] Program classes removed with dropped JARs: 535 (uncompressed .class entry payload bytes: 1.52 MiB; excludes module descriptors and archive sanitation metadata)
[INFO] Raw trace decision drops before graph safety: 2
[INFO]   - commons-codec:commons-codec:jar:1.19.0 (compile): 365.93 KiB original JAR, 115 class entries, 413.65 KiB
[INFO]   - org.apache.httpcomponents:httpclient:jar:4.3.4 (compile): 576.18 KiB original JAR, 420 class entries, 1.11 MiB
[INFO] Program classes pruned from retained JARs: 535 (uncompressed omitted .class payload bytes: 1.93 MiB; excludes module descriptors and archive metadata)
[INFO]   - org.apache.commons:commons-compress:jar:1.28.0 (compile): 535 classes, 1.93 MiB
[INFO] Avoided CVEs (dropped artifacts):
[INFO]   - CVE-2014-3577 org.apache.httpcomponents:httpclient:jar:4.3.4
[INFO] Mitigated CVEs (vulnerable code pruned by trimming): none matched the available vulnerability mappings
[INFO] CVEs inactive due to unmet prerequisite dependencies: none matched the available vulnerability mappings
[INFO] Potentially conservative CVE exclusions: none detected
[INFO] Mediated TEST dependency graph (captured and saved by the elide goal):
[INFO]   - io.github.spockz:example-basic-app:0.1.0-SNAPSHOT {nodeId=n0} [RETAINED]
[INFO]   - io.github.spockz:example-basic-app:0.1.0-SNAPSHOT -> org.apache.commons:commons-compress:jar:1.28.0 (compile) {nodeId=n2} [RETAINED, CLASS_TRIMMED]
[INFO]   - io.github.spockz:example-basic-app:0.1.0-SNAPSHOT -> org.apache.httpcomponents:httpclient:jar:4.3.4 (compile) {nodeId=n1} [EFFECTIVE_DROP]
[INFO]   ... 11 dependency graph rows elided (sha256:0bc2b8d079442ffdd62b0c7c8448bea58357a2287a870859362982360e2dcc12)
[INFO] ------------------------------------------------------------------------
[INFO] ------------------------------------------------------------------------
[INFO] Total time: <BUILD_TIME>
[INFO] Finished at: <TIMESTAMP>
[INFO] ------------------------------------------------------------------------
```

<!-- END:transcript:report-basic-app -->

example-spring-boot-app
<!-- BEGIN:transcript:report-spring-boot-app -->

```text
$ ./mvnw \
  --batch-mode \
  --no-transfer-progress \
  -f \
  examples/example-spring-boot-app/pom.xml \
  io.github.spockz:dependency-elider-maven-plugin:0.1.0-SNAPSHOT:report
Process exit status: 0
[INFO]
[INFO] --------------< io.github.spockz:example-spring-boot-app >--------------
[INFO] Building Example: Spring Boot Application 0.1.0-SNAPSHOT
[INFO]   from pom.xml
[INFO] --------------------------------[ jar ]---------------------------------
[INFO]
[INFO] --- dependency-elider:0.1.0-SNAPSHOT:report (default-cli) @ example-spring-boot-app ---
[INFO] Dependency Elider report
[INFO] Project: io.github.spockz:example-spring-boot-app:0.1.0-SNAPSHOT
[INFO] Snapshot: last successful elide run at <TIMESTAMP>
[INFO] The snapshot does not revalidate changed inputs when this goal runs.
[INFO] Whole artifacts dropped: 0 (original JAR file bytes: 0 B)
[INFO] Program classes removed with dropped JARs: 0 (uncompressed .class entry payload bytes: 0 B; excludes module descriptors and archive sanitation metadata)
[INFO] Raw trace decision drops before graph safety: 0
[INFO] Program classes pruned from retained JARs: 3409 (uncompressed omitted .class payload bytes: 8.49 MiB; excludes module descriptors and archive metadata)
[INFO]   - com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile): 53 classes, 92.44 KiB
[INFO]   - com.fasterxml.jackson.datatype:jackson-datatype-jsr310:jar:2.18.2 (compile): 4 classes, 18.07 KiB
[INFO]   - com.github.spotbugs:spotbugs-annotations:jar:4.10.5 (runtime): 21 classes, 14.79 KiB
[INFO]   - com.google.code.findbugs:jsr305:jar:3.0.2 (runtime): 23 classes, 13.91 KiB
[INFO]   - com.thoughtworks.xstream:xstream:jar:1.4.21 (runtime): 215 classes, 532.65 KiB
[INFO]   - io.micrometer:context-propagation:jar:1.1.2 (runtime): 10 classes, 22.33 KiB
[INFO]   - org.apache.groovy:groovy-xml:jar:4.0.23 (runtime): 48 classes, 186.54 KiB
[INFO]   - org.apache.groovy:groovy:jar:4.0.23 (runtime): 2541 classes, 6.19 MiB
[INFO]   - org.freemarker:freemarker:jar:2.3.33 (runtime): 304 classes, 809.26 KiB
[INFO]   - org.hdrhistogram:HdrHistogram:jar:2.2.2 (runtime): 37 classes, 118.76 KiB
[INFO]   - org.slf4j:slf4j-api:jar:2.0.16 (compile): 5 classes, 6.38 KiB
[INFO]   - org.springframework:spring-jcl:jar:6.1.14 (compile): 1 classes, 1.24 KiB
[INFO]   - org.springframework:spring-webmvc:jar:6.1.14 (compile): 146 classes, 524.46 KiB
[INFO]   - org.webjars:webjars-locator-core:jar:0.58 (runtime): 1 classes, 10.66 KiB
[INFO] Avoided CVEs (dropped artifacts): none matched the available vulnerability mappings
[INFO] Mitigated CVEs (vulnerable code pruned by trimming): none matched the available vulnerability mappings
[INFO] CVEs inactive due to unmet prerequisite dependencies: none matched the available vulnerability mappings
[INFO] Potentially conservative CVE exclusions:
[INFO]   - CVE-2026-68494 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2
[INFO]     Reason: Vulnerable code was retained due to conservative ServiceLoader SPI root com.fasterxml.jackson.core.ObjectCodec, com.fasterxml.jackson.databind.ObjectMapper without positive proof of use in application bytecode.
[INFO]     Actionable POM override to certify if absent classes do not apply to your version:
[INFO]       <configuration>
[INFO]         <conservativeServiceLoaderRoots>false</conservativeServiceLoaderRoots>
[INFO]       </configuration>
[INFO] Mediated TEST dependency graph (captured and saved by the elide goal):
[INFO]   - io.github.spockz:example-spring-boot-app:0.1.0-SNAPSHOT {nodeId=n0} [RETAINED]
[INFO]   - io.github.spockz:example-spring-boot-app:0.1.0-SNAPSHOT -> com.github.spotbugs:spotbugs-annotations:jar:4.10.5 (runtime) {nodeId=n7} [RETAINED, CLASS_TRIMMED]
[INFO]   - io.github.spockz:example-spring-boot-app:0.1.0-SNAPSHOT -> com.google.code.findbugs:jsr305:jar:3.0.2 (runtime) {nodeId=n15} [RETAINED, CLASS_TRIMMED]
[INFO]   ... 89 dependency graph rows elided (sha256:5082109f83310856c6f3acf66c18c39611673d69a08ee28c82234ddc38f21744)
[INFO] ------------------------------------------------------------------------
[INFO] ------------------------------------------------------------------------
[INFO] Total time: <BUILD_TIME>
[INFO] Finished at: <TIMESTAMP>
[INFO] ------------------------------------------------------------------------
```

<!-- END:transcript:report-spring-boot-app -->

example-cve-unused-app
<!-- BEGIN:transcript:report-cve-unused-app -->

```text
$ ./mvnw \
  --batch-mode \
  --no-transfer-progress \
  -f \
  examples/example-cve-unused-app/pom.xml \
  io.github.spockz:dependency-elider-maven-plugin:0.1.0-SNAPSHOT:report
Process exit status: 0
[INFO]
[INFO] --------------< io.github.spockz:example-cve-unused-app >---------------
[INFO] Building Example: Graph-Backed CVE Dependency Analysis 0.1.0-SNAPSHOT
[INFO]   from pom.xml
[INFO] --------------------------------[ jar ]---------------------------------
[INFO]
[INFO] --- dependency-elider:0.1.0-SNAPSHOT:report (default-cli) @ example-cve-unused-app ---
[INFO] Dependency Elider report
[INFO] Project: io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT
[INFO] Snapshot: last successful elide run at <TIMESTAMP>
[INFO] The snapshot does not revalidate changed inputs when this goal runs.
[INFO] Whole artifacts dropped: 0 (original JAR file bytes: 0 B)
[INFO] Program classes removed with dropped JARs: 0 (uncompressed .class entry payload bytes: 0 B; excludes module descriptors and archive sanitation metadata)
[INFO] Raw trace decision drops before graph safety: 0
[INFO] Program classes pruned from retained JARs: 310 (uncompressed omitted .class payload bytes: 985.54 KiB; excludes module descriptors and archive metadata)
[INFO]   - com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile): 70 classes, 163.47 KiB
[INFO]   - org.apache.commons:commons-text:jar:1.9 (compile): 132 classes, 388.41 KiB
[INFO]   - org.codehaus.janino:commons-compiler:jar:3.1.12 (compile): 51 classes, 96.78 KiB
[INFO]   - org.codehaus.janino:janino:jar:3.1.12 (compile): 52 classes, 330.49 KiB
[INFO]   - org.slf4j:slf4j-api:jar:2.0.17 (compile): 5 classes, 6.38 KiB
[INFO] Avoided CVEs (dropped artifacts): none matched the available vulnerability mappings
[INFO] Mitigated CVEs (vulnerable code pruned by trimming):
[INFO]   - CVE-2022-42889 org.apache.commons:commons-text:jar:1.9
[INFO] CVEs inactive due to unmet prerequisite dependencies: none matched the available vulnerability mappings
[INFO] Potentially conservative CVE exclusions: none detected
[INFO] Mediated TEST dependency graph (captured and saved by the elide goal):
[INFO]   - io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT {nodeId=n0} [RETAINED]
[INFO]   - io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT -> ch.qos.logback:logback-classic:jar:1.5.18 (compile) {nodeId=n3} [RETAINED]
[INFO]   - io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT -> com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) {nodeId=n2} [RETAINED, CLASS_TRIMMED]
[INFO]   ... 23 dependency graph rows elided (sha256:5cce3d43de14f83342509d9d36b89de07db34786f505418566e4a51c4126d74c)
[INFO] ------------------------------------------------------------------------
[INFO] ------------------------------------------------------------------------
[INFO] Total time: <BUILD_TIME>
[INFO] Finished at: <TIMESTAMP>
[INFO] ------------------------------------------------------------------------
```

<!-- END:transcript:report-cve-unused-app -->

example-cve-safe-class-app
<!-- BEGIN:transcript:report-cve-safe-class-app -->

```text
$ ./mvnw \
  --batch-mode \
  --no-transfer-progress \
  -f \
  examples/example-cve-safe-class-app/pom.xml \
  io.github.spockz:dependency-elider-maven-plugin:0.1.0-SNAPSHOT:report
Process exit status: 0
[INFO]
[INFO] ------------< io.github.spockz:example-cve-safe-class-app >-------------
[INFO] Building Example: Graph-Backed CVE Dependency Analysis with Logback 0.1.0-SNAPSHOT
[INFO]   from pom.xml
[INFO] --------------------------------[ jar ]---------------------------------
[INFO]
[INFO] --- dependency-elider:0.1.0-SNAPSHOT:report (default-cli) @ example-cve-safe-class-app ---
[INFO] Dependency Elider report
[INFO] Project: io.github.spockz:example-cve-safe-class-app:0.1.0-SNAPSHOT
[INFO] Snapshot: last successful elide run at <TIMESTAMP>
[INFO] The snapshot does not revalidate changed inputs when this goal runs.
[INFO] Whole artifacts dropped: 0 (original JAR file bytes: 0 B)
[INFO] Program classes removed with dropped JARs: 0 (uncompressed .class entry payload bytes: 0 B; excludes module descriptors and archive sanitation metadata)
[INFO] Raw trace decision drops before graph safety: 0
[INFO] Program classes pruned from retained JARs: 5 (uncompressed omitted .class payload bytes: 6.38 KiB; excludes module descriptors and archive metadata)
[INFO]   - org.slf4j:slf4j-api:jar:2.0.17 (compile): 5 classes, 6.38 KiB
[INFO] Avoided CVEs (dropped artifacts): none matched the available vulnerability mappings
[INFO] Mitigated CVEs (vulnerable code pruned by trimming): none matched the available vulnerability mappings
[INFO] CVEs inactive due to unmet prerequisite dependencies:
[INFO]   - CVE-2025-11226 ch.qos.logback:logback-classic:jar:1.5.18
[INFO] Potentially conservative CVE exclusions: none detected
[INFO] Mediated TEST dependency graph (captured and saved by the elide goal):
[INFO]   - io.github.spockz:example-cve-safe-class-app:0.1.0-SNAPSHOT {nodeId=n0} [RETAINED]
[INFO]   - io.github.spockz:example-cve-safe-class-app:0.1.0-SNAPSHOT -> ch.qos.logback:logback-classic:jar:1.5.18 (compile) {nodeId=n1} [RETAINED]
[INFO]   - io.github.spockz:example-cve-safe-class-app:0.1.0-SNAPSHOT -> org.junit.jupiter:junit-jupiter:jar:5.11.4 (test) {nodeId=n3} [RETAINED]
[INFO]   ... 17 dependency graph rows elided (sha256:f0bea8653ca4e1b295c4019add6825462b22699991afed07c449d7c86c161fdf)
[INFO] ------------------------------------------------------------------------
[INFO] ------------------------------------------------------------------------
[INFO] Total time: <BUILD_TIME>
[INFO] Finished at: <TIMESTAMP>
[INFO] ------------------------------------------------------------------------
```

<!-- END:transcript:report-cve-safe-class-app -->

---

## Dry-Run Analysis Output (`analyze`)

The `analyze` goal previews dependencies and byte savings without changing artifacts, classpaths, or packages. It writes class-usage evidence to `elide.reportFile`; the transcript invocation places that output under ignored `.scratch/`:

<!-- BEGIN:transcript:analyze-basic-app -->

```text
$ ./mvnw \
  --batch-mode \
  --no-transfer-progress \
  --offline \
  -f \
  examples/example-basic-app/pom.xml \
  io.github.spockz:dependency-elider-maven-plugin:0.1.0-SNAPSHOT:analyze \
  -Delide.traceFiles=$TRANSCRIPT_EVIDENCE/example-basic-app.log \
  -Delide.trimJars=true \
  -Delide.sourceRootsComplete=true \
  -Dmaven.compiler.proc=none \
  -Delide.excludedArtifacts=commons-io:commons-io,org.apache.commons:commons-lang3 \
  -Delide.cveCacheDirectory=$TRANSCRIPT_EVIDENCE/vulnerability-cache \
  -Delide.reportFile=$PROJECT_ROOT/.scratch/transcript-analysis/analyze-basic-app-class-usage.json
Process exit status: 0
[INFO]
[INFO] -----------------< io.github.spockz:example-basic-app >-----------------
[INFO] Building Example: Basic Maven Application 0.1.0-SNAPSHOT
[INFO]   from pom.xml
[INFO] --------------------------------[ jar ]---------------------------------
[INFO]
[INFO] --- dependency-elider:0.1.0-SNAPSHOT:analyze (default-cli) @ example-basic-app ---
[INFO] Dependency Elider analysis summary
[INFO]   Artifacts that would be elided by this analysis: 2 / 13 (15.4%)
[INFO]   Estimated original JAR bytes for those artifacts: 942.11 KiB (sum of original on-disk input JAR sizes; final package delta may differ)
[INFO]   Program class entries in JARs that would be dropped: 535 (uncompressed .class entry payload bytes: 1.52 MiB; excludes module descriptors and archive sanitation metadata)
[INFO]   JAR trim cache: 0 validated hit(s), 3 analysis run(s)
[INFO]   Avoided CVEs (artifacts that would be dropped):
[INFO]     CVE-2014-3577 org.apache.httpcomponents:httpclient:jar:4.3.4
[INFO]   Mitigated CVEs (vulnerable code that would be pruned by trimming): none matched the available vulnerability mappings
[INFO]   CVEs that would be inactive due to unmet prerequisite dependencies: none matched the available vulnerability mappings
[INFO]   CVEs that would be excluded due to conservative multi-symbol checks: none detected
[INFO]   Class usage report: <PROJECT_ROOT>/.scratch/transcript-analysis/analyze-basic-app-class-usage.json
[INFO] ------------------------------------------------------------------------
[INFO] ------------------------------------------------------------------------
[INFO] Total time: <BUILD_TIME>
[INFO] Finished at: <TIMESTAMP>
[INFO] ------------------------------------------------------------------------
```

<!-- END:transcript:analyze-basic-app -->

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
