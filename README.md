<!-- WHY: Introduces the project, its core value proposition, quick start, and architectural model. -->
# Maven Dependency Elider

[![Build](https://github.com/spockz/maven-dependency-elider/actions/workflows/check.yml/badge.svg)](https://github.com/spockz/maven-dependency-elider/actions/workflows/check.yml)
[![Documentation](https://img.shields.io/badge/docs-GitHub%20Pages-blue.svg)](https://spockz.github.io/maven-dependency-elider/)
[![Java 21](https://img.shields.io/badge/Java-21-blue.svg)](https://openjdk.org/projects/jdk/21/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

Software Composition Analysis (SCA) frequently surfaces vulnerabilities in dependencies that an application never actually executes. **Maven Dependency Elider** combines runtime JVM telemetry with static bytecode reachability to safely drop unused dependencies and slice unreferenced classes during your Maven build.

Whole-artifact removal runs only when a compatible mediated graph proves the exact safe nodes to elide; otherwise candidates are safely retained. Trimmed outputs include schema-valid CycloneDX 1.6 SBOMs with pedigree provenance.

```text
       Dual Evidence Sources              Maven Build Lifecycle               Lean Distribution
┌─────────────────────────────────┐   ┌────────────────────────────┐         ┌───────────────────┐
│ Runtime JVM Telemetry           │   │   compile                  │         │ Slashed JAR Size  │
│ • CDS Class Lists / JFR events  │   │   test  (validates elision)│ ──────> │ Zero Bloat CVEs   │
│ • -Xlog:class+load / JaCoCo     │   │   package (Shade / Boot)   │         │ CycloneDX 1.6 SBOM│
│                                 │──>└────────────────────────────┘         │ Pedigree Provenance│
│ Static Reachability & Closure   │                 ▲                        └───────────────────┘
│ • Application Bytecode & Sources│                 │
│ • ProGuard Core Link Closure    │        In-Memory Redirection
│ • SPI Providers & GraalVM Meta  │      (Transparent to Packagers)
└─────────────────────────────────┘
```

## Why Maven Dependency Elider?

* **Dual Evidence Foundation**: Combines concrete runtime JVM telemetry (CDS lists, `-Xlog:class+load`, JFR events, JaCoCo coverage) with rigorous static bytecode and descriptor reachability (application roots, ProGuard Core closed-world link closure, `ServiceLoader` SPI provider declarations, and GraalVM reachability metadata).
* **Early Regression Detection**: Injects trimmed dependency views into Maven at `process-classes`, after production compilation and before tests and packaging.
* **Two-Tier Size Reduction**:
  * **Whole-Artifact Elision**: Removes unused dependencies from effective classpaths and packaged archives.
  * **Intra-JAR Trimming**: Slices unreferenced classes from retained JARs using ProGuard Core link closure, preserving required resources, SPI providers, and licenses.
* **Transparent Packaging**: Functions out-of-the-box with `maven-shade-plugin` and `spring-boot-maven-plugin` without custom archive wrappers.
* **Verifiable Provenance**: Emits schema-valid CycloneDX 1.6 SBOMs recording trimmed component SHA-256 hashes and ancestral pedigree.

### GraalVM native-image metadata

The plugin models class roots and supported reachability descriptors from dependency `META-INF/native-image/**` metadata. Its audited option inventory is bounded to GraalVM Native Image 21.0.12+7.1; recognized class, package, configuration, and indirection inputs are parsed or reported as errors. Syntactically valid options outside the inventory are accepted without inferred roots, so unknown future options that name classes are not covered by a universal completeness guarantee. Configuration paths and descriptor schemas are documented in [ADR-0009](docs/adr/0009-permissive-graalvm-native-image-metadata-ingestion.md).

---

## Project Modules

| Module | Purpose |
| --- | --- |
| `elider-core` | Maven-independent analysis engine: trace readers, bytecode scanning, ProGuard link-closure trimming, advisory/VEX matching, and CycloneDX 1.6 SBOM/VEX generation. |
| `elider-native-image` | GraalVM Native Image `META-INF/native-image/**` descriptor/configuration parsing and Spring AOT root resolution. |
| `elider-maven-lifecycle` | Maven core extension (`EliderLifecycleParticipant`, Resolver decorators/session hooks), graph capture/projection, effective-graph safety policy, and banished-dependency preflight. |
| `dependency-elider-maven-plugin` | Maven plugin (`analyze`, `elide`, `report`, and advisory index Mojos), Maven execution/report orchestration, and plugin documentation site. |
| `elider-benchmarks` | JMH microbenchmarks for trim-cache and elision hot paths. |
| `examples` | Consumer application fixtures (Basic, Spring Boot, CVE/advisory fixtures) used by integration checks. |

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

> **Note**: Without this extension, ordinary trace-derived whole-artifact drops normally remain retained, though intra-JAR trimming still functions. When an explicit ban is requested, Elide uses isolated current-model Resolver planning and may also evaluate unrelated trace-derived drops; both the ban and ordinary drops require graph and retained-content closure before publication.

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
  -Delide.closedWorld=true \
  -Delide.productionClassesComplete=true \
  -Dmaven.compiler.proc=none \
  -Delide.retainedArtifacts=commons-io:commons-io,org.apache.commons:commons-lang3
```

This sample treats the captured class-load log as the intended workload boundary. Structural
references remain required, while unobserved method-body references may be excluded.

On this Basic fixture, `analyze` identifies two whole-artifact candidates out of thirteen (942.11 KiB of original JAR bytes). The pinned cache retains the `CVE-2014-3577` package finding and its commit-derived `AbstractVerifier` review candidate. Analysis reports these findings without trim proof or VEX.

### 5. Build with Elision (`elide`)

Run `elide` alongside your packaging goals to trim dependencies and generate sanitized outputs:

```sh
../../mvnw clean package \
  -Delide.mode=elision \
  -Delide.traceFiles=target/classes.log \
  -Delide.trimJars=true \
  -Delide.retainedArtifacts=commons-io:commons-io,org.apache.commons:commons-lang3
```

This run drops `httpclient` (420 classes) and `commons-codec` (115 classes), and trims 535 unreferenced classes from retained `commons-compress` (saving 535 classes / 1.52 MiB from dropped JARs and 535 classes / 1.93 MiB from retained JARs).

### 6. Inspect the Post-Elision Dependency Tree

Run `dependency:tree` to confirm that Maven sees the trimmed dependency graph:

```sh
../../mvnw -Delide.mode=elision \
  -Delide.traceFiles=target/classes.log \
  -Delide.trimJars=true \
  -Delide.retainedArtifacts=commons-io:commons-io,org.apache.commons:commons-lang3 \
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
          <!-- Defaults to process-classes; an explicit phase remains authoritative -->
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

* Standard commands (`./mvnw clean package`) run elision automatically during `process-classes`.
* Diagnostic commands (`./mvnw dependency:tree`) reflect the post-elision dependency graph.
* When telemetry files are absent, elision passes through safely without modifying dependencies.

Closed-world class liveness is opt-in with `-Delide.closedWorld=true` or `<closedWorld>true</closedWorld>`.
Each configured evidence file must contain a class observation that matches project output or a
resolved dependency; a valid file does not make an empty, malformed, or irrelevant sibling file
acceptable. The allowed class set combines observed classes with explicit trim roots and active
dynamic roots. Structural class references remain required regardless of this set. JaCoCo
execution data contributes classes with hit probes and is recorded as probe evidence; it does not
claim complete class loading. Graal reachability configuration is not runtime class evidence.
Reports preserve the mode, normalized allowed classes, evidence kinds, and operation fingerprint
under the policy identity.

### Persisted Output Files

The `elide` goal writes two structured JSON records:

* `target/dependency-elider-report.json` (`-Delide.summaryFile`): Persisted snapshot consumed by `dependency-elider:report`.

The persisted Elide summary records ban outcomes in `appliedBans`. Its `rawDroppedCoordinates` metric excludes policy-forced absences, while total absent-artifact metrics include them.

Duplicate classes fail analysis by default. Use `elide.retainDuplicateClassOwners` to accept
specific class names or globs and retain every provider JAR whole, or
`elide.trimDuplicateClassOwners` to keep the duplicates in every provider while trimming unused
sibling classes. Both goals log accepted duplicates and record them under `toleratedDuplicates`
in their reports. See [Plugin Usage](dependency-elider-maven-plugin/src/site/markdown/usage.md)
for matching rules and configuration examples.

* `target/dependency-elider-class-usage.json` (`-Delide.reportFile`): Detailed class-usage evidence.

The `analyze` goal also writes a summary in the same format to
`target/dependency-elider-analysis-report.json` (`-Delide.analysisSummaryFile`). It preserves the
last applied report. Both goals print the same report fields; the `ANALYSIS` snapshot describes
planned actions, while the `APPLIED` snapshot describes the published result. To replay analysis,
run `dependency-elider:report -Delide.summaryFile=target/dependency-elider-analysis-report.json`.
The report goal reads the snapshot and does not re-run the analysis or advisory lookup.
Generic finding rows retain detached `prerequisiteProof` evidence: the selected group
operators, each prerequisite member's observed final presence, provider paths and digests, and
baseline-to-final attribution. The `report` goal renders those saved observations without reopening
the archives; replay does not recreate a proof-capable attestation. An `ANALYSIS` report may carry
verified prerequisite absence from a complete scan of the current runtime inventory when
`elide.preconditionClassPathComplete=true` is enabled. Direct Analyze also requires
`elide.productionClassesComplete=true`. This proof does not depend on Elide having removed the
class during the current invocation. Analyze does not publish CycloneDX or OpenVEX files.

Analyze may also save a separate `prerequisitePrediction` when it forecasts planned artifact or
class removals. It has no final archive fingerprint and remains a forecast; planned absence is not
physical proof. Reports replay both the captured physical observations and forecasts without
reopening the providers.

The saved elision report and Analyze class-usage report include `exclusionReview`, with an explicit
unavailable reason when the pre-resolution lifecycle capture is absent. Repeated exact exclusions
count effective dependency paths once each and retain declaration and exclusion origins
independently; incomplete provenance is stated explicitly. Dependency-management-only exclusions
are separate observations. These are
review findings, not POM edits or proof that a global ban is equivalent: Maven exclusions affect
dependency collection and mediation, while a post-resolution ban affects current project output and
may remove content needed by consumers. The `report` goal replays the saved findings.

The elision report requires `executionEnvironment.targetRelease` and
`executionEnvironment.runtimeRelease`. The target is Elider's selected analysis baseline; a
release from the effective compile configuration takes precedence, then its configured target,
then the active runtime feature as Elider's analysis default. Target-only configuration is valid;
source-only configuration does not select a target. The default `compile` execution is considered
even when its POM entry has no explicit goals, while `testCompile` does not select the production
target. The runtime field records the JDK running Maven. The `report` goal validates and replays both
saved values without substituting the current runtime, and neither value makes the active JDK class
table a historical API model.

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

* OSV Maven, CVE List v5, manual vulnerability mappings, and explicitly selected mapping catalogs independently contribute common findings. Catalogs are resolved as data-only Maven artifacts using `-Delide.vulnerabilityMappingCatalogs=groupId:artifactId:version[:type[:classifier]]`; pin a released version. The artifact must contain `META-INF/elider/vulnerability-mappings.json`. Catalog artifacts do not enter the application dependency graph, classpath, inventory, or SBOM. The saved report records resolved coordinates, observed SHA-256, catalog schema, row IDs, and provenance; the digest identifies observed bytes and does not authenticate the publisher. Automatic code paths normalize into sets and affected-version ranges combine by union, preserving gaps. The merge contract assigns supplied fields scoped priority POM/manual > catalog > automatic. Omitted fields can be enriched, and manual LOW/MEDIUM intent remains review-only. A POM `versionRangeSpec` is evidence scope by default, including an exact pin; set `<assertsAffected>true</assertsAffected>` only when the POM mapping independently asserts affectedness. Scope does not imply unaffectedness outside the range. Provenance is retained for reporting, while effective claims use the same applicability and verification rules. Severity does not affect merging. See [ADR-0014](docs/adr/0014-source-independent-vulnerability-findings.md) and the [vulnerability FAQ](docs/faq.md#which-sources-produce-vulnerability-findings).
* An optional Snyk API lookup adds findings for the project's queried Maven package versions when enabled with an authorized account. See [Snyk configuration](dependency-elider-maven-plugin/src/site/markdown/usage.md#optional-snyk-package-findings).
* Malformed CVE List and OSV records or affected entries are skipped independently. The affected source is reported as `PARTIAL` with diagnostics and a count, so the remaining findings can be used without implying complete coverage.
* Omitted-code proof requires exact component/version binding, unambiguous attribution of the effective declared code to the original artifact, and physical absence of every required declared class from the resulting artifact. Manual priority and confidence labels cannot bypass those checks. Manual `LOW`/`MEDIUM` preserves review-only intent, including when code is enriched from automatic sources. Package-only findings, heuristic hints and unresolved attribution do not establish omission proof. The observation covers declared code, not the independent truth or completeness of an advisory. Precondition evidence additionally requires the complete opted-in inventory described in [ADR-0008](docs/adr/0008-precondition-gated-vex-attestations.md).
* `elide.assumeConventionalJavaSourceLayout` controls the supported source-root translation and is retained with attribution in the saved report; it does not authorize ambiguous filename matching or waive physical verification. The `report` goal replays saved results without reassessing the current configuration. Package-only and heuristic findings retain source attribution and explicit unsupported data; advisory-only identities remain visible without fabricated CVEs. Removed, trimmed and unchanged describe inventory facts rather than mitigation.
* Precondition VEX requires an exact prerequisite class and coordinate plus `-Delide.preconditionClassPathComplete=true` to opt into a complete inventory. The proof's class-provider scan covers production class/resource outputs and non-test-scoped effective dependency archives. Isolated test sources, classes, resources, and test-scoped dependency archives are excluded from that scan; their dependency-scope rows remain in the resolver decision and SBOM. Default `testCompile` and `testResources` may run. Test output overlapping production roots, custom test compiler arguments or output directories that could redirect providers, and unmodeled production writers still suppress proof. Only production compilation needs the modeled compiler processor and target settings. If Maven reaches tests, `-DskipTests=true` is required to prevent test code from changing production outputs after capture; `maven.test.skip=true` is not required. Direct `elide` and `analyze` can inspect current runtime inputs when `elide.productionClassesComplete=true` asserts complete compiled output; lifecycle provenance alone is not required. Analyze records physical absence from the current complete inventory, while removals present only in its plan remain predictions. The proof concerns declared Maven runtime inputs; it does not inspect later packaging or deployment-provided classes. See [ADR-0008](docs/adr/0008-precondition-gated-vex-attestations.md) and [RQ-0013](docs/research/RQ-0013-precondition-gated-vex-and-multi-artifact-exploitability.md).
The guard models packaging only for maven-shade-plugin 3.6.0 with one `package`/`shade` execution and a built-in manifest transformer with a resolved main class. Any request that reaches a modeled JAR package execution must include `clean` first so the standard JAR plugin cannot reuse an older archive; Shade packaging is covered as an additional package path. Clean skip/exclusion/failure overrides and deferred clean modes suppress proof. It accepts only the inherited signature-resource exclusions shown in the examples; custom Shade filters, transformers, inputs, dependencies, source-JAR properties, and custom JAR plugin configuration suppress proof.
If the requested lifecycle reaches `test`, exact-class proof also requires the standard Maven Surefire Plugin 3.5.2 `default-test` execution and explicit `-DskipTests=true`. Maven still compiles test sources, but isolated test outputs are excluded from the runtime inventory; the example harness runs baseline tests normally.
* `PREREQUISITES_ABSENT` requires a complete opted-in inventory proving every effective prerequisite coordinate/class pair absent for the exact affected version. Same-priority pairs combine as sets, and manual supplied pairs replace automatic pairs within scope. Missing or unresolved prerequisites and review-only intent prevent that proof. Code and prerequisite groups are assessed independently; if both proofs succeed, omitted-code evidence is published once.
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
| Single-project Maven elision lifecycle | Fixture verified | Packaged Maven CLI 3.9.11 [integration fixture](dependency-elider-maven-plugin/src/test/java/io/github/spockz/elider/plugin/DependencyContextLifecycleIT.java#L446) runs `elide`, trims an unused class, and verifies a distinct direct TEST resolver call. |
| Shade and Spring Boot packaging | Fixture verified | Basic Shade 3.6.0 and Spring Boot 3.3.5 [example checks](examples/run-elision-cycle.sh#L947) verify trimmed packaging and runtime behavior under JDK 21. |
| Resolver extension and mediated artifact graph | Required; fixture verified | Graph-aware decisions require `.mvn/extensions.xml`. Without it, original repository artifacts remain visible. |
| Bare production `dependency:tree` | Example and fixture verified for Maven CLI 3.9.11 and Dependency Plugin 3.8.1 | With `.mvn/extensions.xml` and an active elider execution, `dependency:tree` automatically runs elision first at the selected phase (process-classes by default). See [production lifecycle tests](dependency-elider-maven-plugin/src/test/java/io/github/spockz/elider/plugin/DependencyContextLifecycleIT.java#L583) and [tree assertions](examples/run-elision-cycle.sh#L808). |
| Class reachability and safe dependency removal | Unit tested; fixture verified | Covers compiled bytecode roots, framework metadata, and graph leaves with retention across ancestors, cycles, and diamonds. |
| Multi-release dependency JARs | Supported; vertical shading by default | With `elide.trimJars=true`, the selected analysis target is elevated and trimmed; upper tiers are preserved, with sibling closure analyzed through the Maven runtime release. `elide.mrjarStrategy=pass-through` preserves MRJAR bytes. |
| JDK platform resolution | Active-runtime modules; target API availability is not emulated | Standard module APIs load hierarchy and member declarations from the JVM running Maven. Missing active-runtime references remain unresolved; the compiler target is separate. |
| Kotlin/JVM libraries and source roots | Partial; JVM bytecode only | Kotlin-compiled dependency bytecode is analyzed through ordinary JVM references. Kotlin metadata is parsed for sibling class isolation but metadata-only references are not closure roots; Kotlin sources are not scanned. See the [Kotlin support matrix](docs/faq.md#what-kotlin-features-are-supported). |
| JARs with root `module-info.class` | Conservative pass-through on classpath | Retained JARs with root module descriptors are not trimmed. JPMS module-path linkage is unsupported. |
| ServiceLoader SPI roots | Supported; positive proof with conservative fallback | Detects constant `ServiceLoader` calls in application bytecode. Unproven SPI roots are retained by default (`<conservativeServiceLoaderRoots>true`); retained declared code prevents omission proof and stays visible in the common finding. |
| Multi-symbol vulnerability interpretation | Strict fail-closed (open design question) | When an advisory maps multiple vulnerable classes across wide version ranges (e.g. Jackson Core `CVE-2026-68494`), all mapped classes must be present in the original JAR for proof of absence. |
| Persisted report and CycloneDX pedigree | Unit tested; fixture verified | Verifies report structure, graph data, class and byte metrics, and example pedigree output. |
| Maven multi-module reactor with active elision | One strict three-module chain verified on Maven CLI 3.9.11 and GraalVM JDK 21.0.12 | By default, elision executes only on leaf modules (`elide.leafOnly=true`). With `leafOnly=false`, sequential and `-T 4` `clean verify` builds pass with module-local schema-1 reports. The chain has no independent siblings, so broader reactor concurrency remains unverified. |
| Other Maven CLI versions | Unverified | Pinned to Maven CLI 3.9.11. Other Maven 3 versions and Maven 4 are unverified. |
| Java 21–27 class files | Supported | Pinned ProGuard Core 9.4.0 engine parses and analyzes class files through Java 27. |
| Process crash during publication | Unverified | Each output file is individually replaced atomically; a set of report/SBOM/VEX files is not all-or-nothing, so a later write failure can leave earlier files updated. Maven artifact-view changes are rolled back if resolver-plan publication fails, but already replaced output files remain. Crash recovery and concurrent writers are not covered. |

### Configuration Rules & Safeguards

* **Reactor Leaf Modules (`elide.leafOnly`)**: Defaults to `true`. In multi-module Maven reactors, the plugin by default only elides leaf modules (modules with no downstream dependents in the reactor DAG, such as packaging applications, fat JARs, and Native Images). Intermediate library modules skip elision, ensuring internal libraries build and test against standard dependencies while the leaf module performs definitive elision across the unified dependency graph. Set `-Delide.leafOnly=false` (or `<elide.leafOnly>false</elide.leafOnly>`) to run elision across every submodule.
* **Production Bytecode (`elide.productionClassesComplete`)**: The default `elide` phase is `process-classes`; an explicit phase remains authoritative. Source-free modules may have absent or empty production output, while projects with Java sources must have compiled production class files. Analysis derives production roots from emitted bytecode in `target/classes`; dependencies referenced only through compile-time-inlined constants can be retained explicitly via `<retainedArtifacts>`. Source roots do not count as runtime evidence, and test-only references are outside this production scan. The legacy `elide.sourceRootsComplete=true` assertion is rejected; use compiled production output. A direct `dependency-elider:elide` can capture physical runtime inputs when `elide.productionClassesComplete=true` asserts the output is complete. Isolated test output is excluded, so ordinary test compilation may continue. Unknown production writers remain unsupported, and `skipTests` prevents tests from changing production output after capture.
* **Conservative ServiceLoader Roots (`elide.conservativeServiceLoaderRoots`)**: Defaults to `true`. Scans application bytecode for constant `ServiceLoader.load` calls. When enabled, unproven SPI providers are retained for runtime safety. Set to `false` (or `-Delide.conservativeServiceLoaderRoots=false`) to permit pruning those providers when they are unnecessary for your application. Vulnerability attribution and physical proof checks still apply.
* **Framework Metadata Protection**: Service providers (`META-INF/services`), Spring factories, and GraalVM reflection configs automatically protect declaring and provider JARs from whole-artifact removal.
* **Bytecode Sanitization**: Trimmed JARs are written to `target/elided-artifacts/` with original files untouched. JAR digital signatures are removed to avoid signature validation failures.
* **Artifact Fingerprinting**: Maven's resolved and direct artifact views are fingerprinted before mutation. Any unexpected change aborts publication.

### Remaining Verification Work

* Add a parallel reactor integration fixture with two independent consumer modules under `mvn -T2`.
* Extend tree verification beyond single leaf graphs to deep transitive conflict and mediated scope graphs.
* Broaden testing across additional Maven CLI distributions beyond 3.9.11.

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
| **`example-basic-app`** | Plain Java + Shade | Elides unused `commons-codec` and `httpclient`, retains the cached package finding and `AbstractVerifier` candidate for review, and produces a shrunken shaded JAR. |
| **`example-spring-boot-app`** | Spring Boot 3 Web | Trims Spring MVC under `BOOT-INF/lib` and exercises Spring Boot repackaging of the application and its dependencies. |
| **`example-cve-unused-app`** | Standalone CVE test | Uses a validated explicit POM `HIGH` assertion for `StringLookup` on Commons Text versions below 1.10.0, proves that class physically absent after trimming, and emits OpenVEX. |
| **`example-multi-module-reactor`** | Three-module Maven reactor with Shade | Exercises module-local reports and dependency elision for `reactor-common` → `reactor-service` → `reactor-app`, under sequential and `-T 4` builds. |
| **`example-cve-safe-class-app`** | Standalone CVE test | Explicitly opts into complete inventory inspection and proves the Janino coordinate and `ClassBodyEvaluator` class absent from the Logback 1.5.18 conditional-script path for `CVE-2025-11226`, then emits CycloneDX and OpenVEX precondition evidence while preserving fixture runtime behavior. |
| **`example-mrjar-app`** | Java 11 app + generated multi-release JAR | Elevates the Java 11 implementation, removes superseded lower and unused target-tier classes, preserves the Java 17 entries byte-for-byte, and runs both selected implementations. |

Run the full end-to-end verification suite across all fixtures:

```sh
make test-examples
```

The five standalone fixture lifecycles run with at most two workers by default.
Set `EXAMPLE_JOBS=1` for a serial comparison or another positive integer to change
the worker limit; scheduling starts after shared plugin and support setup completes.
Each fixture still runs its baseline, trace, elision, report, archive, and runtime
checks in order. Worker logs are captured under the run's `.scratch` evidence
directory during the run and replayed in fixture-list order; failed runs retain the
evidence directory for diagnosis. The multi-module reactor checks run after all
standalone workers finish.

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

Example tests and generated transcripts use complete, pinned OSV Maven and CVE List snapshots stored with [Git LFS](scripts/fixtures/vulnerability-snapshots/README.md). Install Git LFS and run `git lfs pull` before running these checks. The snapshots make the examples reproducible but do not represent live advisory coverage; a normal assessment uses its configured vulnerability cache. Package and heuristic rows remain review-only. Effective declared code from any input uses the same attribution and physical checks; manual `LOW`/`MEDIUM` retains review-only intent.

Read each report from the elision totals through its vulnerability findings and source observations. The examples distinguish package matches and heuristic leads from verified declared-code absence and complete-inventory prerequisite absence. These outcomes retain their scope and do not predict what every package scanner will report.

#### example-basic-app

Look at the dropped-artifact and trimmed-class totals, then the finding for HttpClient. Its package match and heuristic class candidate provide review information without physical proof or VEX. The dependency graph is abbreviated, with the digest identifying omitted rows.

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
[INFO] Dependency Elider report JSON snapshot: <PROJECT_ROOT>/examples/example-basic-app/target/dependency-elider-report.json
[INFO] Dependency Elider report
[INFO] Project: io.github.spockz:example-basic-app:0.1.0-SNAPSHOT
[INFO] Snapshot: last successful elide run at <TIMESTAMP>
[INFO] Analysis target JDK release: 21
[INFO] Elider runtime JDK release: <RUNTIME_RELEASE>
[INFO] Policy: retained=[commons-io:commons-io::jar:, org.apache.commons:commons-lang3::jar:], banished=[]
[INFO] The snapshot does not revalidate changed inputs when this goal runs.
[INFO] Conventional Java source layout assumption saved for this run: true
[INFO] Whole artifacts dropped: 2 / 13 (original JAR file bytes: 942.11 KiB)
[INFO] Program classes removed with dropped JARs: 535 (uncompressed .class entry payload bytes: 1.52 MiB; excludes module descriptors and archive sanitation metadata)
[INFO]   - commons-codec:commons-codec:jar:1.19.0 (compile): 365.93 KiB original JAR, 115 class entries, 413.65 KiB
[INFO]   - org.apache.httpcomponents:httpclient:jar:4.3.4 (compile): 576.18 KiB original JAR, 420 class entries, 1.11 MiB
[INFO] Raw trace decision drops before graph safety: 2
[INFO] Applied bans: none
[INFO] Program classes pruned from retained JARs: 1202 (uncompressed omitted .class payload bytes: 3.81 MiB; excludes module descriptors and archive metadata)
[INFO]   - commons-io:commons-io:jar:2.20.0 (compile): 385 classes, 1.10 MiB
[INFO]   - org.apache.commons:commons-compress:jar:1.28.0 (compile): 535 classes, 1.93 MiB
[INFO]   - org.apache.commons:commons-lang3:jar:3.18.0 (compile): 282 classes, 789.49 KiB
[INFO] Vulnerability findings: 18
[INFO]   - CVE-2011-1498 org.apache.httpcomponents:httpclient:jar:4.3.4 (compile) [REMOVED]
[INFO]     Aliases: [CVE-2011-1498, GHSA-gw85-4gmf-m7rh]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2012-2098 org.apache.commons:commons-compress:jar:1.28.0 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2012-2098, GHSA-6fxm-66hq-fc96]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2012-6153 org.apache.httpcomponents:httpclient:jar:4.3.4 (compile) [REMOVED]
[INFO]     Aliases: [CVE-2012-6153, GHSA-2x83-r56g-cv47]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2013-4366 org.apache.httpcomponents:httpclient:jar:4.3.4 (compile) [REMOVED]
[INFO]     Aliases: [CVE-2013-4366, GHSA-pqwh-44jj-p5rm]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2014-3577 org.apache.httpcomponents:httpclient:jar:4.3.4 (compile) [REMOVED]
[INFO]     Aliases: [CVE-2014-3577, GHSA-cfh5-3ghh-wfjx]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Declared code: [org.apache.http.conn.ssl.AbstractVerifier] REVIEW_LEAD; classes: []; reasons: [HEURISTIC_REQUIRES_REVIEW]
[INFO]     Heuristic leads: [org.apache.http.conn.ssl.AbstractVerifier]
[INFO]     Sources: [OSV]
[INFO]   - CVE-2015-5262 org.apache.httpcomponents:httpclient:jar:4.3.4 (compile) [REMOVED]
[INFO]     Aliases: [CVE-2015-5262, GHSA-fmj5-wv96-r2ch]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-11771 org.apache.commons:commons-compress:jar:1.28.0 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2018-11771, GHSA-hrmr-f5m6-m9pq]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-1324 org.apache.commons:commons-compress:jar:1.28.0 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2018-1324, GHSA-h436-432x-8fvx]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2019-12402 org.apache.commons:commons-compress:jar:1.28.0 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2019-12402, GHSA-53x6-4x5p-rrvv]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-13956 org.apache.httpcomponents:httpclient:jar:4.3.4 (compile) [REMOVED]
[INFO]     Aliases: [CVE-2020-13956, GHSA-7r82-7xv7-xcpj]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-29425 commons-io:commons-io:jar:2.20.0 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2021-29425, GHSA-gwrp-pvrq-jmwv]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-35515 org.apache.commons:commons-compress:jar:1.28.0 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2021-35515, GHSA-7hfm-57qf-j43q]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-35516 org.apache.commons:commons-compress:jar:1.28.0 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2021-35516, GHSA-crv7-7245-f45f]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-35517 org.apache.commons:commons-compress:jar:1.28.0 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2021-35517, GHSA-xqfj-vm6h-2x34]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-36090 org.apache.commons:commons-compress:jar:1.28.0 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2021-36090, GHSA-mc84-pj99-q6hh]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2024-25710 org.apache.commons:commons-compress:jar:1.28.0 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2024-25710, GHSA-4g9r-vxhx-9pgx]
[INFO]     Applicability: UNRESOLVED; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Unresolved coverage: [containers.cna.affected[0]:defaultStatus=unaffected:[version=1.3,status=affected,versionType=semver,lessThan=null,lessThanOrEqual=1.25.0,changes=[]]: CVE default, explicit status, or overlapping statuses are unresolved, containers.cna.affected[0]:version=1.3,status=affected,versionType=semver,lessThan=null,lessThanOrEqual=1.25.0,changes=[]: Unsupported CVE versionType]
[INFO]     Sources: [CVE_LIST, OSV]
[INFO]   - CVE-2024-26308 org.apache.commons:commons-compress:jar:1.28.0 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2024-26308, GHSA-4265-ccf5-phj5]
[INFO]     Applicability: UNRESOLVED; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Unresolved coverage: [containers.cna.affected[0]:defaultStatus=unaffected:[version=1.21,status=affected,versionType=semver,lessThan=1.26.0,lessThanOrEqual=null,changes=[]]: CVE default, explicit status, or overlapping statuses are unresolved, containers.cna.affected[0]:version=1.21,status=affected,versionType=semver,lessThan=1.26.0,lessThanOrEqual=null,changes=[]: Unsupported CVE versionType]
[INFO]     Sources: [CVE_LIST, OSV]
[INFO]   - CVE-2024-47554 commons-io:commons-io:jar:2.20.0 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2024-47554, GHSA-78wr-2p64-hpwj]
[INFO]     Applicability: UNRESOLVED; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Unresolved coverage: [containers.cna.affected[0]:defaultStatus=unaffected:[version=2.0,status=affected,versionType=semver,lessThan=2.14.0,lessThanOrEqual=null,changes=[]]: CVE default, explicit status, or overlapping statuses are unresolved, containers.cna.affected[0]:version=2.0,status=affected,versionType=semver,lessThan=2.14.0,lessThanOrEqual=null,changes=[]: Unsupported CVE versionType]
[INFO]     Sources: [CVE_LIST, OSV]
[INFO] CVE Sources:
[INFO]   - CVE_LIST PARTIAL
[INFO]     Skipped 79 CVE List source row(s)
[INFO]     Source diagnostics are in the JSON snapshot
[INFO]   - OSV CURRENT
[INFO] POM exclusion review (advisory only):
[INFO]   Repeated POM exclusions:
[INFO]     none found across effective dependency paths
[INFO]   Exclusion provenance incomplete for 14 dependency or exclusion origins. Maven
[INFO]   supplied no source location/identity or the location matched zero or multiple
[INFO]   original POM rows. This advisory review does not affect elision.
[INFO]   Full evidence is in the JSON snapshot fields
[INFO]   exclusionReview.snapshot.dependencies and
[INFO]   exclusionReview.snapshot.diagnostics.
[INFO] Mediated TEST dependency graph (captured and saved by the elide goal):
[INFO]   - io.github.spockz:example-basic-app:0.1.0-SNAPSHOT {nodeId=n0} [RETAINED]
[INFO]   - io.github.spockz:example-basic-app:0.1.0-SNAPSHOT -> org.apache.commons:commons-compress:jar:1.28.0 (compile) {nodeId=n2} [RETAINED, CLASS_TRIMMED]
[INFO]   - io.github.spockz:example-basic-app:0.1.0-SNAPSHOT -> org.apache.httpcomponents:httpclient:jar:4.3.4 (compile) {nodeId=n1} [EFFECTIVE_DROP]
[INFO]   ... 11 dependency graph rows elided (sha256:e754b43488489549d3eab2e2e91208c166dd926a768beac0264d5e09942a7a7e)
[INFO] ------------------------------------------------------------------------
[INFO] ------------------------------------------------------------------------
[INFO] Total time: <BUILD_TIME>
[INFO] Finished at: <TIMESTAMP>
[INFO] ------------------------------------------------------------------------
```

<!-- END:transcript:report-basic-app -->

#### example-spring-boot-app

The Spring Boot fixture demonstrates dependency trimming inside a repackaged application. Its independent OWASP Dependency-Check scan reports published advisories for resolved dependencies; those findings do not establish that vulnerable code is reachable or prove that a dependency can be safely removed.

Run the optional OWASP Dependency-Check scan with `./mvnw -f examples/example-spring-boot-app/pom.xml verify -Pcve-scan -Delide.mode=baseline`. The profile is inactive in ordinary builds. It writes `target/dependency-check-report.html` and `target/dependency-check-report.json`. Set `NVD_API_KEY` to use an NVD API key; when one is unavailable, use the public NVD feed URL below. Its initial download can take several minutes.

```sh
./mvnw -f examples/example-spring-boot-app/pom.xml verify -Pcve-scan -Delide.mode=baseline '-DnvdDatafeedUrl=https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{0}.json.gz'
```

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
[INFO] Dependency Elider report JSON snapshot: <PROJECT_ROOT>/examples/example-spring-boot-app/target/dependency-elider-report.json
[INFO] Dependency Elider report
[INFO] Project: io.github.spockz:example-spring-boot-app:0.1.0-SNAPSHOT
[INFO] Snapshot: last successful elide run at <TIMESTAMP>
[INFO] Analysis target JDK release: 21
[INFO] Elider runtime JDK release: <RUNTIME_RELEASE>
[INFO] Policy: retained=[], banished=[]
[INFO] The snapshot does not revalidate changed inputs when this goal runs.
[INFO] Conventional Java source layout assumption saved for this run: true
[INFO] Whole artifacts dropped: 3 / 114 (original JAR file bytes: 7.50 MiB)
[INFO] Program classes removed with dropped JARs: 261 (uncompressed .class entry payload bytes: 841.41 KiB; excludes module descriptors and archive sanitation metadata)
[INFO]   - at.yawk.lz4:lz4-java:jar:1.10.1 (runtime): 888.90 KiB original JAR, 82 class entries, 223.82 KiB
[INFO]   - com.github.luben:zstd-jni:jar:1.5.7-18 (runtime): 6.25 MiB original JAR, 43 class entries, 141.72 KiB
[INFO]   - commons-codec:commons-codec:jar:1.21.0 (compile): 393.06 KiB original JAR, 136 class entries, 475.86 KiB
[INFO] Raw trace decision drops before graph safety: 6
[INFO] Applied bans: none
[INFO] Program classes pruned from retained JARs: 3923 (uncompressed omitted .class payload bytes: 8.99 MiB; excludes module descriptors and archive metadata)
[INFO]   - com.fasterxml.jackson.core:jackson-core:jar:2.21.5 (runtime): 31 classes, 136.62 KiB
[INFO]   - com.github.spotbugs:spotbugs-annotations:jar:4.10.5 (runtime): 22 classes, 15.44 KiB
[INFO]   - com.google.code.findbugs:jsr305:jar:3.0.2 (runtime): 24 classes, 14.44 KiB
[INFO]   - com.thoughtworks.xstream:xstream:jar:1.4.21 (runtime): 215 classes, 532.65 KiB
[INFO]   - commons-logging:commons-logging:jar:1.3.6 (compile): 15 classes, 68.04 KiB
[INFO]   - io.micrometer:context-propagation:jar:1.2.1 (runtime): 11 classes, 23.22 KiB
[INFO]   - io.micrometer:micrometer-jakarta9:jar:1.17.1 (compile): 44 classes, 88.74 KiB
[INFO]   - org.apache.groovy:groovy-xml:jar:5.0.8 (runtime): 49 classes, 198.23 KiB
[INFO]   - org.apache.groovy:groovy:jar:5.0.8 (runtime): 2929 classes, 6.47 MiB
[INFO]   - org.freemarker:freemarker:jar:2.3.34 (runtime): 228 classes, 559.30 KiB
[INFO]   - org.hdrhistogram:HdrHistogram:jar:2.2.2 (runtime): 37 classes, 118.76 KiB
[INFO]   - org.slf4j:slf4j-api:jar:2.0.18 (compile): 5 classes, 6.38 KiB
[INFO]   - org.springframework.boot:spring-boot-health:jar:4.1.1 (compile): 9 classes, 9.95 KiB
[INFO]   - org.springframework.boot:spring-boot-http-converter:jar:4.1.1 (compile): 1 classes, 239 B
[INFO]   - org.springframework.boot:spring-boot-jackson:jar:4.1.1 (compile): 8 classes, 21.83 KiB
[INFO]   - org.springframework.boot:spring-boot-mail:jar:4.1.1 (compile): 2 classes, 451 B
[INFO]   - org.springframework.boot:spring-boot-micrometer-metrics:jar:4.1.1 (compile): 35 classes, 8.64 KiB
[INFO]   - org.springframework.boot:spring-boot-micrometer-observation:jar:4.1.1 (compile): 1 classes, 247 B
[INFO]   - org.springframework.boot:spring-boot-servlet:jar:4.1.1 (compile): 11 classes, 9.01 KiB
[INFO]   - org.springframework.boot:spring-boot-tomcat:jar:4.1.1 (compile): 14 classes, 13.77 KiB
[INFO]   - org.springframework.boot:spring-boot-web-server:jar:4.1.1 (compile): 21 classes, 46.11 KiB
[INFO]   - org.springframework.boot:spring-boot-webmvc:jar:4.1.1 (compile): 16 classes, 25.79 KiB
[INFO]   - org.springframework:spring-webmvc:jar:7.0.9 (compile): 142 classes, 524.72 KiB
[INFO]   - org.webjars:webjars-locator-core:jar:0.59 (runtime): 1 classes, 11.43 KiB
[INFO]   - org.xerial.snappy:snappy-java:jar:1.1.10.7 (runtime): 40 classes, 119.25 KiB
[INFO]   - org.yaml:snakeyaml:jar:2.6 (compile): 12 classes, 29.92 KiB
[INFO] Vulnerability findings: 314
[INFO]   - CVE-2008-1947 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2008-1947, GHSA-f98p-9pp6-7q6c]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2009-1190 org.springframework:spring-core:jar:7.0.9 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2009-1190, GHSA-wjjr-h4wh-w6vv]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2011-2730 org.springframework:spring-core:jar:7.0.9 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2011-2730, GHSA-wv88-pf73-x22p]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2011-2894 org.springframework:spring-core:jar:7.0.9 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2011-2894, GHSA-f866-m9mv-2xr3]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2013-6429 org.springframework:spring-web:jar:7.0.9 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2013-6429, GHSA-g6hf-f9cq-q7w7]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2013-6430 org.springframework:spring-web:jar:7.0.9 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2013-6430, GHSA-xjrf-8x4f-43h4]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2013-7285 com.thoughtworks.xstream:xstream:jar:1.4.21 (runtime) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2013-7285, GHSA-f554-x222-wgf7]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2014-0054 org.springframework:spring-webmvc:jar:7.0.9 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2014-0054, GHSA-8cmm-qj8g-fcp6]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2014-0095 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2014-0095, GHSA-wf5v-jhxj-q632]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2014-0225 org.springframework:spring-webmvc:jar:7.0.9 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2014-0225, GHSA-f93f-g33r-8pcp]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2014-1904 org.springframework:spring-webmvc:jar:7.0.9 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2014-1904, GHSA-ff7p-jqjm-v66h]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2014-3578 org.springframework:spring-core:jar:7.0.9 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2014-3578, GHSA-rhcg-rwhx-qj3j]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2014-3625 org.springframework:spring-webmvc:jar:7.0.9 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2014-3625, GHSA-hhm4-hwq6-3c6w]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2015-0201 org.springframework:spring-core:jar:7.0.9 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2015-0201, GHSA-45vg-2v73-vm62]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2015-3192 org.springframework:spring-web:jar:7.0.9 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2015-3192, GHSA-6v7w-535j-rq5m]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2015-5211 org.springframework:spring-core:jar:7.0.9 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2015-5211, GHSA-pgf9-h69p-pcgf]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2016-1000027 org.springframework:spring-web:jar:7.0.9 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2016-1000027, GHSA-4wrc-f8pq-fpqp]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2016-3674 com.thoughtworks.xstream:xstream:jar:1.4.21 (runtime) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2016-3674, GHSA-rgh3-987h-wpmw]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2016-5007 org.springframework:spring-core:jar:7.0.9 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2016-5007, GHSA-8crv-49fr-2h6j]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2016-9878 org.springframework:spring-webmvc:jar:7.0.9 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2016-9878, GHSA-2m8h-fgr8-2q9w]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2017-12610 org.apache.kafka:kafka-clients:jar:4.2.1 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2017-12610, GHSA-xm78-4m3g-7wm7]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2017-12615 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2017-12615, GHSA-pjfr-qf3p-3q25]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2017-12617 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2017-12617, GHSA-xjgh-84hx-56c5]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2017-18640 org.yaml:snakeyaml:jar:2.6 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2017-18640, GHSA-rvwf-54qp-4r6v]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2017-5648 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2017-5648, GHSA-3vx3-xf6q-r5xp]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2017-5651 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2017-5651, GHSA-9hg2-395j-83rm]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2017-5929 ch.qos.logback:logback-classic:jar:1.5.38 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2017-5929, GHSA-vmfg-rjjm-rjrj]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2017-5929 ch.qos.logback:logback-core:jar:1.5.38 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2017-5929, GHSA-vmfg-rjjm-rjrj]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2017-7957 com.thoughtworks.xstream:xstream:jar:1.4.21 (runtime) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2017-7957, GHSA-7hwc-46rm-65jh]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-11039 org.springframework:spring-web:jar:7.0.9 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2018-11039, GHSA-9gcm-f4x3-8jpw]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-11040 org.springframework:spring-core:jar:7.0.9 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2018-11040, GHSA-f26x-pr96-vw86]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-11784 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2018-11784, GHSA-5q99-f34m-67gc]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-1196 org.springframework.boot:spring-boot:jar:4.1.1 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2018-1196, GHSA-xx65-cc7g-9pfp]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-1199 org.springframework:spring-core:jar:7.0.9 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2018-1199, GHSA-v596-fwhq-8x48]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-1257 org.springframework:spring-core:jar:7.0.9 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2018-1257, GHSA-rcpf-vj53-7h2m]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-1258 org.springframework:spring-core:jar:7.0.9 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2018-1258, GHSA-cxrj-66c5-9fmh]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-1270 org.springframework:spring-messaging:jar:7.0.9 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2018-1270, GHSA-p5hg-3xm3-gcjg]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-1271 org.springframework:spring-core:jar:7.0.9 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2018-1271, GHSA-g8hw-794c-4j9g]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-1272 org.springframework:spring-core:jar:7.0.9 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2018-1272, GHSA-4487-x383-qpph]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-1275 org.springframework:spring-messaging:jar:7.0.9 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2018-1275, GHSA-3rmv-2pg5-xvqj]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-1304 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2018-1304, GHSA-6rxj-58jh-436r]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-1305 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2018-1305, GHSA-jx6h-3fjx-cgv5]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-1336 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2018-1336, GHSA-m59c-jpc8-m2x4]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-15756 org.springframework:spring-core:jar:7.0.9 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2018-15756, GHSA-ffvq-7w96-97p7]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-8014 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2018-8014, GHSA-r4x2-3cq5-hqvp]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-8034 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2018-8034, GHSA-46j3-r4pj-4835]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-8037 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2018-8037, GHSA-6v52-mj5r-7j2m]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2019-0199 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2019-0199, GHSA-qcxh-w3j9-58qr]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2019-0221 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2019-0221, GHSA-jjpq-gp5q-8q6w]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2019-0232 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2019-0232, GHSA-8vmx-qmch-mpqg]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2019-10072 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2019-10072, GHSA-q4hg-rmq2-52q9]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2019-10173 com.thoughtworks.xstream:xstream:jar:1.4.21 (runtime) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2019-10173, GHSA-hf23-9pf7-388p]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2019-12418 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2019-12418, GHSA-hh3j-x4mc-g48r]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2019-17563 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2019-17563, GHSA-9xcj-c8cr-8c3c]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2019-17569 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2019-17569, GHSA-767j-jfh2-jvrc]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-11996 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2020-11996, CVE-2020-11996, GHSA-53hp-jpwq-2jgq]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-13935 org.apache.tomcat.embed:tomcat-embed-websocket:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2020-13935, CVE-2020-13935, GHSA-m7jv-hq7h-mq7c]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-1935 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2020-1935, CVE-2020-1935, GHSA-qxf4-chvg-4r8r]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-1938 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2020-1938, CVE-2020-1938, GHSA-c9hw-wf7x-jp9j]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-26217 com.thoughtworks.xstream:xstream:jar:1.4.21 (runtime) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [BIT-activemq-2020-26217, CVE-2020-26217, GHSA-mw36-7c6c-q4q2]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-26258 com.thoughtworks.xstream:xstream:jar:1.4.21 (runtime) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2020-26258, GHSA-4cch-wxpw-8p28]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-26259 com.thoughtworks.xstream:xstream:jar:1.4.21 (runtime) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2020-26259, GHSA-jfvx-7wrx-43fh]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-5397 org.springframework:spring-webmvc:jar:7.0.9 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2020-5397, GHSA-7pm4-g2qj-j85x]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-5398 org.springframework:spring-webmvc:jar:7.0.9 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2020-5398, GHSA-8wx2-9q48-vm9r]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-9484 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2020-9484, CVE-2020-9484, GHSA-344f-f5vg-2jfj]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-21341 com.thoughtworks.xstream:xstream:jar:1.4.21 (runtime) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [BIT-activemq-2021-21341, CVE-2021-21341, GHSA-2p3x-qw9c-25hh]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-21342 com.thoughtworks.xstream:xstream:jar:1.4.21 (runtime) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [BIT-activemq-2021-21342, CVE-2021-21342, GHSA-hvv8-336g-rx3m]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-21343 com.thoughtworks.xstream:xstream:jar:1.4.21 (runtime) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [BIT-activemq-2021-21343, CVE-2021-21343, GHSA-74cv-f58x-f9wf]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-21344 com.thoughtworks.xstream:xstream:jar:1.4.21 (runtime) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [BIT-activemq-2021-21344, CVE-2021-21344, GHSA-59jw-jqf4-3wq3]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-21345 com.thoughtworks.xstream:xstream:jar:1.4.21 (runtime) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [BIT-activemq-2021-21345, CVE-2021-21345, GHSA-hwpc-8xqv-jvj4]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-21346 com.thoughtworks.xstream:xstream:jar:1.4.21 (runtime) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [BIT-activemq-2021-21346, CVE-2021-21346, GHSA-4hrm-m67v-5cxr]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-21347 com.thoughtworks.xstream:xstream:jar:1.4.21 (runtime) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [BIT-activemq-2021-21347, CVE-2021-21347, GHSA-qpfq-ph7r-qv6f]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-21348 com.thoughtworks.xstream:xstream:jar:1.4.21 (runtime) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [BIT-activemq-2021-21348, CVE-2021-21348, GHSA-56p8-3fh9-4cvq]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-21349 com.thoughtworks.xstream:xstream:jar:1.4.21 (runtime) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [BIT-activemq-2021-21349, CVE-2021-21349, GHSA-f6hm-88x3-mfjv]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-21350 com.thoughtworks.xstream:xstream:jar:1.4.21 (runtime) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [BIT-activemq-2021-21350, CVE-2021-21350, GHSA-43gc-mjxg-gvrq]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-21351 com.thoughtworks.xstream:xstream:jar:1.4.21 (runtime) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [BIT-activemq-2021-21351, CVE-2021-21351, GHSA-hrcp-8f3q-4w2c]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-22060 org.springframework:spring-core:jar:7.0.9 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2021-22060, GHSA-6gf2-pvqw-37ph]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-22096 org.springframework:spring-core:jar:7.0.9 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2021-22096, GHSA-rfmp-97jj-h8m6]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-22118 org.springframework:spring-web:jar:7.0.9 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2021-22118, GHSA-gfwj-fwqj-fp3v]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-24122 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2021-24122, CVE-2021-24122, GHSA-2rvv-w9r2-rg7m]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-25122 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2021-25122, CVE-2021-25122, GHSA-j39c-c8hj-x4j3]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-25329 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2021-25329, CVE-2021-25329, GHSA-jgwr-3qm3-26f3]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-27568 net.minidev:json-smart:jar:2.6.0 (test) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2021-27568, GHSA-v528-7hrm-frqp]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-29505 com.thoughtworks.xstream:xstream:jar:1.4.21 (runtime) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2021-29505, GHSA-7chv-rrw6-w6fc]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-31684 net.minidev:json-smart:jar:2.6.0 (test) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2021-31684, GHSA-fg2v-w576-w4v3]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-38153 org.apache.kafka:kafka-clients:jar:4.2.1 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-kafka-2021-38153, CVE-2021-38153, GHSA-3j6g-hxx5-3q26]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-39139 com.thoughtworks.xstream:xstream:jar:1.4.21 (runtime) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2021-39139, GHSA-64xx-cq4q-mf44]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-39140 com.thoughtworks.xstream:xstream:jar:1.4.21 (runtime) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2021-39140, GHSA-6wf9-jmg9-vxcc]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-39141 com.thoughtworks.xstream:xstream:jar:1.4.21 (runtime) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2021-39141, GHSA-g5w6-mrj7-75h2]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-39144 com.thoughtworks.xstream:xstream:jar:1.4.21 (runtime) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2021-39144, GHSA-j9h8-phrw-h4fh]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-39145 com.thoughtworks.xstream:xstream:jar:1.4.21 (runtime) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2021-39145, GHSA-8jrj-525p-826v]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-39146 com.thoughtworks.xstream:xstream:jar:1.4.21 (runtime) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2021-39146, GHSA-p8pq-r894-fm8f]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-39147 com.thoughtworks.xstream:xstream:jar:1.4.21 (runtime) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2021-39147, GHSA-h7v4-7xg3-hxcc]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-39148 com.thoughtworks.xstream:xstream:jar:1.4.21 (runtime) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2021-39148, GHSA-qrx8-8545-4wg2]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-39149 com.thoughtworks.xstream:xstream:jar:1.4.21 (runtime) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2021-39149, GHSA-3ccq-5vw3-2p6x]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-39150 com.thoughtworks.xstream:xstream:jar:1.4.21 (runtime) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2021-39150, GHSA-cxfm-5m4g-x7xp]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-39151 com.thoughtworks.xstream:xstream:jar:1.4.21 (runtime) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2021-39151, GHSA-hph2-m3g5-xxv4]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-39152 com.thoughtworks.xstream:xstream:jar:1.4.21 (runtime) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2021-39152, GHSA-xw4p-crpj-vjx2]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-39153 com.thoughtworks.xstream:xstream:jar:1.4.21 (runtime) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2021-39153, GHSA-2q8x-2p7f-574v]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-39154 com.thoughtworks.xstream:xstream:jar:1.4.21 (runtime) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2021-39154, GHSA-6w62-hx7r-mw68]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-42550 ch.qos.logback:logback-core:jar:1.5.38 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2021-42550, GHSA-668q-qrv7-99fm]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-43859 com.thoughtworks.xstream:xstream:jar:1.4.21 (runtime) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [BIT-jenkins-2021-43859, CVE-2021-43859, GHSA-rmr5-cpv2-vgjf]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-47621 io.github.classgraph:classgraph:jar:4.8.173 (runtime) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2021-47621, GHSA-v2xm-76pq-phcf]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2022-1471 org.yaml:snakeyaml:jar:2.6 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2022-1471, GHSA-mjmj-j48q-9wg2]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2022-22950 org.springframework:spring-expression:jar:7.0.9 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2022-22950, GHSA-558x-2xjg-6232]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2022-22965 org.springframework:spring-beans:jar:7.0.9 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2022-22965, GHSA-36p3-wjmg-h94x]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2022-22965 org.springframework:spring-webmvc:jar:7.0.9 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2022-22965, GHSA-36p3-wjmg-h94x]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2022-22965 org.springframework.boot:spring-boot-starter-web:jar:4.1.1 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2022-22965, GHSA-36p3-wjmg-h94x]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2022-22968 org.springframework:spring-context:jar:7.0.9 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2022-22968, GHSA-g5mm-vmx4-3rg7]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2022-22970 org.springframework:spring-beans:jar:7.0.9 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2022-22970, GHSA-hh26-6xwr-ggv7]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2022-22971 org.springframework:spring-messaging:jar:7.0.9 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2022-22971, GHSA-rqph-vqwm-22vc]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2022-25857 org.yaml:snakeyaml:jar:2.6 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2022-25857, GHSA-3mc7-4q67-w48m]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2022-27772 org.springframework.boot:spring-boot:jar:4.1.1 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2022-27772, GHSA-cm59-pr5q-cw85]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2022-38749 org.yaml:snakeyaml:jar:2.6 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2022-38749, GHSA-c4r9-r8fh-9vj2]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2022-38750 org.yaml:snakeyaml:jar:2.6 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2022-38750, GHSA-hhhw-99gj-p3c3]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2022-38751 org.yaml:snakeyaml:jar:2.6 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2022-38751, GHSA-98wm-3w3q-mw94]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2022-38752 org.yaml:snakeyaml:jar:2.6 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2022-38752, GHSA-9w3m-gqgf-c4p9]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2022-40151 com.thoughtworks.xstream:xstream:jar:1.4.21 (runtime) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2022-40151, GHSA-f8cc-g7j8-xxpm]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2022-41854 org.yaml:snakeyaml:jar:2.6 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2022-41854, GHSA-w37g-rhq8-7m4j]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2022-41966 com.thoughtworks.xstream:xstream:jar:1.4.21 (runtime) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2022-41966, GHSA-j563-grx4-pjpv]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2022-42252 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2022-42252, CVE-2022-42252, GHSA-p22x-g9px-3945]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2022-45143 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2022-45143, CVE-2022-45143, GHSA-rq2w-37h9-vg94]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2023-1370 net.minidev:json-smart:jar:2.6.0 (test) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2023-1370, GHSA-493p-pfq6-5258]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2023-20860 org.springframework:spring-webmvc:jar:7.0.9 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2023-20860, GHSA-7phw-cxx7-q9vq]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2023-20861 org.springframework:spring-expression:jar:7.0.9 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2023-20861, GHSA-564r-hj7v-mcr5]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2023-20863 org.springframework:spring-expression:jar:7.0.9 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2023-20863, GHSA-wxqc-pxw9-g2p8]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2023-20873 org.springframework.boot:spring-boot-actuator-autoconfigure:jar:4.1.1 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2023-20873, GHSA-g5h3-w546-pj7f]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2023-20883 org.springframework.boot:spring-boot-autoconfigure:jar:4.1.1 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2023-20883, GHSA-xf96-w227-r7c4]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2023-24998 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2023-24998, GHSA-hfrx-6qgj-fp6c]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2023-28709 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2023-28709, CVE-2023-28709, GHSA-cx6h-86xw-9x34]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2023-34040 org.springframework.kafka:spring-kafka:jar:4.1.1 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2023-34040, GHSA-crqf-q9fp-hwjw]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2023-34053 org.springframework:spring-webmvc:jar:7.0.9 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2023-34053, GHSA-v94h-hvhg-mf9h]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2023-34055 org.springframework.boot:spring-boot-actuator:jar:4.1.1 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2023-34055, GHSA-jjfh-589g-3hjx]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2023-34453 org.xerial.snappy:snappy-java:jar:1.1.10.7 (runtime) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2023-34453, GHSA-pqr6-cmr2-h8hf]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2023-34454 org.xerial.snappy:snappy-java:jar:1.1.10.7 (runtime) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2023-34454, GHSA-fjpj-2g6w-x25r]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2023-34455 org.xerial.snappy:snappy-java:jar:1.1.10.7 (runtime) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2023-34455, GHSA-qcwq-55hx-v3vh]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2023-34981 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2023-34981, CVE-2023-34981, GHSA-mppv-79ch-vw6q]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2023-41080 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2023-41080, CVE-2023-41080, GHSA-q3mw-pvr8-9ggc]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2023-42795 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2023-42795, CVE-2023-42795, GHSA-g8pj-r55q-5c2v]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2023-43642 org.xerial.snappy:snappy-java:jar:1.1.10.7 (runtime) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2023-43642, GHSA-55g7-9cwv-5qfv]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2023-44487 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-apisix-2023-44487, BIT-aspnet-core-2023-44487, BIT-contour-2023-44487, BIT-dotnet-2023-44487, BIT-dotnet-sdk-2023-44487, BIT-envoy-2023-44487, BIT-golang-2023-44487, BIT-jenkins-2023-44487, BIT-kong-2023-44487, BIT-nginx-2023-44487, BIT-nginx-gateway-2023-44487, BIT-node-2023-44487, BIT-node-min-2023-44487, BIT-solr-2023-44487, BIT-tomcat-2023-44487, BIT-varnish-2023-44487, CVE-2023-44487, GHSA-qppj-fm5r-hxr3]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2023-45648 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2023-45648, CVE-2023-45648, GHSA-r6j3-px5g-cq3x]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2023-46589 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2023-46589, CVE-2023-46589, GHSA-fccv-jmmp-qg76]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2023-51074 com.jayway.jsonpath:json-path:jar:2.10.0 (test) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2023-51074, GHSA-pfh2-hfmq-phg5]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2023-6378 ch.qos.logback:logback-classic:jar:1.5.38 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2023-6378, GHSA-vmq6-5m68-f53m]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2023-6378 ch.qos.logback:logback-core:jar:1.5.38 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2023-6378, GHSA-vmq6-5m68-f53m]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2023-6481 ch.qos.logback:logback-core:jar:1.5.38 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2023-6481, GHSA-gm62-rw4g-vrc4]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2024-12798 ch.qos.logback:logback-core:jar:1.5.38 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2024-12798, GHSA-pr98-23f8-jwxv]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2024-12801 ch.qos.logback:logback-core:jar:1.5.38 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2024-12801, GHSA-6v67-2wr5-gvf4]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2024-21733 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2024-21733, CVE-2024-21733, GHSA-f4qf-m5gf-8jm8]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2024-22233 org.springframework:spring-core:jar:7.0.9 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2024-22233, GHSA-r4q3-7g4q-x89m]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2024-22243 org.springframework:spring-web:jar:7.0.9 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2024-22243, GHSA-ccgv-vj62-xf9h]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2024-22259 org.springframework:spring-web:jar:7.0.9 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2024-22259, GHSA-hgjh-9rj2-g67j]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2024-22262 org.springframework:spring-web:jar:7.0.9 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2024-22262, GHSA-2wrp-6fg6-hmc5]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2024-23672 org.apache.tomcat.embed:tomcat-embed-websocket:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2024-23672, CVE-2024-23672, GHSA-v682-8vv8-vpwr]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2024-24549 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2024-24549, CVE-2024-24549, GHSA-7w75-32cg-r6g2]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2024-31141 org.apache.kafka:kafka-clients:jar:4.2.1 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2024-31141, GHSA-2x2g-32r7-p4x8]
[INFO]     Applicability: UNRESOLVED; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Unresolved coverage: [containers.cna.affected[0]:defaultStatus=unaffected:[version=2.3.0,status=affected,versionType=semver,lessThan=null,lessThanOrEqual=3.5.2,changes=[], version=3.6.0,status=affected,versionType=semver,lessThan=null,lessThanOrEqual=3.6.2,changes=[], version=3.7.0,status=affected,versionType=semver,lessThan=null,lessThanOrEqual=null,changes=[]]: CVE default, explicit status, or overlapping statuses are unresolved, containers.cna.affected[0]:version=2.3.0,status=affected,versionType=semver,lessThan=null,lessThanOrEqual=3.5.2,changes=[]: Unsupported CVE versionType, containers.cna.affected[0]:version=3.6.0,status=affected,versionType=semver,lessThan=null,lessThanOrEqual=3.6.2,changes=[]: Unsupported CVE versionType, containers.cna.affected[0]:version=3.7.0,status=affected,versionType=semver,lessThan=null,lessThanOrEqual=null,changes=[]: Unsupported CVE versionType]
[INFO]     Sources: [CVE_LIST, OSV]
[INFO]   - CVE-2024-31573 org.xmlunit:xmlunit-core:jar:2.11.0 (test) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2024-31573, GHSA-chfm-68vv-pvw5]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2024-34750 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2024-34750, CVE-2024-34750, GHSA-wm9w-rjj3-j356]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2024-38286 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2024-38286, CVE-2024-38286, GHSA-7jqf-v358-p8g7]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2024-38808 org.springframework:spring-expression:jar:7.0.9 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2024-38808, GHSA-9cmq-m9j5-mvww]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2024-38809 org.springframework:spring-web:jar:7.0.9 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2024-38809, GHSA-2rmj-mq67-h97g]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2024-38816 org.springframework:spring-webmvc:jar:7.0.9 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2024-38816, GHSA-cx7f-g6mp-7hqm]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2024-38819 org.springframework:spring-webmvc:jar:7.0.9 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2024-38819, GHSA-g5vr-rgqm-vf78]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2024-38820 org.springframework:spring-context:jar:7.0.9 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2024-38820, GHSA-4gc7-5j7h-4qph]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2024-38820 org.springframework:spring-web:jar:7.0.9 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2024-38820, GHSA-4gc7-5j7h-4qph]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2024-38828 org.springframework:spring-webmvc:jar:7.0.9 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2024-38828, GHSA-w3c8-7r8f-9jp8]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2024-47072 com.thoughtworks.xstream:xstream:jar:1.4.21 (runtime) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2024-47072, GHSA-hfq9-hggm-c56q]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2024-50379 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2024-50379, CVE-2024-50379, GHSA-5j33-cvvr-w245]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2024-52317 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2024-52317, CVE-2024-52317, GHSA-qvf5-hvjx-wm27]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2024-56337 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2024-56337, CVE-2024-56337, GHSA-27hp-xhwr-wr2m]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2024-57699 net.minidev:json-smart:jar:2.6.0 (test) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2024-57699, GHSA-pq2g-wx69-c263]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2025-11226 ch.qos.logback:logback-core:jar:1.5.38 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2025-11226, GHSA-25qh-j22f-pwp8]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [CATALOG, OSV]
[INFO]   - CVE-2025-12183 at.yawk.lz4:lz4-java:jar:1.10.1 (runtime) [REMOVED]
[INFO]     Aliases: [CVE-2025-12183, GHSA-vqf4-7m7x-wgfc]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2025-22233 org.springframework:spring-context:jar:7.0.9 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2025-22233, GHSA-4wp7-92pw-q264]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2025-22235 org.springframework.boot:spring-boot:jar:4.1.1 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2025-22235, GHSA-rc42-6c7j-7h5r]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2025-24813 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2025-24813, CVE-2025-24813, GHSA-83qj-6fr2-vhqg]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2025-27817 org.apache.kafka:kafka-clients:jar:4.2.1 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-kafka-2025-27817, CVE-2025-27817, GHSA-vgq5-3255-v292]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2025-31650 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2025-31650, CVE-2025-31650, GHSA-3p2h-wqq4-wf4h]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2025-31651 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2025-31651, CVE-2025-31651, GHSA-ff77-26x5-69cr]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2025-41234 org.springframework:spring-web:jar:7.0.9 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2025-41234, GHSA-6r3c-xf4w-jxjm]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2025-41242 org.springframework:spring-webmvc:jar:7.0.9 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2025-41242, GHSA-r936-gwx5-v52f]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2025-41249 org.springframework:spring-core:jar:7.0.9 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2025-41249, GHSA-jmp9-x22r-554x]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2025-46701 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2025-46701, CVE-2025-46701, GHSA-h2fw-rfh5-95r3]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2025-48988 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2025-48988, CVE-2025-48988, GHSA-h3gc-qfqq-6h8f]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2025-48989 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2025-48989, CVE-2025-48989, GHSA-gqp3-2cvr-x8m3]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2025-49124 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2025-49124, CVE-2025-49124, GHSA-42wg-hm62-jcwg]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2025-49125 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2025-49125, CVE-2025-49125, GHSA-wc4r-xq3c-5cf3]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2025-49128 com.fasterxml.jackson.core:jackson-core:jar:2.21.5 (runtime) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2025-49128, GHSA-wf8f-6423-gfxg]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2025-52434 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2025-52434, CVE-2025-52434, GHSA-4j3c-42xv-3f84]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2025-52520 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2025-52520, CVE-2025-52520, GHSA-wr62-c79q-cv37]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2025-52999 com.fasterxml.jackson.core:jackson-core:jar:2.21.5 (runtime) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2025-52999, GHSA-h46c-h94j-95f3]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2025-53506 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2025-53506, CVE-2025-53506, GHSA-25xr-qj8w-c4vf]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2025-55668 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2025-55668, CVE-2025-55668, GHSA-23hv-mwm6-g8jf]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2025-55752 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2025-55752, CVE-2025-55752, GHSA-wmwf-9ccg-fff5]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2025-55754 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2025-55754, CVE-2025-55754, GHSA-vfww-5hm6-hx2j]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2025-61795 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2025-61795, CVE-2025-61795, GHSA-hgrr-935x-pq79]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2025-66566 at.yawk.lz4:lz4-java:jar:1.10.1 (runtime) [REMOVED]
[INFO]     Aliases: [CVE-2025-66566, GHSA-cmp6-m4wj-q63q]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2025-66614 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2025-66614, CVE-2025-66614, GHSA-fpj8-gq4v-p354]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-10532 ch.qos.logback:logback-core:jar:1.5.38 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-10532, GHSA-jhq6-gfmj-v8fx]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-106449 at.yawk.lz4:lz4-java:jar:1.10.1 (runtime) [REMOVED]
[INFO]     Aliases: [CVE-2026-106449, GHSA-343h-94h5-c4wr]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-106450 at.yawk.lz4:lz4-java:jar:1.10.1 (runtime) [REMOVED]
[INFO]     Aliases: [CVE-2026-106450, GHSA-gm45-99xc-r7wv]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-106451 at.yawk.lz4:lz4-java:jar:1.10.1 (runtime) [REMOVED]
[INFO]     Aliases: [CVE-2026-106451, GHSA-mcr4-qmvw-px4g]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-106452 at.yawk.lz4:lz4-java:jar:1.10.1 (runtime) [REMOVED]
[INFO]     Aliases: [CVE-2026-106452, GHSA-4v53-57pg-c464]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-106453 at.yawk.lz4:lz4-java:jar:1.10.1 (runtime) [REMOVED]
[INFO]     Aliases: [CVE-2026-106453, GHSA-6cx8-rjf8-pr8g]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-108104 org.xerial.snappy:snappy-java:jar:1.1.10.7 (runtime) [RETAINED_AND_TRIMMED]
[INFO]     Applicability: UNRESOLVED; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Unresolved coverage: [containers.cna.affected[0]:defaultStatus=unaffected:[version=1.1.7.4,status=affected,versionType=custom,lessThan=1.1.10.10,lessThanOrEqual=null,changes=[], version=1.1.10.10,status=unaffected,versionType=custom,lessThan=null,lessThanOrEqual=null,changes=[]]: CVE default, explicit status, or overlapping statuses are unresolved, containers.cna.affected[0]:version=1.1.10.10,status=unaffected,versionType=custom,lessThan=null,lessThanOrEqual=null,changes=[]: Unsupported CVE versionType, containers.cna.affected[0]:version=1.1.7.4,status=affected,versionType=custom,lessThan=1.1.10.10,lessThanOrEqual=null,changes=[]: Unsupported CVE versionType]
[INFO]     Sources: [CVE_LIST]
[INFO]   - CVE-2026-108106 org.xerial.snappy:snappy-java:jar:1.1.10.7 (runtime) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2026-108106, GHSA-q233-g92q-qxp6]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration
[INFO]     Declared code: [org.xerial.snappy.Snappy] REVIEW_LEAD; classes: []; reasons: [HEURISTIC_REQUIRES_REVIEW]
[INFO]     Heuristic leads: [org.xerial.snappy.Snappy]
[INFO]     Unresolved coverage: [containers.cna.affected[0]:defaultStatus=unaffected:[version=0,status=affected,versionType=custom,lessThan=1.1.10.9,lessThanOrEqual=null,changes=[], version=1.1.10.9,status=unaffected,versionType=custom,lessThan=null,lessThanOrEqual=null,changes=[]]: CVE default, explicit status, or overlapping statuses are unresolved, containers.cna.affected[0]:version=0,status=affected,versionType=custom,lessThan=1.1.10.9,lessThanOrEqual=null,changes=[]: Unsupported CVE versionType, containers.cna.affected[0]:version=1.1.10.9,status=unaffected,versionType=custom,lessThan=null,lessThanOrEqual=null,changes=[]: Unsupported CVE versionType]
[INFO]     Sources: [CVE_LIST, OSV]
[INFO]   - CVE-2026-110257 org.ow2.asm:asm:jar:9.10.1 (test) [RETAINED_UNCHANGED]
[INFO]     Applicability: UNRESOLVED; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Unresolved coverage: [containers.cna.affected[0]:packageURL=pkg:maven/org.ow2.asm/asm,collectionURL=https://repo1.maven.org/maven2/,packageName=null: Conflicting or unsupported CVE package identities]
[INFO]     Sources: [CVE_LIST]
[INFO]   - CVE-2026-110258 org.ow2.asm:asm:jar:9.10.1 (test) [RETAINED_UNCHANGED]
[INFO]     Applicability: UNRESOLVED; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Unresolved coverage: [containers.cna.affected[0]:packageURL=pkg:maven/org.ow2.asm/asm,collectionURL=https://repo1.maven.org/maven2/,packageName=null: Conflicting or unsupported CVE package identities]
[INFO]     Sources: [CVE_LIST]
[INFO]   - CVE-2026-110259 org.ow2.asm:asm:jar:9.10.1 (test) [RETAINED_UNCHANGED]
[INFO]     Applicability: UNRESOLVED; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Unresolved coverage: [containers.cna.affected[0]:packageURL=pkg:maven/org.ow2.asm/asm,collectionURL=https://repo1.maven.org/maven2/,packageName=null: Conflicting or unsupported CVE package identities]
[INFO]     Sources: [CVE_LIST]
[INFO]   - CVE-2026-110260 org.ow2.asm:asm:jar:9.10.1 (test) [RETAINED_UNCHANGED]
[INFO]     Applicability: UNRESOLVED; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Unresolved coverage: [containers.cna.affected[0]:packageURL=pkg:maven/org.ow2.asm/asm,collectionURL=https://repo1.maven.org/maven2/,packageName=null: Conflicting or unsupported CVE package identities]
[INFO]     Sources: [CVE_LIST]
[INFO]   - CVE-2026-110261 org.ow2.asm:asm:jar:9.10.1 (test) [RETAINED_UNCHANGED]
[INFO]     Applicability: UNRESOLVED; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Unresolved coverage: [containers.cna.affected[0]:packageURL=pkg:maven/org.ow2.asm/asm,collectionURL=https://repo1.maven.org/maven2/,packageName=null: Conflicting or unsupported CVE package identities]
[INFO]     Sources: [CVE_LIST]
[INFO]   - CVE-2026-110263 org.ow2.asm:asm:jar:9.10.1 (test) [RETAINED_UNCHANGED]
[INFO]     Applicability: UNRESOLVED; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Unresolved coverage: [containers.cna.affected[0]:packageURL=pkg:maven/org.ow2.asm/asm,collectionURL=https://repo1.maven.org/maven2/,packageName=null: Conflicting or unsupported CVE package identities]
[INFO]     Sources: [CVE_LIST]
[INFO]   - CVE-2026-110879 tools.jackson.core:jackson-databind:jar:3.1.5 (compile) [RETAINED_UNCHANGED]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Declared code: [src/main/java/tools/jackson/databind/DatabindContext.java] RESOLVED; classes: [tools.jackson.databind.DatabindContext, tools.jackson.databind.DatabindContext$1]; reasons: []
[INFO]     Declared code: [src/main/java/tools/jackson/databind/jsontype/DefaultBaseTypeLimitingValidator.java] RESOLVED; classes: [tools.jackson.databind.jsontype.DefaultBaseTypeLimitingValidator, tools.jackson.databind.jsontype.DefaultBaseTypeLimitingValidator$UnsafeBaseTypes]; reasons: []
[INFO]     Declared code: [src/main/java/tools/jackson/databind/jsontype/impl/StdTypeResolverBuilder.java] RESOLVED; classes: [tools.jackson.databind.jsontype.impl.StdTypeResolverBuilder, tools.jackson.databind.jsontype.impl.StdTypeResolverBuilder$1]; reasons: []
[INFO]     Declared code: [DatabindContext._resolveAndValidateGeneric] RESOLVED; classes: [tools.jackson.databind.DatabindContext, tools.jackson.databind.DatabindContext$1]; reasons: []
[INFO]     Declared code: [DatabindContext._validateTypeParameter] RESOLVED; classes: [tools.jackson.databind.DatabindContext, tools.jackson.databind.DatabindContext$1]; reasons: []
[INFO]     Declared code: [DefaultBaseTypeLimitingValidator] UNRESOLVED; classes: []; reasons: [ROUTINE_METHOD_NOT_FOUND]
[INFO]     Declared code: [StdTypeResolverBuilder] UNRESOLVED; classes: []; reasons: [ROUTINE_METHOD_NOT_FOUND]
[INFO]     Sources: [CVE_LIST]
[INFO]   - CVE-2026-110974 com.vaadin.external.google:android-json:jar:0.0.20131108.vaadin1 (test) [RETAINED_UNCHANGED]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [CVE_LIST]
[INFO]   - CVE-2026-111551 org.apache.kafka:kafka-clients:jar:4.2.1 (compile) [RETAINED_UNCHANGED]
[INFO]     Applicability: UNRESOLVED; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Unresolved coverage: [containers.cna.affected[1]:defaultStatus=unaffected:[version=0.10.0.0,status=affected,versionType=semver,lessThan=null,lessThanOrEqual=4.1.2,changes=[], version=4.2.0,status=affected,versionType=semver,lessThan=null,lessThanOrEqual=4.2.1,changes=[], version=4.3.0,status=affected,versionType=semver,lessThan=null,lessThanOrEqual=4.3.1,changes=[]]: CVE default, explicit status, or overlapping statuses are unresolved, containers.cna.affected[1]:version=0.10.0.0,status=affected,versionType=semver,lessThan=null,lessThanOrEqual=4.1.2,changes=[]: Unsupported CVE versionType, containers.cna.affected[1]:version=4.2.0,status=affected,versionType=semver,lessThan=null,lessThanOrEqual=4.2.1,changes=[]: Unsupported CVE versionType, containers.cna.affected[1]:version=4.3.0,status=affected,versionType=semver,lessThan=null,lessThanOrEqual=4.3.1,changes=[]: Unsupported CVE versionType]
[INFO]     Sources: [CVE_LIST]
[INFO]   - CVE-2026-112046 org.ow2.asm:asm:jar:9.10.1 (test) [RETAINED_UNCHANGED]
[INFO]     Applicability: UNRESOLVED; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Unresolved coverage: [containers.cna.affected[0]:packageURL=pkg:maven/org.ow2.asm/asm,collectionURL=https://repo1.maven.org/maven2/,packageName=null: Conflicting or unsupported CVE package identities]
[INFO]     Sources: [CVE_LIST]
[INFO]   - CVE-2026-113602 net.minidev:json-smart:jar:2.6.0 (test) [RETAINED_UNCHANGED]
[INFO]     Applicability: UNRESOLVED; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Unresolved coverage: [containers.cna.affected[0]:defaultStatus=unaffected:[version=0,status=affected,versionType=semver,lessThan=null,lessThanOrEqual=2.6.0,changes=[]]: CVE default, explicit status, or overlapping statuses are unresolved, containers.cna.affected[0]:version=0,status=affected,versionType=semver,lessThan=null,lessThanOrEqual=2.6.0,changes=[]: Unsupported CVE versionType]
[INFO]     Sources: [CVE_LIST]
[INFO]   - CVE-2026-116486 org.objenesis:objenesis:jar:3.3 (test) [RETAINED_UNCHANGED]
[INFO]     Applicability: UNRESOLVED; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Unresolved coverage: [containers.cna.affected[0]:defaultStatus=unaffected:[version=0,status=affected,versionType=custom,lessThan=3.6,lessThanOrEqual=null,changes=[], version=3.6,status=unaffected,versionType=custom,lessThan=null,lessThanOrEqual=null,changes=[]]: CVE default, explicit status, or overlapping statuses are unresolved, containers.cna.affected[0]:version=0,status=affected,versionType=custom,lessThan=3.6,lessThanOrEqual=null,changes=[]: Unsupported CVE versionType, containers.cna.affected[0]:version=3.6,status=unaffected,versionType=custom,lessThan=null,lessThanOrEqual=null,changes=[]: Unsupported CVE versionType]
[INFO]     Sources: [CVE_LIST]
[INFO]   - CVE-2026-116590 org.xerial.snappy:snappy-java:jar:1.1.10.7 (runtime) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2026-116590, GHSA-xqrx-qh46-34m7]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-1225 ch.qos.logback:logback-core:jar:1.5.38 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-1225, GHSA-qqpg-mvqg-649v]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-19032 tools.jackson.core:jackson-databind:jar:3.1.5 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-19032, GHSA-wjgm-6hv5-3cvf]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Declared code: [src/main/java/tools/jackson/databind/deser/jdk/JDKFromStringDeserializer.java] RESOLVED; classes: [tools.jackson.databind.deser.jdk.JDKFromStringDeserializer, tools.jackson.databind.deser.jdk.JDKFromStringDeserializer$NioPathHelper, tools.jackson.databind.deser.jdk.JDKFromStringDeserializer$NioPathHelper$NioPathWindowsChecker, tools.jackson.databind.deser.jdk.JDKFromStringDeserializer$StringBufferDeserializer, tools.jackson.databind.deser.jdk.JDKFromStringDeserializer$StringBuilderDeserializer]; reasons: []
[INFO]     Declared code: [tools.jackson.databind.deser.jdk.JDKFromStringDeserializer.NioPathHelper.deserialize] UNRESOLVED; classes: []; reasons: [ROUTINE_OWNER_NOT_FOUND]
[INFO]     Declared code: [tools.jackson.databind.ObjectMapper] REVIEW_LEAD; classes: []; reasons: [HEURISTIC_REQUIRES_REVIEW]
[INFO]     Declared code: [tools.jackson.databind.exc.ValueInstantiationException] REVIEW_LEAD; classes: []; reasons: [HEURISTIC_REQUIRES_REVIEW]
[INFO]     Declared code: [tools.jackson.databind.json.JsonMapper] REVIEW_LEAD; classes: []; reasons: [HEURISTIC_REQUIRES_REVIEW]
[INFO]     Heuristic leads: [tools.jackson.databind.ObjectMapper, tools.jackson.databind.exc.ValueInstantiationException, tools.jackson.databind.json.JsonMapper]
[INFO]     Sources: [CVE_LIST, OSV]
[INFO]   - CVE-2026-22731 org.springframework.boot:spring-boot-starter-actuator:jar:4.1.1 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-22731, GHSA-8hfc-fq58-r658]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-22733 org.springframework.boot:spring-boot-starter-actuator:jar:4.1.1 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-22733, GHSA-mgvc-8q2h-5pgc]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-22735 org.springframework:spring-webmvc:jar:7.0.9 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2026-22735, GHSA-6hcq-hmm3-jj3c]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-22737 org.springframework:spring-webmvc:jar:7.0.9 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2026-22737, GHSA-4773-3jfm-qmx3]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-22741 org.springframework:spring-webmvc:jar:7.0.9 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2026-22741, GHSA-wg35-8jpf-2xv3]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-22745 org.springframework:spring-webmvc:jar:7.0.9 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2026-22745, GHSA-6p4f-wcwh-5vvm]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-24400 org.assertj:assertj-core:jar:3.27.3 (test) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-24400, GHSA-rqfh-9r24-8c9r]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Declared code: [org.assertj.core.api.AbstractCharSequenceAssert] REVIEW_LEAD; classes: []; reasons: [HEURISTIC_REQUIRES_REVIEW]
[INFO]     Declared code: [org.assertj.core.util.xml.XmlStringPrettyFormatter] REVIEW_LEAD; classes: []; reasons: [HEURISTIC_REQUIRES_REVIEW]
[INFO]     Heuristic leads: [org.assertj.core.api.AbstractCharSequenceAssert, org.assertj.core.util.xml.XmlStringPrettyFormatter]
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-24734 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2026-24734, CVE-2026-24734, GHSA-mgp5-rv84-w37q]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-24880 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2026-24880, CVE-2026-24880, GHSA-563x-q5rq-57qp]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-25854 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2026-25854, CVE-2026-25854, GHSA-9m3c-qcxr-9x87]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-29062 tools.jackson.core:jackson-core:jar:3.1.5 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-29062, GHSA-6v53-7c9g-w56r]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-29129 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2026-29129, CVE-2026-29129, GHSA-69cc-cv78-qc8g]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-32990 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2026-32990, CVE-2026-32990, GHSA-8mc5-53m5-3qj2]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-33557 org.apache.kafka:kafka-clients:jar:4.2.1 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-kafka-2026-33557, CVE-2026-33557, GHSA-28jg-cgg7-j4wc]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-33558 org.apache.kafka:kafka-clients:jar:4.2.1 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-kafka-2026-33558, CVE-2026-33558, GHSA-wf66-mphr-4c4r]
[INFO]     Applicability: UNRESOLVED; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Unresolved coverage: [containers.cna.affected[1]:defaultStatus=unaffected:[version=0.11.0,status=affected,versionType=semver,lessThan=null,lessThanOrEqual=3.9.1,changes=[], version=4.0.0,status=affected,versionType=semver,lessThan=null,lessThanOrEqual=null,changes=[]]: CVE default, explicit status, or overlapping statuses are unresolved, containers.cna.affected[1]:version=0.11.0,status=affected,versionType=semver,lessThan=null,lessThanOrEqual=3.9.1,changes=[]: Unsupported CVE versionType, containers.cna.affected[1]:version=4.0.0,status=affected,versionType=semver,lessThan=null,lessThanOrEqual=null,changes=[]: Unsupported CVE versionType]
[INFO]     Sources: [CVE_LIST, OSV]
[INFO]   - CVE-2026-34483 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2026-34483, CVE-2026-34483, GHSA-rv64-5gf8-9qq8]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-34487 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2026-34487, CVE-2026-34487, GHSA-x4m4-345f-5h5g]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-35554 org.apache.kafka:kafka-clients:jar:4.2.1 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-35554, GHSA-5qcv-4rpc-jp93]
[INFO]     Applicability: UNRESOLVED; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Unresolved coverage: [containers.cna.affected[0]:defaultStatus=unaffected:[version=2.8.0,status=affected,versionType=semver,lessThan=null,lessThanOrEqual=3.9.1,changes=[], version=4.0.0,status=affected,versionType=semver,lessThan=null,lessThanOrEqual=4.0.1,changes=[], version=4.1.0,status=affected,versionType=semver,lessThan=null,lessThanOrEqual=4.1.1,changes=[]]: CVE default, explicit status, or overlapping statuses are unresolved, containers.cna.affected[0]:version=2.8.0,status=affected,versionType=semver,lessThan=null,lessThanOrEqual=3.9.1,changes=[]: Unsupported CVE versionType, containers.cna.affected[0]:version=4.0.0,status=affected,versionType=semver,lessThan=null,lessThanOrEqual=4.0.1,changes=[]: Unsupported CVE versionType, containers.cna.affected[0]:version=4.1.0,status=affected,versionType=semver,lessThan=null,lessThanOrEqual=4.1.1,changes=[]: Unsupported CVE versionType]
[INFO]     Sources: [CVE_LIST, OSV]
[INFO]   - CVE-2026-40973 org.springframework.boot:spring-boot:jar:4.1.1 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-40973, GHSA-wwpq-f5c3-7hvx]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-40976 org.springframework.boot:spring-boot:jar:4.1.1 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-40976, GHSA-8v8j-3hxp-93wr]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-40983 io.micrometer:micrometer-core:jar:1.17.1 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-40983, GHSA-w737-wx49-qj23]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-40984 io.micrometer:micrometer-core:jar:1.17.1 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-40984, GHSA-g3pr-3p32-fp23]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-40992 org.springframework.boot:spring-boot-starter-mail:jar:4.1.1 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-40992, GHSA-9wxp-w4px-32vh]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-41001 org.springframework.boot:spring-boot-autoconfigure:jar:4.1.1 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-41001, GHSA-ggg2-9786-hwc8]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-41284 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2026-41284, CVE-2026-41284, GHSA-gx5v-xp9w-j4cg]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-41293 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2026-41293, CVE-2026-41293, GHSA-r29c-68gh-xp6x]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-41726 org.springframework.kafka:spring-kafka:jar:4.1.1 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-41726, GHSA-xvfq-4q6q-gxx7]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-41727 org.springframework.kafka:spring-kafka:jar:4.1.1 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-41727, GHSA-53w6-v7cv-fc9h]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-41731 org.springframework.kafka:spring-kafka:jar:4.1.1 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-41731, GHSA-xq69-5h5v-x9x4]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-41841 org.springframework:spring-webmvc:jar:7.0.9 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2026-41841, GHSA-mq64-j8f9-9gcj]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-41842 org.springframework:spring-webmvc:jar:7.0.9 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2026-41842, GHSA-x23c-287f-qqv5]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-41843 org.springframework:spring-webmvc:jar:7.0.9 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2026-41843, GHSA-72pg-x5f8-j25j]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-41844 org.springframework:spring-webmvc:jar:7.0.9 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2026-41844, GHSA-h3qp-gqrc-q736]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-41845 org.springframework:spring-webmvc:jar:7.0.9 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2026-41845, GHSA-3chg-m5w7-qfv5]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-41846 org.springframework:spring-webmvc:jar:7.0.9 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2026-41846, GHSA-957g-f97v-vppc]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-41848 org.springframework:spring-core:jar:7.0.9 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-41848, GHSA-659m-px2c-25wj]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-41849 org.springframework:spring-expression:jar:7.0.9 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-41849, GHSA-775g-4xr8-78h8]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-41850 org.springframework:spring-expression:jar:7.0.9 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-41850, GHSA-r5w3-xv2f-j59q]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-41851 org.springframework:spring-expression:jar:7.0.9 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-41851, GHSA-wxpp-56q6-5pcg]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-41852 org.springframework:spring-expression:jar:7.0.9 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-41852, GHSA-9f52-rjqv-25qv]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-41853 org.springframework:spring-webmvc:jar:7.0.9 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2026-41853, GHSA-cjpg-rgq5-fr37]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-41854 org.springframework:spring-web:jar:7.0.9 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-41854, GHSA-7m2p-62gw-p8qq]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-42498 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2026-42498, CVE-2026-42498, GHSA-fv25-8xcx-gqjc]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-43512 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2026-43512, CVE-2026-43512, GHSA-h6fc-48rj-7qqh]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-43513 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2026-43513, CVE-2026-43513, GHSA-5mp6-jrq3-r938]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-43514 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2026-43514, CVE-2026-43514, GHSA-9m89-8frq-c98c]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-43515 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2026-43515, CVE-2026-43515, GHSA-5m62-pw8w-7w9f]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-47884 org.springframework:spring-webmvc:jar:7.0.9 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2026-47884, GHSA-pc63-qcmh-9cmg]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-47890 org.springframework:spring-webmvc:jar:7.0.9 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2026-47890, GHSA-j9f9-w8pj-32f8]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-53404 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2026-53404, CVE-2026-53404, GHSA-h792-v28v-ppgr]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-54512 tools.jackson.core:jackson-databind:jar:3.1.5 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-54512, GHSA-j3rv-43j4-c7qm]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-54513 tools.jackson.core:jackson-databind:jar:3.1.5 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-54513, GHSA-rmj7-2vxq-3g9f]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-54514 tools.jackson.core:jackson-databind:jar:3.1.5 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-54514, GHSA-hgj6-7826-r7m5]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-54515 tools.jackson.core:jackson-databind:jar:3.1.5 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-54515, GHSA-5jmj-h7xm-6q6v]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-54516 tools.jackson.core:jackson-databind:jar:3.1.5 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-54516, GHSA-9fxm-vc8v-hj55]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-54517 tools.jackson.core:jackson-databind:jar:3.1.5 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-54517, GHSA-5hh8-q8hv-fr38]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-54518 tools.jackson.core:jackson-databind:jar:3.1.5 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-54518, GHSA-rcqc-6cw3-h962]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-55276 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2026-55276, CVE-2026-55276, GHSA-mqg3-r7h5-24x4]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-55956 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2026-55956, CVE-2026-55956, GHSA-5v3h-fjv2-54fg]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-55957 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2026-55957, CVE-2026-55957, GHSA-7895-gffq-w6jq]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-59888 tools.jackson.core:jackson-databind:jar:3.1.5 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-59888, GHSA-3pjw-73gf-8qr5]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-59889 tools.jackson.core:jackson-databind:jar:3.1.5 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-59889, GHSA-5gvw-p9qm-jgwh]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-59949 at.yawk.lz4:lz4-java:jar:1.10.1 (runtime) [REMOVED]
[INFO]     Aliases: [CVE-2026-59949, GHSA-xx22-p4ch-683r]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-65182 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2026-65182, CVE-2026-65182, GHSA-gcx9-497g-6cp6]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-65637 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2026-65637, CVE-2026-65637, GHSA-f525-44xv-f2qj]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-65905 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2026-65905, CVE-2026-65905, GHSA-9xv2-5v5q-p794]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-68497 tools.jackson.core:jackson-databind:jar:3.1.5 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-68497, GHSA-q4xh-88c3-wmh7]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Declared code: [src/main/java/tools/jackson/databind/ext/CoreXMLDeserializers.java] RESOLVED; classes: [tools.jackson.databind.ext.CoreXMLDeserializers, tools.jackson.databind.ext.CoreXMLDeserializers$Std]; reasons: []
[INFO]     Declared code: [tools.jackson.databind.ext.CoreXMLDeserializers.Std._deserialize] UNRESOLVED; classes: []; reasons: [ROUTINE_OWNER_NOT_FOUND]
[INFO]     Declared code: [tools.jackson.databind.ObjectMapper] REVIEW_LEAD; classes: []; reasons: [HEURISTIC_REQUIRES_REVIEW]
[INFO]     Declared code: [tools.jackson.databind.json.JsonMapper] REVIEW_LEAD; classes: []; reasons: [HEURISTIC_REQUIRES_REVIEW]
[INFO]     Heuristic leads: [tools.jackson.databind.ObjectMapper, tools.jackson.databind.json.JsonMapper]
[INFO]     Sources: [CVE_LIST, OSV]
[INFO]   - CVE-2026-68498 com.fasterxml.jackson.core:jackson-core:jar:2.21.5 (runtime) [RETAINED_AND_TRIMMED]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; Vulnerable class survives trimmed archive: com.fasterxml.jackson.core.json.ReaderBasedJsonParser
[INFO]     Declared code: [src/main/java/com/fasterxml/jackson/core/json/ReaderBasedJsonParser.java] RESOLVED; classes: [com.fasterxml.jackson.core.json.ReaderBasedJsonParser]; reasons: []
[INFO]     Declared code: [ReaderBasedJsonParser._parseName2] RESOLVED; classes: [com.fasterxml.jackson.core.json.ReaderBasedJsonParser]; reasons: []
[INFO]     Sources: [CVE_LIST]
[INFO]   - CVE-2026-68498 tools.jackson.core:jackson-core:jar:3.1.5 (compile) [RETAINED_UNCHANGED]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Declared code: [src/main/java/tools/jackson/core/json/ReaderBasedJsonParser.java] RESOLVED; classes: [tools.jackson.core.json.ReaderBasedJsonParser]; reasons: []
[INFO]     Declared code: [ReaderBasedJsonParser._parseName2] RESOLVED; classes: [tools.jackson.core.json.ReaderBasedJsonParser]; reasons: []
[INFO]     Sources: [CVE_LIST]
[INFO]   - CVE-2026-68525 org.apache.tomcat.embed:tomcat-embed-core:jar:11.0.24 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2026-68525, CVE-2026-68525, GHSA-h3x4-894j-xpx5]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-77310 tools.jackson.core:jackson-databind:jar:3.1.5 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-77310, GHSA-vvgp-rfg2-7rr6]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-83557 tools.jackson.core:jackson-databind:jar:3.1.5 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-83557, GHSA-gx83-3vf8-gh7j]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Declared code: [src/main/java/tools/jackson/databind/jsontype/DefaultBaseTypeLimitingValidator.java] RESOLVED; classes: [tools.jackson.databind.jsontype.DefaultBaseTypeLimitingValidator, tools.jackson.databind.jsontype.DefaultBaseTypeLimitingValidator$UnsafeBaseTypes]; reasons: []
[INFO]     Declared code: [tools.jackson.databind.jsontype.DefaultBaseTypeLimitingValidator.isUnsafeBaseType] RESOLVED; classes: [tools.jackson.databind.jsontype.DefaultBaseTypeLimitingValidator, tools.jackson.databind.jsontype.DefaultBaseTypeLimitingValidator$UnsafeBaseTypes]; reasons: []
[INFO]     Sources: [CVE_LIST, OSV]
[INFO]   - CVE-2026-84939 org.freemarker:freemarker:jar:2.3.34 (runtime) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2026-84939, GHSA-27j2-h3m2-8237]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration
[INFO]     Unresolved coverage: [containers.cna.affected[0]:defaultStatus=unaffected:[version=2.2.0,status=affected,versionType=semver,lessThan=null,lessThanOrEqual=2.3.34,changes=[], version=2.3.35,status=unaffected,versionType=semver,lessThan=null,lessThanOrEqual=null,changes=[]]: CVE default, explicit status, or overlapping statuses are unresolved, containers.cna.affected[0]:version=2.2.0,status=affected,versionType=semver,lessThan=null,lessThanOrEqual=2.3.34,changes=[]: Unsupported CVE versionType, containers.cna.affected[0]:version=2.3.35,status=unaffected,versionType=semver,lessThan=null,lessThanOrEqual=null,changes=[]: Unsupported CVE versionType]
[INFO]     Sources: [CVE_LIST, OSV]
[INFO]   - CVE-2026-87795 com.github.luben:zstd-jni:jar:1.5.7-18 (runtime) [REMOVED]
[INFO]     Applicability: UNRESOLVED; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Unresolved coverage: [containers.cna.affected[0]:packageURL=pkg:maven/com.github.luben/zstd-jni,collectionURL=https://repo1.maven.org/maven2/com/github/luben/zstd-jni/,packageName=null: Conflicting or unsupported CVE package identities]
[INFO]     Sources: [CVE_LIST]
[INFO]   - CVE-2026-87823 com.github.luben:zstd-jni:jar:1.5.7-18 (runtime) [REMOVED]
[INFO]     Applicability: UNRESOLVED; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Unresolved coverage: [containers.cna.affected[0]:packageURL=pkg:maven/com.github.luben/zstd-jni,collectionURL=https://repo1.maven.org/maven2/com/github/luben/zstd-jni/,packageName=null: Conflicting or unsupported CVE package identities]
[INFO]     Sources: [CVE_LIST]
[INFO]   - CVE-2026-87824 com.github.luben:zstd-jni:jar:1.5.7-18 (runtime) [REMOVED]
[INFO]     Applicability: UNRESOLVED; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Unresolved coverage: [containers.cna.affected[0]:packageURL=pkg:maven/com.github.luben/zstd-jni,collectionURL=https://repo1.maven.org/maven2/com/github/luben/zstd-jni/,packageName=null: Conflicting or unsupported CVE package identities]
[INFO]     Sources: [CVE_LIST]
[INFO]   - CVE-2026-87825 com.github.luben:zstd-jni:jar:1.5.7-18 (runtime) [REMOVED]
[INFO]     Applicability: UNRESOLVED; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Unresolved coverage: [containers.cna.affected[0]:packageURL=pkg:maven/com.github.luben/zstd-jni,collectionURL=https://repo1.maven.org/maven2/com/github/luben/zstd-jni/,packageName=null: Conflicting or unsupported CVE package identities]
[INFO]     Sources: [CVE_LIST]
[INFO]   - CVE-2026-87877 com.github.luben:zstd-jni:jar:1.5.7-18 (runtime) [REMOVED]
[INFO]     Applicability: UNRESOLVED; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Unresolved coverage: [containers.cna.affected[0]:packageURL=pkg:maven/com.github.luben/zstd-jni,collectionURL=https://repo1.maven.org/maven2/com/github/luben/zstd-jni/,packageName=null: Conflicting or unsupported CVE package identities]
[INFO]     Sources: [CVE_LIST]
[INFO]   - CVE-2026-89045 com.github.luben:zstd-jni:jar:1.5.7-18 (runtime) [REMOVED]
[INFO]     Applicability: UNRESOLVED; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Unresolved coverage: [containers.cna.affected[0]:packageURL=pkg:maven/com.github.luben/zstd-jni,collectionURL=https://repo1.maven.org/maven2/com/github/luben/zstd-jni/,packageName=null: Conflicting or unsupported CVE package identities]
[INFO]     Sources: [CVE_LIST]
[INFO]   - CVE-2026-89046 com.github.luben:zstd-jni:jar:1.5.7-18 (runtime) [REMOVED]
[INFO]     Applicability: UNRESOLVED; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Unresolved coverage: [containers.cna.affected[0]:packageURL=pkg:maven/com.github.luben/zstd-jni,collectionURL=https://repo1.maven.org/maven2/com/github/luben/zstd-jni/,packageName=null: Conflicting or unsupported CVE package identities]
[INFO]     Sources: [CVE_LIST]
[INFO]   - CVE-2026-89407 com.fasterxml.jackson.core:jackson-core:jar:2.21.5 (runtime) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2026-89407, GHSA-p6pp-m3f8-5c89]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; Vulnerable class survives trimmed archive: com.fasterxml.jackson.core.io.NumberInput
[INFO]     Declared code: [com.fasterxml.jackson.core.io.NumberInput.looksLikeValidNumber] RESOLVED; classes: [com.fasterxml.jackson.core.io.NumberInput]; reasons: []
[INFO]     Declared code: [com.fasterxml.jackson.core.io.NumberInput] REVIEW_LEAD; classes: []; reasons: [HEURISTIC_REQUIRES_REVIEW]
[INFO]     Heuristic leads: [com.fasterxml.jackson.core.io.NumberInput]
[INFO]     Sources: [CVE_LIST, OSV]
[INFO]   - CVE-2026-89407 tools.jackson.core:jackson-core:jar:3.1.5 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-89407, GHSA-p6pp-m3f8-5c89]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Declared code: [tools.jackson.core.io.NumberInput.looksLikeValidNumber] RESOLVED; classes: [tools.jackson.core.io.NumberInput]; reasons: []
[INFO]     Sources: [CVE_LIST, OSV]
[INFO]   - CVE-2026-89425 com.fasterxml.jackson.core:jackson-core:jar:2.21.5 (runtime) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2026-89425, GHSA-7hhh-6rmp-j9qf]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; Vulnerable class survives trimmed archive: com.fasterxml.jackson.core.json.UTF8DataInputJsonParser
[INFO]     Declared code: [com.fasterxml.jackson.core.json.UTF8DataInputJsonParser._reportInvalidToken] RESOLVED; classes: [com.fasterxml.jackson.core.json.UTF8DataInputJsonParser]; reasons: []
[INFO]     Sources: [CVE_LIST, OSV]
[INFO]   - CVE-2026-89425 tools.jackson.core:jackson-core:jar:3.1.5 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-89425, GHSA-7hhh-6rmp-j9qf]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Declared code: [tools.jackson.core.json.UTF8DataInputJsonParser._reportInvalidToken] RESOLVED; classes: [tools.jackson.core.json.UTF8DataInputJsonParser]; reasons: []
[INFO]     Sources: [CVE_LIST, OSV]
[INFO]   - CVE-2026-90559 org.xerial.snappy:snappy-java:jar:1.1.10.7 (runtime) [RETAINED_AND_TRIMMED]
[INFO]     Applicability: UNRESOLVED; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Unresolved coverage: [containers.cna.affected[0]:packageURL=pkg:maven/org.xerial.snappy/snappy-java,collectionURL=https://repo1.maven.org/maven2/org/xerial/snappy-java/,packageName=null: Conflicting or unsupported CVE package identities]
[INFO]     Sources: [CVE_LIST]
[INFO]   - CVE-2026-90560 com.github.luben:zstd-jni:jar:1.5.7-18 (runtime) [REMOVED]
[INFO]     Applicability: UNRESOLVED; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Unresolved coverage: [containers.cna.affected[0]:packageURL=pkg:maven/com.github.luben/zstd-jni,collectionURL=https://repo1.maven.org/maven2/com/github/luben/zstd-jni/,packageName=null: Conflicting or unsupported CVE package identities]
[INFO]     Sources: [CVE_LIST]
[INFO]   - CVE-2026-91776 tools.jackson.core:jackson-databind:jar:3.1.5 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-91776, GHSA-wv8q-qhhj-9h54]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Declared code: [tools.jackson.databind.jsontype.impl.TypeDeserializerBase._findDeserializer] RESOLVED; classes: [tools.jackson.databind.jsontype.impl.TypeDeserializerBase]; reasons: []
[INFO]     Sources: [CVE_LIST, OSV]
[INFO]   - CVE-2026-91777 tools.jackson.core:jackson-databind:jar:3.1.5 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-91777, GHSA-cxp5-3px4-pw24]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Declared code: [tools.jackson.databind.deser.jdk.CollectionDeserializer.CollectionReferringAccumulator.resolveForwardReference] UNRESOLVED; classes: []; reasons: [ROUTINE_OWNER_NOT_FOUND]
[INFO]     Declared code: [tools.jackson.databind.deser.jdk.MapDeserializer.MapReferringAccumulator.resolveForwardReference] UNRESOLVED; classes: []; reasons: [ROUTINE_OWNER_NOT_FOUND]
[INFO]     Sources: [CVE_LIST, OSV]
[INFO]   - CVE-2026-93451 org.xerial.snappy:snappy-java:jar:1.1.10.7 (runtime) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2026-93451, GHSA-gwq9-9ffj-mvrv]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration
[INFO]     Declared code: [org.xerial.snappy.Snappy] REVIEW_LEAD; classes: []; reasons: [HEURISTIC_REQUIRES_REVIEW]
[INFO]     Heuristic leads: [org.xerial.snappy.Snappy]
[INFO]     Unresolved coverage: [containers.cna.affected[0]:packageURL=pkg:maven/org.xerial.snappy/snappy-java,collectionURL=https://repo1.maven.org/maven2/org/xerial/snappy-java/,packageName=null: Conflicting or unsupported CVE package identities]
[INFO]     Sources: [CVE_LIST, OSV]
[INFO]   - CVE-2026-93452 org.xerial.snappy:snappy-java:jar:1.1.10.7 (runtime) [RETAINED_AND_TRIMMED]
[INFO]     Applicability: UNRESOLVED; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Unresolved coverage: [containers.cna.affected[0]:packageURL=pkg:maven/org.xerial.snappy/snappy-java,collectionURL=https://repo1.maven.org/maven2/org/xerial/snappy-java/,packageName=null: Conflicting or unsupported CVE package identities]
[INFO]     Sources: [CVE_LIST]
[INFO]   - CVE-2026-9828 ch.qos.logback:logback-core:jar:1.5.38 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-9828, GHSA-p47f-322f-whfh]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - GHSA-2m67-wjpj-xhg9 tools.jackson.core:jackson-core:jar:3.1.5 (compile) [RETAINED_UNCHANGED]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO] CVE Sources:
[INFO]   - CVE_LIST PARTIAL
[INFO]     Skipped 79 CVE List source row(s)
[INFO]     Source diagnostics are in the JSON snapshot
[INFO]   - OSV CURRENT
[INFO] Adopted vulnerability mapping catalogs:
[INFO]   - io.github.spockz.catalogs:logback-vulnerability-mapping-catalog:1.0.0:jar: (catalogId=logback-core-cve-2025-11226, sha256=a1339af5e23c58c06ca8ebb86dda095173d3f52de8363284fce031014bf82ff2, mappings=2, unresolved=0)
[INFO] POM exclusion review (advisory only):
[INFO]   Repeated POM exclusions:
[INFO]     none found across effective dependency paths
[INFO]   Exclusion provenance incomplete for 1925 dependency or exclusion origins.
[INFO]   Maven supplied no source location/identity or the location matched zero or
[INFO]   multiple original POM rows. This advisory review does not affect elision.
[INFO]   Full evidence is in the JSON snapshot fields
[INFO]   exclusionReview.snapshot.dependencies and
[INFO]   exclusionReview.snapshot.diagnostics.
[INFO] Mediated TEST dependency graph (captured and saved by the elide goal):
[INFO]   - io.github.spockz:example-spring-boot-app:0.1.0-SNAPSHOT {nodeId=n0} [RETAINED]
[INFO]   - io.github.spockz:example-spring-boot-app:0.1.0-SNAPSHOT -> com.github.luben:zstd-jni:jar:1.5.7-18 (runtime) {nodeId=n6} [EFFECTIVE_DROP]
[INFO]   - io.github.spockz:example-spring-boot-app:0.1.0-SNAPSHOT -> com.github.spotbugs:spotbugs-annotations:jar:4.10.5 (runtime) {nodeId=n9} [RETAINED, CLASS_TRIMMED]
[INFO]   ... 112 dependency graph rows elided (sha256:3d7f8a05e6f8c18cdc4b9bcd6c7d85edab3103e5f7b633e97e8563c0692e0a3c)
[INFO] ------------------------------------------------------------------------
[INFO] ------------------------------------------------------------------------
[INFO] Total time: <BUILD_TIME>
[INFO] Finished at: <TIMESTAMP>
[INFO] ------------------------------------------------------------------------
```

<!-- END:transcript:report-spring-boot-app -->

#### example-cve-unused-app

Look at the `DECLARED_CODE_ABSENT` finding for `CVE-2022-42889`. An explicit POM mapping identifies `StringLookup` and requests verification with `HIGH`; trimming removes that class from Commons Text, allowing the common checks to prove the declared code absent and publish VEX. The fixture's package and heuristic claims provide review context.

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
[INFO] Dependency Elider report JSON snapshot: <PROJECT_ROOT>/examples/example-cve-unused-app/target/dependency-elider-report.json
[INFO] Dependency Elider report
[INFO] Project: io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT
[INFO] Snapshot: last successful elide run at <TIMESTAMP>
[INFO] Analysis target JDK release: 21
[INFO] Elider runtime JDK release: <RUNTIME_RELEASE>
[INFO] Policy: retained=[], banished=[]
[INFO] The snapshot does not revalidate changed inputs when this goal runs.
[INFO] Conventional Java source layout assumption saved for this run: true
[INFO] Whole artifacts dropped: 1 / 26 (original JAR file bytes: 657.80 KiB)
[INFO] Program classes removed with dropped JARs: 395 (uncompressed .class entry payload bytes: 1.37 MiB; excludes module descriptors and archive sanitation metadata)
[INFO]   - org.apache.commons:commons-lang3:jar:3.17.0 (compile): 657.80 KiB original JAR, 395 class entries, 1.37 MiB
[INFO] Raw trace decision drops before graph safety: 2
[INFO] Applied bans: none
[INFO] Program classes pruned from retained JARs: 331 (uncompressed omitted .class payload bytes: 1.04 MiB; excludes module descriptors and archive metadata)
[INFO]   - com.fasterxml.jackson.core:jackson-core:jar:2.19.0 (compile): 20 classes, 82.33 KiB
[INFO]   - com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile): 70 classes, 163.47 KiB
[INFO]   - org.apache.commons:commons-text:jar:1.9 (compile): 132 classes, 388.41 KiB
[INFO]   - org.codehaus.janino:commons-compiler:jar:3.1.12 (compile): 51 classes, 96.78 KiB
[INFO]   - org.codehaus.janino:janino:jar:3.1.12 (compile): 52 classes, 330.49 KiB
[INFO]   - org.slf4j:slf4j-api:jar:2.0.17 (compile): 6 classes, 7.65 KiB
[INFO] Vulnerability findings: 140
[INFO]   - CVE-2009-1190 org.springframework:spring-core:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2009-1190, GHSA-wjjr-h4wh-w6vv]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2011-2730 org.springframework:spring-core:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2011-2730, GHSA-wv88-pf73-x22p]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2011-2894 org.springframework:spring-core:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2011-2894, GHSA-f866-m9mv-2xr3]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2014-3578 org.springframework:spring-core:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2014-3578, GHSA-rhcg-rwhx-qj3j]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2015-0201 org.springframework:spring-core:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2015-0201, GHSA-45vg-2v73-vm62]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2015-5211 org.springframework:spring-core:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2015-5211, GHSA-pgf9-h69p-pcgf]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2016-5007 org.springframework:spring-core:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2016-5007, GHSA-8crv-49fr-2h6j]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2017-15095 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2017-15095, GHSA-h592-38cm-4ggp]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2017-17485 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2017-17485, GHSA-rfx6-vp9g-rh7v]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2017-5929 ch.qos.logback:logback-classic:jar:1.5.18 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2017-5929, GHSA-vmfg-rjjm-rjrj]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2017-5929 ch.qos.logback:logback-core:jar:1.5.18 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2017-5929, GHSA-vmfg-rjjm-rjrj]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2017-7525 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2017-7525, GHSA-qxxx-2pp7-5hmx]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-11040 org.springframework:spring-core:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2018-11040, GHSA-f26x-pr96-vw86]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-11307 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2018-11307, GHSA-qr7j-h6gg-jmgc]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-1199 org.springframework:spring-core:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2018-1199, GHSA-v596-fwhq-8x48]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-12022 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2018-12022, GHSA-cjjf-94ff-43w7]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-12023 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2018-12023, GHSA-6wqp-v4v6-c87c]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-1257 org.springframework:spring-core:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2018-1257, GHSA-rcpf-vj53-7h2m]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-1258 org.springframework:spring-core:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2018-1258, GHSA-cxrj-66c5-9fmh]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-1271 org.springframework:spring-core:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2018-1271, GHSA-g8hw-794c-4j9g]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-1272 org.springframework:spring-core:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2018-1272, GHSA-4487-x383-qpph]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-14718 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2018-14718, GHSA-645p-88qh-w398]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-14719 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2018-14719, GHSA-4gq5-ch57-c2mg]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-14720 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2018-14720, GHSA-x2w5-5m2g-7h5m]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-14721 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2018-14721, GHSA-9mxf-g3x6-wv74]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-15756 org.springframework:spring-core:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2018-15756, GHSA-ffvq-7w96-97p7]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-19360 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2018-19360, GHSA-f9hv-mg5h-xcw9]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-19361 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2018-19361, GHSA-mx9v-gmh4-mgqw]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-19362 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2018-19362, GHSA-c8hm-7hpq-7jhg]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-5968 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2018-5968, GHSA-w3f4-3q6j-rh82]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-7489 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2018-7489, GHSA-cggj-fvv3-cqwv]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2019-12086 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2019-12086, GHSA-5ww9-j83m-q7qx]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2019-12384 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2019-12384, GHSA-mph4-vhrx-mv67]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2019-12814 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2019-12814, GHSA-cmfg-87vq-g5g4]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2019-14379 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2019-14379, GHSA-6fpp-rgj9-8rwc]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2019-14439 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2019-14439, GHSA-gwp4-hfv6-p7hw]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2019-14540 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2019-14540, GHSA-h822-r4r5-v8jg]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2019-14892 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2019-14892, GHSA-cf6r-3wgc-h863]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2019-14893 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2019-14893, GHSA-qmqc-x3r4-6v39]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2019-16335 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2019-16335, GHSA-85cw-hj65-qqv9]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2019-16942 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2019-16942, GHSA-mx7p-6679-8g3q]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2019-16943 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2019-16943, GHSA-fmmc-742q-jg75]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2019-17267 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2019-17267, GHSA-f3j5-rmmp-3fc5]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2019-17531 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2019-17531, GHSA-gjmw-vf9h-g25v]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2019-20330 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2019-20330, GHSA-gww7-p5w4-wrfv]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-10650 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2020-10650, GHSA-rpr3-cw39-3pxh]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-10672 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2020-10672, GHSA-95cm-88f5-f2c7]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-10673 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2020-10673, GHSA-fqwf-pjwf-7vqv]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-10968 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2020-10968, GHSA-rf6r-2c4q-2vwg]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-10969 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2020-10969, GHSA-758m-v56v-grj4]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-11111 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2020-11111, GHSA-v3xw-c963-f5hc]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-11112 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2020-11112, GHSA-58pp-9c76-5625]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-11113 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2020-11113, GHSA-9vvp-fxw6-jcxr]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-11619 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2020-11619, GHSA-27xj-rqx5-2255]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-11620 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2020-11620, GHSA-h4rc-386g-6m85]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-14060 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2020-14060, GHSA-j823-4qch-3rgm]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-14061 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2020-14061, GHSA-c2q3-4qrh-fm48]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-14062 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2020-14062, GHSA-c265-37vj-cwcc]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-14195 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2020-14195, GHSA-mc6h-4qgp-37qh]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-24616 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2020-24616, GHSA-h3cw-g4mq-c5x2]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-24750 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2020-24750, GHSA-qjw2-hr98-qgfh]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-25649 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2020-25649, GHSA-288c-cq4h-88gq]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-35490 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2020-35490, GHSA-wh8g-3j2c-rqj5]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-35491 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2020-35491, GHSA-r3gr-cxrf-hg25]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-35728 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2020-35728, GHSA-5r5r-6hpj-8gg9]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-36179 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2020-36179, GHSA-9gph-22xh-8x98]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-36180 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2020-36180, GHSA-8c4j-34r4-xr8g]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-36181 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2020-36181, GHSA-cvm9-fjm9-3572]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-36182 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2020-36182, GHSA-89qr-369f-5m5x]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-36183 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2020-36183, GHSA-9m6f-7xcq-8vf8]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-36184 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2020-36184, GHSA-m6x4-97wx-4q27]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-36185 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2020-36185, GHSA-8w26-6f25-cm9x]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-36186 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2020-36186, GHSA-v585-23hc-c647]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-36187 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2020-36187, GHSA-r695-7vr9-jgc2]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-36188 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2020-36188, GHSA-f9xh-2qgp-cq57]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-36189 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2020-36189, GHSA-vfqx-33qm-g869]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-36518 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2020-36518, GHSA-57j2-w4cx-62h2]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-8840 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2020-8840, GHSA-4w82-r329-3q67]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-9546 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2020-9546, GHSA-5p34-5m6p-p58g]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-9547 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2020-9547, GHSA-q93h-jc49-78gg]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-9548 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2020-9548, GHSA-p43x-xfjf-5jhr]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-20190 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [BIT-nifi-2021-20190, CVE-2021-20190, GHSA-5949-rw7g-wx7w]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-22060 org.springframework:spring-core:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2021-22060, GHSA-6gf2-pvqw-37ph]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-22096 org.springframework:spring-core:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2021-22096, GHSA-rfmp-97jj-h8m6]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-42550 ch.qos.logback:logback-core:jar:1.5.18 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2021-42550, GHSA-668q-qrv7-99fm]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-46877 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2021-46877, GHSA-3x8x-79m2-3w2w]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2022-22950 org.springframework:spring-expression:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2022-22950, GHSA-558x-2xjg-6232]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2022-22965 org.springframework:spring-beans:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2022-22965, GHSA-36p3-wjmg-h94x]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2022-22968 org.springframework:spring-context:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2022-22968, GHSA-g5mm-vmx4-3rg7]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2022-22970 org.springframework:spring-beans:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2022-22970, GHSA-hh26-6xwr-ggv7]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2022-42003 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2022-42003, GHSA-jjjh-jjxp-wpff]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2022-42004 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2022-42004, GHSA-rgv9-q543-rqg4]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2022-42889 org.apache.commons:commons-text:jar:1.9 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2022-42889, GHSA-599f-7c49-w659]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: DECLARED_CODE_ABSENT; All effective declared code and its nested classes are absent from the trimmed artifact. This observation is limited to the declared code and does not establish declaration completeness.
[INFO]     Declared code: [org.apache.commons.text.lookup.StringLookup] RESOLVED; classes: [org.apache.commons.text.lookup.StringLookup]; reasons: []
[INFO]     Declared code: [org.apache.commons.text.lookup.StringLookup] REVIEW_LEAD; classes: []; reasons: [HEURISTIC_REQUIRES_REVIEW]
[INFO]     Heuristic leads: [org.apache.commons.text.lookup.StringLookup]
[INFO]     Overridden fields: [code, intent]
[INFO]     Sources: [OSV, POM]
[INFO]   - CVE-2023-20861 org.springframework:spring-expression:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2023-20861, GHSA-564r-hj7v-mcr5]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2023-20863 org.springframework:spring-expression:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2023-20863, GHSA-wxqc-pxw9-g2p8]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2023-6378 ch.qos.logback:logback-classic:jar:1.5.18 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2023-6378, GHSA-vmq6-5m68-f53m]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2023-6378 ch.qos.logback:logback-core:jar:1.5.18 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2023-6378, GHSA-vmq6-5m68-f53m]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2023-6481 ch.qos.logback:logback-core:jar:1.5.18 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2023-6481, GHSA-gm62-rw4g-vrc4]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2024-12798 ch.qos.logback:logback-core:jar:1.5.18 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2024-12798, GHSA-pr98-23f8-jwxv]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2024-12801 ch.qos.logback:logback-core:jar:1.5.18 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2024-12801, GHSA-6v67-2wr5-gvf4]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2024-22233 org.springframework:spring-core:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2024-22233, GHSA-r4q3-7g4q-x89m]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2024-38808 org.springframework:spring-expression:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2024-38808, GHSA-9cmq-m9j5-mvww]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2024-38820 org.springframework:spring-context:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2024-38820, GHSA-4gc7-5j7h-4qph]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2025-11226 ch.qos.logback:logback-core:jar:1.5.18 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2025-11226, GHSA-25qh-j22f-pwp8]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2025-22233 org.springframework:spring-context:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2025-22233, GHSA-4wp7-92pw-q264]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2025-41249 org.springframework:spring-core:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2025-41249, GHSA-jmp9-x22r-554x]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2025-48924 org.apache.commons:commons-lang3:jar:3.17.0 (compile) [REMOVED]
[INFO]     Aliases: [CVE-2025-48924, GHSA-j288-q9x7-2f5v]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [CVE_LIST, OSV]
[INFO]   - CVE-2025-49128 com.fasterxml.jackson.core:jackson-core:jar:2.19.0 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2025-49128, GHSA-wf8f-6423-gfxg]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2025-52999 com.fasterxml.jackson.core:jackson-core:jar:2.19.0 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2025-52999, GHSA-h46c-h94j-95f3]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-10532 ch.qos.logback:logback-core:jar:1.5.18 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-10532, GHSA-jhq6-gfmj-v8fx]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-110879 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration
[INFO]     Declared code: [src/main/java/com/fasterxml/jackson/databind/DatabindContext.java] RESOLVED; classes: [com.fasterxml.jackson.databind.DatabindContext]; reasons: []
[INFO]     Declared code: [src/main/java/com/fasterxml/jackson/databind/jsontype/DefaultBaseTypeLimitingValidator.java] RESOLVED; classes: [com.fasterxml.jackson.databind.jsontype.DefaultBaseTypeLimitingValidator, com.fasterxml.jackson.databind.jsontype.DefaultBaseTypeLimitingValidator$UnsafeBaseTypes]; reasons: []
[INFO]     Declared code: [src/main/java/com/fasterxml/jackson/databind/jsontype/impl/StdTypeResolverBuilder.java] RESOLVED; classes: [com.fasterxml.jackson.databind.jsontype.impl.StdTypeResolverBuilder, com.fasterxml.jackson.databind.jsontype.impl.StdTypeResolverBuilder$1]; reasons: []
[INFO]     Declared code: [DatabindContext._resolveAndValidateGeneric] RESOLVED; classes: [com.fasterxml.jackson.databind.DatabindContext]; reasons: []
[INFO]     Declared code: [DatabindContext._validateTypeParameter] UNRESOLVED; classes: []; reasons: [ROUTINE_METHOD_NOT_FOUND]
[INFO]     Declared code: [DefaultBaseTypeLimitingValidator] UNRESOLVED; classes: []; reasons: [ROUTINE_METHOD_NOT_FOUND]
[INFO]     Declared code: [StdTypeResolverBuilder] UNRESOLVED; classes: []; reasons: [ROUTINE_METHOD_NOT_FOUND]
[INFO]     Sources: [CVE_LIST]
[INFO]   - CVE-2026-1225 ch.qos.logback:logback-core:jar:1.5.18 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-1225, GHSA-qqpg-mvqg-649v]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-18401 com.fasterxml.jackson.core:jackson-core:jar:2.19.0 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2026-18401, GHSA-72hv-8253-57qq]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration
[INFO]     Declared code: [src/main/java/com/fasterxml/jackson/core/json/async/NonBlockingUtf8JsonParserBase.java] RESOLVED; classes: [com.fasterxml.jackson.core.json.async.NonBlockingUtf8JsonParserBase]; reasons: []
[INFO]     Declared code: [NonBlockingUtf8JsonParserBase._finishNumberIntegralPart] RESOLVED; classes: [com.fasterxml.jackson.core.json.async.NonBlockingUtf8JsonParserBase]; reasons: []
[INFO]     Declared code: [NonBlockingUtf8JsonParserBase._valueComplete] UNRESOLVED; classes: []; reasons: [ROUTINE_METHOD_NOT_FOUND]
[INFO]     Sources: [CVE_LIST, OSV]
[INFO]   - CVE-2026-19032 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2026-19032, GHSA-wjgm-6hv5-3cvf]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; Vulnerable class survives trimmed archive: com.fasterxml.jackson.databind.ext.NioPathDeserializer
[INFO]     Declared code: [src/main/java/com/fasterxml/jackson/databind/ext/NioPathDeserializer.java] RESOLVED; classes: [com.fasterxml.jackson.databind.ext.NioPathDeserializer]; reasons: []
[INFO]     Declared code: [com.fasterxml.jackson.databind.ext.NioPathDeserializer.deserialize] RESOLVED; classes: [com.fasterxml.jackson.databind.ext.NioPathDeserializer]; reasons: []
[INFO]     Sources: [CVE_LIST, OSV]
[INFO]   - CVE-2026-41848 org.springframework:spring-core:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-41848, GHSA-659m-px2c-25wj]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-41849 org.springframework:spring-expression:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-41849, GHSA-775g-4xr8-78h8]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-41850 org.springframework:spring-expression:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-41850, GHSA-r5w3-xv2f-j59q]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-41851 org.springframework:spring-expression:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-41851, GHSA-wxpp-56q6-5pcg]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-41852 org.springframework:spring-expression:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-41852, GHSA-9f52-rjqv-25qv]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-50193 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2026-50193, GHSA-3wrr-7qpf-2prh]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-54512 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2026-54512, GHSA-j3rv-43j4-c7qm]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-54513 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2026-54513, GHSA-rmj7-2vxq-3g9f]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-54514 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2026-54514, GHSA-hgj6-7826-r7m5]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-54515 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2026-54515, GHSA-5jmj-h7xm-6q6v]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-54516 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2026-54516, GHSA-9fxm-vc8v-hj55]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-54517 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2026-54517, GHSA-5hh8-q8hv-fr38]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-54518 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2026-54518, GHSA-rcqc-6cw3-h962]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-59888 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2026-59888, GHSA-3pjw-73gf-8qr5]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-59889 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2026-59889, GHSA-5gvw-p9qm-jgwh]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-68494 com.fasterxml.jackson.core:jackson-core:jar:2.19.0 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2026-68494, GHSA-r7wm-3cxj-wff9]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; Vulnerable class survives trimmed archive: com.fasterxml.jackson.core.json.async.NonBlockingUtf8JsonParserBase
[INFO]     Declared code: [src/main/java/com/fasterxml/jackson/core/json/async/NonBlockingUtf8JsonParserBase.java] RESOLVED; classes: [com.fasterxml.jackson.core.json.async.NonBlockingUtf8JsonParserBase]; reasons: []
[INFO]     Declared code: [NonBlockingUtf8JsonParserBase._finishNumberIntegralPart] RESOLVED; classes: [com.fasterxml.jackson.core.json.async.NonBlockingUtf8JsonParserBase]; reasons: []
[INFO]     Declared code: [NonBlockingUtf8JsonParserBase._startNegativeNumber] RESOLVED; classes: [com.fasterxml.jackson.core.json.async.NonBlockingUtf8JsonParserBase]; reasons: []
[INFO]     Declared code: [NonBlockingUtf8JsonParserBase._startPositiveNumber] RESOLVED; classes: [com.fasterxml.jackson.core.json.async.NonBlockingUtf8JsonParserBase]; reasons: []
[INFO]     Declared code: [com.fasterxml.jackson.core.async.ByteArrayFeeder] REVIEW_LEAD; classes: []; reasons: [HEURISTIC_REQUIRES_REVIEW]
[INFO]     Declared code: [com.fasterxml.jackson.core.exc.StreamConstraintsException] REVIEW_LEAD; classes: []; reasons: [HEURISTIC_REQUIRES_REVIEW]
[INFO]     Heuristic leads: [com.fasterxml.jackson.core.async.ByteArrayFeeder, com.fasterxml.jackson.core.exc.StreamConstraintsException]
[INFO]     Sources: [CVE_LIST, OSV]
[INFO]   - CVE-2026-68497 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2026-68497, GHSA-q4xh-88c3-wmh7]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration
[INFO]     Declared code: [src/main/java/com/fasterxml/jackson/databind/ext/CoreXMLDeserializers.java] RESOLVED; classes: [com.fasterxml.jackson.databind.ext.CoreXMLDeserializers, com.fasterxml.jackson.databind.ext.CoreXMLDeserializers$Std]; reasons: []
[INFO]     Declared code: [com.fasterxml.jackson.databind.ext.CoreXMLDeserializers.Std._deserialize] UNRESOLVED; classes: []; reasons: [ROUTINE_OWNER_NOT_FOUND]
[INFO]     Sources: [CVE_LIST, OSV]
[INFO]   - CVE-2026-68498 com.fasterxml.jackson.core:jackson-core:jar:2.19.0 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; Vulnerable class survives trimmed archive: com.fasterxml.jackson.core.json.ReaderBasedJsonParser
[INFO]     Declared code: [src/main/java/com/fasterxml/jackson/core/json/ReaderBasedJsonParser.java] RESOLVED; classes: [com.fasterxml.jackson.core.json.ReaderBasedJsonParser]; reasons: []
[INFO]     Declared code: [ReaderBasedJsonParser._parseName2] RESOLVED; classes: [com.fasterxml.jackson.core.json.ReaderBasedJsonParser]; reasons: []
[INFO]     Sources: [CVE_LIST]
[INFO]   - CVE-2026-77310 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2026-77310, GHSA-vvgp-rfg2-7rr6]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-83557 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2026-83557, GHSA-gx83-3vf8-gh7j]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; Vulnerable class survives trimmed archive: com.fasterxml.jackson.databind.jsontype.DefaultBaseTypeLimitingValidator
[INFO]     Declared code: [src/main/java/com/fasterxml/jackson/databind/jsontype/DefaultBaseTypeLimitingValidator.java] RESOLVED; classes: [com.fasterxml.jackson.databind.jsontype.DefaultBaseTypeLimitingValidator, com.fasterxml.jackson.databind.jsontype.DefaultBaseTypeLimitingValidator$UnsafeBaseTypes]; reasons: []
[INFO]     Declared code: [com.fasterxml.jackson.databind.jsontype.DefaultBaseTypeLimitingValidator.isUnsafeBaseType] RESOLVED; classes: [com.fasterxml.jackson.databind.jsontype.DefaultBaseTypeLimitingValidator, com.fasterxml.jackson.databind.jsontype.DefaultBaseTypeLimitingValidator$UnsafeBaseTypes]; reasons: []
[INFO]     Sources: [CVE_LIST, OSV]
[INFO]   - CVE-2026-89407 com.fasterxml.jackson.core:jackson-core:jar:2.19.0 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2026-89407, GHSA-p6pp-m3f8-5c89]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; Vulnerable class survives trimmed archive: com.fasterxml.jackson.core.io.NumberInput
[INFO]     Declared code: [com.fasterxml.jackson.core.io.NumberInput.looksLikeValidNumber] RESOLVED; classes: [com.fasterxml.jackson.core.io.NumberInput]; reasons: []
[INFO]     Declared code: [com.fasterxml.jackson.core.io.NumberInput] REVIEW_LEAD; classes: []; reasons: [HEURISTIC_REQUIRES_REVIEW]
[INFO]     Heuristic leads: [com.fasterxml.jackson.core.io.NumberInput]
[INFO]     Sources: [CVE_LIST, OSV]
[INFO]   - CVE-2026-89425 com.fasterxml.jackson.core:jackson-core:jar:2.19.0 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2026-89425, GHSA-7hhh-6rmp-j9qf]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; Vulnerable class survives trimmed archive: com.fasterxml.jackson.core.json.UTF8DataInputJsonParser
[INFO]     Declared code: [com.fasterxml.jackson.core.json.UTF8DataInputJsonParser._reportInvalidToken] RESOLVED; classes: [com.fasterxml.jackson.core.json.UTF8DataInputJsonParser]; reasons: []
[INFO]     Sources: [CVE_LIST, OSV]
[INFO]   - CVE-2026-91776 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2026-91776, GHSA-wv8q-qhhj-9h54]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; Vulnerable class survives trimmed archive: com.fasterxml.jackson.databind.jsontype.impl.TypeDeserializerBase
[INFO]     Declared code: [com.fasterxml.jackson.databind.jsontype.impl.TypeDeserializerBase._findDeserializer] RESOLVED; classes: [com.fasterxml.jackson.databind.jsontype.impl.TypeDeserializerBase]; reasons: []
[INFO]     Sources: [CVE_LIST, OSV]
[INFO]   - CVE-2026-91777 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2026-91777, GHSA-cxp5-3px4-pw24]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration
[INFO]     Declared code: [com.fasterxml.jackson.databind.deser.std.CollectionDeserializer.CollectionReferringAccumulator.resolveForwardReference] UNRESOLVED; classes: []; reasons: [ROUTINE_OWNER_NOT_FOUND]
[INFO]     Declared code: [com.fasterxml.jackson.databind.deser.std.MapDeserializer.MapReferringAccumulator.resolveForwardReference] UNRESOLVED; classes: []; reasons: [ROUTINE_OWNER_NOT_FOUND]
[INFO]     Sources: [CVE_LIST, OSV]
[INFO]   - CVE-2026-9828 ch.qos.logback:logback-core:jar:1.5.18 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-9828, GHSA-p47f-322f-whfh]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - GHSA-mhm7-754m-9p8w com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration
[INFO]     Sources: [OSV]
[INFO] CVE Sources:
[INFO]   - CVE_LIST PARTIAL
[INFO]     Skipped 79 CVE List source row(s)
[INFO]     Source diagnostics are in the JSON snapshot
[INFO]   - OSV CURRENT
[INFO] POM exclusion review (advisory only):
[INFO]   Repeated POM exclusions:
[INFO]     none found across effective dependency paths
[INFO]   Exclusion provenance incomplete for 1536 dependency or exclusion origins.
[INFO]   Maven supplied no source location/identity or the location matched zero or
[INFO]   multiple original POM rows. This advisory review does not affect elision.
[INFO]   Full evidence is in the JSON snapshot fields
[INFO]   exclusionReview.snapshot.dependencies and
[INFO]   exclusionReview.snapshot.diagnostics.
[INFO] Mediated TEST dependency graph (captured and saved by the elide goal):
[INFO]   - io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT {nodeId=n0} [RETAINED]
[INFO]   - io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT -> ch.qos.logback:logback-classic:jar:1.5.18 (compile) {nodeId=n3} [RETAINED]
[INFO]   - io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT -> com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) {nodeId=n2} [RETAINED, CLASS_TRIMMED]
[INFO]   ... 24 dependency graph rows elided (sha256:c244800e70bf8895abe523a5be65f054741a2b7f5ff21c8924ec401f79ac1973)
[INFO] ------------------------------------------------------------------------
[INFO] ------------------------------------------------------------------------
[INFO] Total time: <BUILD_TIME>
[INFO] Finished at: <TIMESTAMP>
[INFO] ------------------------------------------------------------------------
```

<!-- END:transcript:report-cve-unused-app -->

#### example-cve-safe-class-app

Look at the inactive precondition row for `CVE-2025-11226`. Logback remains in the application, but the opted-in complete inventory proves that its required Janino dependency and `ClassBodyEvaluator` class are absent. This is a precondition VEX result, distinct from proving vulnerable code was trimmed out of the affected artifact.

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
[INFO] Dependency Elider report JSON snapshot: <PROJECT_ROOT>/examples/example-cve-safe-class-app/target/dependency-elider-report.json
[INFO] Dependency Elider report
[INFO] Project: io.github.spockz:example-cve-safe-class-app:0.1.0-SNAPSHOT
[INFO] Snapshot: last successful elide run at <TIMESTAMP>
[INFO] Analysis target JDK release: 21
[INFO] Elider runtime JDK release: <RUNTIME_RELEASE>
[INFO] Policy: retained=[], banished=[]
[INFO] The snapshot does not revalidate changed inputs when this goal runs.
[INFO] Conventional Java source layout assumption saved for this run: true
[INFO] Whole artifacts dropped: 0 / 19 (original JAR file bytes: 0 B)
[INFO] Program classes removed with dropped JARs: 0 (uncompressed .class entry payload bytes: 0 B; excludes module descriptors and archive sanitation metadata)
[INFO] Raw trace decision drops before graph safety: 0
[INFO] Applied bans: none
[INFO] Program classes pruned from retained JARs: 6 (uncompressed omitted .class payload bytes: 7.65 KiB; excludes module descriptors and archive metadata)
[INFO]   - org.slf4j:slf4j-api:jar:2.0.17 (compile): 6 classes, 7.65 KiB
[INFO] Vulnerability findings: 44
[INFO]   - CVE-2009-1190 org.springframework:spring-core:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2009-1190, GHSA-wjjr-h4wh-w6vv]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2011-2730 org.springframework:spring-core:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2011-2730, GHSA-wv88-pf73-x22p]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2011-2894 org.springframework:spring-core:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2011-2894, GHSA-f866-m9mv-2xr3]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2014-3578 org.springframework:spring-core:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2014-3578, GHSA-rhcg-rwhx-qj3j]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2015-0201 org.springframework:spring-core:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2015-0201, GHSA-45vg-2v73-vm62]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2015-5211 org.springframework:spring-core:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2015-5211, GHSA-pgf9-h69p-pcgf]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2016-5007 org.springframework:spring-core:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2016-5007, GHSA-8crv-49fr-2h6j]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2017-5929 ch.qos.logback:logback-classic:jar:1.5.18 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2017-5929, GHSA-vmfg-rjjm-rjrj]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2017-5929 ch.qos.logback:logback-core:jar:1.5.18 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2017-5929, GHSA-vmfg-rjjm-rjrj]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-11040 org.springframework:spring-core:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2018-11040, GHSA-f26x-pr96-vw86]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-1199 org.springframework:spring-core:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2018-1199, GHSA-v596-fwhq-8x48]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-1257 org.springframework:spring-core:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2018-1257, GHSA-rcpf-vj53-7h2m]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-1258 org.springframework:spring-core:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2018-1258, GHSA-cxrj-66c5-9fmh]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-1271 org.springframework:spring-core:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2018-1271, GHSA-g8hw-794c-4j9g]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-1272 org.springframework:spring-core:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2018-1272, GHSA-4487-x383-qpph]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-15756 org.springframework:spring-core:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2018-15756, GHSA-ffvq-7w96-97p7]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-22060 org.springframework:spring-core:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2021-22060, GHSA-6gf2-pvqw-37ph]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-22096 org.springframework:spring-core:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2021-22096, GHSA-rfmp-97jj-h8m6]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-42550 ch.qos.logback:logback-core:jar:1.5.18 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2021-42550, GHSA-668q-qrv7-99fm]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2022-22950 org.springframework:spring-expression:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2022-22950, GHSA-558x-2xjg-6232]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2022-22965 org.springframework:spring-beans:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2022-22965, GHSA-36p3-wjmg-h94x]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2022-22968 org.springframework:spring-context:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2022-22968, GHSA-g5mm-vmx4-3rg7]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2022-22970 org.springframework:spring-beans:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2022-22970, GHSA-hh26-6xwr-ggv7]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2023-20861 org.springframework:spring-expression:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2023-20861, GHSA-564r-hj7v-mcr5]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2023-20863 org.springframework:spring-expression:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2023-20863, GHSA-wxqc-pxw9-g2p8]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2023-6378 ch.qos.logback:logback-classic:jar:1.5.18 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2023-6378, GHSA-vmq6-5m68-f53m]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2023-6378 ch.qos.logback:logback-core:jar:1.5.18 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2023-6378, GHSA-vmq6-5m68-f53m]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2023-6481 ch.qos.logback:logback-core:jar:1.5.18 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2023-6481, GHSA-gm62-rw4g-vrc4]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2024-12798 ch.qos.logback:logback-core:jar:1.5.18 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2024-12798, GHSA-pr98-23f8-jwxv]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2024-12801 ch.qos.logback:logback-core:jar:1.5.18 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2024-12801, GHSA-6v67-2wr5-gvf4]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2024-22233 org.springframework:spring-core:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2024-22233, GHSA-r4q3-7g4q-x89m]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2024-38808 org.springframework:spring-expression:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2024-38808, GHSA-9cmq-m9j5-mvww]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2024-38820 org.springframework:spring-context:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2024-38820, GHSA-4gc7-5j7h-4qph]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2025-11226 ch.qos.logback:logback-core:jar:1.5.18 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2025-11226, GHSA-25qh-j22f-pwp8]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: PREREQUISITES_ABSENT; Required prerequisite groups were disarmed in the complete declared Maven inventory: ANY_OF is disarmed because every member is absent: org.codehaus.janino:janino / org.codehaus.janino.ClassBodyEvaluator=ABSENT. The proof does not cover providers introduced outside that inventory.
[INFO]     Effective prerequisites: [org.codehaus.janino:janino / org.codehaus.janino.ClassBodyEvaluator]
[INFO]     Prerequisite proof evidence: final inventory <PATH_BOUND_SHA256>
[INFO]       ANY_OF group attribution: ALREADY_ABSENT
[INFO]         org.codehaus.janino:janino / org.codehaus.janino.ClassBodyEvaluator=ABSENT (ALREADY_ABSENT)
[INFO]     Overridden fields: [intent]
[INFO]     Sources: [CATALOG, OSV]
[INFO]   - CVE-2025-22233 org.springframework:spring-context:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2025-22233, GHSA-4wp7-92pw-q264]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2025-41249 org.springframework:spring-core:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2025-41249, GHSA-jmp9-x22r-554x]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-10532 ch.qos.logback:logback-core:jar:1.5.18 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-10532, GHSA-jhq6-gfmj-v8fx]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-1225 ch.qos.logback:logback-core:jar:1.5.18 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-1225, GHSA-qqpg-mvqg-649v]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-41848 org.springframework:spring-core:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-41848, GHSA-659m-px2c-25wj]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-41849 org.springframework:spring-expression:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-41849, GHSA-775g-4xr8-78h8]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-41850 org.springframework:spring-expression:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-41850, GHSA-r5w3-xv2f-j59q]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-41851 org.springframework:spring-expression:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-41851, GHSA-wxpp-56q6-5pcg]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-41852 org.springframework:spring-expression:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-41852, GHSA-9f52-rjqv-25qv]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-9828 ch.qos.logback:logback-core:jar:1.5.18 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-9828, GHSA-p47f-322f-whfh]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO] CVE Sources:
[INFO]   - CVE_LIST PARTIAL
[INFO]     Skipped 79 CVE List source row(s)
[INFO]     Source diagnostics are in the JSON snapshot
[INFO]   - OSV CURRENT
[INFO] Adopted vulnerability mapping catalogs:
[INFO]   - io.github.spockz.catalogs:logback-vulnerability-mapping-catalog:1.0.0:jar: (catalogId=logback-core-cve-2025-11226, sha256=a1339af5e23c58c06ca8ebb86dda095173d3f52de8363284fce031014bf82ff2, mappings=2, unresolved=0)
[INFO] POM exclusion review (advisory only):
[INFO]   Repeated POM exclusions:
[INFO]     none found across effective dependency paths
[INFO]   Exclusion provenance incomplete for 1536 dependency or exclusion origins.
[INFO]   Maven supplied no source location/identity or the location matched zero or
[INFO]   multiple original POM rows. This advisory review does not affect elision.
[INFO]   Full evidence is in the JSON snapshot fields
[INFO]   exclusionReview.snapshot.dependencies and
[INFO]   exclusionReview.snapshot.diagnostics.
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

The `analyze` goal previews dependencies and byte savings without changing Maven artifact views or resolver plans. It writes class-usage evidence and a `dependencyPrediction` section to `elide.reportFile`. The prediction records retained/elided coordinates, planned class removals marked `PLANNED_UNVERIFIED`, environment/inventory/operation fingerprints, and whether it used the captured effective Resolver graph or a detached current-model resolution. Detached provenance describes only that request-local resolution. Its separate summary reports `PLANNED_CODE_ABSENT` when all attributed classes for a complete declared code group are planned for removal. This is a forecast, not proof that an output archive lacks the code, a scanner finding will disappear, or a CVE is mitigated. Analyze does not publish VEX, trim archives, or output-manifest/generation state. MRJAR analysis may create temporary classpath projections in an operation-owned directory; that directory is removed when prediction completes or fails. The transcript invocation places the class-usage report under ignored `.scratch/`:

Persisted elision report schema 1 lists changed root `META-INF/services/*` descriptors in each `trimmedArtifacts` row as `serviceDescriptorChanges`, with outcome `REPLACED` or `OMIT`; unchanged descriptors are not listed. A zero-class output row is valid when an MRJAR was elevated (`mrjarStatus=elevated_and_trimmed`), a service descriptor changed, or classpath-only transformation removed the root `module-info.class` (`mrjarStatus=classpath-only`). Classpath-only transformations retain `mrjarStatus=classpath-only` when the output also prunes classes or changes a descriptor.

With or without the core extension, `analyze` can predict strict `banishedDependencies` for supported compile/runtime JARs, using either a detached current-model Resolver graph or the captured effective graph with a complete original-input audit. The schema-1 `dependencyPrediction.banPlan` records each request as matched (`FORCED_ABSENT_AFTER_RESOLUTION`), excluded before resolution (`EXCLUDED_BEFORE_RESOLUTION`), or unmatched (`UNMATCHED`); every prediction row has `applied=false`. Matched and pre-resolution-excluded requests require complete production class output (`elide.productionClassesComplete=true`) or a trusted `process-classes` lifecycle binding. A request matching an unsupported scope or type fails closed. The plan also fails if runtime trace, production bytecode, dynamic metadata, retained-resource/provider closure, or graph protection requires a banned artifact. An unmatched entry is not an absence proof. Analyze replaces the report only after prediction and vulnerability assessment succeed; it never changes Maven artifact views.

The `elide` goal applies only a validated ban plan before publishing outputs. Each report, SBOM, or VEX file is replaced atomically on its own; the complete set is not an all-or-nothing transaction. If resolver-plan publication fails after output writes, Maven artifact views and resolver-plan state are restored while already replaced output files remain. It reports the same three outcomes in `appliedBans`; unmatched requests are not applied, and neither pre-resolution exclusions nor unmatched requests identify a live artifact to remove. Policy-forced absences are excluded from `rawDroppedCoordinates` but included in total absent-artifact metrics.

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
  -Delide.closedWorld=true \
  -Delide.trimJars=true \
  -Delide.productionClassesComplete=true \
  -Dmaven.compiler.proc=none \
  -Delide.retainedArtifacts=commons-io:commons-io,org.apache.commons:commons-lang3 \
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
[INFO] Dependency Elider report
[INFO] Project: io.github.spockz:example-basic-app:0.1.0-SNAPSHOT
[INFO] Snapshot: analysis prediction at <TIMESTAMP>
[INFO] Analysis target JDK release: 21
[INFO] Elider runtime JDK release: <RUNTIME_RELEASE>
[INFO] Policy: retained=[commons-io:commons-io::jar:, org.apache.commons:commons-lang3::jar:], banished=[]
[INFO] The snapshot does not revalidate changed inputs when this goal runs.
[INFO] Conventional Java source layout assumption saved for this run: true
[INFO] Whole artifacts that would be dropped: 2 / 13 (original JAR file bytes: 942.11 KiB)
[INFO] Program classes that would be removed with dropped JARs: 535 (uncompressed .class entry payload bytes: 1.52 MiB; excludes module descriptors and archive sanitation metadata)
[INFO]   - commons-codec:commons-codec:jar:1.19.0 (compile): 365.93 KiB original JAR, 115 class entries, 413.65 KiB
[INFO]   - org.apache.httpcomponents:httpclient:jar:4.3.4 (compile): 576.18 KiB original JAR, 420 class entries, 1.11 MiB
[INFO] Raw trace decision drops before graph safety: 2
[INFO] Planned bans: none
[INFO] Program classes that would be pruned from retained JARs: 1366 (uncompressed omitted .class payload bytes: unknown; excludes module descriptors and archive metadata)
[INFO]   - commons-io:commons-io:jar:2.20.0 (compile): 387 classes, unknown
[INFO]     Classes that would be pruned from this JAR: [org.apache.commons.io.ByteBuffers, org.apache.commons.io.ByteOrderMark, org.apache.commons.io.ByteOrderParser, org.apache.commons.io.Charsets, org.apache.commons.io.CloseableURLConnection, ... (+382 more in analysis report)]
[INFO]   - org.apache.commons:commons-compress:jar:1.28.0 (compile): 566 classes, unknown
[INFO]     Classes that would be pruned from this JAR: [org.apache.commons.compress.CompressException, org.apache.commons.compress.CompressFilterOutputStream, org.apache.commons.compress.MemoryLimitException, org.apache.commons.compress.PasswordRequiredException, org.apache.commons.compress.archivers.ArchiveException, ... (+561 more in analysis report)]
[INFO]   - org.apache.commons:commons-lang3:jar:3.18.0 (compile): 413 classes, unknown
[INFO]     Classes that would be pruned from this JAR: [org.apache.commons.lang3.AnnotationUtils, org.apache.commons.lang3.AnnotationUtils$1, org.apache.commons.lang3.AppendableJoiner, org.apache.commons.lang3.AppendableJoiner$1, org.apache.commons.lang3.AppendableJoiner$Builder, ... (+408 more in analysis report)]
[INFO] Analysis only: no trim proof or published changes
[INFO] Vulnerability findings: 18
[INFO]   - CVE-2011-1498 org.apache.httpcomponents:httpclient:jar:4.3.4 (compile) [PLANNED_UNVERIFIED]
[INFO]     Aliases: [CVE-2011-1498, GHSA-gw85-4gmf-m7rh]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2012-2098 org.apache.commons:commons-compress:jar:1.28.0 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2012-2098, GHSA-6fxm-66hq-fc96]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2012-6153 org.apache.httpcomponents:httpclient:jar:4.3.4 (compile) [PLANNED_UNVERIFIED]
[INFO]     Aliases: [CVE-2012-6153, GHSA-2x83-r56g-cv47]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2013-4366 org.apache.httpcomponents:httpclient:jar:4.3.4 (compile) [PLANNED_UNVERIFIED]
[INFO]     Aliases: [CVE-2013-4366, GHSA-pqwh-44jj-p5rm]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2014-3577 org.apache.httpcomponents:httpclient:jar:4.3.4 (compile) [PLANNED_UNVERIFIED]
[INFO]     Aliases: [CVE-2014-3577, GHSA-cfh5-3ghh-wfjx]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Declared code: [org.apache.http.conn.ssl.AbstractVerifier] REVIEW_LEAD; classes: []; reasons: [HEURISTIC_REQUIRES_REVIEW]
[INFO]     Heuristic leads: [org.apache.http.conn.ssl.AbstractVerifier]
[INFO]     Sources: [OSV]
[INFO]   - CVE-2015-5262 org.apache.httpcomponents:httpclient:jar:4.3.4 (compile) [PLANNED_UNVERIFIED]
[INFO]     Aliases: [CVE-2015-5262, GHSA-fmj5-wv96-r2ch]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-11771 org.apache.commons:commons-compress:jar:1.28.0 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2018-11771, GHSA-hrmr-f5m6-m9pq]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-1324 org.apache.commons:commons-compress:jar:1.28.0 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2018-1324, GHSA-h436-432x-8fvx]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2019-12402 org.apache.commons:commons-compress:jar:1.28.0 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2019-12402, GHSA-53x6-4x5p-rrvv]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-13956 org.apache.httpcomponents:httpclient:jar:4.3.4 (compile) [PLANNED_UNVERIFIED]
[INFO]     Aliases: [CVE-2020-13956, GHSA-7r82-7xv7-xcpj]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-29425 commons-io:commons-io:jar:2.20.0 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2021-29425, GHSA-gwrp-pvrq-jmwv]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-35515 org.apache.commons:commons-compress:jar:1.28.0 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2021-35515, GHSA-7hfm-57qf-j43q]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-35516 org.apache.commons:commons-compress:jar:1.28.0 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2021-35516, GHSA-crv7-7245-f45f]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-35517 org.apache.commons:commons-compress:jar:1.28.0 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2021-35517, GHSA-xqfj-vm6h-2x34]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-36090 org.apache.commons:commons-compress:jar:1.28.0 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2021-36090, GHSA-mc84-pj99-q6hh]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2024-25710 org.apache.commons:commons-compress:jar:1.28.0 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2024-25710, GHSA-4g9r-vxhx-9pgx]
[INFO]     Applicability: UNRESOLVED; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Unresolved coverage: [containers.cna.affected[0]:defaultStatus=unaffected:[version=1.3,status=affected,versionType=semver,lessThan=null,lessThanOrEqual=1.25.0,changes=[]]: CVE default, explicit status, or overlapping statuses are unresolved, containers.cna.affected[0]:version=1.3,status=affected,versionType=semver,lessThan=null,lessThanOrEqual=1.25.0,changes=[]: Unsupported CVE versionType]
[INFO]     Sources: [CVE_LIST, OSV]
[INFO]   - CVE-2024-26308 org.apache.commons:commons-compress:jar:1.28.0 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2024-26308, GHSA-4265-ccf5-phj5]
[INFO]     Applicability: UNRESOLVED; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Unresolved coverage: [containers.cna.affected[0]:defaultStatus=unaffected:[version=1.21,status=affected,versionType=semver,lessThan=1.26.0,lessThanOrEqual=null,changes=[]]: CVE default, explicit status, or overlapping statuses are unresolved, containers.cna.affected[0]:version=1.21,status=affected,versionType=semver,lessThan=1.26.0,lessThanOrEqual=null,changes=[]: Unsupported CVE versionType]
[INFO]     Sources: [CVE_LIST, OSV]
[INFO]   - CVE-2024-47554 commons-io:commons-io:jar:2.20.0 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2024-47554, GHSA-78wr-2p64-hpwj]
[INFO]     Applicability: UNRESOLVED; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Unresolved coverage: [containers.cna.affected[0]:defaultStatus=unaffected:[version=2.0,status=affected,versionType=semver,lessThan=2.14.0,lessThanOrEqual=null,changes=[]]: CVE default, explicit status, or overlapping statuses are unresolved, containers.cna.affected[0]:version=2.0,status=affected,versionType=semver,lessThan=2.14.0,lessThanOrEqual=null,changes=[]: Unsupported CVE versionType]
[INFO]     Sources: [CVE_LIST, OSV]
[INFO] CVE Sources:
[INFO]   - CVE_LIST PARTIAL
[INFO]     Skipped 79 CVE List source row(s)
[INFO]     Source diagnostics are in the JSON snapshot
[INFO]   - OSV CURRENT
[INFO] POM exclusion review (advisory only):
[INFO]   Repeated POM exclusions:
[INFO]     none found across effective dependency paths
[INFO]   Exclusion provenance incomplete for 14 dependency or exclusion origins. Maven
[INFO]   supplied no source location/identity or the location matched zero or multiple
[INFO]   original POM rows. This advisory review does not affect elision.
[INFO]   Full evidence is in the JSON snapshot fields
[INFO]   exclusionReview.snapshot.dependencies and
[INFO]   exclusionReview.snapshot.diagnostics.
[INFO] Mediated TEST dependency graph (captured and saved by the analyze goal):
[INFO]   - io.github.spockz:example-basic-app:0.1.0-SNAPSHOT {nodeId=n0} [RETAINED]
[INFO]   - io.github.spockz:example-basic-app:0.1.0-SNAPSHOT -> org.apache.commons:commons-compress:jar:1.28.0 (compile) {nodeId=n2} [RETAINED, WOULD_TRIM]
[INFO]   - io.github.spockz:example-basic-app:0.1.0-SNAPSHOT -> org.apache.httpcomponents:httpclient:jar:4.3.4 (compile) {nodeId=n1} [WOULD_DROP]
[INFO]   - io.github.spockz:example-basic-app:0.1.0-SNAPSHOT -> org.junit.jupiter:junit-jupiter:jar:5.11.4 (test) {nodeId=n3} [RETAINED]
[INFO]   - io.github.spockz:example-basic-app:0.1.0-SNAPSHOT -> org.apache.commons:commons-compress:jar:1.28.0 (compile) -> commons-codec:commons-codec:jar:1.19.0 (compile) {nodeId=n4} [WOULD_DROP]
[INFO]   - io.github.spockz:example-basic-app:0.1.0-SNAPSHOT -> org.apache.commons:commons-compress:jar:1.28.0 (compile) -> commons-io:commons-io:jar:2.20.0 (compile) {nodeId=n5} [RETAINED, WOULD_TRIM]
[INFO]   - io.github.spockz:example-basic-app:0.1.0-SNAPSHOT -> org.apache.commons:commons-compress:jar:1.28.0 (compile) -> org.apache.commons:commons-lang3:jar:3.18.0 (compile) {nodeId=n6} [RETAINED, WOULD_TRIM]
[INFO]   - io.github.spockz:example-basic-app:0.1.0-SNAPSHOT -> org.junit.jupiter:junit-jupiter:jar:5.11.4 (test) -> org.junit.jupiter:junit-jupiter-api:jar:5.11.4 (test) {nodeId=n7} [RETAINED]
[INFO]   - io.github.spockz:example-basic-app:0.1.0-SNAPSHOT -> org.junit.jupiter:junit-jupiter:jar:5.11.4 (test) -> org.junit.jupiter:junit-jupiter-engine:jar:5.11.4 (test) {nodeId=n9} [RETAINED]
[INFO]   - io.github.spockz:example-basic-app:0.1.0-SNAPSHOT -> org.junit.jupiter:junit-jupiter:jar:5.11.4 (test) -> org.junit.jupiter:junit-jupiter-params:jar:5.11.4 (test) {nodeId=n8} [RETAINED]
[INFO]   - io.github.spockz:example-basic-app:0.1.0-SNAPSHOT -> org.junit.jupiter:junit-jupiter:jar:5.11.4 (test) -> org.junit.jupiter:junit-jupiter-api:jar:5.11.4 (test) -> org.apiguardian:apiguardian-api:jar:1.1.2 (test) {nodeId=n12} [RETAINED]
[INFO]   - io.github.spockz:example-basic-app:0.1.0-SNAPSHOT -> org.junit.jupiter:junit-jupiter:jar:5.11.4 (test) -> org.junit.jupiter:junit-jupiter-api:jar:5.11.4 (test) -> org.junit.platform:junit-platform-commons:jar:1.11.4 (test) {nodeId=n11} [RETAINED]
[INFO]   - io.github.spockz:example-basic-app:0.1.0-SNAPSHOT -> org.junit.jupiter:junit-jupiter:jar:5.11.4 (test) -> org.junit.jupiter:junit-jupiter-api:jar:5.11.4 (test) -> org.opentest4j:opentest4j:jar:1.3.0 (test) {nodeId=n10} [RETAINED]
[INFO]   - io.github.spockz:example-basic-app:0.1.0-SNAPSHOT -> org.junit.jupiter:junit-jupiter:jar:5.11.4 (test) -> org.junit.jupiter:junit-jupiter-engine:jar:5.11.4 (test) -> org.junit.platform:junit-platform-engine:jar:1.11.4 (test) {nodeId=n13} [RETAINED]
[INFO]   JAR trim cache: unavailable (Analyze reports an in-memory prediction only)
[INFO]   Analysis report: <PROJECT_ROOT>/examples/example-basic-app/target/dependency-elider-analysis-report.json
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
