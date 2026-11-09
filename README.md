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
the archives; replay does not recreate a proof-capable attestation. `ANALYSIS` snapshots remain
predictions and cannot contain verified prerequisite-absence evidence.
Analyze may also save a separate `prerequisitePrediction` for selected prerequisite groups. It
compares baseline provider bytes with planned artifact/class removals and is labeled as a forecast;
it has no final archive fingerprint, never creates VEX, and is replayed without reopening the
baseline archives. Only `APPLIED` reports can carry physical prerequisite proof.

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
* Precondition VEX requires an exact prerequisite class as well as its coordinate, plus explicit `-Delide.preconditionClassPathComplete=true` confirmation that the declared Maven build inventory is complete. The opt-in cannot override detected downstream generators: both `compile` and `testCompile` must explicitly resolve `maven.compiler.proc=none` under a known Maven Compiler Plugin version from 3.13 through 3.x, with Java release or source/target at least 11. Processor paths, processor lists, compiler arguments other than the exact diagnostic-only `-Xlint:all`, custom compiler/executable modes, compiler plugin dependencies, and missing, unresolved, or conflicting settings leave proof incomplete. Unmodeled plugin executions before or after `process-classes`, configured clean/site executions with unmodeled ordering, Enforcer executions at or after inventory capture or with unknown phases, filtered resources, resource plugin dependencies, unsupported packaging/extensions, and custom compiler/resource roots also suppress proof. Proof supports `jar` and `pom` packaging; `war` and `maven-plugin` packaging remain incomplete because their provider-generation paths are not modeled. The inventory includes `<build.directory>/generated-sources/annotations` and `<build.directory>/generated-test-sources/test-annotations`; custom generated-source directories suppress proof. Pre-capture Enforcer rules are limited to verified built-ins, without custom implementation attributes or plugin dependencies. Interface assertions are also rejected because javac can emit an additional helper class for them. The Maven request must contain one default-lifecycle goal, optionally preceded by `clean`; direct plugin goals and multiple lifecycle segments suppress proof. The publisher revalidates provider membership and digests before commit; serializers recheck the affected component path and digest. Unchanged plugin-owned OpenVEX is removed when no qualifying evidence remains. Modified or unowned output is preserved. `elide.trimJars=false` disables physical JAR replacement only; report, SBOM and OpenVEX publication, complete-inventory assessment, and ownership-aware stale OpenVEX cleanup still run. The claim does not cover providers added by later packaging or deployment runtime mechanisms. See [RQ-0013](docs/research/RQ-0013-precondition-gated-vex-and-multi-artifact-exploitability.md).
The guard models packaging only for maven-shade-plugin 3.6.0 with one `package`/`shade` execution and a built-in manifest transformer with a resolved main class. Any request that reaches a modeled JAR package execution must include `clean` first so the standard JAR plugin cannot reuse an older archive; Shade packaging is covered as an additional package path. Clean skip/exclusion/failure overrides and deferred clean modes suppress proof. It accepts only the inherited signature-resource exclusions shown in the examples; custom Shade filters, transformers, inputs, dependencies, source-JAR properties, and custom JAR plugin configuration suppress proof.
If the requested lifecycle reaches `test`, exact-class proof also requires the standard Maven Surefire Plugin 3.5.2 `default-test` execution and explicit `-DskipTests=true`. Maven still compiles test sources so they remain inventoried; the example harness runs baseline tests normally.
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
* **Production Bytecode (`elide.productionClassesComplete`)**: The default `elide` phase is `process-classes`; an explicit phase remains authoritative. Source-free modules may have absent or empty production output, while projects with Java sources must have compiled production class files. Analysis derives production roots from emitted bytecode in `target/classes`; dependencies referenced only through compile-time-inlined constants can be retained explicitly via `<retainedArtifacts>`. Source roots do not count as runtime evidence, and test-only references are not guaranteed. The legacy `elide.sourceRootsComplete=true` assertion is rejected; bind the goal to `process-classes` and use compiled production output. A direct `dependency-elider:elide` invocation does not establish trusted lifecycle capture. Unknown writers at `process-classes` or later remain unsupported, and `skipTests` does not skip `testCompile` safeguards.
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
[INFO]   Exclusion provenance incomplete for 12 dependency or exclusion origins. Maven
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
[INFO] Whole artifacts dropped: 1 / 91 (original JAR file bytes: 356.90 KiB)
[INFO] Program classes removed with dropped JARs: 109 (uncompressed .class entry payload bytes: 398.93 KiB; excludes module descriptors and archive sanitation metadata)
[INFO]   - commons-codec:commons-codec:jar:1.16.1 (compile): 356.90 KiB original JAR, 109 class entries, 398.93 KiB
[INFO] Raw trace decision drops before graph safety: 3
[INFO] Applied bans: none
[INFO] Program classes pruned from retained JARs: 3441 (uncompressed omitted .class payload bytes: 8.61 MiB; excludes module descriptors and archive metadata)
[INFO]   - com.fasterxml.jackson.core:jackson-core:jar:2.18.2 (compile): 20 classes, 82.33 KiB
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
[INFO]   - org.latencyutils:LatencyUtils:jar:2.0.3 (runtime): 3 classes, 10.14 KiB
[INFO]   - org.slf4j:slf4j-api:jar:2.0.16 (compile): 5 classes, 6.38 KiB
[INFO]   - org.springframework:spring-jcl:jar:6.1.14 (compile): 1 classes, 1.24 KiB
[INFO]   - org.springframework:spring-webmvc:jar:6.1.14 (compile): 146 classes, 524.46 KiB
[INFO]   - org.webjars:webjars-locator-core:jar:0.58 (runtime): 1 classes, 10.66 KiB
[INFO]   - org.yaml:snakeyaml:jar:2.2 (compile): 9 classes, 25.85 KiB
[INFO] Vulnerability findings: 343
[INFO]   - CVE-2008-1947 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2008-1947, GHSA-f98p-9pp6-7q6c]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2009-1190 org.springframework:spring-core:jar:6.1.14 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2009-1190, GHSA-wjjr-h4wh-w6vv]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2011-2730 org.springframework:spring-core:jar:6.1.14 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2011-2730, GHSA-wv88-pf73-x22p]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2011-2894 org.springframework:spring-core:jar:6.1.14 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2011-2894, GHSA-f866-m9mv-2xr3]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2013-6429 org.springframework:spring-web:jar:6.1.14 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2013-6429, GHSA-g6hf-f9cq-q7w7]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2013-6430 org.springframework:spring-web:jar:6.1.14 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2013-6430, GHSA-xjrf-8x4f-43h4]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2013-7285 com.thoughtworks.xstream:xstream:jar:1.4.21 (runtime) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2013-7285, GHSA-f554-x222-wgf7]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2014-0054 org.springframework:spring-webmvc:jar:6.1.14 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2014-0054, GHSA-8cmm-qj8g-fcp6]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2014-0095 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2014-0095, GHSA-wf5v-jhxj-q632]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2014-0225 org.springframework:spring-webmvc:jar:6.1.14 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2014-0225, GHSA-f93f-g33r-8pcp]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2014-1904 org.springframework:spring-webmvc:jar:6.1.14 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2014-1904, GHSA-ff7p-jqjm-v66h]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2014-3578 org.springframework:spring-core:jar:6.1.14 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2014-3578, GHSA-rhcg-rwhx-qj3j]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2014-3625 org.springframework:spring-webmvc:jar:6.1.14 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2014-3625, GHSA-hhm4-hwq6-3c6w]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2015-0201 org.springframework:spring-core:jar:6.1.14 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2015-0201, GHSA-45vg-2v73-vm62]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2015-3192 org.springframework:spring-web:jar:6.1.14 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2015-3192, GHSA-6v7w-535j-rq5m]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2015-5211 org.springframework:spring-core:jar:6.1.14 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2015-5211, GHSA-pgf9-h69p-pcgf]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2016-1000027 org.springframework:spring-web:jar:6.1.14 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2016-1000027, GHSA-4wrc-f8pq-fpqp]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2016-3674 com.thoughtworks.xstream:xstream:jar:1.4.21 (runtime) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2016-3674, GHSA-rgh3-987h-wpmw]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2016-5007 org.springframework:spring-core:jar:6.1.14 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2016-5007, GHSA-8crv-49fr-2h6j]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2016-9878 org.springframework:spring-webmvc:jar:6.1.14 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2016-9878, GHSA-2m8h-fgr8-2q9w]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2017-12615 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2017-12615, GHSA-pjfr-qf3p-3q25]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2017-12617 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2017-12617, GHSA-xjgh-84hx-56c5]
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
[INFO]   - CVE-2017-18640 org.yaml:snakeyaml:jar:2.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2017-18640, GHSA-rvwf-54qp-4r6v]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2017-5648 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2017-5648, GHSA-3vx3-xf6q-r5xp]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2017-5651 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2017-5651, GHSA-9hg2-395j-83rm]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2017-5929 ch.qos.logback:logback-classic:jar:1.5.11 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2017-5929, GHSA-vmfg-rjjm-rjrj]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2017-5929 ch.qos.logback:logback-core:jar:1.5.11 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2017-5929, GHSA-vmfg-rjjm-rjrj]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2017-7525 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2017-7525, GHSA-qxxx-2pp7-5hmx]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2017-7957 com.thoughtworks.xstream:xstream:jar:1.4.21 (runtime) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2017-7957, GHSA-7hwc-46rm-65jh]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-1000873 com.fasterxml.jackson.datatype:jackson-datatype-jsr310:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2018-1000873, GHSA-h4x4-5qp2-wp46]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-11039 org.springframework:spring-web:jar:6.1.14 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2018-11039, GHSA-9gcm-f4x3-8jpw]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-11040 org.springframework:spring-core:jar:6.1.14 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2018-11040, GHSA-f26x-pr96-vw86]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-11307 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2018-11307, GHSA-qr7j-h6gg-jmgc]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-11784 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2018-11784, GHSA-5q99-f34m-67gc]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-1196 org.springframework.boot:spring-boot:jar:3.3.5 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2018-1196, GHSA-xx65-cc7g-9pfp]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-1199 org.springframework:spring-core:jar:6.1.14 (compile) [RETAINED_UNCHANGED]
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
[INFO]   - CVE-2018-1257 org.springframework:spring-core:jar:6.1.14 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2018-1257, GHSA-rcpf-vj53-7h2m]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-1258 org.springframework:spring-core:jar:6.1.14 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2018-1258, GHSA-cxrj-66c5-9fmh]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-1271 org.springframework:spring-core:jar:6.1.14 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2018-1271, GHSA-g8hw-794c-4j9g]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-1272 org.springframework:spring-core:jar:6.1.14 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2018-1272, GHSA-4487-x383-qpph]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-1304 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2018-1304, GHSA-6rxj-58jh-436r]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-1305 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2018-1305, GHSA-jx6h-3fjx-cgv5]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-1336 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2018-1336, GHSA-m59c-jpc8-m2x4]
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
[INFO]   - CVE-2018-15756 org.springframework:spring-core:jar:6.1.14 (compile) [RETAINED_UNCHANGED]
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
[INFO]   - CVE-2018-8014 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2018-8014, GHSA-r4x2-3cq5-hqvp]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-8034 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2018-8034, GHSA-46j3-r4pj-4835]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-8037 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2018-8037, GHSA-6v52-mj5r-7j2m]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2019-0199 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2019-0199, GHSA-qcxh-w3j9-58qr]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2019-0221 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2019-0221, GHSA-jjpq-gp5q-8q6w]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2019-0232 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2019-0232, GHSA-8vmx-qmch-mpqg]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2019-10072 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2019-10072, GHSA-q4hg-rmq2-52q9]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2019-10173 com.thoughtworks.xstream:xstream:jar:1.4.21 (runtime) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2019-10173, GHSA-hf23-9pf7-388p]
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
[INFO]   - CVE-2019-12418 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2019-12418, GHSA-hh3j-x4mc-g48r]
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
[INFO]   - CVE-2019-17563 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2019-17563, GHSA-9xcj-c8cr-8c3c]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2019-17569 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2019-17569, GHSA-767j-jfh2-jvrc]
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
[INFO]   - CVE-2020-11996 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2020-11996, CVE-2020-11996, GHSA-53hp-jpwq-2jgq]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-13935 org.apache.tomcat.embed:tomcat-embed-websocket:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2020-13935, CVE-2020-13935, GHSA-m7jv-hq7h-mq7c]
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
[INFO]   - CVE-2020-1935 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2020-1935, CVE-2020-1935, GHSA-qxf4-chvg-4r8r]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-1938 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2020-1938, CVE-2020-1938, GHSA-c9hw-wf7x-jp9j]
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
[INFO]   - CVE-2020-5397 org.springframework:spring-webmvc:jar:6.1.14 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2020-5397, GHSA-7pm4-g2qj-j85x]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-5398 org.springframework:spring-webmvc:jar:6.1.14 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2020-5398, GHSA-8wx2-9q48-vm9r]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-8840 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2020-8840, GHSA-4w82-r329-3q67]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-9484 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2020-9484, CVE-2020-9484, GHSA-344f-f5vg-2jfj]
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
[INFO]   - CVE-2021-22060 org.springframework:spring-core:jar:6.1.14 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2021-22060, GHSA-6gf2-pvqw-37ph]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-22096 org.springframework:spring-core:jar:6.1.14 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2021-22096, GHSA-rfmp-97jj-h8m6]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-22118 org.springframework:spring-web:jar:6.1.14 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2021-22118, GHSA-gfwj-fwqj-fp3v]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-24122 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2021-24122, CVE-2021-24122, GHSA-2rvv-w9r2-rg7m]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-25122 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2021-25122, CVE-2021-25122, GHSA-j39c-c8hj-x4j3]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-25329 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2021-25329, CVE-2021-25329, GHSA-jgwr-3qm3-26f3]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-27568 net.minidev:json-smart:jar:2.5.1 (test) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2021-27568, GHSA-v528-7hrm-frqp]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-29505 com.thoughtworks.xstream:xstream:jar:1.4.21 (runtime) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2021-29505, GHSA-7chv-rrw6-w6fc]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-31684 net.minidev:json-smart:jar:2.5.1 (test) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2021-31684, GHSA-fg2v-w576-w4v3]
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
[INFO]   - CVE-2021-42550 ch.qos.logback:logback-core:jar:1.5.11 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2021-42550, GHSA-668q-qrv7-99fm]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-43859 com.thoughtworks.xstream:xstream:jar:1.4.21 (runtime) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [BIT-jenkins-2021-43859, CVE-2021-43859, GHSA-rmr5-cpv2-vgjf]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-46877 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2021-46877, GHSA-3x8x-79m2-3w2w]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-47621 io.github.classgraph:classgraph:jar:4.8.168 (runtime) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2021-47621, GHSA-v2xm-76pq-phcf]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2022-1471 org.yaml:snakeyaml:jar:2.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2022-1471, GHSA-mjmj-j48q-9wg2]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2022-22950 org.springframework:spring-expression:jar:6.1.14 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2022-22950, GHSA-558x-2xjg-6232]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2022-22965 org.springframework:spring-beans:jar:6.1.14 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2022-22965, GHSA-36p3-wjmg-h94x]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2022-22965 org.springframework:spring-webmvc:jar:6.1.14 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2022-22965, GHSA-36p3-wjmg-h94x]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2022-22965 org.springframework.boot:spring-boot-starter-web:jar:3.3.5 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2022-22965, GHSA-36p3-wjmg-h94x]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2022-22968 org.springframework:spring-context:jar:6.1.14 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2022-22968, GHSA-g5mm-vmx4-3rg7]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2022-22970 org.springframework:spring-beans:jar:6.1.14 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2022-22970, GHSA-hh26-6xwr-ggv7]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2022-25857 org.yaml:snakeyaml:jar:2.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2022-25857, GHSA-3mc7-4q67-w48m]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2022-27772 org.springframework.boot:spring-boot:jar:3.3.5 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2022-27772, GHSA-cm59-pr5q-cw85]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2022-38749 org.yaml:snakeyaml:jar:2.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2022-38749, GHSA-c4r9-r8fh-9vj2]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2022-38750 org.yaml:snakeyaml:jar:2.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2022-38750, GHSA-hhhw-99gj-p3c3]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2022-38751 org.yaml:snakeyaml:jar:2.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2022-38751, GHSA-98wm-3w3q-mw94]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2022-38752 org.yaml:snakeyaml:jar:2.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2022-38752, GHSA-9w3m-gqgf-c4p9]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2022-40151 com.thoughtworks.xstream:xstream:jar:1.4.21 (runtime) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2022-40151, GHSA-f8cc-g7j8-xxpm]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2022-41854 org.yaml:snakeyaml:jar:2.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2022-41854, GHSA-w37g-rhq8-7m4j]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2022-41966 com.thoughtworks.xstream:xstream:jar:1.4.21 (runtime) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2022-41966, GHSA-j563-grx4-pjpv]
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
[INFO]   - CVE-2022-42252 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2022-42252, CVE-2022-42252, GHSA-p22x-g9px-3945]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2022-45143 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2022-45143, CVE-2022-45143, GHSA-rq2w-37h9-vg94]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2023-1370 net.minidev:json-smart:jar:2.5.1 (test) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2023-1370, GHSA-493p-pfq6-5258]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2023-20860 org.springframework:spring-webmvc:jar:6.1.14 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2023-20860, GHSA-7phw-cxx7-q9vq]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2023-20861 org.springframework:spring-expression:jar:6.1.14 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2023-20861, GHSA-564r-hj7v-mcr5]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2023-20863 org.springframework:spring-expression:jar:6.1.14 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2023-20863, GHSA-wxqc-pxw9-g2p8]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2023-20873 org.springframework.boot:spring-boot-actuator-autoconfigure:jar:3.3.5 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2023-20873, GHSA-g5h3-w546-pj7f]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2023-20883 org.springframework.boot:spring-boot-autoconfigure:jar:3.3.5 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2023-20883, GHSA-xf96-w227-r7c4]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2023-24998 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2023-24998, GHSA-hfrx-6qgj-fp6c]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2023-28709 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2023-28709, CVE-2023-28709, GHSA-cx6h-86xw-9x34]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2023-34053 org.springframework:spring-webmvc:jar:6.1.14 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2023-34053, GHSA-v94h-hvhg-mf9h]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2023-34055 org.springframework.boot:spring-boot-actuator:jar:3.3.5 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2023-34055, GHSA-jjfh-589g-3hjx]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2023-34981 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2023-34981, CVE-2023-34981, GHSA-mppv-79ch-vw6q]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2023-41080 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2023-41080, CVE-2023-41080, GHSA-q3mw-pvr8-9ggc]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2023-42795 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2023-42795, CVE-2023-42795, GHSA-g8pj-r55q-5c2v]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2023-44487 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-apisix-2023-44487, BIT-aspnet-core-2023-44487, BIT-contour-2023-44487, BIT-dotnet-2023-44487, BIT-dotnet-sdk-2023-44487, BIT-envoy-2023-44487, BIT-golang-2023-44487, BIT-jenkins-2023-44487, BIT-kong-2023-44487, BIT-nginx-2023-44487, BIT-nginx-gateway-2023-44487, BIT-node-2023-44487, BIT-node-min-2023-44487, BIT-solr-2023-44487, BIT-tomcat-2023-44487, BIT-varnish-2023-44487, CVE-2023-44487, GHSA-qppj-fm5r-hxr3]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2023-45648 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2023-45648, CVE-2023-45648, GHSA-r6j3-px5g-cq3x]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2023-46589 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2023-46589, CVE-2023-46589, GHSA-fccv-jmmp-qg76]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2023-51074 com.jayway.jsonpath:json-path:jar:2.9.0 (test) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2023-51074, GHSA-pfh2-hfmq-phg5]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2023-6378 ch.qos.logback:logback-classic:jar:1.5.11 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2023-6378, GHSA-vmq6-5m68-f53m]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2023-6378 ch.qos.logback:logback-core:jar:1.5.11 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2023-6378, GHSA-vmq6-5m68-f53m]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2023-6481 ch.qos.logback:logback-core:jar:1.5.11 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2023-6481, GHSA-gm62-rw4g-vrc4]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2024-12798 ch.qos.logback:logback-core:jar:1.5.11 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2024-12798, GHSA-pr98-23f8-jwxv]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2024-12801 ch.qos.logback:logback-core:jar:1.5.11 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2024-12801, GHSA-6v67-2wr5-gvf4]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2024-21733 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2024-21733, CVE-2024-21733, GHSA-f4qf-m5gf-8jm8]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2024-22233 org.springframework:spring-core:jar:6.1.14 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2024-22233, GHSA-r4q3-7g4q-x89m]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2024-22243 org.springframework:spring-web:jar:6.1.14 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2024-22243, GHSA-ccgv-vj62-xf9h]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2024-22259 org.springframework:spring-web:jar:6.1.14 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2024-22259, GHSA-hgjh-9rj2-g67j]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2024-22262 org.springframework:spring-web:jar:6.1.14 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2024-22262, GHSA-2wrp-6fg6-hmc5]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2024-23672 org.apache.tomcat.embed:tomcat-embed-websocket:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2024-23672, CVE-2024-23672, GHSA-v682-8vv8-vpwr]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2024-24549 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2024-24549, CVE-2024-24549, GHSA-7w75-32cg-r6g2]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2024-31573 org.xmlunit:xmlunit-core:jar:2.9.1 (test) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2024-31573, GHSA-chfm-68vv-pvw5]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2024-34750 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2024-34750, CVE-2024-34750, GHSA-wm9w-rjj3-j356]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2024-38286 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2024-38286, CVE-2024-38286, GHSA-7jqf-v358-p8g7]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2024-38808 org.springframework:spring-expression:jar:6.1.14 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2024-38808, GHSA-9cmq-m9j5-mvww]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2024-38809 org.springframework:spring-web:jar:6.1.14 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2024-38809, GHSA-2rmj-mq67-h97g]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2024-38816 org.springframework:spring-webmvc:jar:6.1.14 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2024-38816, GHSA-cx7f-g6mp-7hqm]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2024-38819 org.springframework:spring-webmvc:jar:6.1.14 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2024-38819, GHSA-g5vr-rgqm-vf78]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2024-38820 org.springframework:spring-context:jar:6.1.14 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2024-38820, GHSA-4gc7-5j7h-4qph]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2024-38820 org.springframework:spring-web:jar:6.1.14 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2024-38820, GHSA-4gc7-5j7h-4qph]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2024-38828 org.springframework:spring-webmvc:jar:6.1.14 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2024-38828, GHSA-w3c8-7r8f-9jp8]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2024-47072 com.thoughtworks.xstream:xstream:jar:1.4.21 (runtime) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2024-47072, GHSA-hfq9-hggm-c56q]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2024-50379 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2024-50379, CVE-2024-50379, GHSA-5j33-cvvr-w245]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2024-52317 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2024-52317, CVE-2024-52317, GHSA-qvf5-hvjx-wm27]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2024-56337 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2024-56337, CVE-2024-56337, GHSA-27hp-xhwr-wr2m]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2024-57699 net.minidev:json-smart:jar:2.5.1 (test) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2024-57699, GHSA-pq2g-wx69-c263]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2025-11226 ch.qos.logback:logback-core:jar:1.5.11 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2025-11226, GHSA-25qh-j22f-pwp8]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; Could not capture complete Maven class-provider inventory: Maven downstream provider generation is unsupported: Maven tests must be explicitly skipped with effective skipTests=true. No unique trimmed artifact is available for physical omission proof
[INFO]     Effective prerequisites: [org.codehaus.janino:janino / org.codehaus.janino.ClassBodyEvaluator]
[INFO]     Overridden fields: [intent]
[INFO]     Sources: [CATALOG, OSV]
[INFO]   - CVE-2025-22233 org.springframework:spring-context:jar:6.1.14 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2025-22233, GHSA-4wp7-92pw-q264]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2025-22235 org.springframework.boot:spring-boot:jar:3.3.5 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2025-22235, GHSA-rc42-6c7j-7h5r]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2025-24813 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2025-24813, CVE-2025-24813, GHSA-83qj-6fr2-vhqg]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2025-31650 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2025-31650, CVE-2025-31650, GHSA-3p2h-wqq4-wf4h]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2025-31651 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2025-31651, CVE-2025-31651, GHSA-ff77-26x5-69cr]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2025-41234 org.springframework:spring-web:jar:6.1.14 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2025-41234, GHSA-6r3c-xf4w-jxjm]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Declared code: [org.springframework.http.ContentDisposition] REVIEW_LEAD; classes: []; reasons: [HEURISTIC_REQUIRES_REVIEW]
[INFO]     Heuristic leads: [org.springframework.http.ContentDisposition]
[INFO]     Sources: [OSV]
[INFO]   - CVE-2025-41242 org.springframework:spring-webmvc:jar:6.1.14 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2025-41242, GHSA-r936-gwx5-v52f]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration
[INFO]     Sources: [OSV]
[INFO]   - CVE-2025-41249 org.springframework:spring-core:jar:6.1.14 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2025-41249, GHSA-jmp9-x22r-554x]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2025-46701 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2025-46701, CVE-2025-46701, GHSA-h2fw-rfh5-95r3]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2025-48988 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2025-48988, CVE-2025-48988, GHSA-h3gc-qfqq-6h8f]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2025-48989 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2025-48989, CVE-2025-48989, GHSA-gqp3-2cvr-x8m3]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2025-49124 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2025-49124, CVE-2025-49124, GHSA-42wg-hm62-jcwg]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2025-49125 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2025-49125, CVE-2025-49125, GHSA-wc4r-xq3c-5cf3]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2025-49128 com.fasterxml.jackson.core:jackson-core:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2025-49128, GHSA-wf8f-6423-gfxg]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2025-52434 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2025-52434, CVE-2025-52434, GHSA-4j3c-42xv-3f84]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2025-52520 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2025-52520, CVE-2025-52520, GHSA-wr62-c79q-cv37]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2025-52999 com.fasterxml.jackson.core:jackson-core:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2025-52999, GHSA-h46c-h94j-95f3]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2025-53506 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2025-53506, CVE-2025-53506, GHSA-25xr-qj8w-c4vf]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2025-55668 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2025-55668, CVE-2025-55668, GHSA-23hv-mwm6-g8jf]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2025-55752 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2025-55752, CVE-2025-55752, GHSA-wmwf-9ccg-fff5]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2025-55754 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2025-55754, CVE-2025-55754, GHSA-vfww-5hm6-hx2j]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2025-61795 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2025-61795, CVE-2025-61795, GHSA-hgrr-935x-pq79]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2025-66614 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2025-66614, CVE-2025-66614, GHSA-fpj8-gq4v-p354]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-10532 ch.qos.logback:logback-core:jar:1.5.11 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-10532, GHSA-jhq6-gfmj-v8fx]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
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
[INFO]   - CVE-2026-110974 com.vaadin.external.google:android-json:jar:0.0.20131108.vaadin1 (test) [RETAINED_UNCHANGED]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [CVE_LIST]
[INFO]   - CVE-2026-112046 org.ow2.asm:asm:jar:9.10.1 (test) [RETAINED_UNCHANGED]
[INFO]     Applicability: UNRESOLVED; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Unresolved coverage: [containers.cna.affected[0]:packageURL=pkg:maven/org.ow2.asm/asm,collectionURL=https://repo1.maven.org/maven2/,packageName=null: Conflicting or unsupported CVE package identities]
[INFO]     Sources: [CVE_LIST]
[INFO]   - CVE-2026-113602 net.minidev:json-smart:jar:2.5.1 (test) [RETAINED_UNCHANGED]
[INFO]     Applicability: UNRESOLVED; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Unresolved coverage: [containers.cna.affected[0]:defaultStatus=unaffected:[version=0,status=affected,versionType=semver,lessThan=null,lessThanOrEqual=2.6.0,changes=[]]: CVE default, explicit status, or overlapping statuses are unresolved, containers.cna.affected[0]:version=0,status=affected,versionType=semver,lessThan=null,lessThanOrEqual=2.6.0,changes=[]: Unsupported CVE versionType]
[INFO]     Sources: [CVE_LIST]
[INFO]   - CVE-2026-116486 org.objenesis:objenesis:jar:3.3 (test) [RETAINED_UNCHANGED]
[INFO]     Applicability: UNRESOLVED; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Unresolved coverage: [containers.cna.affected[0]:defaultStatus=unaffected:[version=0,status=affected,versionType=custom,lessThan=3.6,lessThanOrEqual=null,changes=[], version=3.6,status=unaffected,versionType=custom,lessThan=null,lessThanOrEqual=null,changes=[]]: CVE default, explicit status, or overlapping statuses are unresolved, containers.cna.affected[0]:version=0,status=affected,versionType=custom,lessThan=3.6,lessThanOrEqual=null,changes=[]: Unsupported CVE versionType, containers.cna.affected[0]:version=3.6,status=unaffected,versionType=custom,lessThan=null,lessThanOrEqual=null,changes=[]: Unsupported CVE versionType]
[INFO]     Sources: [CVE_LIST]
[INFO]   - CVE-2026-1225 ch.qos.logback:logback-core:jar:1.5.11 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-1225, GHSA-qqpg-mvqg-649v]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-18401 com.fasterxml.jackson.core:jackson-core:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
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
[INFO]   - CVE-2026-22731 org.springframework.boot:spring-boot-starter-actuator:jar:3.3.5 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-22731, GHSA-8hfc-fq58-r658]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-22733 org.springframework.boot:spring-boot-starter-actuator:jar:3.3.5 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-22733, GHSA-mgvc-8q2h-5pgc]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-22735 org.springframework:spring-webmvc:jar:6.1.14 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2026-22735, GHSA-6hcq-hmm3-jj3c]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-22737 org.springframework:spring-webmvc:jar:6.1.14 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2026-22737, GHSA-4773-3jfm-qmx3]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-22741 org.springframework:spring-webmvc:jar:6.1.14 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2026-22741, GHSA-wg35-8jpf-2xv3]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-22745 org.springframework:spring-webmvc:jar:6.1.14 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2026-22745, GHSA-6p4f-wcwh-5vvm]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-24400 org.assertj:assertj-core:jar:3.27.3 (test) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-24400, GHSA-rqfh-9r24-8c9r]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Declared code: [org.assertj.core.api.AbstractCharSequenceAssert] REVIEW_LEAD; classes: []; reasons: [HEURISTIC_REQUIRES_REVIEW]
[INFO]     Declared code: [org.assertj.core.util.xml.XmlStringPrettyFormatter] REVIEW_LEAD; classes: []; reasons: [HEURISTIC_REQUIRES_REVIEW]
[INFO]     Heuristic leads: [org.assertj.core.api.AbstractCharSequenceAssert, org.assertj.core.util.xml.XmlStringPrettyFormatter]
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-24734 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2026-24734, CVE-2026-24734, GHSA-mgp5-rv84-w37q]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-24880 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2026-24880, CVE-2026-24880, GHSA-563x-q5rq-57qp]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-25854 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2026-25854, CVE-2026-25854, GHSA-9m3c-qcxr-9x87]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-29129 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2026-29129, CVE-2026-29129, GHSA-69cc-cv78-qc8g]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-32990 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2026-32990, CVE-2026-32990, GHSA-8mc5-53m5-3qj2]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-34483 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2026-34483, CVE-2026-34483, GHSA-rv64-5gf8-9qq8]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-34487 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2026-34487, CVE-2026-34487, GHSA-x4m4-345f-5h5g]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-40973 org.springframework.boot:spring-boot:jar:3.3.5 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-40973, GHSA-wwpq-f5c3-7hvx]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-40976 org.springframework.boot:spring-boot:jar:3.3.5 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-40976, GHSA-8v8j-3hxp-93wr]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-40983 io.micrometer:micrometer-core:jar:1.13.6 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-40983, GHSA-w737-wx49-qj23]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-40984 io.micrometer:micrometer-core:jar:1.13.6 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-40984, GHSA-g3pr-3p32-fp23]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-40992 org.springframework.boot:spring-boot-starter-mail:jar:3.3.5 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-40992, GHSA-9wxp-w4px-32vh]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-41001 org.springframework.boot:spring-boot-autoconfigure:jar:3.3.5 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-41001, GHSA-ggg2-9786-hwc8]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-41284 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2026-41284, CVE-2026-41284, GHSA-gx5v-xp9w-j4cg]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-41293 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2026-41293, CVE-2026-41293, GHSA-r29c-68gh-xp6x]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-41841 org.springframework:spring-webmvc:jar:6.1.14 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2026-41841, GHSA-mq64-j8f9-9gcj]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-41842 org.springframework:spring-webmvc:jar:6.1.14 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2026-41842, GHSA-x23c-287f-qqv5]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-41843 org.springframework:spring-webmvc:jar:6.1.14 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2026-41843, GHSA-72pg-x5f8-j25j]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-41844 org.springframework:spring-webmvc:jar:6.1.14 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2026-41844, GHSA-h3qp-gqrc-q736]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-41845 org.springframework:spring-webmvc:jar:6.1.14 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2026-41845, GHSA-3chg-m5w7-qfv5]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-41846 org.springframework:spring-webmvc:jar:6.1.14 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2026-41846, GHSA-957g-f97v-vppc]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-41848 org.springframework:spring-core:jar:6.1.14 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-41848, GHSA-659m-px2c-25wj]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-41849 org.springframework:spring-expression:jar:6.1.14 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-41849, GHSA-775g-4xr8-78h8]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-41850 org.springframework:spring-expression:jar:6.1.14 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-41850, GHSA-r5w3-xv2f-j59q]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-41851 org.springframework:spring-expression:jar:6.1.14 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-41851, GHSA-wxpp-56q6-5pcg]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-41852 org.springframework:spring-expression:jar:6.1.14 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-41852, GHSA-9f52-rjqv-25qv]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-41853 org.springframework:spring-webmvc:jar:6.1.14 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2026-41853, GHSA-cjpg-rgq5-fr37]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-41854 org.springframework:spring-web:jar:6.1.14 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-41854, GHSA-7m2p-62gw-p8qq]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-42498 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2026-42498, CVE-2026-42498, GHSA-fv25-8xcx-gqjc]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-43512 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2026-43512, CVE-2026-43512, GHSA-h6fc-48rj-7qqh]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-43513 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2026-43513, CVE-2026-43513, GHSA-5mp6-jrq3-r938]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-43514 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2026-43514, CVE-2026-43514, GHSA-9m89-8frq-c98c]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-43515 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2026-43515, CVE-2026-43515, GHSA-5m62-pw8w-7w9f]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-47884 org.springframework:spring-webmvc:jar:6.1.14 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2026-47884, GHSA-pc63-qcmh-9cmg]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-47890 org.springframework:spring-webmvc:jar:6.1.14 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2026-47890, GHSA-j9f9-w8pj-32f8]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-49844 org.apache.logging.log4j:log4j-api:jar:2.23.1 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-49844, GHSA-qv9r-c865-cp47]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [CVE_LIST, OSV]
[INFO]   - CVE-2026-50193 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2026-50193, GHSA-3wrr-7qpf-2prh]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-53404 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2026-53404, CVE-2026-53404, GHSA-h792-v28v-ppgr]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
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
[INFO]   - CVE-2026-55276 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2026-55276, CVE-2026-55276, GHSA-mqg3-r7h5-24x4]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-55956 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2026-55956, CVE-2026-55956, GHSA-5v3h-fjv2-54fg]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-55957 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2026-55957, CVE-2026-55957, GHSA-7895-gffq-w6jq]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
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
[INFO]   - CVE-2026-65182 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2026-65182, CVE-2026-65182, GHSA-gcx9-497g-6cp6]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-65637 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2026-65637, CVE-2026-65637, GHSA-f525-44xv-f2qj]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-65905 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2026-65905, CVE-2026-65905, GHSA-9xv2-5v5q-p794]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-68494 com.fasterxml.jackson.core:jackson-core:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
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
[INFO]   - CVE-2026-68498 com.fasterxml.jackson.core:jackson-core:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; Vulnerable class survives trimmed archive: com.fasterxml.jackson.core.json.ReaderBasedJsonParser
[INFO]     Declared code: [src/main/java/com/fasterxml/jackson/core/json/ReaderBasedJsonParser.java] RESOLVED; classes: [com.fasterxml.jackson.core.json.ReaderBasedJsonParser]; reasons: []
[INFO]     Declared code: [ReaderBasedJsonParser._parseName2] RESOLVED; classes: [com.fasterxml.jackson.core.json.ReaderBasedJsonParser]; reasons: []
[INFO]     Sources: [CVE_LIST]
[INFO]   - CVE-2026-68525 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2026-68525, CVE-2026-68525, GHSA-h3x4-894j-xpx5]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
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
[INFO]   - CVE-2026-84939 org.freemarker:freemarker:jar:2.3.33 (runtime) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2026-84939, GHSA-27j2-h3m2-8237]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration
[INFO]     Unresolved coverage: [containers.cna.affected[0]:defaultStatus=unaffected:[version=2.2.0,status=affected,versionType=semver,lessThan=null,lessThanOrEqual=2.3.34,changes=[], version=2.3.35,status=unaffected,versionType=semver,lessThan=null,lessThanOrEqual=null,changes=[]]: CVE default, explicit status, or overlapping statuses are unresolved, containers.cna.affected[0]:version=2.2.0,status=affected,versionType=semver,lessThan=null,lessThanOrEqual=2.3.34,changes=[]: Unsupported CVE versionType, containers.cna.affected[0]:version=2.3.35,status=unaffected,versionType=semver,lessThan=null,lessThanOrEqual=null,changes=[]: Unsupported CVE versionType]
[INFO]     Sources: [CVE_LIST, OSV]
[INFO]   - CVE-2026-89407 com.fasterxml.jackson.core:jackson-core:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2026-89407, GHSA-p6pp-m3f8-5c89]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; Vulnerable class survives trimmed archive: com.fasterxml.jackson.core.io.NumberInput
[INFO]     Declared code: [com.fasterxml.jackson.core.io.NumberInput.looksLikeValidNumber] RESOLVED; classes: [com.fasterxml.jackson.core.io.NumberInput]; reasons: []
[INFO]     Declared code: [com.fasterxml.jackson.core.io.NumberInput] REVIEW_LEAD; classes: []; reasons: [HEURISTIC_REQUIRES_REVIEW]
[INFO]     Heuristic leads: [com.fasterxml.jackson.core.io.NumberInput]
[INFO]     Sources: [CVE_LIST, OSV]
[INFO]   - CVE-2026-89425 com.fasterxml.jackson.core:jackson-core:jar:2.18.2 (compile) [RETAINED_AND_TRIMMED]
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
[INFO]   - CVE-2026-9828 ch.qos.logback:logback-core:jar:1.5.11 (compile) [RETAINED_UNCHANGED]
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
[INFO] Adopted vulnerability mapping catalogs:
[INFO]   - io.github.spockz.catalogs:logback-vulnerability-mapping-catalog:1.0.0:jar: (catalogId=logback-core-cve-2025-11226, sha256=1e01a18825c5a284eee487128a7a76e18e0b3071b2614721e5b8afd1599fe865, mappings=2, unresolved=0)
[INFO] POM exclusion review (advisory only):
[INFO]   Repeated POM exclusions:
[INFO]     none found across effective dependency paths
[INFO]   Exclusion provenance incomplete for 1529 dependency or exclusion origins.
[INFO]   Maven supplied no source location/identity or the location matched zero or
[INFO]   multiple original POM rows. This advisory review does not affect elision.
[INFO]   Full evidence is in the JSON snapshot fields
[INFO]   exclusionReview.snapshot.dependencies and
[INFO]   exclusionReview.snapshot.diagnostics.
[INFO] Mediated TEST dependency graph (captured and saved by the elide goal):
[INFO]   - io.github.spockz:example-spring-boot-app:0.1.0-SNAPSHOT {nodeId=n0} [RETAINED]
[INFO]   - io.github.spockz:example-spring-boot-app:0.1.0-SNAPSHOT -> com.github.spotbugs:spotbugs-annotations:jar:4.10.5 (runtime) {nodeId=n7} [RETAINED, CLASS_TRIMMED]
[INFO]   - io.github.spockz:example-spring-boot-app:0.1.0-SNAPSHOT -> com.google.code.findbugs:jsr305:jar:3.0.2 (runtime) {nodeId=n15} [RETAINED, CLASS_TRIMMED]
[INFO]   ... 89 dependency graph rows elided (sha256:b9f90252b8e5b90c56c2c4e2bcf798e875af6976a6e3aa2019ab21e754970f3b)
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
[INFO] Program classes pruned from retained JARs: 330 (uncompressed omitted .class payload bytes: 1.04 MiB; excludes module descriptors and archive metadata)
[INFO]   - com.fasterxml.jackson.core:jackson-core:jar:2.19.0 (compile): 20 classes, 82.33 KiB
[INFO]   - com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile): 70 classes, 163.47 KiB
[INFO]   - org.apache.commons:commons-text:jar:1.9 (compile): 132 classes, 388.41 KiB
[INFO]   - org.codehaus.janino:commons-compiler:jar:3.1.12 (compile): 51 classes, 96.78 KiB
[INFO]   - org.codehaus.janino:janino:jar:3.1.12 (compile): 52 classes, 330.49 KiB
[INFO]   - org.slf4j:slf4j-api:jar:2.0.17 (compile): 5 classes, 6.38 KiB
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
[INFO]   Exclusion provenance incomplete for 1534 dependency or exclusion origins.
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
[INFO] Program classes pruned from retained JARs: 5 (uncompressed omitted .class payload bytes: 6.38 KiB; excludes module descriptors and archive metadata)
[INFO]   - org.slf4j:slf4j-api:jar:2.0.17 (compile): 5 classes, 6.38 KiB
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
[INFO]   - io.github.spockz.catalogs:logback-vulnerability-mapping-catalog:1.0.0:jar: (catalogId=logback-core-cve-2025-11226, sha256=1e01a18825c5a284eee487128a7a76e18e0b3071b2614721e5b8afd1599fe865, mappings=2, unresolved=0)
[INFO] POM exclusion review (advisory only):
[INFO]   Repeated POM exclusions:
[INFO]     none found across effective dependency paths
[INFO]   Exclusion provenance incomplete for 1534 dependency or exclusion origins.
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
[INFO]     Would remove classes: [org.apache.commons.io.ByteBuffers, org.apache.commons.io.ByteOrderMark, org.apache.commons.io.ByteOrderParser, org.apache.commons.io.Charsets, org.apache.commons.io.CloseableURLConnection, org.apache.commons.io.CopyUtils, org.apache.commons.io.DirectoryWalker, org.apache.commons.io.DirectoryWalker$CancelException, org.apache.commons.io.EndianUtils, org.apache.commons.io.FileCleaner, org.apache.commons.io.FileCleaningTracker, org.apache.commons.io.FileCleaningTracker$Reaper, org.apache.commons.io.FileCleaningTracker$Tracker, org.apache.commons.io.FileDeleteStrategy, org.apache.commons.io.FileDeleteStrategy$ForceFileDeleteStrategy, org.apache.commons.io.FileExistsException, org.apache.commons.io.FileSystem, org.apache.commons.io.FileSystemUtils, org.apache.commons.io.FileUtils, org.apache.commons.io.FilenameUtils, org.apache.commons.io.HexDump, org.apache.commons.io.IO, org.apache.commons.io.IOCase, org.apache.commons.io.IOExceptionList, org.apache.commons.io.IOExceptionWithCause, org.apache.commons.io.IOIndexedException, org.apache.commons.io.IORandomAccessFile, org.apache.commons.io.IOUtils, org.apache.commons.io.LineIterator, org.apache.commons.io.RandomAccessFileMode, org.apache.commons.io.RandomAccessFileMode$1, org.apache.commons.io.RandomAccessFiles, org.apache.commons.io.StandardLineSeparator, org.apache.commons.io.StreamIterator, org.apache.commons.io.TaggedIOException, org.apache.commons.io.ThreadMonitor, org.apache.commons.io.ThreadUtils, org.apache.commons.io.UncheckedIOExceptions, org.apache.commons.io.build.AbstractOrigin, org.apache.commons.io.build.AbstractOrigin$AbstractRandomAccessFileOrigin, org.apache.commons.io.build.AbstractOrigin$ByteArrayOrigin, org.apache.commons.io.build.AbstractOrigin$CharSequenceOrigin, org.apache.commons.io.build.AbstractOrigin$FileOrigin, org.apache.commons.io.build.AbstractOrigin$IORandomAccessFileOrigin, org.apache.commons.io.build.AbstractOrigin$InputStreamOrigin, org.apache.commons.io.build.AbstractOrigin$OutputStreamOrigin, org.apache.commons.io.build.AbstractOrigin$PathOrigin, org.apache.commons.io.build.AbstractOrigin$RandomAccessFileOrigin, org.apache.commons.io.build.AbstractOrigin$ReaderOrigin, org.apache.commons.io.build.AbstractOrigin$URIOrigin, org.apache.commons.io.build.AbstractOrigin$WriterOrigin, org.apache.commons.io.build.AbstractOriginSupplier, org.apache.commons.io.build.AbstractStreamBuilder, org.apache.commons.io.build.AbstractSupplier, org.apache.commons.io.build.package-info, org.apache.commons.io.channels.FileChannels, org.apache.commons.io.channels.package-info, org.apache.commons.io.charset.CharsetDecoders, org.apache.commons.io.charset.CharsetEncoders, org.apache.commons.io.charset.package-info, org.apache.commons.io.comparator.AbstractFileComparator, org.apache.commons.io.comparator.CompositeFileComparator, org.apache.commons.io.comparator.DefaultFileComparator, org.apache.commons.io.comparator.DirectoryFileComparator, org.apache.commons.io.comparator.ExtensionFileComparator, org.apache.commons.io.comparator.LastModifiedFileComparator, org.apache.commons.io.comparator.NameFileComparator, org.apache.commons.io.comparator.PathFileComparator, org.apache.commons.io.comparator.ReverseFileComparator, org.apache.commons.io.comparator.SizeFileComparator, org.apache.commons.io.comparator.package-info, org.apache.commons.io.file.AccumulatorPathVisitor, org.apache.commons.io.file.AccumulatorPathVisitor$1, org.apache.commons.io.file.AccumulatorPathVisitor$Builder, org.apache.commons.io.file.CleaningPathVisitor, org.apache.commons.io.file.CopyDirectoryVisitor, org.apache.commons.io.file.Counters, org.apache.commons.io.file.Counters$1, org.apache.commons.io.file.Counters$AbstractPathCounters, org.apache.commons.io.file.Counters$BigIntegerCounter, org.apache.commons.io.file.Counters$BigIntegerPathCounters, org.apache.commons.io.file.Counters$Counter, org.apache.commons.io.file.Counters$LongCounter, org.apache.commons.io.file.Counters$LongPathCounters, org.apache.commons.io.file.Counters$NoopCounter, org.apache.commons.io.file.Counters$NoopPathCounters, org.apache.commons.io.file.Counters$PathCounters, org.apache.commons.io.file.CountingPathVisitor, org.apache.commons.io.file.CountingPathVisitor$AbstractBuilder, org.apache.commons.io.file.CountingPathVisitor$Builder, org.apache.commons.io.file.DeleteOption, org.apache.commons.io.file.DeletingPathVisitor, org.apache.commons.io.file.DirectoryStreamFilter, org.apache.commons.io.file.FilesUncheck, org.apache.commons.io.file.NoopPathVisitor, org.apache.commons.io.file.PathFilter, org.apache.commons.io.file.PathUtils, org.apache.commons.io.file.PathUtils$1, org.apache.commons.io.file.PathUtils$RelativeSortedPaths, org.apache.commons.io.file.PathVisitor, org.apache.commons.io.file.SimplePathVisitor, org.apache.commons.io.file.SimplePathVisitor$AbstractBuilder, org.apache.commons.io.file.StandardDeleteOption, org.apache.commons.io.file.attribute.FileTimes, org.apache.commons.io.file.attribute.package-info, org.apache.commons.io.file.package-info, org.apache.commons.io.file.spi.FileSystemProviders, org.apache.commons.io.file.spi.package-info, org.apache.commons.io.filefilter.AbstractFileFilter, org.apache.commons.io.filefilter.AgeFileFilter, org.apache.commons.io.filefilter.AndFileFilter, org.apache.commons.io.filefilter.CanExecuteFileFilter, org.apache.commons.io.filefilter.CanReadFileFilter, org.apache.commons.io.filefilter.CanWriteFileFilter, org.apache.commons.io.filefilter.ConditionalFileFilter, org.apache.commons.io.filefilter.DelegateFileFilter, org.apache.commons.io.filefilter.DirectoryFileFilter, org.apache.commons.io.filefilter.EmptyFileFilter, org.apache.commons.io.filefilter.FalseFileFilter, org.apache.commons.io.filefilter.FileEqualsFileFilter, org.apache.commons.io.filefilter.FileFileFilter, org.apache.commons.io.filefilter.FileFilterUtils, org.apache.commons.io.filefilter.HiddenFileFilter, org.apache.commons.io.filefilter.IOFileFilter, org.apache.commons.io.filefilter.MagicNumberFileFilter, org.apache.commons.io.filefilter.NameFileFilter, org.apache.commons.io.filefilter.NotFileFilter, org.apache.commons.io.filefilter.OrFileFilter, org.apache.commons.io.filefilter.PathEqualsFileFilter, org.apache.commons.io.filefilter.PathMatcherFileFilter, org.apache.commons.io.filefilter.PathVisitorFileFilter, org.apache.commons.io.filefilter.PrefixFileFilter, org.apache.commons.io.filefilter.RegexFileFilter, org.apache.commons.io.filefilter.SizeFileFilter, org.apache.commons.io.filefilter.SuffixFileFilter, org.apache.commons.io.filefilter.SymbolicLinkFileFilter, org.apache.commons.io.filefilter.TrueFileFilter, org.apache.commons.io.filefilter.WildcardFileFilter, org.apache.commons.io.filefilter.WildcardFileFilter$1, org.apache.commons.io.filefilter.WildcardFileFilter$Builder, org.apache.commons.io.filefilter.WildcardFilter, org.apache.commons.io.filefilter.package-info, org.apache.commons.io.function.Constants, org.apache.commons.io.function.Erase, org.apache.commons.io.function.IOBaseStream, org.apache.commons.io.function.IOBaseStreamAdapter, org.apache.commons.io.function.IOBiConsumer, org.apache.commons.io.function.IOBiFunction, org.apache.commons.io.function.IOBinaryOperator, org.apache.commons.io.function.IOBooleanSupplier, org.apache.commons.io.function.IOComparator, org.apache.commons.io.function.IOConsumer, org.apache.commons.io.function.IOFunction, org.apache.commons.io.function.IOIntConsumer, org.apache.commons.io.function.IOIntSupplier, org.apache.commons.io.function.IOIterable, org.apache.commons.io.function.IOIterator, org.apache.commons.io.function.IOIteratorAdapter, org.apache.commons.io.function.IOLongSupplier, org.apache.commons.io.function.IOPredicate, org.apache.commons.io.function.IOQuadFunction, org.apache.commons.io.function.IORunnable, org.apache.commons.io.function.IOSpliterator, org.apache.commons.io.function.IOSpliteratorAdapter, org.apache.commons.io.function.IOStream, org.apache.commons.io.function.IOStream$1, org.apache.commons.io.function.IOStreamAdapter, org.apache.commons.io.function.IOStreams, org.apache.commons.io.function.IOSupplier, org.apache.commons.io.function.IOTriConsumer, org.apache.commons.io.function.IOTriFunction, org.apache.commons.io.function.IOUnaryOperator, org.apache.commons.io.function.Uncheck, org.apache.commons.io.function.UncheckedIOBaseStream, org.apache.commons.io.function.UncheckedIOIterable, org.apache.commons.io.function.UncheckedIOIterator, org.apache.commons.io.function.UncheckedIOSpliterator, org.apache.commons.io.function.package-info, org.apache.commons.io.input.AbstractCharacterFilterReader, org.apache.commons.io.input.AbstractInputStream, org.apache.commons.io.input.AutoCloseInputStream, org.apache.commons.io.input.AutoCloseInputStream$1, org.apache.commons.io.input.AutoCloseInputStream$Builder, org.apache.commons.io.input.BOMInputStream, org.apache.commons.io.input.BOMInputStream$1, org.apache.commons.io.input.BOMInputStream$Builder, org.apache.commons.io.input.BoundedInputStream, org.apache.commons.io.input.BoundedInputStream$AbstractBuilder, org.apache.commons.io.input.BoundedInputStream$Builder, org.apache.commons.io.input.BoundedReader, org.apache.commons.io.input.BrokenInputStream, org.apache.commons.io.input.BrokenReader, org.apache.commons.io.input.BufferedFileChannelInputStream, org.apache.commons.io.input.BufferedFileChannelInputStream$1, org.apache.commons.io.input.BufferedFileChannelInputStream$Builder, org.apache.commons.io.input.ByteBufferCleaner, org.apache.commons.io.input.ByteBufferCleaner$1, org.apache.commons.io.input.ByteBufferCleaner$Cleaner, org.apache.commons.io.input.ByteBufferCleaner$Java8Cleaner, org.apache.commons.io.input.ByteBufferCleaner$Java9Cleaner, org.apache.commons.io.input.CharSequenceInputStream, org.apache.commons.io.input.CharSequenceInputStream$1, org.apache.commons.io.input.CharSequenceInputStream$Builder, org.apache.commons.io.input.CharSequenceReader, org.apache.commons.io.input.CharacterFilterReader, org.apache.commons.io.input.CharacterSetFilterReader, org.apache.commons.io.input.ChecksumInputStream, org.apache.commons.io.input.ChecksumInputStream$1, org.apache.commons.io.input.ChecksumInputStream$Builder, org.apache.commons.io.input.CircularInputStream, org.apache.commons.io.input.ClassLoaderObjectInputStream, org.apache.commons.io.input.CloseShieldInputStream, org.apache.commons.io.input.CloseShieldReader, org.apache.commons.io.input.ClosedInputStream, org.apache.commons.io.input.ClosedReader, org.apache.commons.io.input.CountingInputStream, org.apache.commons.io.input.DemuxInputStream, org.apache.commons.io.input.InfiniteCircularInputStream, org.apache.commons.io.input.Input, org.apache.commons.io.input.MarkShieldInputStream, org.apache.commons.io.input.MemoryMappedFileInputStream, org.apache.commons.io.input.MemoryMappedFileInputStream$1, org.apache.commons.io.input.MemoryMappedFileInputStream$Builder, org.apache.commons.io.input.MessageDigestCalculatingInputStream, org.apache.commons.io.input.MessageDigestCalculatingInputStream$1, org.apache.commons.io.input.MessageDigestCalculatingInputStream$Builder, org.apache.commons.io.input.MessageDigestCalculatingInputStream$MessageDigestMaintainingObserver, org.apache.commons.io.input.MessageDigestInputStream, org.apache.commons.io.input.MessageDigestInputStream$1, org.apache.commons.io.input.MessageDigestInputStream$Builder, org.apache.commons.io.input.MessageDigestInputStream$MessageDigestMaintainingObserver, org.apache.commons.io.input.NullInputStream, org.apache.commons.io.input.NullReader, org.apache.commons.io.input.ObservableInputStream, org.apache.commons.io.input.ObservableInputStream$AbstractBuilder, org.apache.commons.io.input.ObservableInputStream$Builder, org.apache.commons.io.input.ObservableInputStream$Observer, org.apache.commons.io.input.ProxyInputStream, org.apache.commons.io.input.ProxyInputStream$AbstractBuilder, org.apache.commons.io.input.ProxyReader, org.apache.commons.io.input.QueueInputStream, org.apache.commons.io.input.QueueInputStream$1, org.apache.commons.io.input.QueueInputStream$Builder, org.apache.commons.io.input.RandomAccessFileInputStream, org.apache.commons.io.input.RandomAccessFileInputStream$1, org.apache.commons.io.input.RandomAccessFileInputStream$Builder, org.apache.commons.io.input.ReadAheadInputStream, org.apache.commons.io.input.ReadAheadInputStream$1, org.apache.commons.io.input.ReadAheadInputStream$Builder, org.apache.commons.io.input.ReaderInputStream, org.apache.commons.io.input.ReaderInputStream$1, org.apache.commons.io.input.ReaderInputStream$Builder, org.apache.commons.io.input.ReversedLinesFileReader, org.apache.commons.io.input.ReversedLinesFileReader$1, org.apache.commons.io.input.ReversedLinesFileReader$Builder, org.apache.commons.io.input.ReversedLinesFileReader$FilePart, org.apache.commons.io.input.SequenceReader, org.apache.commons.io.input.SwappedDataInputStream, org.apache.commons.io.input.TaggedInputStream, org.apache.commons.io.input.TaggedReader, org.apache.commons.io.input.Tailer, org.apache.commons.io.input.Tailer$1, org.apache.commons.io.input.Tailer$Builder, org.apache.commons.io.input.Tailer$RandomAccessFileBridge, org.apache.commons.io.input.Tailer$RandomAccessResourceBridge, org.apache.commons.io.input.Tailer$Tailable, org.apache.commons.io.input.Tailer$TailablePath, org.apache.commons.io.input.TailerListener, org.apache.commons.io.input.TailerListenerAdapter, org.apache.commons.io.input.TeeInputStream, org.apache.commons.io.input.TeeReader, org.apache.commons.io.input.ThrottledInputStream, org.apache.commons.io.input.ThrottledInputStream$1, org.apache.commons.io.input.ThrottledInputStream$Builder, org.apache.commons.io.input.TimestampedObserver, org.apache.commons.io.input.UncheckedBufferedReader, org.apache.commons.io.input.UncheckedBufferedReader$1, org.apache.commons.io.input.UncheckedBufferedReader$Builder, org.apache.commons.io.input.UncheckedFilterInputStream, org.apache.commons.io.input.UncheckedFilterInputStream$1, org.apache.commons.io.input.UncheckedFilterInputStream$Builder, org.apache.commons.io.input.UncheckedFilterReader, org.apache.commons.io.input.UncheckedFilterReader$1, org.apache.commons.io.input.UncheckedFilterReader$Builder, org.apache.commons.io.input.UnixLineEndingInputStream, org.apache.commons.io.input.UnsupportedOperationExceptions, org.apache.commons.io.input.UnsynchronizedBufferedInputStream, org.apache.commons.io.input.UnsynchronizedBufferedInputStream$1, org.apache.commons.io.input.UnsynchronizedBufferedInputStream$Builder, org.apache.commons.io.input.UnsynchronizedBufferedReader, org.apache.commons.io.input.UnsynchronizedByteArrayInputStream, org.apache.commons.io.input.UnsynchronizedByteArrayInputStream$1, org.apache.commons.io.input.UnsynchronizedByteArrayInputStream$Builder, org.apache.commons.io.input.UnsynchronizedFilterInputStream, org.apache.commons.io.input.UnsynchronizedFilterInputStream$Builder, org.apache.commons.io.input.UnsynchronizedReader, org.apache.commons.io.input.WindowsLineEndingInputStream, org.apache.commons.io.input.XmlStreamReader, org.apache.commons.io.input.XmlStreamReader$Builder, org.apache.commons.io.input.XmlStreamReaderException, org.apache.commons.io.input.buffer.CircularBufferInputStream, org.apache.commons.io.input.buffer.CircularByteBuffer, org.apache.commons.io.input.buffer.PeekableInputStream, org.apache.commons.io.input.buffer.package-info, org.apache.commons.io.input.package-info, org.apache.commons.io.monitor.FileAlterationListener, org.apache.commons.io.monitor.FileAlterationListenerAdaptor, org.apache.commons.io.monitor.FileAlterationMonitor, org.apache.commons.io.monitor.FileAlterationObserver, org.apache.commons.io.monitor.FileAlterationObserver$1, org.apache.commons.io.monitor.FileAlterationObserver$Builder, org.apache.commons.io.monitor.FileEntry, org.apache.commons.io.monitor.SerializableFileTime, org.apache.commons.io.monitor.package-info, org.apache.commons.io.output.AbstractByteArrayOutputStream, org.apache.commons.io.output.AbstractByteArrayOutputStream$InputStreamConstructor, org.apache.commons.io.output.AppendableOutputStream, org.apache.commons.io.output.AppendableWriter, org.apache.commons.io.output.BrokenOutputStream, org.apache.commons.io.output.BrokenWriter, org.apache.commons.io.output.ByteArrayOutputStream, org.apache.commons.io.output.ChunkedOutputStream, org.apache.commons.io.output.ChunkedOutputStream$1, org.apache.commons.io.output.ChunkedOutputStream$Builder, org.apache.commons.io.output.ChunkedWriter, org.apache.commons.io.output.CloseShieldOutputStream, org.apache.commons.io.output.CloseShieldWriter, org.apache.commons.io.output.ClosedOutputStream, org.apache.commons.io.output.ClosedWriter, org.apache.commons.io.output.CountingOutputStream, org.apache.commons.io.output.DeferredFileOutputStream, org.apache.commons.io.output.DeferredFileOutputStream$1, org.apache.commons.io.output.DeferredFileOutputStream$Builder, org.apache.commons.io.output.DemuxOutputStream, org.apache.commons.io.output.FileWriterWithEncoding, org.apache.commons.io.output.FileWriterWithEncoding$1, org.apache.commons.io.output.FileWriterWithEncoding$Builder, org.apache.commons.io.output.FilterCollectionWriter, org.apache.commons.io.output.LockableFileWriter, org.apache.commons.io.output.LockableFileWriter$1, org.apache.commons.io.output.LockableFileWriter$Builder, org.apache.commons.io.output.NullAppendable, org.apache.commons.io.output.NullOutputStream, org.apache.commons.io.output.NullPrintStream, org.apache.commons.io.output.NullWriter, org.apache.commons.io.output.ProxyCollectionWriter, org.apache.commons.io.output.ProxyOutputStream, org.apache.commons.io.output.ProxyOutputStream$Builder, org.apache.commons.io.output.ProxyWriter, org.apache.commons.io.output.QueueOutputStream, org.apache.commons.io.output.RandomAccessFileOutputStream, org.apache.commons.io.output.RandomAccessFileOutputStream$1, org.apache.commons.io.output.RandomAccessFileOutputStream$Builder, org.apache.commons.io.output.StringBuilderWriter, org.apache.commons.io.output.TaggedOutputStream, org.apache.commons.io.output.TaggedWriter, org.apache.commons.io.output.TeeOutputStream, org.apache.commons.io.output.TeeWriter, org.apache.commons.io.output.ThresholdingOutputStream, org.apache.commons.io.output.UncheckedAppendable, org.apache.commons.io.output.UncheckedAppendableImpl, org.apache.commons.io.output.UncheckedFilterOutputStream, org.apache.commons.io.output.UncheckedFilterOutputStream$1, org.apache.commons.io.output.UncheckedFilterOutputStream$Builder, org.apache.commons.io.output.UncheckedFilterWriter, org.apache.commons.io.output.UncheckedFilterWriter$1, org.apache.commons.io.output.UncheckedFilterWriter$Builder, org.apache.commons.io.output.UnsynchronizedByteArrayOutputStream, org.apache.commons.io.output.UnsynchronizedByteArrayOutputStream$1, org.apache.commons.io.output.UnsynchronizedByteArrayOutputStream$Builder, org.apache.commons.io.output.WriterOutputStream, org.apache.commons.io.output.WriterOutputStream$1, org.apache.commons.io.output.WriterOutputStream$Builder, org.apache.commons.io.output.XmlStreamWriter, org.apache.commons.io.output.XmlStreamWriter$1, org.apache.commons.io.output.XmlStreamWriter$Builder, org.apache.commons.io.output.package-info, org.apache.commons.io.package-info, org.apache.commons.io.serialization.ClassNameMatcher, org.apache.commons.io.serialization.FullClassNameMatcher, org.apache.commons.io.serialization.ObjectStreamClassPredicate, org.apache.commons.io.serialization.RegexpClassNameMatcher, org.apache.commons.io.serialization.ValidatingObjectInputStream, org.apache.commons.io.serialization.ValidatingObjectInputStream$1, org.apache.commons.io.serialization.ValidatingObjectInputStream$Builder, org.apache.commons.io.serialization.WildcardClassNameMatcher, org.apache.commons.io.serialization.package-info]
[INFO]   - org.apache.commons:commons-compress:jar:1.28.0 (compile): 566 classes, unknown
[INFO]     Would remove classes: [org.apache.commons.compress.CompressException, org.apache.commons.compress.CompressFilterOutputStream, org.apache.commons.compress.MemoryLimitException, org.apache.commons.compress.PasswordRequiredException, org.apache.commons.compress.archivers.ArchiveException, org.apache.commons.compress.archivers.ArchiveInputStream, org.apache.commons.compress.archivers.ArchiveInputStream$ArchiveEntryIOIterator, org.apache.commons.compress.archivers.ArchiveOutputStream, org.apache.commons.compress.archivers.ArchiveStreamFactory, org.apache.commons.compress.archivers.ArchiveStreamProvider, org.apache.commons.compress.archivers.Lister, org.apache.commons.compress.archivers.StreamingNotSupportedException, org.apache.commons.compress.archivers.ar.ArArchiveEntry, org.apache.commons.compress.archivers.ar.ArArchiveInputStream, org.apache.commons.compress.archivers.ar.ArArchiveOutputStream, org.apache.commons.compress.archivers.ar.package-info, org.apache.commons.compress.archivers.arj.ArjArchiveEntry, org.apache.commons.compress.archivers.arj.ArjArchiveEntry$HostOs, org.apache.commons.compress.archivers.arj.ArjArchiveInputStream, org.apache.commons.compress.archivers.arj.LocalFileHeader, org.apache.commons.compress.archivers.arj.LocalFileHeader$FileTypes, org.apache.commons.compress.archivers.arj.LocalFileHeader$Flags, org.apache.commons.compress.archivers.arj.LocalFileHeader$Methods, org.apache.commons.compress.archivers.arj.MainHeader, org.apache.commons.compress.archivers.arj.MainHeader$Flags, org.apache.commons.compress.archivers.arj.MainHeader$HostOS, org.apache.commons.compress.archivers.arj.package-info, org.apache.commons.compress.archivers.cpio.CpioArchiveEntry, org.apache.commons.compress.archivers.cpio.CpioArchiveInputStream, org.apache.commons.compress.archivers.cpio.CpioArchiveOutputStream, org.apache.commons.compress.archivers.cpio.CpioConstants, org.apache.commons.compress.archivers.cpio.CpioUtil, org.apache.commons.compress.archivers.cpio.package-info, org.apache.commons.compress.archivers.dump.Dirent, org.apache.commons.compress.archivers.dump.DumpArchiveConstants, org.apache.commons.compress.archivers.dump.DumpArchiveConstants$COMPRESSION_TYPE, org.apache.commons.compress.archivers.dump.DumpArchiveConstants$SEGMENT_TYPE, org.apache.commons.compress.archivers.dump.DumpArchiveEntry, org.apache.commons.compress.archivers.dump.DumpArchiveEntry$PERMISSION, org.apache.commons.compress.archivers.dump.DumpArchiveEntry$TYPE, org.apache.commons.compress.archivers.dump.DumpArchiveEntry$TapeSegmentHeader, org.apache.commons.compress.archivers.dump.DumpArchiveException, org.apache.commons.compress.archivers.dump.DumpArchiveInputStream, org.apache.commons.compress.archivers.dump.DumpArchiveSummary, org.apache.commons.compress.archivers.dump.DumpArchiveUtil, org.apache.commons.compress.archivers.dump.InvalidFormatException, org.apache.commons.compress.archivers.dump.ShortFileException, org.apache.commons.compress.archivers.dump.TapeInputStream, org.apache.commons.compress.archivers.dump.TapeInputStream$1, org.apache.commons.compress.archivers.dump.UnrecognizedFormatException, org.apache.commons.compress.archivers.dump.UnsupportedCompressionAlgorithmException, org.apache.commons.compress.archivers.dump.package-info, org.apache.commons.compress.archivers.examples.Archiver, org.apache.commons.compress.archivers.examples.Archiver$1, org.apache.commons.compress.archivers.examples.Archiver$ArchiverFileVisitor, org.apache.commons.compress.archivers.examples.CloseableConsumer, org.apache.commons.compress.archivers.examples.CloseableConsumerAdapter, org.apache.commons.compress.archivers.examples.Expander, org.apache.commons.compress.archivers.examples.Expander$ArchiveEntryBiConsumer, org.apache.commons.compress.archivers.examples.Expander$ArchiveEntrySupplier, org.apache.commons.compress.archivers.examples.package-info, org.apache.commons.compress.archivers.jar.JarArchiveEntry, org.apache.commons.compress.archivers.jar.JarArchiveInputStream, org.apache.commons.compress.archivers.jar.JarArchiveOutputStream, org.apache.commons.compress.archivers.jar.package-info, org.apache.commons.compress.archivers.package-info, org.apache.commons.compress.archivers.sevenz.AES256Options, org.apache.commons.compress.archivers.sevenz.AES256SHA256Decoder, org.apache.commons.compress.archivers.sevenz.AES256SHA256Decoder$1, org.apache.commons.compress.archivers.sevenz.AES256SHA256Decoder$AES256SHA256DecoderInputStream, org.apache.commons.compress.archivers.sevenz.AES256SHA256Decoder$AES256SHA256DecoderOutputStream, org.apache.commons.compress.archivers.sevenz.AbstractCoder, org.apache.commons.compress.archivers.sevenz.Archive, org.apache.commons.compress.archivers.sevenz.BindPair, org.apache.commons.compress.archivers.sevenz.BoundedSeekableByteChannelInputStream, org.apache.commons.compress.archivers.sevenz.CLI, org.apache.commons.compress.archivers.sevenz.CLI$1, org.apache.commons.compress.archivers.sevenz.CLI$Mode, org.apache.commons.compress.archivers.sevenz.CLI$Mode$1, org.apache.commons.compress.archivers.sevenz.Coder, org.apache.commons.compress.archivers.sevenz.Coders, org.apache.commons.compress.archivers.sevenz.Coders$1, org.apache.commons.compress.archivers.sevenz.Coders$BCJDecoder, org.apache.commons.compress.archivers.sevenz.Coders$BZIP2Decoder, org.apache.commons.compress.archivers.sevenz.Coders$CopyDecoder, org.apache.commons.compress.archivers.sevenz.Coders$Deflate64Decoder, org.apache.commons.compress.archivers.sevenz.Coders$DeflateDecoder, org.apache.commons.compress.archivers.sevenz.Coders$DeflateDecoder$DeflateDecoderInputStream, org.apache.commons.compress.archivers.sevenz.Coders$DeflateDecoder$DeflateDecoderOutputStream, org.apache.commons.compress.archivers.sevenz.DeltaDecoder, org.apache.commons.compress.archivers.sevenz.Folder, org.apache.commons.compress.archivers.sevenz.LZMA2Decoder, org.apache.commons.compress.archivers.sevenz.LZMADecoder, org.apache.commons.compress.archivers.sevenz.NID, org.apache.commons.compress.archivers.sevenz.SevenZArchiveEntry, org.apache.commons.compress.archivers.sevenz.SevenZFile, org.apache.commons.compress.archivers.sevenz.SevenZFile$1, org.apache.commons.compress.archivers.sevenz.SevenZFile$2, org.apache.commons.compress.archivers.sevenz.SevenZFile$ArchiveStatistics, org.apache.commons.compress.archivers.sevenz.SevenZFile$Builder, org.apache.commons.compress.archivers.sevenz.SevenZFileOptions, org.apache.commons.compress.archivers.sevenz.SevenZFileOptions$1, org.apache.commons.compress.archivers.sevenz.SevenZFileOptions$Builder, org.apache.commons.compress.archivers.sevenz.SevenZMethod, org.apache.commons.compress.archivers.sevenz.SevenZMethodConfiguration, org.apache.commons.compress.archivers.sevenz.SevenZOutputFile, org.apache.commons.compress.archivers.sevenz.SevenZOutputFile$1, org.apache.commons.compress.archivers.sevenz.SevenZOutputFile$OutputStreamWrapper, org.apache.commons.compress.archivers.sevenz.StartHeader, org.apache.commons.compress.archivers.sevenz.StreamMap, org.apache.commons.compress.archivers.sevenz.SubStreamsInfo, org.apache.commons.compress.archivers.sevenz.package-info, org.apache.commons.compress.archivers.tar.TarArchiveEntry, org.apache.commons.compress.archivers.tar.TarArchiveInputStream, org.apache.commons.compress.archivers.tar.TarArchiveOutputStream, org.apache.commons.compress.archivers.tar.TarArchiveSparseEntry, org.apache.commons.compress.archivers.tar.TarArchiveSparseZeroInputStream, org.apache.commons.compress.archivers.tar.TarArchiveStructSparse, org.apache.commons.compress.archivers.tar.TarConstants, org.apache.commons.compress.archivers.tar.TarFile, org.apache.commons.compress.archivers.tar.TarFile$BoundedTarEntryInputStream, org.apache.commons.compress.archivers.tar.TarGnuSparseKeys, org.apache.commons.compress.archivers.tar.TarUtils, org.apache.commons.compress.archivers.tar.TarUtils$1, org.apache.commons.compress.archivers.tar.package-info, org.apache.commons.compress.archivers.zip.AbstractUnicodeExtraField, org.apache.commons.compress.archivers.zip.AsiExtraField, org.apache.commons.compress.archivers.zip.BinaryTree, org.apache.commons.compress.archivers.zip.BitStream, org.apache.commons.compress.archivers.zip.CharsetAccessor, org.apache.commons.compress.archivers.zip.CircularBuffer, org.apache.commons.compress.archivers.zip.DefaultBackingStoreSupplier, org.apache.commons.compress.archivers.zip.ExplodingInputStream, org.apache.commons.compress.archivers.zip.FileRandomAccessOutputStream, org.apache.commons.compress.archivers.zip.InflaterInputStreamWithStatistics, org.apache.commons.compress.archivers.zip.JarMarker, org.apache.commons.compress.archivers.zip.NioZipEncoding, org.apache.commons.compress.archivers.zip.PKWareExtraHeader, org.apache.commons.compress.archivers.zip.PKWareExtraHeader$EncryptionAlgorithm, org.apache.commons.compress.archivers.zip.PKWareExtraHeader$HashAlgorithm, org.apache.commons.compress.archivers.zip.ParallelScatterZipCreator, org.apache.commons.compress.archivers.zip.ParallelScatterZipCreator$1, org.apache.commons.compress.archivers.zip.RandomAccessOutputStream, org.apache.commons.compress.archivers.zip.ResourceAlignmentExtraField, org.apache.commons.compress.archivers.zip.ScatterStatistics, org.apache.commons.compress.archivers.zip.ScatterZipOutputStream, org.apache.commons.compress.archivers.zip.ScatterZipOutputStream$CompressedEntry, org.apache.commons.compress.archivers.zip.ScatterZipOutputStream$ZipEntryWriter, org.apache.commons.compress.archivers.zip.SeekableChannelRandomAccessOutputStream, org.apache.commons.compress.archivers.zip.StreamCompressor, org.apache.commons.compress.archivers.zip.StreamCompressor$DataOutputCompressor, org.apache.commons.compress.archivers.zip.StreamCompressor$OutputStreamCompressor, org.apache.commons.compress.archivers.zip.StreamCompressor$ScatterGatherBackingStoreCompressor, org.apache.commons.compress.archivers.zip.StreamCompressor$SeekableByteChannelCompressor, org.apache.commons.compress.archivers.zip.UnicodeCommentExtraField, org.apache.commons.compress.archivers.zip.UnicodePathExtraField, org.apache.commons.compress.archivers.zip.UnixStat, org.apache.commons.compress.archivers.zip.UnshrinkingInputStream, org.apache.commons.compress.archivers.zip.UnsupportedZipFeatureException, org.apache.commons.compress.archivers.zip.UnsupportedZipFeatureException$Feature, org.apache.commons.compress.archivers.zip.X0014_X509Certificates, org.apache.commons.compress.archivers.zip.X0015_CertificateIdForFile, org.apache.commons.compress.archivers.zip.X0016_CertificateIdForCentralDirectory, org.apache.commons.compress.archivers.zip.X0017_StrongEncryptionHeader, org.apache.commons.compress.archivers.zip.X0019_EncryptionRecipientCertificateList, org.apache.commons.compress.archivers.zip.X7875_NewUnix, org.apache.commons.compress.archivers.zip.Zip64ExtendedInformationExtraField, org.apache.commons.compress.archivers.zip.Zip64Mode, org.apache.commons.compress.archivers.zip.Zip64RequiredException, org.apache.commons.compress.archivers.zip.ZipArchiveEntryPredicate, org.apache.commons.compress.archivers.zip.ZipArchiveEntryRequest, org.apache.commons.compress.archivers.zip.ZipArchiveEntryRequestSupplier, org.apache.commons.compress.archivers.zip.ZipArchiveInputStream, org.apache.commons.compress.archivers.zip.ZipArchiveInputStream$1, org.apache.commons.compress.archivers.zip.ZipArchiveInputStream$BoundCountInputStream, org.apache.commons.compress.archivers.zip.ZipArchiveInputStream$CurrentEntry, org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream, org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream$1, org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream$CurrentEntry, org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream$EntryMetaData, org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream$UnicodeExtraFieldPolicy, org.apache.commons.compress.archivers.zip.ZipConstants, org.apache.commons.compress.archivers.zip.ZipEncoding, org.apache.commons.compress.archivers.zip.ZipEncodingHelper, org.apache.commons.compress.archivers.zip.ZipFile, org.apache.commons.compress.archivers.zip.ZipFile$1, org.apache.commons.compress.archivers.zip.ZipFile$2, org.apache.commons.compress.archivers.zip.ZipFile$BoundedFileChannelInputStream, org.apache.commons.compress.archivers.zip.ZipFile$Builder, org.apache.commons.compress.archivers.zip.ZipFile$Entry, org.apache.commons.compress.archivers.zip.ZipFile$NameAndComment, org.apache.commons.compress.archivers.zip.ZipFile$StoredStatisticsStream, org.apache.commons.compress.archivers.zip.ZipIoUtil, org.apache.commons.compress.archivers.zip.ZipMethod, org.apache.commons.compress.archivers.zip.ZipSplitOutputStream, org.apache.commons.compress.archivers.zip.ZipSplitReadOnlySeekableByteChannel, org.apache.commons.compress.archivers.zip.ZipSplitReadOnlySeekableByteChannel$1, org.apache.commons.compress.archivers.zip.ZipSplitReadOnlySeekableByteChannel$ZipSplitSegmentComparator, org.apache.commons.compress.archivers.zip.ZipUtil, org.apache.commons.compress.archivers.zip.package-info, org.apache.commons.compress.changes.Change, org.apache.commons.compress.changes.Change$ChangeType, org.apache.commons.compress.changes.ChangeSet, org.apache.commons.compress.changes.ChangeSetPerformer, org.apache.commons.compress.changes.ChangeSetPerformer$ArchiveEntryIterator, org.apache.commons.compress.changes.ChangeSetPerformer$ArchiveInputStreamIterator, org.apache.commons.compress.changes.ChangeSetPerformer$ZipFileIterator, org.apache.commons.compress.changes.ChangeSetResults, org.apache.commons.compress.changes.package-info, org.apache.commons.compress.compressors.CompressorException, org.apache.commons.compress.compressors.CompressorInputStream, org.apache.commons.compress.compressors.CompressorOutputStream, org.apache.commons.compress.compressors.CompressorStreamFactory, org.apache.commons.compress.compressors.CompressorStreamProvider, org.apache.commons.compress.compressors.FileNameUtil, org.apache.commons.compress.compressors.brotli.BrotliCompressorInputStream, org.apache.commons.compress.compressors.brotli.BrotliUtils, org.apache.commons.compress.compressors.brotli.BrotliUtils$CachedAvailability, org.apache.commons.compress.compressors.brotli.package-info, org.apache.commons.compress.compressors.bzip2.BZip2CompressorInputStream, org.apache.commons.compress.compressors.bzip2.BZip2CompressorInputStream$Data, org.apache.commons.compress.compressors.bzip2.BZip2CompressorOutputStream, org.apache.commons.compress.compressors.bzip2.BZip2CompressorOutputStream$Data, org.apache.commons.compress.compressors.bzip2.BZip2Constants, org.apache.commons.compress.compressors.bzip2.BZip2Utils, org.apache.commons.compress.compressors.bzip2.BlockSort, org.apache.commons.compress.compressors.bzip2.CRC, org.apache.commons.compress.compressors.bzip2.Rand, org.apache.commons.compress.compressors.bzip2.package-info, org.apache.commons.compress.compressors.deflate.DeflateCompressorInputStream, org.apache.commons.compress.compressors.deflate.DeflateCompressorOutputStream, org.apache.commons.compress.compressors.deflate.DeflateParameters, org.apache.commons.compress.compressors.deflate.package-info, org.apache.commons.compress.compressors.deflate64.Deflate64CompressorInputStream, org.apache.commons.compress.compressors.deflate64.HuffmanDecoder, org.apache.commons.compress.compressors.deflate64.HuffmanDecoder$1, org.apache.commons.compress.compressors.deflate64.HuffmanDecoder$BinaryTreeNode, org.apache.commons.compress.compressors.deflate64.HuffmanDecoder$DecoderState, org.apache.commons.compress.compressors.deflate64.HuffmanDecoder$DecodingMemory, org.apache.commons.compress.compressors.deflate64.HuffmanDecoder$HuffmanCodes, org.apache.commons.compress.compressors.deflate64.HuffmanDecoder$InitialState, org.apache.commons.compress.compressors.deflate64.HuffmanDecoder$UncompressedState, org.apache.commons.compress.compressors.deflate64.HuffmanState, org.apache.commons.compress.compressors.deflate64.package-info, org.apache.commons.compress.compressors.gzip.ExtraField, org.apache.commons.compress.compressors.gzip.ExtraField$SubField, org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream, org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream$1, org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream$Builder, org.apache.commons.compress.compressors.gzip.GzipCompressorOutputStream, org.apache.commons.compress.compressors.gzip.GzipParameters, org.apache.commons.compress.compressors.gzip.GzipParameters$OS, org.apache.commons.compress.compressors.gzip.GzipUtils, org.apache.commons.compress.compressors.gzip.package-info, org.apache.commons.compress.compressors.lz4.BlockLZ4CompressorInputStream, org.apache.commons.compress.compressors.lz4.BlockLZ4CompressorInputStream$State, org.apache.commons.compress.compressors.lz4.BlockLZ4CompressorOutputStream, org.apache.commons.compress.compressors.lz4.BlockLZ4CompressorOutputStream$1, org.apache.commons.compress.compressors.lz4.BlockLZ4CompressorOutputStream$Pair, org.apache.commons.compress.compressors.lz4.FramedLZ4CompressorInputStream, org.apache.commons.compress.compressors.lz4.FramedLZ4CompressorOutputStream, org.apache.commons.compress.compressors.lz4.FramedLZ4CompressorOutputStream$BlockSize, org.apache.commons.compress.compressors.lz4.FramedLZ4CompressorOutputStream$Parameters, org.apache.commons.compress.compressors.lz4.XXHash32, org.apache.commons.compress.compressors.lz4.package-info, org.apache.commons.compress.compressors.lz77support.AbstractLZ77CompressorInputStream, org.apache.commons.compress.compressors.lz77support.LZ77Compressor, org.apache.commons.compress.compressors.lz77support.LZ77Compressor$AbstractReference, org.apache.commons.compress.compressors.lz77support.LZ77Compressor$BackReference, org.apache.commons.compress.compressors.lz77support.LZ77Compressor$Block, org.apache.commons.compress.compressors.lz77support.LZ77Compressor$Block$BlockType, org.apache.commons.compress.compressors.lz77support.LZ77Compressor$Callback, org.apache.commons.compress.compressors.lz77support.LZ77Compressor$EOD, org.apache.commons.compress.compressors.lz77support.LZ77Compressor$LiteralBlock, org.apache.commons.compress.compressors.lz77support.Parameters, org.apache.commons.compress.compressors.lz77support.Parameters$1, org.apache.commons.compress.compressors.lz77support.Parameters$Builder, org.apache.commons.compress.compressors.lz77support.package-info, org.apache.commons.compress.compressors.lzma.LZMACompressorInputStream, org.apache.commons.compress.compressors.lzma.LZMACompressorInputStream$1, org.apache.commons.compress.compressors.lzma.LZMACompressorInputStream$Builder, org.apache.commons.compress.compressors.lzma.LZMACompressorOutputStream, org.apache.commons.compress.compressors.lzma.LZMACompressorOutputStream$1, org.apache.commons.compress.compressors.lzma.LZMACompressorOutputStream$Builder, org.apache.commons.compress.compressors.lzma.LZMAUtils, org.apache.commons.compress.compressors.lzma.LZMAUtils$CachedAvailability, org.apache.commons.compress.compressors.lzma.package-info, org.apache.commons.compress.compressors.lzw.LZWInputStream, org.apache.commons.compress.compressors.lzw.package-info, org.apache.commons.compress.compressors.pack200.AbstractStreamBridge, org.apache.commons.compress.compressors.pack200.InMemoryCachingStreamBridge, org.apache.commons.compress.compressors.pack200.Pack200CompressorInputStream, org.apache.commons.compress.compressors.pack200.Pack200CompressorOutputStream, org.apache.commons.compress.compressors.pack200.Pack200Strategy, org.apache.commons.compress.compressors.pack200.Pack200Strategy$1, org.apache.commons.compress.compressors.pack200.Pack200Strategy$2, org.apache.commons.compress.compressors.pack200.Pack200Utils, org.apache.commons.compress.compressors.pack200.TempFileCachingStreamBridge, org.apache.commons.compress.compressors.pack200.TempFileCachingStreamBridge$1, org.apache.commons.compress.compressors.pack200.package-info, org.apache.commons.compress.compressors.package-info, org.apache.commons.compress.compressors.snappy.FramedSnappyCompressorInputStream, org.apache.commons.compress.compressors.snappy.FramedSnappyCompressorOutputStream, org.apache.commons.compress.compressors.snappy.FramedSnappyDialect, org.apache.commons.compress.compressors.snappy.SnappyCompressorInputStream, org.apache.commons.compress.compressors.snappy.SnappyCompressorInputStream$State, org.apache.commons.compress.compressors.snappy.SnappyCompressorOutputStream, org.apache.commons.compress.compressors.snappy.SnappyCompressorOutputStream$1, org.apache.commons.compress.compressors.snappy.package-info, org.apache.commons.compress.compressors.xz.XZCompressorInputStream, org.apache.commons.compress.compressors.xz.XZCompressorInputStream$1, org.apache.commons.compress.compressors.xz.XZCompressorInputStream$Builder, org.apache.commons.compress.compressors.xz.XZCompressorOutputStream, org.apache.commons.compress.compressors.xz.XZCompressorOutputStream$1, org.apache.commons.compress.compressors.xz.XZCompressorOutputStream$Builder, org.apache.commons.compress.compressors.xz.XZUtils, org.apache.commons.compress.compressors.xz.XZUtils$CachedAvailability, org.apache.commons.compress.compressors.xz.package-info, org.apache.commons.compress.compressors.z.ZCompressorInputStream, org.apache.commons.compress.compressors.z.package-info, org.apache.commons.compress.compressors.zstandard.ZstdCompressorInputStream, org.apache.commons.compress.compressors.zstandard.ZstdCompressorOutputStream, org.apache.commons.compress.compressors.zstandard.ZstdCompressorOutputStream$1, org.apache.commons.compress.compressors.zstandard.ZstdCompressorOutputStream$Builder, org.apache.commons.compress.compressors.zstandard.ZstdConstants, org.apache.commons.compress.compressors.zstandard.ZstdUtils, org.apache.commons.compress.compressors.zstandard.ZstdUtils$CachedAvailability, org.apache.commons.compress.compressors.zstandard.package-info, org.apache.commons.compress.harmony.archive.internal.nls.Messages, org.apache.commons.compress.harmony.archive.internal.nls.package-info, org.apache.commons.compress.harmony.pack200.Archive, org.apache.commons.compress.harmony.pack200.Archive$PackingFile, org.apache.commons.compress.harmony.pack200.Archive$SegmentUnit, org.apache.commons.compress.harmony.pack200.AttributeDefinitionBands, org.apache.commons.compress.harmony.pack200.AttributeDefinitionBands$AttributeDefinition, org.apache.commons.compress.harmony.pack200.BHSDCodec, org.apache.commons.compress.harmony.pack200.BandSet, org.apache.commons.compress.harmony.pack200.BandSet$BandAnalysisResults, org.apache.commons.compress.harmony.pack200.BandSet$BandData, org.apache.commons.compress.harmony.pack200.BcBands, org.apache.commons.compress.harmony.pack200.CPClass, org.apache.commons.compress.harmony.pack200.CPConstant, org.apache.commons.compress.harmony.pack200.CPDouble, org.apache.commons.compress.harmony.pack200.CPFloat, org.apache.commons.compress.harmony.pack200.CPInt, org.apache.commons.compress.harmony.pack200.CPLong, org.apache.commons.compress.harmony.pack200.CPMethodOrField, org.apache.commons.compress.harmony.pack200.CPNameAndType, org.apache.commons.compress.harmony.pack200.CPSignature, org.apache.commons.compress.harmony.pack200.CPString, org.apache.commons.compress.harmony.pack200.CPUTF8, org.apache.commons.compress.harmony.pack200.CanonicalCodecFamilies, org.apache.commons.compress.harmony.pack200.ClassBands, org.apache.commons.compress.harmony.pack200.ClassBands$TempParamAnnotation, org.apache.commons.compress.harmony.pack200.Codec, org.apache.commons.compress.harmony.pack200.CodecEncoding, org.apache.commons.compress.harmony.pack200.ConstantPoolEntry, org.apache.commons.compress.harmony.pack200.CpBands, org.apache.commons.compress.harmony.pack200.FileBands, org.apache.commons.compress.harmony.pack200.IcBands, org.apache.commons.compress.harmony.pack200.IcBands$IcTuple, org.apache.commons.compress.harmony.pack200.IntList, org.apache.commons.compress.harmony.pack200.MetadataBandGroup, org.apache.commons.compress.harmony.pack200.NewAttribute, org.apache.commons.compress.harmony.pack200.NewAttribute$ErrorAttribute, org.apache.commons.compress.harmony.pack200.NewAttribute$PassAttribute, org.apache.commons.compress.harmony.pack200.NewAttribute$StripAttribute, org.apache.commons.compress.harmony.pack200.NewAttributeBands, org.apache.commons.compress.harmony.pack200.NewAttributeBands$AttributeLayoutElement, org.apache.commons.compress.harmony.pack200.NewAttributeBands$Call, org.apache.commons.compress.harmony.pack200.NewAttributeBands$Callable, org.apache.commons.compress.harmony.pack200.NewAttributeBands$Integral, org.apache.commons.compress.harmony.pack200.NewAttributeBands$LayoutElement, org.apache.commons.compress.harmony.pack200.NewAttributeBands$Reference, org.apache.commons.compress.harmony.pack200.NewAttributeBands$Replication, org.apache.commons.compress.harmony.pack200.NewAttributeBands$Union, org.apache.commons.compress.harmony.pack200.NewAttributeBands$UnionCase, org.apache.commons.compress.harmony.pack200.Pack200Adapter, org.apache.commons.compress.harmony.pack200.Pack200ClassReader, org.apache.commons.compress.harmony.pack200.Pack200Exception, org.apache.commons.compress.harmony.pack200.Pack200PackerAdapter, org.apache.commons.compress.harmony.pack200.PackingOptions, org.apache.commons.compress.harmony.pack200.PackingUtils, org.apache.commons.compress.harmony.pack200.PackingUtils$PackingLogger, org.apache.commons.compress.harmony.pack200.PopulationCodec, org.apache.commons.compress.harmony.pack200.RunCodec, org.apache.commons.compress.harmony.pack200.Segment, org.apache.commons.compress.harmony.pack200.Segment$ArrayVisitor, org.apache.commons.compress.harmony.pack200.Segment$PassException, org.apache.commons.compress.harmony.pack200.Segment$SegmentAnnotationVisitor, org.apache.commons.compress.harmony.pack200.Segment$SegmentAnnotationVisitor$1, org.apache.commons.compress.harmony.pack200.Segment$SegmentFieldVisitor, org.apache.commons.compress.harmony.pack200.Segment$SegmentMethodVisitor, org.apache.commons.compress.harmony.pack200.SegmentHeader, org.apache.commons.compress.harmony.pack200.SegmentHeader$1, org.apache.commons.compress.harmony.pack200.SegmentHeader$Counter, org.apache.commons.compress.harmony.pack200.package-info, org.apache.commons.compress.harmony.package-info, org.apache.commons.compress.harmony.unpack200.Archive, org.apache.commons.compress.harmony.unpack200.AttrDefinitionBands, org.apache.commons.compress.harmony.unpack200.AttributeLayout, org.apache.commons.compress.harmony.unpack200.AttributeLayoutMap, org.apache.commons.compress.harmony.unpack200.BandSet, org.apache.commons.compress.harmony.unpack200.BcBands, org.apache.commons.compress.harmony.unpack200.ClassBands, org.apache.commons.compress.harmony.unpack200.CpBands, org.apache.commons.compress.harmony.unpack200.FileBands, org.apache.commons.compress.harmony.unpack200.IMatcher, org.apache.commons.compress.harmony.unpack200.IcBands, org.apache.commons.compress.harmony.unpack200.IcTuple, org.apache.commons.compress.harmony.unpack200.MetadataBandGroup, org.apache.commons.compress.harmony.unpack200.NewAttributeBands, org.apache.commons.compress.harmony.unpack200.NewAttributeBands$1, org.apache.commons.compress.harmony.unpack200.NewAttributeBands$AttributeLayoutElement, org.apache.commons.compress.harmony.unpack200.NewAttributeBands$Call, org.apache.commons.compress.harmony.unpack200.NewAttributeBands$Callable, org.apache.commons.compress.harmony.unpack200.NewAttributeBands$Integral, org.apache.commons.compress.harmony.unpack200.NewAttributeBands$LayoutElement, org.apache.commons.compress.harmony.unpack200.NewAttributeBands$Reference, org.apache.commons.compress.harmony.unpack200.NewAttributeBands$Replication, org.apache.commons.compress.harmony.unpack200.NewAttributeBands$Union, org.apache.commons.compress.harmony.unpack200.NewAttributeBands$UnionCase, org.apache.commons.compress.harmony.unpack200.Pack200UnpackerAdapter, org.apache.commons.compress.harmony.unpack200.Segment, org.apache.commons.compress.harmony.unpack200.SegmentConstantPool, org.apache.commons.compress.harmony.unpack200.SegmentConstantPoolArrayCache, org.apache.commons.compress.harmony.unpack200.SegmentConstantPoolArrayCache$CachedArray, org.apache.commons.compress.harmony.unpack200.SegmentHeader, org.apache.commons.compress.harmony.unpack200.SegmentOptions, org.apache.commons.compress.harmony.unpack200.SegmentUtils, org.apache.commons.compress.harmony.unpack200.bytecode.AnnotationDefaultAttribute, org.apache.commons.compress.harmony.unpack200.bytecode.AnnotationsAttribute, org.apache.commons.compress.harmony.unpack200.bytecode.AnnotationsAttribute$Annotation, org.apache.commons.compress.harmony.unpack200.bytecode.AnnotationsAttribute$ElementValue, org.apache.commons.compress.harmony.unpack200.bytecode.Attribute, org.apache.commons.compress.harmony.unpack200.bytecode.BCIRenumberedAttribute, org.apache.commons.compress.harmony.unpack200.bytecode.ByteCode, org.apache.commons.compress.harmony.unpack200.bytecode.CPClass, org.apache.commons.compress.harmony.unpack200.bytecode.CPConstant, org.apache.commons.compress.harmony.unpack200.bytecode.CPConstantNumber, org.apache.commons.compress.harmony.unpack200.bytecode.CPDouble, org.apache.commons.compress.harmony.unpack200.bytecode.CPField, org.apache.commons.compress.harmony.unpack200.bytecode.CPFieldRef, org.apache.commons.compress.harmony.unpack200.bytecode.CPFloat, org.apache.commons.compress.harmony.unpack200.bytecode.CPInteger, org.apache.commons.compress.harmony.unpack200.bytecode.CPInterfaceMethodRef, org.apache.commons.compress.harmony.unpack200.bytecode.CPLong, org.apache.commons.compress.harmony.unpack200.bytecode.CPMember, org.apache.commons.compress.harmony.unpack200.bytecode.CPMethod, org.apache.commons.compress.harmony.unpack200.bytecode.CPMethodRef, org.apache.commons.compress.harmony.unpack200.bytecode.CPNameAndType, org.apache.commons.compress.harmony.unpack200.bytecode.CPRef, org.apache.commons.compress.harmony.unpack200.bytecode.CPString, org.apache.commons.compress.harmony.unpack200.bytecode.CPUTF8, org.apache.commons.compress.harmony.unpack200.bytecode.ClassConstantPool, org.apache.commons.compress.harmony.unpack200.bytecode.ClassFile, org.apache.commons.compress.harmony.unpack200.bytecode.ClassFileEntry, org.apache.commons.compress.harmony.unpack200.bytecode.CodeAttribute, org.apache.commons.compress.harmony.unpack200.bytecode.ConstantPoolEntry, org.apache.commons.compress.harmony.unpack200.bytecode.ConstantValueAttribute, org.apache.commons.compress.harmony.unpack200.bytecode.DeprecatedAttribute, org.apache.commons.compress.harmony.unpack200.bytecode.EnclosingMethodAttribute, org.apache.commons.compress.harmony.unpack200.bytecode.ExceptionTableEntry, org.apache.commons.compress.harmony.unpack200.bytecode.ExceptionsAttribute, org.apache.commons.compress.harmony.unpack200.bytecode.InnerClassesAttribute, org.apache.commons.compress.harmony.unpack200.bytecode.InnerClassesAttribute$InnerClassesEntry, org.apache.commons.compress.harmony.unpack200.bytecode.LineNumberTableAttribute, org.apache.commons.compress.harmony.unpack200.bytecode.LocalVariableTableAttribute, org.apache.commons.compress.harmony.unpack200.bytecode.LocalVariableTypeTableAttribute, org.apache.commons.compress.harmony.unpack200.bytecode.NewAttribute, org.apache.commons.compress.harmony.unpack200.bytecode.NewAttribute$1, org.apache.commons.compress.harmony.unpack200.bytecode.NewAttribute$AbstractBcValue, org.apache.commons.compress.harmony.unpack200.bytecode.NewAttribute$BCIndex, org.apache.commons.compress.harmony.unpack200.bytecode.NewAttribute$BCLength, org.apache.commons.compress.harmony.unpack200.bytecode.NewAttribute$BCOffset, org.apache.commons.compress.harmony.unpack200.bytecode.OperandManager, org.apache.commons.compress.harmony.unpack200.bytecode.RuntimeVisibleorInvisibleAnnotationsAttribute, org.apache.commons.compress.harmony.unpack200.bytecode.RuntimeVisibleorInvisibleParameterAnnotationsAttribute, org.apache.commons.compress.harmony.unpack200.bytecode.RuntimeVisibleorInvisibleParameterAnnotationsAttribute$ParameterAnnotation, org.apache.commons.compress.harmony.unpack200.bytecode.SignatureAttribute, org.apache.commons.compress.harmony.unpack200.bytecode.SourceFileAttribute, org.apache.commons.compress.harmony.unpack200.bytecode.forms.ByteCodeForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.ByteForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.ClassRefForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.ClassSpecificReferenceForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.DoubleForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.FieldRefForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.FloatRefForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.IMethodRefForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.IincForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.InitMethodReferenceForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.IntRefForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.LabelForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.LocalForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.LongForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.LookupSwitchForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.MethodRefForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.MultiANewArrayForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.NarrowClassRefForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.NewClassRefForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.NewInitMethodRefForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.NoArgumentForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.ReferenceForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.ShortForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.SingleByteReferenceForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.StringRefForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.SuperFieldRefForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.SuperInitMethodRefForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.SuperMethodRefForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.SwitchForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.TableSwitchForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.ThisFieldRefForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.ThisInitMethodRefForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.ThisMethodRefForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.VariableInstructionForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.WideForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.package-info, org.apache.commons.compress.harmony.unpack200.bytecode.package-info, org.apache.commons.compress.harmony.unpack200.package-info, org.apache.commons.compress.java.util.jar.Pack200, org.apache.commons.compress.java.util.jar.Pack200$Packer, org.apache.commons.compress.java.util.jar.Pack200$Unpacker, org.apache.commons.compress.java.util.jar.package-info, org.apache.commons.compress.package-info, org.apache.commons.compress.parallel.FileBasedScatterGatherBackingStore, org.apache.commons.compress.parallel.InputStreamSupplier, org.apache.commons.compress.parallel.ScatterGatherBackingStore, org.apache.commons.compress.parallel.ScatterGatherBackingStoreSupplier, org.apache.commons.compress.parallel.package-info, org.apache.commons.compress.utils.ArchiveUtils, org.apache.commons.compress.utils.BitInputStream, org.apache.commons.compress.utils.BoundedArchiveInputStream, org.apache.commons.compress.utils.BoundedInputStream, org.apache.commons.compress.utils.BoundedSeekableByteChannelInputStream, org.apache.commons.compress.utils.ByteUtils, org.apache.commons.compress.utils.ByteUtils$ByteConsumer, org.apache.commons.compress.utils.ByteUtils$ByteSupplier, org.apache.commons.compress.utils.ByteUtils$InputStreamByteSupplier, org.apache.commons.compress.utils.ByteUtils$OutputStreamByteConsumer, org.apache.commons.compress.utils.CRC32VerifyingInputStream, org.apache.commons.compress.utils.CharsetNames, org.apache.commons.compress.utils.Charsets, org.apache.commons.compress.utils.ChecksumCalculatingInputStream, org.apache.commons.compress.utils.ChecksumVerifyingInputStream, org.apache.commons.compress.utils.CloseShieldFilterInputStream, org.apache.commons.compress.utils.CountingInputStream, org.apache.commons.compress.utils.CountingOutputStream, org.apache.commons.compress.utils.ExactMath, org.apache.commons.compress.utils.FileNameUtils, org.apache.commons.compress.utils.FixedLengthBlockOutputStream, org.apache.commons.compress.utils.FixedLengthBlockOutputStream$1, org.apache.commons.compress.utils.FixedLengthBlockOutputStream$BufferAtATimeOutputChannel, org.apache.commons.compress.utils.FlushShieldFilterOutputStream, org.apache.commons.compress.utils.IOUtils, org.apache.commons.compress.utils.InputStreamStatistics, org.apache.commons.compress.utils.Iterators, org.apache.commons.compress.utils.Lists, org.apache.commons.compress.utils.MultiReadOnlySeekableByteChannel, org.apache.commons.compress.utils.OsgiUtils, org.apache.commons.compress.utils.ParsingUtils, org.apache.commons.compress.utils.SeekableInMemoryByteChannel, org.apache.commons.compress.utils.ServiceLoaderIterator, org.apache.commons.compress.utils.Sets, org.apache.commons.compress.utils.SkipShieldingInputStream, org.apache.commons.compress.utils.TimeUtils, org.apache.commons.compress.utils.package-info]
[INFO]   - org.apache.commons:commons-lang3:jar:3.18.0 (compile): 413 classes, unknown
[INFO]     Would remove classes: [org.apache.commons.lang3.AnnotationUtils, org.apache.commons.lang3.AnnotationUtils$1, org.apache.commons.lang3.AppendableJoiner, org.apache.commons.lang3.AppendableJoiner$1, org.apache.commons.lang3.AppendableJoiner$Builder, org.apache.commons.lang3.ArchUtils, org.apache.commons.lang3.ArrayFill, org.apache.commons.lang3.ArraySorter, org.apache.commons.lang3.ArrayUtils, org.apache.commons.lang3.BitField, org.apache.commons.lang3.BooleanUtils, org.apache.commons.lang3.CachedRandomBits, org.apache.commons.lang3.CharEncoding, org.apache.commons.lang3.CharRange, org.apache.commons.lang3.CharRange$1, org.apache.commons.lang3.CharRange$CharacterIterator, org.apache.commons.lang3.CharSequenceUtils, org.apache.commons.lang3.CharSet, org.apache.commons.lang3.CharSetUtils, org.apache.commons.lang3.CharUtils, org.apache.commons.lang3.Charsets, org.apache.commons.lang3.ClassLoaderUtils, org.apache.commons.lang3.ClassPathUtils, org.apache.commons.lang3.ClassUtils, org.apache.commons.lang3.ClassUtils$1, org.apache.commons.lang3.ClassUtils$2, org.apache.commons.lang3.ClassUtils$Interfaces, org.apache.commons.lang3.Conversion, org.apache.commons.lang3.DoubleRange, org.apache.commons.lang3.EnumUtils, org.apache.commons.lang3.Functions, org.apache.commons.lang3.Functions$FailableBiConsumer, org.apache.commons.lang3.Functions$FailableBiFunction, org.apache.commons.lang3.Functions$FailableBiPredicate, org.apache.commons.lang3.Functions$FailableCallable, org.apache.commons.lang3.Functions$FailableConsumer, org.apache.commons.lang3.Functions$FailableFunction, org.apache.commons.lang3.Functions$FailablePredicate, org.apache.commons.lang3.Functions$FailableRunnable, org.apache.commons.lang3.Functions$FailableSupplier, org.apache.commons.lang3.IntegerRange, org.apache.commons.lang3.JavaVersion, org.apache.commons.lang3.LocaleUtils, org.apache.commons.lang3.LocaleUtils$SyncAvoid, org.apache.commons.lang3.LongRange, org.apache.commons.lang3.NotImplementedException, org.apache.commons.lang3.NumberRange, org.apache.commons.lang3.ObjectUtils, org.apache.commons.lang3.ObjectUtils$Null, org.apache.commons.lang3.RandomStringUtils, org.apache.commons.lang3.RandomUtils, org.apache.commons.lang3.Range, org.apache.commons.lang3.Range$ComparableComparator, org.apache.commons.lang3.RegExUtils, org.apache.commons.lang3.RuntimeEnvironment, org.apache.commons.lang3.SerializationException, org.apache.commons.lang3.SerializationUtils, org.apache.commons.lang3.SerializationUtils$ClassLoaderAwareObjectInputStream, org.apache.commons.lang3.Streams, org.apache.commons.lang3.Streams$ArrayCollector, org.apache.commons.lang3.Streams$FailableStream, org.apache.commons.lang3.StringEscapeUtils, org.apache.commons.lang3.StringEscapeUtils$1, org.apache.commons.lang3.StringEscapeUtils$CsvEscaper, org.apache.commons.lang3.StringEscapeUtils$CsvUnescaper, org.apache.commons.lang3.StringUtils, org.apache.commons.lang3.Strings, org.apache.commons.lang3.Strings$1, org.apache.commons.lang3.Strings$Builder, org.apache.commons.lang3.Strings$CiStrings, org.apache.commons.lang3.Strings$CsStrings, org.apache.commons.lang3.SystemProperties, org.apache.commons.lang3.SystemUtils, org.apache.commons.lang3.ThreadUtils, org.apache.commons.lang3.ThreadUtils$1, org.apache.commons.lang3.ThreadUtils$AlwaysTruePredicate, org.apache.commons.lang3.ThreadUtils$NamePredicate, org.apache.commons.lang3.ThreadUtils$ThreadGroupPredicate, org.apache.commons.lang3.ThreadUtils$ThreadIdPredicate, org.apache.commons.lang3.ThreadUtils$ThreadPredicate, org.apache.commons.lang3.Validate, org.apache.commons.lang3.arch.Processor, org.apache.commons.lang3.arch.Processor$Arch, org.apache.commons.lang3.arch.Processor$Type, org.apache.commons.lang3.arch.package-info, org.apache.commons.lang3.builder.AbstractSupplier, org.apache.commons.lang3.builder.Builder, org.apache.commons.lang3.builder.CompareToBuilder, org.apache.commons.lang3.builder.Diff, org.apache.commons.lang3.builder.DiffBuilder, org.apache.commons.lang3.builder.DiffBuilder$1, org.apache.commons.lang3.builder.DiffBuilder$Builder, org.apache.commons.lang3.builder.DiffBuilder$SDiff, org.apache.commons.lang3.builder.DiffBuilder$SerializableSupplier, org.apache.commons.lang3.builder.DiffExclude, org.apache.commons.lang3.builder.DiffResult, org.apache.commons.lang3.builder.Diffable, org.apache.commons.lang3.builder.EqualsBuilder, org.apache.commons.lang3.builder.EqualsExclude, org.apache.commons.lang3.builder.HashCodeBuilder, org.apache.commons.lang3.builder.HashCodeExclude, org.apache.commons.lang3.builder.IDKey, org.apache.commons.lang3.builder.MultilineRecursiveToStringStyle, org.apache.commons.lang3.builder.RecursiveToStringStyle, org.apache.commons.lang3.builder.Reflection, org.apache.commons.lang3.builder.ReflectionDiffBuilder, org.apache.commons.lang3.builder.ReflectionDiffBuilder$1, org.apache.commons.lang3.builder.ReflectionDiffBuilder$Builder, org.apache.commons.lang3.builder.ReflectionToStringBuilder, org.apache.commons.lang3.builder.StandardToStringStyle, org.apache.commons.lang3.builder.ToStringBuilder, org.apache.commons.lang3.builder.ToStringExclude, org.apache.commons.lang3.builder.ToStringStyle, org.apache.commons.lang3.builder.ToStringStyle$DefaultToStringStyle, org.apache.commons.lang3.builder.ToStringStyle$JsonToStringStyle, org.apache.commons.lang3.builder.ToStringStyle$MultiLineToStringStyle, org.apache.commons.lang3.builder.ToStringStyle$NoClassNameToStringStyle, org.apache.commons.lang3.builder.ToStringStyle$NoFieldNameToStringStyle, org.apache.commons.lang3.builder.ToStringStyle$ShortPrefixToStringStyle, org.apache.commons.lang3.builder.ToStringStyle$SimpleToStringStyle, org.apache.commons.lang3.builder.ToStringSummary, org.apache.commons.lang3.builder.package-info, org.apache.commons.lang3.compare.ComparableUtils, org.apache.commons.lang3.compare.ComparableUtils$1, org.apache.commons.lang3.compare.ComparableUtils$ComparableCheckBuilder, org.apache.commons.lang3.compare.ObjectToStringComparator, org.apache.commons.lang3.compare.package-info, org.apache.commons.lang3.concurrent.AbstractCircuitBreaker, org.apache.commons.lang3.concurrent.AbstractCircuitBreaker$1, org.apache.commons.lang3.concurrent.AbstractCircuitBreaker$State, org.apache.commons.lang3.concurrent.AbstractCircuitBreaker$State$1, org.apache.commons.lang3.concurrent.AbstractCircuitBreaker$State$2, org.apache.commons.lang3.concurrent.AbstractConcurrentInitializer, org.apache.commons.lang3.concurrent.AbstractConcurrentInitializer$AbstractBuilder, org.apache.commons.lang3.concurrent.AbstractFutureProxy, org.apache.commons.lang3.concurrent.AtomicInitializer, org.apache.commons.lang3.concurrent.AtomicInitializer$1, org.apache.commons.lang3.concurrent.AtomicInitializer$Builder, org.apache.commons.lang3.concurrent.AtomicSafeInitializer, org.apache.commons.lang3.concurrent.AtomicSafeInitializer$1, org.apache.commons.lang3.concurrent.AtomicSafeInitializer$Builder, org.apache.commons.lang3.concurrent.BackgroundInitializer, org.apache.commons.lang3.concurrent.BackgroundInitializer$1, org.apache.commons.lang3.concurrent.BackgroundInitializer$Builder, org.apache.commons.lang3.concurrent.BackgroundInitializer$InitializationTask, org.apache.commons.lang3.concurrent.BasicThreadFactory, org.apache.commons.lang3.concurrent.BasicThreadFactory$1, org.apache.commons.lang3.concurrent.BasicThreadFactory$Builder, org.apache.commons.lang3.concurrent.CallableBackgroundInitializer, org.apache.commons.lang3.concurrent.CircuitBreaker, org.apache.commons.lang3.concurrent.CircuitBreakingException, org.apache.commons.lang3.concurrent.Computable, org.apache.commons.lang3.concurrent.ConcurrentException, org.apache.commons.lang3.concurrent.ConcurrentInitializer, org.apache.commons.lang3.concurrent.ConcurrentRuntimeException, org.apache.commons.lang3.concurrent.ConcurrentUtils, org.apache.commons.lang3.concurrent.ConcurrentUtils$ConstantFuture, org.apache.commons.lang3.concurrent.ConstantInitializer, org.apache.commons.lang3.concurrent.EventCountCircuitBreaker, org.apache.commons.lang3.concurrent.EventCountCircuitBreaker$1, org.apache.commons.lang3.concurrent.EventCountCircuitBreaker$AbstractStateStrategy, org.apache.commons.lang3.concurrent.EventCountCircuitBreaker$CheckIntervalData, org.apache.commons.lang3.concurrent.EventCountCircuitBreaker$StateStrategyClosed, org.apache.commons.lang3.concurrent.EventCountCircuitBreaker$StateStrategyOpen, org.apache.commons.lang3.concurrent.FutureTasks, org.apache.commons.lang3.concurrent.LazyInitializer, org.apache.commons.lang3.concurrent.LazyInitializer$1, org.apache.commons.lang3.concurrent.LazyInitializer$Builder, org.apache.commons.lang3.concurrent.Memoizer, org.apache.commons.lang3.concurrent.MultiBackgroundInitializer, org.apache.commons.lang3.concurrent.MultiBackgroundInitializer$1, org.apache.commons.lang3.concurrent.MultiBackgroundInitializer$MultiBackgroundInitializerResults, org.apache.commons.lang3.concurrent.ThresholdCircuitBreaker, org.apache.commons.lang3.concurrent.TimedSemaphore, org.apache.commons.lang3.concurrent.UncheckedExecutionException, org.apache.commons.lang3.concurrent.UncheckedFuture, org.apache.commons.lang3.concurrent.UncheckedFutureImpl, org.apache.commons.lang3.concurrent.UncheckedTimeoutException, org.apache.commons.lang3.concurrent.locks.LockingVisitors, org.apache.commons.lang3.concurrent.locks.LockingVisitors$1, org.apache.commons.lang3.concurrent.locks.LockingVisitors$LockVisitor, org.apache.commons.lang3.concurrent.locks.LockingVisitors$LockVisitor$LVBuilder, org.apache.commons.lang3.concurrent.locks.LockingVisitors$ReadWriteLockVisitor, org.apache.commons.lang3.concurrent.locks.LockingVisitors$ReadWriteLockVisitor$Builder, org.apache.commons.lang3.concurrent.locks.LockingVisitors$ReentrantLockVisitor, org.apache.commons.lang3.concurrent.locks.LockingVisitors$ReentrantLockVisitor$Builder, org.apache.commons.lang3.concurrent.locks.LockingVisitors$StampedLockVisitor, org.apache.commons.lang3.concurrent.locks.LockingVisitors$StampedLockVisitor$Builder, org.apache.commons.lang3.concurrent.locks.package-info, org.apache.commons.lang3.concurrent.package-info, org.apache.commons.lang3.event.EventListenerSupport, org.apache.commons.lang3.event.EventListenerSupport$ProxyInvocationHandler, org.apache.commons.lang3.event.EventUtils, org.apache.commons.lang3.event.EventUtils$EventBindingInvocationHandler, org.apache.commons.lang3.event.package-info, org.apache.commons.lang3.exception.CloneFailedException, org.apache.commons.lang3.exception.ContextedException, org.apache.commons.lang3.exception.ContextedRuntimeException, org.apache.commons.lang3.exception.DefaultExceptionContext, org.apache.commons.lang3.exception.ExceptionContext, org.apache.commons.lang3.exception.ExceptionUtils, org.apache.commons.lang3.exception.UncheckedException, org.apache.commons.lang3.exception.UncheckedIllegalAccessException, org.apache.commons.lang3.exception.UncheckedInterruptedException, org.apache.commons.lang3.exception.UncheckedReflectiveOperationException, org.apache.commons.lang3.exception.package-info, org.apache.commons.lang3.function.BooleanConsumer, org.apache.commons.lang3.function.Consumers, org.apache.commons.lang3.function.Failable, org.apache.commons.lang3.function.FailableBiConsumer, org.apache.commons.lang3.function.FailableBiFunction, org.apache.commons.lang3.function.FailableBiPredicate, org.apache.commons.lang3.function.FailableBooleanSupplier, org.apache.commons.lang3.function.FailableCallable, org.apache.commons.lang3.function.FailableConsumer, org.apache.commons.lang3.function.FailableDoubleBinaryOperator, org.apache.commons.lang3.function.FailableDoubleConsumer, org.apache.commons.lang3.function.FailableDoubleFunction, org.apache.commons.lang3.function.FailableDoublePredicate, org.apache.commons.lang3.function.FailableDoubleSupplier, org.apache.commons.lang3.function.FailableDoubleToIntFunction, org.apache.commons.lang3.function.FailableDoubleToLongFunction, org.apache.commons.lang3.function.FailableDoubleUnaryOperator, org.apache.commons.lang3.function.FailableFunction, org.apache.commons.lang3.function.FailableIntBinaryOperator, org.apache.commons.lang3.function.FailableIntConsumer, org.apache.commons.lang3.function.FailableIntFunction, org.apache.commons.lang3.function.FailableIntPredicate, org.apache.commons.lang3.function.FailableIntSupplier, org.apache.commons.lang3.function.FailableIntToDoubleFunction, org.apache.commons.lang3.function.FailableIntToFloatFunction, org.apache.commons.lang3.function.FailableIntToLongFunction, org.apache.commons.lang3.function.FailableIntUnaryOperator, org.apache.commons.lang3.function.FailableLongBinaryOperator, org.apache.commons.lang3.function.FailableLongConsumer, org.apache.commons.lang3.function.FailableLongFunction, org.apache.commons.lang3.function.FailableLongPredicate, org.apache.commons.lang3.function.FailableLongSupplier, org.apache.commons.lang3.function.FailableLongToDoubleFunction, org.apache.commons.lang3.function.FailableLongToIntFunction, org.apache.commons.lang3.function.FailableLongUnaryOperator, org.apache.commons.lang3.function.FailableObjDoubleConsumer, org.apache.commons.lang3.function.FailableObjIntConsumer, org.apache.commons.lang3.function.FailableObjLongConsumer, org.apache.commons.lang3.function.FailablePredicate, org.apache.commons.lang3.function.FailableRunnable, org.apache.commons.lang3.function.FailableShortSupplier, org.apache.commons.lang3.function.FailableSupplier, org.apache.commons.lang3.function.FailableToBooleanFunction, org.apache.commons.lang3.function.FailableToDoubleBiFunction, org.apache.commons.lang3.function.FailableToDoubleFunction, org.apache.commons.lang3.function.FailableToIntBiFunction, org.apache.commons.lang3.function.FailableToIntFunction, org.apache.commons.lang3.function.FailableToLongBiFunction, org.apache.commons.lang3.function.FailableToLongFunction, org.apache.commons.lang3.function.Functions, org.apache.commons.lang3.function.IntToCharFunction, org.apache.commons.lang3.function.MethodInvokers, org.apache.commons.lang3.function.Predicates, org.apache.commons.lang3.function.Suppliers, org.apache.commons.lang3.function.ToBooleanBiFunction, org.apache.commons.lang3.function.TriConsumer, org.apache.commons.lang3.function.TriFunction, org.apache.commons.lang3.function.package-info, org.apache.commons.lang3.math.Fraction, org.apache.commons.lang3.math.IEEE754rUtils, org.apache.commons.lang3.math.NumberUtils, org.apache.commons.lang3.math.package-info, org.apache.commons.lang3.mutable.Mutable, org.apache.commons.lang3.mutable.MutableBoolean, org.apache.commons.lang3.mutable.MutableByte, org.apache.commons.lang3.mutable.MutableDouble, org.apache.commons.lang3.mutable.MutableFloat, org.apache.commons.lang3.mutable.MutableInt, org.apache.commons.lang3.mutable.MutableLong, org.apache.commons.lang3.mutable.MutableObject, org.apache.commons.lang3.mutable.MutableShort, org.apache.commons.lang3.mutable.package-info, org.apache.commons.lang3.package-info, org.apache.commons.lang3.reflect.ConstructorUtils, org.apache.commons.lang3.reflect.FieldUtils, org.apache.commons.lang3.reflect.InheritanceUtils, org.apache.commons.lang3.reflect.MemberUtils, org.apache.commons.lang3.reflect.MemberUtils$Executable, org.apache.commons.lang3.reflect.MethodUtils, org.apache.commons.lang3.reflect.TypeLiteral, org.apache.commons.lang3.reflect.TypeUtils, org.apache.commons.lang3.reflect.TypeUtils$1, org.apache.commons.lang3.reflect.TypeUtils$GenericArrayTypeImpl, org.apache.commons.lang3.reflect.TypeUtils$ParameterizedTypeImpl, org.apache.commons.lang3.reflect.TypeUtils$WildcardTypeBuilder, org.apache.commons.lang3.reflect.TypeUtils$WildcardTypeImpl, org.apache.commons.lang3.reflect.Typed, org.apache.commons.lang3.reflect.package-info, org.apache.commons.lang3.stream.IntStreams, org.apache.commons.lang3.stream.LangCollectors, org.apache.commons.lang3.stream.LangCollectors$1, org.apache.commons.lang3.stream.LangCollectors$SimpleCollector, org.apache.commons.lang3.stream.Streams, org.apache.commons.lang3.stream.Streams$ArrayCollector, org.apache.commons.lang3.stream.Streams$EnumerationSpliterator, org.apache.commons.lang3.stream.Streams$FailableStream, org.apache.commons.lang3.stream.package-info, org.apache.commons.lang3.text.CompositeFormat, org.apache.commons.lang3.text.ExtendedMessageFormat, org.apache.commons.lang3.text.FormatFactory, org.apache.commons.lang3.text.FormattableUtils, org.apache.commons.lang3.text.StrBuilder, org.apache.commons.lang3.text.StrBuilder$StrBuilderReader, org.apache.commons.lang3.text.StrBuilder$StrBuilderTokenizer, org.apache.commons.lang3.text.StrBuilder$StrBuilderWriter, org.apache.commons.lang3.text.StrLookup, org.apache.commons.lang3.text.StrLookup$1, org.apache.commons.lang3.text.StrLookup$MapStrLookup, org.apache.commons.lang3.text.StrLookup$SystemPropertiesStrLookup, org.apache.commons.lang3.text.StrMatcher, org.apache.commons.lang3.text.StrMatcher$CharMatcher, org.apache.commons.lang3.text.StrMatcher$CharSetMatcher, org.apache.commons.lang3.text.StrMatcher$NoMatcher, org.apache.commons.lang3.text.StrMatcher$StringMatcher, org.apache.commons.lang3.text.StrMatcher$TrimMatcher, org.apache.commons.lang3.text.StrSubstitutor, org.apache.commons.lang3.text.StrTokenizer, org.apache.commons.lang3.text.WordUtils, org.apache.commons.lang3.text.package-info, org.apache.commons.lang3.text.translate.AggregateTranslator, org.apache.commons.lang3.text.translate.CharSequenceTranslator, org.apache.commons.lang3.text.translate.CodePointTranslator, org.apache.commons.lang3.text.translate.EntityArrays, org.apache.commons.lang3.text.translate.JavaUnicodeEscaper, org.apache.commons.lang3.text.translate.LookupTranslator, org.apache.commons.lang3.text.translate.NumericEntityEscaper, org.apache.commons.lang3.text.translate.NumericEntityUnescaper, org.apache.commons.lang3.text.translate.NumericEntityUnescaper$OPTION, org.apache.commons.lang3.text.translate.OctalUnescaper, org.apache.commons.lang3.text.translate.UnicodeEscaper, org.apache.commons.lang3.text.translate.UnicodeUnescaper, org.apache.commons.lang3.text.translate.UnicodeUnpairedSurrogateRemover, org.apache.commons.lang3.text.translate.package-info, org.apache.commons.lang3.time.AbstractFormatCache, org.apache.commons.lang3.time.AbstractFormatCache$ArrayKey, org.apache.commons.lang3.time.CalendarUtils, org.apache.commons.lang3.time.DateFormatUtils, org.apache.commons.lang3.time.DateParser, org.apache.commons.lang3.time.DatePrinter, org.apache.commons.lang3.time.DateUtils, org.apache.commons.lang3.time.DateUtils$DateIterator, org.apache.commons.lang3.time.DateUtils$ModifyType, org.apache.commons.lang3.time.DurationFormatUtils, org.apache.commons.lang3.time.DurationFormatUtils$Token, org.apache.commons.lang3.time.DurationUtils, org.apache.commons.lang3.time.DurationUtils$1, org.apache.commons.lang3.time.FastDateFormat, org.apache.commons.lang3.time.FastDateFormat$1, org.apache.commons.lang3.time.FastDateParser, org.apache.commons.lang3.time.FastDateParser$1, org.apache.commons.lang3.time.FastDateParser$2, org.apache.commons.lang3.time.FastDateParser$3, org.apache.commons.lang3.time.FastDateParser$4, org.apache.commons.lang3.time.FastDateParser$5, org.apache.commons.lang3.time.FastDateParser$CaseInsensitiveTextStrategy, org.apache.commons.lang3.time.FastDateParser$CopyQuotedStrategy, org.apache.commons.lang3.time.FastDateParser$ISO8601TimeZoneStrategy, org.apache.commons.lang3.time.FastDateParser$NumberStrategy, org.apache.commons.lang3.time.FastDateParser$PatternStrategy, org.apache.commons.lang3.time.FastDateParser$Strategy, org.apache.commons.lang3.time.FastDateParser$StrategyAndWidth, org.apache.commons.lang3.time.FastDateParser$StrategyParser, org.apache.commons.lang3.time.FastDateParser$TimeZoneStrategy, org.apache.commons.lang3.time.FastDateParser$TimeZoneStrategy$TzInfo, org.apache.commons.lang3.time.FastDatePrinter, org.apache.commons.lang3.time.FastDatePrinter$CharacterLiteral, org.apache.commons.lang3.time.FastDatePrinter$DayInWeekField, org.apache.commons.lang3.time.FastDatePrinter$Iso8601_Rule, org.apache.commons.lang3.time.FastDatePrinter$NumberRule, org.apache.commons.lang3.time.FastDatePrinter$PaddedNumberField, org.apache.commons.lang3.time.FastDatePrinter$Rule, org.apache.commons.lang3.time.FastDatePrinter$StringLiteral, org.apache.commons.lang3.time.FastDatePrinter$TextField, org.apache.commons.lang3.time.FastDatePrinter$TimeZoneDisplayKey, org.apache.commons.lang3.time.FastDatePrinter$TimeZoneNameRule, org.apache.commons.lang3.time.FastDatePrinter$TimeZoneNumberRule, org.apache.commons.lang3.time.FastDatePrinter$TwelveHourField, org.apache.commons.lang3.time.FastDatePrinter$TwentyFourHourField, org.apache.commons.lang3.time.FastDatePrinter$TwoDigitMonthField, org.apache.commons.lang3.time.FastDatePrinter$TwoDigitNumberField, org.apache.commons.lang3.time.FastDatePrinter$TwoDigitYearField, org.apache.commons.lang3.time.FastDatePrinter$UnpaddedMonthField, org.apache.commons.lang3.time.FastDatePrinter$UnpaddedNumberField, org.apache.commons.lang3.time.FastDatePrinter$WeekYear, org.apache.commons.lang3.time.FastTimeZone, org.apache.commons.lang3.time.GmtTimeZone, org.apache.commons.lang3.time.StopWatch, org.apache.commons.lang3.time.StopWatch$1, org.apache.commons.lang3.time.StopWatch$SplitState, org.apache.commons.lang3.time.StopWatch$State, org.apache.commons.lang3.time.StopWatch$State$1, org.apache.commons.lang3.time.StopWatch$State$2, org.apache.commons.lang3.time.StopWatch$State$3, org.apache.commons.lang3.time.StopWatch$State$4, org.apache.commons.lang3.time.TimeZones, org.apache.commons.lang3.time.package-info, org.apache.commons.lang3.tuple.ImmutablePair, org.apache.commons.lang3.tuple.ImmutableTriple, org.apache.commons.lang3.tuple.MutablePair, org.apache.commons.lang3.tuple.MutableTriple, org.apache.commons.lang3.tuple.Pair, org.apache.commons.lang3.tuple.Triple, org.apache.commons.lang3.tuple.package-info, org.apache.commons.lang3.util.FluentBitSet, org.apache.commons.lang3.util.IterableStringTokenizer, org.apache.commons.lang3.util.IterableStringTokenizer$1, org.apache.commons.lang3.util.package-info]
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
[INFO]   Exclusion provenance incomplete for 12 dependency or exclusion origins. Maven
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
