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
* **Early Regression Detection**: Injects trimmed dependency views into Maven at `INITIALIZE`. Your standard `test` and `verify` phases execute against the trimmed classpath, catching regressions *before* packaging.
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
  -Delide.sourceRootsComplete=true \
  -Dmaven.compiler.proc=none \
  -Delide.retainedArtifacts=commons-io:commons-io,org.apache.commons:commons-lang3
```

On this Basic fixture, `analyze` identifies two whole-artifact candidates out of thirteen (942.11 KiB of original JAR bytes). The pinned cache retains the `CVE-2014-3577` package finding and its commit-derived `AbstractVerifier` review candidate. Analysis reports these findings without trim proof or VEX.

### 5. Build with Elision (`elide`)

Run `elide` alongside your packaging goals to trim dependencies and generate sanitized outputs:

```sh
../../mvnw io.github.spockz:dependency-elider-maven-plugin:0.1.0-SNAPSHOT:elide package \
  -Delide.skip=false \
  -Delide.traceFiles=target/classes.log \
  -Delide.trimJars=true \
  -Delide.sourceRootsComplete=true \
  -Dmaven.compiler.proc=none \
  -Delide.retainedArtifacts=commons-io:commons-io,org.apache.commons:commons-lang3
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
* Precondition VEX requires an exact prerequisite class as well as its coordinate, plus explicit `-Delide.preconditionClassPathComplete=true` confirmation that the declared Maven build inventory is complete. The opt-in cannot override detected downstream generators: both `compile` and `testCompile` must explicitly resolve `maven.compiler.proc=none` under a known Maven Compiler Plugin version from 3.13 through 3.x, with Java release or source/target at least 11. Processor paths, processor lists, compiler arguments other than the exact diagnostic-only `-Xlint:all`, custom compiler/executable modes, compiler plugin dependencies, and missing, unresolved, or conflicting settings leave proof incomplete. Unmodeled plugin executions before or after `INITIALIZE`, configured clean/site executions with unmodeled ordering, Enforcer executions at or after inventory capture or with unknown phases, filtered resources, resource plugin dependencies, unsupported packaging/extensions, and custom compiler/resource roots also suppress proof. Proof supports `jar` and `pom` packaging; `war` and `maven-plugin` packaging remain incomplete because their provider-generation paths are not modeled. The inventory includes `<build.directory>/generated-sources/annotations` and `<build.directory>/generated-test-sources/test-annotations`; custom generated-source directories suppress proof. Pre-capture Enforcer rules are limited to verified built-ins, without custom implementation attributes or plugin dependencies. Interface assertions are also rejected because javac can emit an additional helper class for them. The Maven request must contain one default-lifecycle goal, optionally preceded by `clean`; direct plugin goals and multiple lifecycle segments suppress proof. The publisher revalidates provider membership and digests before commit; serializers recheck the affected component path and digest. Unchanged plugin-owned OpenVEX is removed when no qualifying evidence remains. Modified or unowned output is preserved. With `elide.trimJars=false`, SBOM/VEX publication and stale VEX cleanup do not run. The claim does not cover providers added by later packaging or deployment runtime mechanisms. See [RQ-0013](docs/research/RQ-0013-precondition-gated-vex-and-multi-artifact-exploitability.md).
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
| Bare production `dependency:tree` | Example and fixture verified for Maven CLI 3.9.11 and Dependency Plugin 3.8.1 | With `.mvn/extensions.xml` and an active initialize-bound execution, `dependency:tree` automatically runs elision first. See [production lifecycle tests](dependency-elider-maven-plugin/src/test/java/io/github/spockz/elider/plugin/DependencyContextLifecycleIT.java#L583) and [tree assertions](examples/run-elision-cycle.sh#L808). |
| Class reachability and safe dependency removal | Unit tested; fixture verified | Covers explicit roots, source references, framework metadata, and graph leaves with retention across ancestors, cycles, and diamonds. |
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

* **Source Roots (`elide.sourceRootsComplete`)**: Defaults to `false` (conservatively retains all compile-classpath JARs and classes). Set to `true` only when all production and generated sources exist before `INITIALIZE` with no downstream generation.
* **Reactor Leaf Modules (`elide.leafOnly`)**: Defaults to `true`. In multi-module Maven reactors, the plugin by default only elides leaf modules (modules with no downstream dependents in the reactor DAG, such as packaging applications, fat JARs, and Native Images). Intermediate library modules skip elision, ensuring internal libraries build and test against standard dependencies while the leaf module performs definitive elision across the unified dependency graph. Set `-Delide.leafOnly=false` (or `<elide.leafOnly>false</elide.leafOnly>`) to run elision across every submodule.
* **Production Bytecode (`elide.productionClassesComplete`)**: For generated production code, enable the Maven extension and set this property to `true` to rebind the default `elide` execution from `initialize` to `process-classes`. The output directory must contain compiled production classes. Analysis derives production roots directly from emitted bytecode in `target/classes`; dependencies referenced exclusively through compile-time-inlined primitive or String constants are retained explicitly via `<retainedArtifacts>`. Source roots do not count as runtime evidence, and test-only references are not guaranteed. A direct `dependency-elider:elide` invocation does not establish trusted lifecycle capture; bind the goal to `process-classes` or run the normal lifecycle. Unknown writers at `process-classes` or later remain unsupported, and `skipTests` does not skip `testCompile` safeguards.
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
[INFO] Program classes pruned from retained JARs: 535 (uncompressed omitted .class payload bytes: 1.93 MiB; excludes module descriptors and archive metadata)
[INFO]   - org.apache.commons:commons-compress:jar:1.28.0 (compile): 535 classes, 1.93 MiB
[INFO] Vulnerability findings: 6
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
[INFO]   - CVE-2020-13956 org.apache.httpcomponents:httpclient:jar:4.3.4 (compile) [REMOVED]
[INFO]     Aliases: [CVE-2020-13956, GHSA-7r82-7xv7-xcpj]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
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
[INFO]   - CVE-2024-47554 commons-io:commons-io:jar:2.20.0 (compile) [RETAINED_UNCHANGED]
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
[INFO]   ... 11 dependency graph rows elided (sha256:0bc2b8d079442ffdd62b0c7c8448bea58357a2287a870859362982360e2dcc12)
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
[INFO] Whole artifacts dropped: 0 / 91 (original JAR file bytes: 0 B)
[INFO] Program classes removed with dropped JARs: 0 (uncompressed .class entry payload bytes: 0 B; excludes module descriptors and archive sanitation metadata)
[INFO] Raw trace decision drops before graph safety: 0
[INFO] Applied bans: none
[INFO] Program classes pruned from retained JARs: 3429 (uncompressed omitted .class payload bytes: 8.57 MiB; excludes module descriptors and archive metadata)
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
[INFO]   - org.slf4j:slf4j-api:jar:2.0.16 (compile): 5 classes, 6.38 KiB
[INFO]   - org.springframework:spring-jcl:jar:6.1.14 (compile): 1 classes, 1.24 KiB
[INFO]   - org.springframework:spring-webmvc:jar:6.1.14 (compile): 146 classes, 524.46 KiB
[INFO]   - org.webjars:webjars-locator-core:jar:0.58 (runtime): 1 classes, 10.66 KiB
[INFO]   - org.yaml:snakeyaml:jar:2.2 (compile): 0 classes, 2.65 KiB
[INFO] Vulnerability findings: 101
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
[INFO]   - CVE-2024-31573 org.xmlunit:xmlunit-core:jar:2.9.1 (test) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2024-31573, GHSA-chfm-68vv-pvw5]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2024-50379 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2024-50379, CVE-2024-50379, GHSA-5j33-cvvr-w245]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
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
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
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
[INFO]   - CVE-2025-52520 org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.31 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [BIT-tomcat-2025-52520, CVE-2025-52520, GHSA-wr62-c79q-cv37]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
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
[INFO]   - CVE-2026-40984 io.micrometer:micrometer-core:jar:1.13.6 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-40984, GHSA-g3pr-3p32-fp23]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
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
[INFO]   - CVE-2026-49844 org.apache.logging.log4j:log4j-api:jar:2.23.1 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-49844, GHSA-qv9r-c865-cp47]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [CVE_LIST, OSV]
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
[INFO]   ... 89 dependency graph rows elided (sha256:e6937888bdd78a897958920bd8fded79829b88d17211bacbad38ba400a18cbee)
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
[INFO] Whole artifacts dropped: 0 / 25 (original JAR file bytes: 0 B)
[INFO] Program classes removed with dropped JARs: 0 (uncompressed .class entry payload bytes: 0 B; excludes module descriptors and archive sanitation metadata)
[INFO] Raw trace decision drops before graph safety: 0
[INFO] Applied bans: none
[INFO] Program classes pruned from retained JARs: 330 (uncompressed omitted .class payload bytes: 1.04 MiB; excludes module descriptors and archive metadata)
[INFO]   - com.fasterxml.jackson.core:jackson-core:jar:2.19.0 (compile): 20 classes, 82.33 KiB
[INFO]   - com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile): 70 classes, 163.47 KiB
[INFO]   - org.apache.commons:commons-text:jar:1.9 (compile): 132 classes, 388.41 KiB
[INFO]   - org.codehaus.janino:commons-compiler:jar:3.1.12 (compile): 51 classes, 96.78 KiB
[INFO]   - org.codehaus.janino:janino:jar:3.1.12 (compile): 52 classes, 330.49 KiB
[INFO]   - org.slf4j:slf4j-api:jar:2.0.17 (compile): 5 classes, 6.38 KiB
[INFO] Vulnerability findings: 29
[INFO]   - CVE-2022-42889 org.apache.commons:commons-text:jar:1.9 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Aliases: [CVE-2022-42889, GHSA-599f-7c49-w659]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: DECLARED_CODE_ABSENT; All effective declared code and its nested classes are absent from the trimmed artifact. This observation is limited to the declared code and does not establish declaration completeness.
[INFO]     Declared code: [org.apache.commons.text.lookup.StringLookup] RESOLVED; classes: [org.apache.commons.text.lookup.StringLookup]; reasons: []
[INFO]     Declared code: [org.apache.commons.text.lookup.StringLookup] REVIEW_LEAD; classes: []; reasons: [HEURISTIC_REQUIRES_REVIEW]
[INFO]     Heuristic leads: [org.apache.commons.text.lookup.StringLookup]
[INFO]     Overridden fields: [code, intent]
[INFO]     Sources: [OSV, POM]
[INFO]   - CVE-2025-11226 ch.qos.logback:logback-core:jar:1.5.18 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2025-11226, GHSA-25qh-j22f-pwp8]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
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
[INFO]   ... 23 dependency graph rows elided (sha256:8a675b0fd592f936ac623440cdc52ef26f9fcd2f560856078b665a575c9587c0)
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
[INFO] Vulnerability findings: 9
[INFO]   - CVE-2025-11226 ch.qos.logback:logback-core:jar:1.5.18 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2025-11226, GHSA-25qh-j22f-pwp8]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: PREREQUISITES_ABSENT; Required prerequisite pairs org.codehaus.janino:janino / org.codehaus.janino.ClassBodyEvaluator are absent from the complete declared Maven inventory. The proof does not cover providers introduced outside that inventory.
[INFO]     Effective prerequisites: [org.codehaus.janino:janino / org.codehaus.janino.ClassBodyEvaluator]
[INFO]     Overridden fields: [intent]
[INFO]     Enriched fields: [prerequisites]
[INFO]     Sources: [OSV, POM]
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

Persisted elision report schema 1 lists changed root `META-INF/services/*` descriptors in each `trimmedArtifacts` row as `serviceDescriptorChanges`, with outcome `REPLACED` or `OMIT`; unchanged descriptors are not listed. A zero-class output row is valid when an MRJAR was elevated (`mrjarStatus=elevated_and_trimmed`), a service descriptor changed, or classpath-only transformation removed the root `module-info.class` (`mrjarStatus=classpath-only`).

With or without the core extension, `analyze` can predict strict `banishedDependencies` for supported compile/runtime JARs, using either a detached current-model Resolver graph or the captured effective graph with a complete original-input audit. The schema-1 `dependencyPrediction.banPlan` records each request as matched (`FORCED_ABSENT_AFTER_RESOLUTION`), excluded before resolution (`EXCLUDED_BEFORE_RESOLUTION`), or unmatched (`UNMATCHED`); every prediction row has `applied=false`. Matched and pre-resolution-excluded requests require complete source roots (`elide.sourceRootsComplete=true`) or complete production class output (`elide.productionClassesComplete=true`); the two assertions are mutually exclusive. A request matching an unsupported scope or type fails closed. The plan also fails if runtime trace, source, production bytecode, dynamic metadata, retained-resource/provider closure, or graph protection requires a banned artifact. An unmatched entry is not an absence proof. Analyze replaces the report only after prediction and vulnerability assessment succeed; it never changes Maven artifact views.

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
  -Delide.trimJars=true \
  -Delide.sourceRootsComplete=true \
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
[INFO] Program classes that would be pruned from retained JARs: 535 (uncompressed omitted .class payload bytes: unknown; excludes module descriptors and archive metadata)
[INFO]   - org.apache.commons:commons-compress:jar:1.28.0 (compile): 535 classes, unknown
[INFO]     Would remove classes: [org.apache.commons.compress.CompressException, org.apache.commons.compress.CompressFilterOutputStream, org.apache.commons.compress.MemoryLimitException, org.apache.commons.compress.PasswordRequiredException, org.apache.commons.compress.archivers.ArchiveException, org.apache.commons.compress.archivers.ArchiveInputStream, org.apache.commons.compress.archivers.ArchiveInputStream$ArchiveEntryIOIterator, org.apache.commons.compress.archivers.ArchiveOutputStream, org.apache.commons.compress.archivers.ArchiveStreamFactory, org.apache.commons.compress.archivers.ArchiveStreamProvider, org.apache.commons.compress.archivers.Lister, org.apache.commons.compress.archivers.StreamingNotSupportedException, org.apache.commons.compress.archivers.ar.ArArchiveEntry, org.apache.commons.compress.archivers.ar.ArArchiveInputStream, org.apache.commons.compress.archivers.ar.ArArchiveOutputStream, org.apache.commons.compress.archivers.ar.package-info, org.apache.commons.compress.archivers.arj.ArjArchiveEntry, org.apache.commons.compress.archivers.arj.ArjArchiveEntry$HostOs, org.apache.commons.compress.archivers.arj.ArjArchiveInputStream, org.apache.commons.compress.archivers.arj.LocalFileHeader, org.apache.commons.compress.archivers.arj.LocalFileHeader$FileTypes, org.apache.commons.compress.archivers.arj.LocalFileHeader$Flags, org.apache.commons.compress.archivers.arj.LocalFileHeader$Methods, org.apache.commons.compress.archivers.arj.MainHeader, org.apache.commons.compress.archivers.arj.MainHeader$Flags, org.apache.commons.compress.archivers.arj.MainHeader$HostOS, org.apache.commons.compress.archivers.arj.package-info, org.apache.commons.compress.archivers.cpio.CpioArchiveEntry, org.apache.commons.compress.archivers.cpio.CpioArchiveInputStream, org.apache.commons.compress.archivers.cpio.CpioArchiveOutputStream, org.apache.commons.compress.archivers.cpio.CpioConstants, org.apache.commons.compress.archivers.cpio.CpioUtil, org.apache.commons.compress.archivers.cpio.package-info, org.apache.commons.compress.archivers.dump.Dirent, org.apache.commons.compress.archivers.dump.DumpArchiveConstants, org.apache.commons.compress.archivers.dump.DumpArchiveConstants$COMPRESSION_TYPE, org.apache.commons.compress.archivers.dump.DumpArchiveConstants$SEGMENT_TYPE, org.apache.commons.compress.archivers.dump.DumpArchiveEntry, org.apache.commons.compress.archivers.dump.DumpArchiveEntry$PERMISSION, org.apache.commons.compress.archivers.dump.DumpArchiveEntry$TYPE, org.apache.commons.compress.archivers.dump.DumpArchiveEntry$TapeSegmentHeader, org.apache.commons.compress.archivers.dump.DumpArchiveException, org.apache.commons.compress.archivers.dump.DumpArchiveInputStream, org.apache.commons.compress.archivers.dump.DumpArchiveSummary, org.apache.commons.compress.archivers.dump.DumpArchiveUtil, org.apache.commons.compress.archivers.dump.InvalidFormatException, org.apache.commons.compress.archivers.dump.ShortFileException, org.apache.commons.compress.archivers.dump.TapeInputStream, org.apache.commons.compress.archivers.dump.TapeInputStream$1, org.apache.commons.compress.archivers.dump.UnrecognizedFormatException, org.apache.commons.compress.archivers.dump.UnsupportedCompressionAlgorithmException, org.apache.commons.compress.archivers.dump.package-info, org.apache.commons.compress.archivers.examples.Archiver, org.apache.commons.compress.archivers.examples.Archiver$1, org.apache.commons.compress.archivers.examples.Archiver$ArchiverFileVisitor, org.apache.commons.compress.archivers.examples.CloseableConsumer, org.apache.commons.compress.archivers.examples.CloseableConsumerAdapter, org.apache.commons.compress.archivers.examples.Expander, org.apache.commons.compress.archivers.examples.Expander$ArchiveEntryBiConsumer, org.apache.commons.compress.archivers.examples.Expander$ArchiveEntrySupplier, org.apache.commons.compress.archivers.examples.package-info, org.apache.commons.compress.archivers.jar.JarArchiveEntry, org.apache.commons.compress.archivers.jar.JarArchiveInputStream, org.apache.commons.compress.archivers.jar.JarArchiveOutputStream, org.apache.commons.compress.archivers.jar.package-info, org.apache.commons.compress.archivers.package-info, org.apache.commons.compress.archivers.sevenz.AES256Options, org.apache.commons.compress.archivers.sevenz.AES256SHA256Decoder, org.apache.commons.compress.archivers.sevenz.AES256SHA256Decoder$1, org.apache.commons.compress.archivers.sevenz.AES256SHA256Decoder$AES256SHA256DecoderInputStream, org.apache.commons.compress.archivers.sevenz.AES256SHA256Decoder$AES256SHA256DecoderOutputStream, org.apache.commons.compress.archivers.sevenz.AbstractCoder, org.apache.commons.compress.archivers.sevenz.Archive, org.apache.commons.compress.archivers.sevenz.BindPair, org.apache.commons.compress.archivers.sevenz.BoundedSeekableByteChannelInputStream, org.apache.commons.compress.archivers.sevenz.CLI, org.apache.commons.compress.archivers.sevenz.CLI$1, org.apache.commons.compress.archivers.sevenz.CLI$Mode, org.apache.commons.compress.archivers.sevenz.CLI$Mode$1, org.apache.commons.compress.archivers.sevenz.Coder, org.apache.commons.compress.archivers.sevenz.Coders, org.apache.commons.compress.archivers.sevenz.Coders$1, org.apache.commons.compress.archivers.sevenz.Coders$BCJDecoder, org.apache.commons.compress.archivers.sevenz.Coders$BZIP2Decoder, org.apache.commons.compress.archivers.sevenz.Coders$CopyDecoder, org.apache.commons.compress.archivers.sevenz.Coders$Deflate64Decoder, org.apache.commons.compress.archivers.sevenz.Coders$DeflateDecoder, org.apache.commons.compress.archivers.sevenz.Coders$DeflateDecoder$DeflateDecoderInputStream, org.apache.commons.compress.archivers.sevenz.Coders$DeflateDecoder$DeflateDecoderOutputStream, org.apache.commons.compress.archivers.sevenz.DeltaDecoder, org.apache.commons.compress.archivers.sevenz.Folder, org.apache.commons.compress.archivers.sevenz.LZMA2Decoder, org.apache.commons.compress.archivers.sevenz.LZMADecoder, org.apache.commons.compress.archivers.sevenz.NID, org.apache.commons.compress.archivers.sevenz.SevenZArchiveEntry, org.apache.commons.compress.archivers.sevenz.SevenZFile, org.apache.commons.compress.archivers.sevenz.SevenZFile$1, org.apache.commons.compress.archivers.sevenz.SevenZFile$2, org.apache.commons.compress.archivers.sevenz.SevenZFile$ArchiveStatistics, org.apache.commons.compress.archivers.sevenz.SevenZFile$Builder, org.apache.commons.compress.archivers.sevenz.SevenZFileOptions, org.apache.commons.compress.archivers.sevenz.SevenZFileOptions$1, org.apache.commons.compress.archivers.sevenz.SevenZFileOptions$Builder, org.apache.commons.compress.archivers.sevenz.SevenZMethod, org.apache.commons.compress.archivers.sevenz.SevenZMethodConfiguration, org.apache.commons.compress.archivers.sevenz.SevenZOutputFile, org.apache.commons.compress.archivers.sevenz.SevenZOutputFile$1, org.apache.commons.compress.archivers.sevenz.SevenZOutputFile$OutputStreamWrapper, org.apache.commons.compress.archivers.sevenz.StartHeader, org.apache.commons.compress.archivers.sevenz.StreamMap, org.apache.commons.compress.archivers.sevenz.SubStreamsInfo, org.apache.commons.compress.archivers.sevenz.package-info, org.apache.commons.compress.archivers.tar.TarArchiveEntry, org.apache.commons.compress.archivers.tar.TarArchiveInputStream, org.apache.commons.compress.archivers.tar.TarArchiveOutputStream, org.apache.commons.compress.archivers.tar.TarArchiveSparseEntry, org.apache.commons.compress.archivers.tar.TarArchiveSparseZeroInputStream, org.apache.commons.compress.archivers.tar.TarArchiveStructSparse, org.apache.commons.compress.archivers.tar.TarConstants, org.apache.commons.compress.archivers.tar.TarFile, org.apache.commons.compress.archivers.tar.TarFile$BoundedTarEntryInputStream, org.apache.commons.compress.archivers.tar.TarGnuSparseKeys, org.apache.commons.compress.archivers.tar.TarUtils, org.apache.commons.compress.archivers.tar.TarUtils$1, org.apache.commons.compress.archivers.tar.package-info, org.apache.commons.compress.archivers.zip.BinaryTree, org.apache.commons.compress.archivers.zip.BitStream, org.apache.commons.compress.archivers.zip.CircularBuffer, org.apache.commons.compress.archivers.zip.DefaultBackingStoreSupplier, org.apache.commons.compress.archivers.zip.ExplodingInputStream, org.apache.commons.compress.archivers.zip.FileRandomAccessOutputStream, org.apache.commons.compress.archivers.zip.InflaterInputStreamWithStatistics, org.apache.commons.compress.archivers.zip.ParallelScatterZipCreator, org.apache.commons.compress.archivers.zip.ParallelScatterZipCreator$1, org.apache.commons.compress.archivers.zip.RandomAccessOutputStream, org.apache.commons.compress.archivers.zip.ScatterStatistics, org.apache.commons.compress.archivers.zip.ScatterZipOutputStream, org.apache.commons.compress.archivers.zip.ScatterZipOutputStream$CompressedEntry, org.apache.commons.compress.archivers.zip.ScatterZipOutputStream$ZipEntryWriter, org.apache.commons.compress.archivers.zip.SeekableChannelRandomAccessOutputStream, org.apache.commons.compress.archivers.zip.StreamCompressor, org.apache.commons.compress.archivers.zip.StreamCompressor$DataOutputCompressor, org.apache.commons.compress.archivers.zip.StreamCompressor$OutputStreamCompressor, org.apache.commons.compress.archivers.zip.StreamCompressor$ScatterGatherBackingStoreCompressor, org.apache.commons.compress.archivers.zip.StreamCompressor$SeekableByteChannelCompressor, org.apache.commons.compress.archivers.zip.UnshrinkingInputStream, org.apache.commons.compress.archivers.zip.Zip64Mode, org.apache.commons.compress.archivers.zip.Zip64RequiredException, org.apache.commons.compress.archivers.zip.ZipArchiveEntryPredicate, org.apache.commons.compress.archivers.zip.ZipArchiveEntryRequest, org.apache.commons.compress.archivers.zip.ZipArchiveEntryRequestSupplier, org.apache.commons.compress.archivers.zip.ZipArchiveInputStream, org.apache.commons.compress.archivers.zip.ZipArchiveInputStream$1, org.apache.commons.compress.archivers.zip.ZipArchiveInputStream$BoundCountInputStream, org.apache.commons.compress.archivers.zip.ZipArchiveInputStream$CurrentEntry, org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream, org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream$1, org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream$CurrentEntry, org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream$EntryMetaData, org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream$UnicodeExtraFieldPolicy, org.apache.commons.compress.archivers.zip.ZipFile, org.apache.commons.compress.archivers.zip.ZipFile$1, org.apache.commons.compress.archivers.zip.ZipFile$2, org.apache.commons.compress.archivers.zip.ZipFile$BoundedFileChannelInputStream, org.apache.commons.compress.archivers.zip.ZipFile$Builder, org.apache.commons.compress.archivers.zip.ZipFile$Entry, org.apache.commons.compress.archivers.zip.ZipFile$NameAndComment, org.apache.commons.compress.archivers.zip.ZipFile$StoredStatisticsStream, org.apache.commons.compress.archivers.zip.ZipIoUtil, org.apache.commons.compress.archivers.zip.ZipSplitOutputStream, org.apache.commons.compress.archivers.zip.ZipSplitReadOnlySeekableByteChannel, org.apache.commons.compress.archivers.zip.ZipSplitReadOnlySeekableByteChannel$1, org.apache.commons.compress.archivers.zip.ZipSplitReadOnlySeekableByteChannel$ZipSplitSegmentComparator, org.apache.commons.compress.archivers.zip.package-info, org.apache.commons.compress.changes.Change, org.apache.commons.compress.changes.Change$ChangeType, org.apache.commons.compress.changes.ChangeSet, org.apache.commons.compress.changes.ChangeSetPerformer, org.apache.commons.compress.changes.ChangeSetPerformer$ArchiveEntryIterator, org.apache.commons.compress.changes.ChangeSetPerformer$ArchiveInputStreamIterator, org.apache.commons.compress.changes.ChangeSetPerformer$ZipFileIterator, org.apache.commons.compress.changes.ChangeSetResults, org.apache.commons.compress.changes.package-info, org.apache.commons.compress.compressors.CompressorException, org.apache.commons.compress.compressors.CompressorInputStream, org.apache.commons.compress.compressors.CompressorOutputStream, org.apache.commons.compress.compressors.CompressorStreamFactory, org.apache.commons.compress.compressors.CompressorStreamProvider, org.apache.commons.compress.compressors.FileNameUtil, org.apache.commons.compress.compressors.brotli.BrotliCompressorInputStream, org.apache.commons.compress.compressors.brotli.BrotliUtils, org.apache.commons.compress.compressors.brotli.BrotliUtils$CachedAvailability, org.apache.commons.compress.compressors.brotli.package-info, org.apache.commons.compress.compressors.bzip2.BZip2CompressorInputStream, org.apache.commons.compress.compressors.bzip2.BZip2CompressorInputStream$Data, org.apache.commons.compress.compressors.bzip2.BZip2CompressorOutputStream, org.apache.commons.compress.compressors.bzip2.BZip2CompressorOutputStream$Data, org.apache.commons.compress.compressors.bzip2.BZip2Constants, org.apache.commons.compress.compressors.bzip2.BZip2Utils, org.apache.commons.compress.compressors.bzip2.BlockSort, org.apache.commons.compress.compressors.bzip2.CRC, org.apache.commons.compress.compressors.bzip2.Rand, org.apache.commons.compress.compressors.bzip2.package-info, org.apache.commons.compress.compressors.deflate.DeflateCompressorInputStream, org.apache.commons.compress.compressors.deflate.DeflateCompressorOutputStream, org.apache.commons.compress.compressors.deflate.DeflateParameters, org.apache.commons.compress.compressors.deflate.package-info, org.apache.commons.compress.compressors.deflate64.Deflate64CompressorInputStream, org.apache.commons.compress.compressors.deflate64.HuffmanDecoder, org.apache.commons.compress.compressors.deflate64.HuffmanDecoder$1, org.apache.commons.compress.compressors.deflate64.HuffmanDecoder$BinaryTreeNode, org.apache.commons.compress.compressors.deflate64.HuffmanDecoder$DecoderState, org.apache.commons.compress.compressors.deflate64.HuffmanDecoder$DecodingMemory, org.apache.commons.compress.compressors.deflate64.HuffmanDecoder$HuffmanCodes, org.apache.commons.compress.compressors.deflate64.HuffmanDecoder$InitialState, org.apache.commons.compress.compressors.deflate64.HuffmanDecoder$UncompressedState, org.apache.commons.compress.compressors.deflate64.HuffmanState, org.apache.commons.compress.compressors.deflate64.package-info, org.apache.commons.compress.compressors.gzip.ExtraField, org.apache.commons.compress.compressors.gzip.ExtraField$SubField, org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream, org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream$1, org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream$Builder, org.apache.commons.compress.compressors.gzip.GzipCompressorOutputStream, org.apache.commons.compress.compressors.gzip.GzipParameters, org.apache.commons.compress.compressors.gzip.GzipParameters$OS, org.apache.commons.compress.compressors.gzip.GzipUtils, org.apache.commons.compress.compressors.gzip.package-info, org.apache.commons.compress.compressors.lz4.BlockLZ4CompressorInputStream, org.apache.commons.compress.compressors.lz4.BlockLZ4CompressorInputStream$State, org.apache.commons.compress.compressors.lz4.BlockLZ4CompressorOutputStream, org.apache.commons.compress.compressors.lz4.BlockLZ4CompressorOutputStream$1, org.apache.commons.compress.compressors.lz4.BlockLZ4CompressorOutputStream$Pair, org.apache.commons.compress.compressors.lz4.FramedLZ4CompressorInputStream, org.apache.commons.compress.compressors.lz4.FramedLZ4CompressorOutputStream, org.apache.commons.compress.compressors.lz4.FramedLZ4CompressorOutputStream$BlockSize, org.apache.commons.compress.compressors.lz4.FramedLZ4CompressorOutputStream$Parameters, org.apache.commons.compress.compressors.lz4.XXHash32, org.apache.commons.compress.compressors.lz4.package-info, org.apache.commons.compress.compressors.lz77support.AbstractLZ77CompressorInputStream, org.apache.commons.compress.compressors.lz77support.LZ77Compressor, org.apache.commons.compress.compressors.lz77support.LZ77Compressor$AbstractReference, org.apache.commons.compress.compressors.lz77support.LZ77Compressor$BackReference, org.apache.commons.compress.compressors.lz77support.LZ77Compressor$Block, org.apache.commons.compress.compressors.lz77support.LZ77Compressor$Block$BlockType, org.apache.commons.compress.compressors.lz77support.LZ77Compressor$Callback, org.apache.commons.compress.compressors.lz77support.LZ77Compressor$EOD, org.apache.commons.compress.compressors.lz77support.LZ77Compressor$LiteralBlock, org.apache.commons.compress.compressors.lz77support.Parameters, org.apache.commons.compress.compressors.lz77support.Parameters$1, org.apache.commons.compress.compressors.lz77support.Parameters$Builder, org.apache.commons.compress.compressors.lz77support.package-info, org.apache.commons.compress.compressors.lzma.LZMACompressorInputStream, org.apache.commons.compress.compressors.lzma.LZMACompressorInputStream$1, org.apache.commons.compress.compressors.lzma.LZMACompressorInputStream$Builder, org.apache.commons.compress.compressors.lzma.LZMACompressorOutputStream, org.apache.commons.compress.compressors.lzma.LZMACompressorOutputStream$1, org.apache.commons.compress.compressors.lzma.LZMACompressorOutputStream$Builder, org.apache.commons.compress.compressors.lzma.LZMAUtils, org.apache.commons.compress.compressors.lzma.LZMAUtils$CachedAvailability, org.apache.commons.compress.compressors.lzma.package-info, org.apache.commons.compress.compressors.lzw.LZWInputStream, org.apache.commons.compress.compressors.lzw.package-info, org.apache.commons.compress.compressors.pack200.AbstractStreamBridge, org.apache.commons.compress.compressors.pack200.InMemoryCachingStreamBridge, org.apache.commons.compress.compressors.pack200.Pack200CompressorInputStream, org.apache.commons.compress.compressors.pack200.Pack200CompressorOutputStream, org.apache.commons.compress.compressors.pack200.Pack200Strategy, org.apache.commons.compress.compressors.pack200.Pack200Strategy$1, org.apache.commons.compress.compressors.pack200.Pack200Strategy$2, org.apache.commons.compress.compressors.pack200.Pack200Utils, org.apache.commons.compress.compressors.pack200.TempFileCachingStreamBridge, org.apache.commons.compress.compressors.pack200.TempFileCachingStreamBridge$1, org.apache.commons.compress.compressors.pack200.package-info, org.apache.commons.compress.compressors.package-info, org.apache.commons.compress.compressors.snappy.FramedSnappyCompressorInputStream, org.apache.commons.compress.compressors.snappy.FramedSnappyCompressorOutputStream, org.apache.commons.compress.compressors.snappy.FramedSnappyDialect, org.apache.commons.compress.compressors.snappy.SnappyCompressorInputStream, org.apache.commons.compress.compressors.snappy.SnappyCompressorInputStream$State, org.apache.commons.compress.compressors.snappy.SnappyCompressorOutputStream, org.apache.commons.compress.compressors.snappy.SnappyCompressorOutputStream$1, org.apache.commons.compress.compressors.snappy.package-info, org.apache.commons.compress.compressors.xz.XZCompressorInputStream, org.apache.commons.compress.compressors.xz.XZCompressorInputStream$1, org.apache.commons.compress.compressors.xz.XZCompressorInputStream$Builder, org.apache.commons.compress.compressors.xz.XZCompressorOutputStream, org.apache.commons.compress.compressors.xz.XZCompressorOutputStream$1, org.apache.commons.compress.compressors.xz.XZCompressorOutputStream$Builder, org.apache.commons.compress.compressors.xz.XZUtils, org.apache.commons.compress.compressors.xz.XZUtils$CachedAvailability, org.apache.commons.compress.compressors.xz.package-info, org.apache.commons.compress.compressors.z.ZCompressorInputStream, org.apache.commons.compress.compressors.z.package-info, org.apache.commons.compress.compressors.zstandard.ZstdCompressorInputStream, org.apache.commons.compress.compressors.zstandard.ZstdCompressorOutputStream, org.apache.commons.compress.compressors.zstandard.ZstdCompressorOutputStream$1, org.apache.commons.compress.compressors.zstandard.ZstdCompressorOutputStream$Builder, org.apache.commons.compress.compressors.zstandard.ZstdConstants, org.apache.commons.compress.compressors.zstandard.ZstdUtils, org.apache.commons.compress.compressors.zstandard.ZstdUtils$CachedAvailability, org.apache.commons.compress.compressors.zstandard.package-info, org.apache.commons.compress.harmony.archive.internal.nls.Messages, org.apache.commons.compress.harmony.archive.internal.nls.package-info, org.apache.commons.compress.harmony.pack200.Archive, org.apache.commons.compress.harmony.pack200.Archive$PackingFile, org.apache.commons.compress.harmony.pack200.Archive$SegmentUnit, org.apache.commons.compress.harmony.pack200.AttributeDefinitionBands, org.apache.commons.compress.harmony.pack200.AttributeDefinitionBands$AttributeDefinition, org.apache.commons.compress.harmony.pack200.BHSDCodec, org.apache.commons.compress.harmony.pack200.BandSet, org.apache.commons.compress.harmony.pack200.BandSet$BandAnalysisResults, org.apache.commons.compress.harmony.pack200.BandSet$BandData, org.apache.commons.compress.harmony.pack200.BcBands, org.apache.commons.compress.harmony.pack200.CPClass, org.apache.commons.compress.harmony.pack200.CPConstant, org.apache.commons.compress.harmony.pack200.CPDouble, org.apache.commons.compress.harmony.pack200.CPFloat, org.apache.commons.compress.harmony.pack200.CPInt, org.apache.commons.compress.harmony.pack200.CPLong, org.apache.commons.compress.harmony.pack200.CPMethodOrField, org.apache.commons.compress.harmony.pack200.CPNameAndType, org.apache.commons.compress.harmony.pack200.CPSignature, org.apache.commons.compress.harmony.pack200.CPString, org.apache.commons.compress.harmony.pack200.CPUTF8, org.apache.commons.compress.harmony.pack200.CanonicalCodecFamilies, org.apache.commons.compress.harmony.pack200.ClassBands, org.apache.commons.compress.harmony.pack200.ClassBands$TempParamAnnotation, org.apache.commons.compress.harmony.pack200.Codec, org.apache.commons.compress.harmony.pack200.CodecEncoding, org.apache.commons.compress.harmony.pack200.ConstantPoolEntry, org.apache.commons.compress.harmony.pack200.CpBands, org.apache.commons.compress.harmony.pack200.FileBands, org.apache.commons.compress.harmony.pack200.IcBands, org.apache.commons.compress.harmony.pack200.IcBands$IcTuple, org.apache.commons.compress.harmony.pack200.IntList, org.apache.commons.compress.harmony.pack200.MetadataBandGroup, org.apache.commons.compress.harmony.pack200.NewAttribute, org.apache.commons.compress.harmony.pack200.NewAttribute$ErrorAttribute, org.apache.commons.compress.harmony.pack200.NewAttribute$PassAttribute, org.apache.commons.compress.harmony.pack200.NewAttribute$StripAttribute, org.apache.commons.compress.harmony.pack200.NewAttributeBands, org.apache.commons.compress.harmony.pack200.NewAttributeBands$AttributeLayoutElement, org.apache.commons.compress.harmony.pack200.NewAttributeBands$Call, org.apache.commons.compress.harmony.pack200.NewAttributeBands$Callable, org.apache.commons.compress.harmony.pack200.NewAttributeBands$Integral, org.apache.commons.compress.harmony.pack200.NewAttributeBands$LayoutElement, org.apache.commons.compress.harmony.pack200.NewAttributeBands$Reference, org.apache.commons.compress.harmony.pack200.NewAttributeBands$Replication, org.apache.commons.compress.harmony.pack200.NewAttributeBands$Union, org.apache.commons.compress.harmony.pack200.NewAttributeBands$UnionCase, org.apache.commons.compress.harmony.pack200.Pack200Adapter, org.apache.commons.compress.harmony.pack200.Pack200ClassReader, org.apache.commons.compress.harmony.pack200.Pack200Exception, org.apache.commons.compress.harmony.pack200.Pack200PackerAdapter, org.apache.commons.compress.harmony.pack200.PackingOptions, org.apache.commons.compress.harmony.pack200.PackingUtils, org.apache.commons.compress.harmony.pack200.PackingUtils$PackingLogger, org.apache.commons.compress.harmony.pack200.PopulationCodec, org.apache.commons.compress.harmony.pack200.RunCodec, org.apache.commons.compress.harmony.pack200.Segment, org.apache.commons.compress.harmony.pack200.Segment$ArrayVisitor, org.apache.commons.compress.harmony.pack200.Segment$PassException, org.apache.commons.compress.harmony.pack200.Segment$SegmentAnnotationVisitor, org.apache.commons.compress.harmony.pack200.Segment$SegmentAnnotationVisitor$1, org.apache.commons.compress.harmony.pack200.Segment$SegmentFieldVisitor, org.apache.commons.compress.harmony.pack200.Segment$SegmentMethodVisitor, org.apache.commons.compress.harmony.pack200.SegmentHeader, org.apache.commons.compress.harmony.pack200.SegmentHeader$1, org.apache.commons.compress.harmony.pack200.SegmentHeader$Counter, org.apache.commons.compress.harmony.pack200.package-info, org.apache.commons.compress.harmony.package-info, org.apache.commons.compress.harmony.unpack200.Archive, org.apache.commons.compress.harmony.unpack200.AttrDefinitionBands, org.apache.commons.compress.harmony.unpack200.AttributeLayout, org.apache.commons.compress.harmony.unpack200.AttributeLayoutMap, org.apache.commons.compress.harmony.unpack200.BandSet, org.apache.commons.compress.harmony.unpack200.BcBands, org.apache.commons.compress.harmony.unpack200.ClassBands, org.apache.commons.compress.harmony.unpack200.CpBands, org.apache.commons.compress.harmony.unpack200.FileBands, org.apache.commons.compress.harmony.unpack200.IMatcher, org.apache.commons.compress.harmony.unpack200.IcBands, org.apache.commons.compress.harmony.unpack200.IcTuple, org.apache.commons.compress.harmony.unpack200.MetadataBandGroup, org.apache.commons.compress.harmony.unpack200.NewAttributeBands, org.apache.commons.compress.harmony.unpack200.NewAttributeBands$1, org.apache.commons.compress.harmony.unpack200.NewAttributeBands$AttributeLayoutElement, org.apache.commons.compress.harmony.unpack200.NewAttributeBands$Call, org.apache.commons.compress.harmony.unpack200.NewAttributeBands$Callable, org.apache.commons.compress.harmony.unpack200.NewAttributeBands$Integral, org.apache.commons.compress.harmony.unpack200.NewAttributeBands$LayoutElement, org.apache.commons.compress.harmony.unpack200.NewAttributeBands$Reference, org.apache.commons.compress.harmony.unpack200.NewAttributeBands$Replication, org.apache.commons.compress.harmony.unpack200.NewAttributeBands$Union, org.apache.commons.compress.harmony.unpack200.NewAttributeBands$UnionCase, org.apache.commons.compress.harmony.unpack200.Pack200UnpackerAdapter, org.apache.commons.compress.harmony.unpack200.Segment, org.apache.commons.compress.harmony.unpack200.SegmentConstantPool, org.apache.commons.compress.harmony.unpack200.SegmentConstantPoolArrayCache, org.apache.commons.compress.harmony.unpack200.SegmentConstantPoolArrayCache$CachedArray, org.apache.commons.compress.harmony.unpack200.SegmentHeader, org.apache.commons.compress.harmony.unpack200.SegmentOptions, org.apache.commons.compress.harmony.unpack200.SegmentUtils, org.apache.commons.compress.harmony.unpack200.bytecode.AnnotationDefaultAttribute, org.apache.commons.compress.harmony.unpack200.bytecode.AnnotationsAttribute, org.apache.commons.compress.harmony.unpack200.bytecode.AnnotationsAttribute$Annotation, org.apache.commons.compress.harmony.unpack200.bytecode.AnnotationsAttribute$ElementValue, org.apache.commons.compress.harmony.unpack200.bytecode.Attribute, org.apache.commons.compress.harmony.unpack200.bytecode.BCIRenumberedAttribute, org.apache.commons.compress.harmony.unpack200.bytecode.ByteCode, org.apache.commons.compress.harmony.unpack200.bytecode.CPClass, org.apache.commons.compress.harmony.unpack200.bytecode.CPConstant, org.apache.commons.compress.harmony.unpack200.bytecode.CPConstantNumber, org.apache.commons.compress.harmony.unpack200.bytecode.CPDouble, org.apache.commons.compress.harmony.unpack200.bytecode.CPField, org.apache.commons.compress.harmony.unpack200.bytecode.CPFieldRef, org.apache.commons.compress.harmony.unpack200.bytecode.CPFloat, org.apache.commons.compress.harmony.unpack200.bytecode.CPInteger, org.apache.commons.compress.harmony.unpack200.bytecode.CPInterfaceMethodRef, org.apache.commons.compress.harmony.unpack200.bytecode.CPLong, org.apache.commons.compress.harmony.unpack200.bytecode.CPMember, org.apache.commons.compress.harmony.unpack200.bytecode.CPMethod, org.apache.commons.compress.harmony.unpack200.bytecode.CPMethodRef, org.apache.commons.compress.harmony.unpack200.bytecode.CPNameAndType, org.apache.commons.compress.harmony.unpack200.bytecode.CPRef, org.apache.commons.compress.harmony.unpack200.bytecode.CPString, org.apache.commons.compress.harmony.unpack200.bytecode.CPUTF8, org.apache.commons.compress.harmony.unpack200.bytecode.ClassConstantPool, org.apache.commons.compress.harmony.unpack200.bytecode.ClassFile, org.apache.commons.compress.harmony.unpack200.bytecode.ClassFileEntry, org.apache.commons.compress.harmony.unpack200.bytecode.CodeAttribute, org.apache.commons.compress.harmony.unpack200.bytecode.ConstantPoolEntry, org.apache.commons.compress.harmony.unpack200.bytecode.ConstantValueAttribute, org.apache.commons.compress.harmony.unpack200.bytecode.DeprecatedAttribute, org.apache.commons.compress.harmony.unpack200.bytecode.EnclosingMethodAttribute, org.apache.commons.compress.harmony.unpack200.bytecode.ExceptionTableEntry, org.apache.commons.compress.harmony.unpack200.bytecode.ExceptionsAttribute, org.apache.commons.compress.harmony.unpack200.bytecode.InnerClassesAttribute, org.apache.commons.compress.harmony.unpack200.bytecode.InnerClassesAttribute$InnerClassesEntry, org.apache.commons.compress.harmony.unpack200.bytecode.LineNumberTableAttribute, org.apache.commons.compress.harmony.unpack200.bytecode.LocalVariableTableAttribute, org.apache.commons.compress.harmony.unpack200.bytecode.LocalVariableTypeTableAttribute, org.apache.commons.compress.harmony.unpack200.bytecode.NewAttribute, org.apache.commons.compress.harmony.unpack200.bytecode.NewAttribute$1, org.apache.commons.compress.harmony.unpack200.bytecode.NewAttribute$AbstractBcValue, org.apache.commons.compress.harmony.unpack200.bytecode.NewAttribute$BCIndex, org.apache.commons.compress.harmony.unpack200.bytecode.NewAttribute$BCLength, org.apache.commons.compress.harmony.unpack200.bytecode.NewAttribute$BCOffset, org.apache.commons.compress.harmony.unpack200.bytecode.OperandManager, org.apache.commons.compress.harmony.unpack200.bytecode.RuntimeVisibleorInvisibleAnnotationsAttribute, org.apache.commons.compress.harmony.unpack200.bytecode.RuntimeVisibleorInvisibleParameterAnnotationsAttribute, org.apache.commons.compress.harmony.unpack200.bytecode.RuntimeVisibleorInvisibleParameterAnnotationsAttribute$ParameterAnnotation, org.apache.commons.compress.harmony.unpack200.bytecode.SignatureAttribute, org.apache.commons.compress.harmony.unpack200.bytecode.SourceFileAttribute, org.apache.commons.compress.harmony.unpack200.bytecode.forms.ByteCodeForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.ByteForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.ClassRefForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.ClassSpecificReferenceForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.DoubleForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.FieldRefForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.FloatRefForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.IMethodRefForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.IincForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.InitMethodReferenceForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.IntRefForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.LabelForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.LocalForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.LongForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.LookupSwitchForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.MethodRefForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.MultiANewArrayForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.NarrowClassRefForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.NewClassRefForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.NewInitMethodRefForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.NoArgumentForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.ReferenceForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.ShortForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.SingleByteReferenceForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.StringRefForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.SuperFieldRefForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.SuperInitMethodRefForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.SuperMethodRefForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.SwitchForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.TableSwitchForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.ThisFieldRefForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.ThisInitMethodRefForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.ThisMethodRefForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.VariableInstructionForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.WideForm, org.apache.commons.compress.harmony.unpack200.bytecode.forms.package-info, org.apache.commons.compress.harmony.unpack200.bytecode.package-info, org.apache.commons.compress.harmony.unpack200.package-info, org.apache.commons.compress.java.util.jar.Pack200, org.apache.commons.compress.java.util.jar.Pack200$Packer, org.apache.commons.compress.java.util.jar.Pack200$Unpacker, org.apache.commons.compress.java.util.jar.package-info, org.apache.commons.compress.package-info, org.apache.commons.compress.parallel.FileBasedScatterGatherBackingStore, org.apache.commons.compress.parallel.InputStreamSupplier, org.apache.commons.compress.parallel.ScatterGatherBackingStore, org.apache.commons.compress.parallel.ScatterGatherBackingStoreSupplier, org.apache.commons.compress.parallel.package-info, org.apache.commons.compress.utils.ArchiveUtils, org.apache.commons.compress.utils.BitInputStream, org.apache.commons.compress.utils.BoundedArchiveInputStream, org.apache.commons.compress.utils.BoundedInputStream, org.apache.commons.compress.utils.BoundedSeekableByteChannelInputStream, org.apache.commons.compress.utils.CRC32VerifyingInputStream, org.apache.commons.compress.utils.CharsetNames, org.apache.commons.compress.utils.Charsets, org.apache.commons.compress.utils.ChecksumCalculatingInputStream, org.apache.commons.compress.utils.ChecksumVerifyingInputStream, org.apache.commons.compress.utils.CloseShieldFilterInputStream, org.apache.commons.compress.utils.CountingInputStream, org.apache.commons.compress.utils.CountingOutputStream, org.apache.commons.compress.utils.ExactMath, org.apache.commons.compress.utils.FileNameUtils, org.apache.commons.compress.utils.FixedLengthBlockOutputStream, org.apache.commons.compress.utils.FixedLengthBlockOutputStream$1, org.apache.commons.compress.utils.FixedLengthBlockOutputStream$BufferAtATimeOutputChannel, org.apache.commons.compress.utils.FlushShieldFilterOutputStream, org.apache.commons.compress.utils.IOUtils, org.apache.commons.compress.utils.InputStreamStatistics, org.apache.commons.compress.utils.Iterators, org.apache.commons.compress.utils.Lists, org.apache.commons.compress.utils.MultiReadOnlySeekableByteChannel, org.apache.commons.compress.utils.OsgiUtils, org.apache.commons.compress.utils.ParsingUtils, org.apache.commons.compress.utils.SeekableInMemoryByteChannel, org.apache.commons.compress.utils.ServiceLoaderIterator, org.apache.commons.compress.utils.Sets, org.apache.commons.compress.utils.SkipShieldingInputStream, org.apache.commons.compress.utils.TimeUtils, org.apache.commons.compress.utils.package-info]
[INFO] Analysis only: no trim proof or published changes
[INFO] Vulnerability findings: 6
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
[INFO]   - CVE-2020-13956 org.apache.httpcomponents:httpclient:jar:4.3.4 (compile) [PLANNED_UNVERIFIED]
[INFO]     Aliases: [CVE-2020-13956, GHSA-7r82-7xv7-xcpj]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
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
[INFO]   - CVE-2024-47554 commons-io:commons-io:jar:2.20.0 (compile) [RETAINED_UNCHANGED]
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
[INFO]   - io.github.spockz:example-basic-app:0.1.0-SNAPSHOT -> org.apache.commons:commons-compress:jar:1.28.0 (compile) -> commons-io:commons-io:jar:2.20.0 (compile) {nodeId=n5} [RETAINED]
[INFO]   - io.github.spockz:example-basic-app:0.1.0-SNAPSHOT -> org.apache.commons:commons-compress:jar:1.28.0 (compile) -> org.apache.commons:commons-lang3:jar:3.18.0 (compile) {nodeId=n6} [RETAINED]
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
