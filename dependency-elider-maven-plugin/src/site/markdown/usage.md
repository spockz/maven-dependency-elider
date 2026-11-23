<!-- WHY: Documents the usable Maven goal and the lifecycle safety boundary for plugin consumers. -->
# Maven Plugin Usage

Maven Dependency Elider provides these goals:

* `analyze`: Dry-run that identifies removable dependencies and estimates size savings without changing dependency artifacts, classpaths, or packages. It may write the configured class-usage report.
* `elide`: Active build-time goal that prunes unneeded JARs and trims unreferenced classes during the `process-classes` phase.
* `report`: Displays the persisted elision snapshot and mediated dependency graph from the last successful build.
* `prepare-test-view`: Prepares test-only runtime additions from compiled tests when the isolated test view is enabled. The core extension schedules it at `process-test-classes`.
* `update-cve-index`: Refreshes local vulnerability intelligence from OSV and CVEList v5.

For common questions, see the [User FAQ](faq.html) and [Contributor Decisions and FAQ](https://github.com/spockz/maven-dependency-elider/blob/main/docs/contributor-decisions-and-faq.md).

---

## 1. Quick Installation

Install the plugin and core engine into your local Maven repository:

```sh
./mvnw -pl dependency-elider-maven-plugin -am install
```

---

## 2. Capturing Runtime Telemetry

Elision requires evidence of classes loaded during execution. Capture runtime telemetry using any supported JVM sensor:

| Telemetry Format | File Extension | JVM Flag or Tool Command |
| :--- | :--- | :--- |
| **Class-load logs** | `.log`, `.txt` | `-Xlog:class+load=info:file=target/classes.log` |
| **CDS Class List** | `.lst` | `-XX:DumpLoadedClassList=target/classes.lst` |
| **JDK Flight Recorder** | `.jfr` | `-XX:StartFlightRecording=dumponexit=true,filename=target/recording.jfr` |
| **GraalVM Reflection** | `.json` | Native Image Tracing Agent (`-agentlib:native-image-agent=config-output-dir=...`) |
| **JaCoCo Execution** | `.exec` | JaCoCo Java Agent (`-javaagent:jacocoagent.jar=destfile=target/jacoco.exec`) |

### Telemetry Rules

* Pass one or more file paths as a comma-separated list via `-Delide.traceFiles`.
* Every specified file must exist, be readable, and use a supported format.
* The merged trace set must be non-empty and match at least one class in a resolved JAR dependency.
* Malformed traces or traces with no matching classes fail the goal.

---

## 3. Dry-Run Analysis (`analyze`)

Run `analyze` to inspect potential dependency drops and byte savings without altering Maven artifact views, resolver plans, or packaged outputs. The goal writes class-usage evidence to `elide.reportFile` (default `target/dependency-elider-class-usage.json`) and a summary to `elide.analysisSummaryFile` (default `target/dependency-elider-analysis-report.json`). The summary uses the same schema and renderer as the applied report, marks its mode `ANALYSIS`, and leaves unavailable output byte measurements unknown. The `report` goal can replay it using `-Delide.summaryFile=target/dependency-elider-analysis-report.json` without re-running analysis. The applied report remains separate.

With `elide.preconditionClassPathComplete=true`, Analyze can record physical prerequisite absence after inspecting a complete current runtime inventory. A direct Analyze goal also requires `elide.productionClassesComplete=true`. This observation does not require a removal in the current invocation. The proof scan excludes test-scoped archives, while the dependency decision and SBOM retain their resolved scope rows. Analyze still does not publish CycloneDX or OpenVEX files; classes absent only under its planned elision remain forecasts.

Class-usage schema 1 includes a `dependencyPrediction` section with retained and predicted-elided coordinates, planned class removals marked `PLANNED_UNVERIFIED`, environment/inventory/operation fingerprints, and provenance (`CAPTURED_EFFECTIVE_RESOLVER` or `DETACHED_CURRENT_MODEL`). Detached provenance describes only that request-local resolution. A `PLANNED_CODE_ABSENT` finding means all attributed classes for a complete declared code group are planned for removal; it is not verified archive evidence, a scanner result, a CVE mitigation claim, or a VEX attestation. Prediction does not publish trim archives or output-manifest/generation state. MRJAR analysis may create temporary classpath projections in an operation-owned directory; that directory is removed when prediction completes or fails. Choose a path under `.scratch` if the class-usage report should not be kept with build artifacts:

With or without the core extension, `analyze` can predict exact `groupId:artifactId` bans for supported compile/runtime JARs. It uses either a detached current-model Resolver graph or the captured effective graph with a complete original-input audit. Schema-1 `dependencyPrediction.banPlan` classifies each request as matched (`FORCED_ABSENT_AFTER_RESOLUTION`), excluded before resolution (`EXCLUDED_BEFORE_RESOLUTION`), or unmatched (`UNMATCHED`); every prediction row has `applied=false`. Analysis fails if trace, source, bytecode, retained-resource/provider metadata, or graph closure requires a banned artifact. An unmatched request is not an absence proof. Analyze only predicts and never applies bans or changes Maven artifact views.

```sh
mvn io.github.spockz:dependency-elider-maven-plugin:0.1.0-SNAPSHOT:analyze \
  -Delide.traceFiles=target/classes.log
```

The repository's CVE example transcript includes its configured command, exit status, and captured analysis output. It uses the complete pinned [OSV Maven and CVE List snapshots](https://github.com/spockz/maven-dependency-elider/blob/main/scripts/fixtures/vulnerability-snapshots/README.md), stored with Git LFS. The results reflect those snapshots, not live coverage. `$PROJECT_ROOT` and `$TRANSCRIPT_EVIDENCE` stand for the repository and temporary trace directory created by `make update-transcripts`:

<!-- BEGIN:transcript:analyze-cve-unused-app -->

```text
$ ./mvnw \
  --batch-mode \
  --no-transfer-progress \
  --offline \
  -f \
  examples/example-cve-unused-app/pom.xml \
  io.github.spockz:dependency-elider-maven-plugin:0.1.0-SNAPSHOT:analyze \
  -Delide.traceFiles=$TRANSCRIPT_EVIDENCE/example-cve-unused-app.log \
  -Delide.trimJars=true \
  -Delide.productionClassesComplete=true \
  -Dmaven.compiler.proc=none \
  -Delide.trimSkipArtifacts=org.springframework:spring-context:6.2.7:jar:,org.springframework:spring-beans:6.2.7:jar:,org.springframework:spring-aop:6.2.7:jar:,org.springframework:spring-expression:6.2.7:jar:,org.springframework:spring-core:6.2.7:jar:,org.springframework:spring-jcl:6.2.7:jar:,io.micrometer:micrometer-observation:1.15.0:jar:,io.micrometer:micrometer-commons:1.15.0:jar: \
  -Delide.cveCacheDirectory=$TRANSCRIPT_EVIDENCE/vulnerability-cache \
  -Delide.reportFile=$PROJECT_ROOT/.scratch/transcript-analysis/analyze-cve-unused-app-class-usage.json
Process exit status: 0
[INFO]
[INFO] --------------< io.github.spockz:example-cve-unused-app >---------------
[INFO] Building Example: Graph-Backed CVE Dependency Analysis 0.1.0-SNAPSHOT
[INFO]   from pom.xml
[INFO] --------------------------------[ jar ]---------------------------------
[INFO]
[INFO] --- dependency-elider:0.1.0-SNAPSHOT:analyze (default-cli) @ example-cve-unused-app ---
[WARNING] Dynamic root io.micrometer.context.ThreadLocalAccessor declared by archive io.micrometer:micrometer-observation:jar:1.15.0 (compile) does not resolve to an application or dependency class; it will not retain unrelated archives.
[WARNING] Dynamic root jakarta.servlet.ServletContainerInitializer declared by archive ch.qos.logback:logback-classic:jar:1.5.18 (compile) does not resolve to an application or dependency class; it will not retain unrelated archives.
[WARNING] Dynamic root org.springframework.aop.scope.ScopedProxyBeanRegistrationContributionProvider declared by archive org.springframework:spring-aop:jar:6.2.7 (compile) does not resolve to an application or dependency class; it will not retain unrelated archives.
[WARNING] Dynamic root org.springframework.beans.factory.generator.BeanRegistrationContributionProvider declared by archive org.springframework:spring-aop:jar:6.2.7 (compile) does not resolve to an application or dependency class; it will not retain unrelated archives.
[WARNING] Dynamic root reactor.blockhound.integration.BlockHoundIntegration declared by archive org.springframework:spring-core:jar:6.2.7 (compile) does not resolve to an application or dependency class; it will not retain unrelated archives.
[INFO] Dependency Elider report
[INFO] Project: io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT
[INFO] Snapshot: analysis prediction at <TIMESTAMP>
[INFO] Analysis target JDK release: 21
[INFO] Elider runtime JDK release: <RUNTIME_RELEASE>
[INFO] Analyzed runtime releases: [<RUNTIME_RELEASE>]
[INFO] Runtime input <RUNTIME_IMAGE>: Java <RUNTIME_VERSION> (<RUNTIME_IDENTITY>)
[INFO] Policy: retained=[], banished=[]
[INFO] The snapshot does not revalidate changed inputs when this goal runs.
[INFO] Conventional Java source layout assumption saved for this run: true
[INFO] Whole artifacts that would be dropped: 1 / 26 (original JAR file bytes: 657.80 KiB)
[INFO] Program classes that would be removed with dropped JARs: 395 (uncompressed .class entry payload bytes: 1.37 MiB; excludes module descriptors and archive sanitation metadata)
[INFO]   - org.apache.commons:commons-lang3:jar:3.17.0 (compile): 657.80 KiB original JAR, 395 class entries, 1.37 MiB
[INFO] Raw trace decision drops before graph safety: 2
[INFO] Planned bans: none
[INFO] Program classes that would be pruned from retained JARs: 331 (uncompressed omitted .class payload bytes: unknown; excludes module descriptors and archive metadata)
[INFO]   - com.fasterxml.jackson.core:jackson-core:jar:2.19.0 (compile): 20 classes, unknown
[INFO]     Classes that would be pruned from this JAR: [com.fasterxml.jackson.core.JsonpCharacterEscapes, com.fasterxml.jackson.core.async.package-info, com.fasterxml.jackson.core.base.package-info, com.fasterxml.jackson.core.exc.package-info, com.fasterxml.jackson.core.filter.FilteringGeneratorDelegate, ... (+15 more in analysis report)]
[INFO]   - com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile): 70 classes, unknown
[INFO]     Classes that would be pruned from this JAR: [com.fasterxml.jackson.databind.EnumNamingStrategies, com.fasterxml.jackson.databind.EnumNamingStrategies$CamelCaseStrategy, com.fasterxml.jackson.databind.PropertyNamingStrategies, com.fasterxml.jackson.databind.PropertyNamingStrategies$KebabCaseStrategy, com.fasterxml.jackson.databind.PropertyNamingStrategies$LowerCamelCaseStrategy, ... (+65 more in analysis report)]
[INFO]   - org.apache.commons:commons-text:jar:1.9 (compile): 132 classes, unknown
[INFO]     Classes that would be pruned from this JAR: [org.apache.commons.text.AlphabetConverter, org.apache.commons.text.Builder, org.apache.commons.text.CaseUtils, org.apache.commons.text.CharacterPredicate, org.apache.commons.text.CharacterPredicates, ... (+127 more in analysis report)]
[INFO]   - org.codehaus.janino:commons-compiler:jar:3.1.12 (compile): 51 classes, unknown
[INFO]     Classes that would be pruned from this JAR: [org.codehaus.commons.compiler.Sandbox, org.codehaus.commons.compiler.Sandbox$1, org.codehaus.commons.compiler.io.InputStreams, org.codehaus.commons.compiler.io.package-info, org.codehaus.commons.compiler.java8.java.util.function.package-info, ... (+46 more in analysis report)]
[INFO]   - org.codehaus.janino:janino:jar:3.1.12 (compile): 52 classes, unknown
[INFO]     Classes that would be pruned from this JAR: [org.codehaus.janino.AntCompilerAdapter, org.codehaus.janino.CachingJavaSourceClassLoader, org.codehaus.janino.Unparser, org.codehaus.janino.Unparser$1, org.codehaus.janino.Unparser$10, ... (+47 more in analysis report)]
[INFO]   - org.slf4j:slf4j-api:jar:2.0.17 (compile): 6 classes, unknown
[INFO]     Classes that would be pruned from this JAR: [org.slf4j.LoggerFactoryFriend, org.slf4j.MarkerFactory, org.slf4j.helpers.MarkerIgnoringBase, org.slf4j.helpers.Slf4jEnvUtil, org.slf4j.spi.LoggerFactoryBinder, ... (+1 more in analysis report)]
[INFO] Analysis only: no trim proof or published changes
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
[INFO]   - CVE-2017-15095 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2017-15095, GHSA-h592-38cm-4ggp]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2017-17485 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
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
[INFO]   - CVE-2017-7525 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2017-7525, GHSA-qxxx-2pp7-5hmx]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-11040 org.springframework:spring-core:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2018-11040, GHSA-f26x-pr96-vw86]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-11307 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2018-11307, GHSA-qr7j-h6gg-jmgc]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-1199 org.springframework:spring-core:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2018-1199, GHSA-v596-fwhq-8x48]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-12022 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2018-12022, GHSA-cjjf-94ff-43w7]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-12023 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
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
[INFO]   - CVE-2018-14718 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2018-14718, GHSA-645p-88qh-w398]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-14719 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2018-14719, GHSA-4gq5-ch57-c2mg]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-14720 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2018-14720, GHSA-x2w5-5m2g-7h5m]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-14721 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2018-14721, GHSA-9mxf-g3x6-wv74]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-15756 org.springframework:spring-core:jar:6.2.7 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2018-15756, GHSA-ffvq-7w96-97p7]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-19360 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2018-19360, GHSA-f9hv-mg5h-xcw9]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-19361 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2018-19361, GHSA-mx9v-gmh4-mgqw]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-19362 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2018-19362, GHSA-c8hm-7hpq-7jhg]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-5968 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2018-5968, GHSA-w3f4-3q6j-rh82]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2018-7489 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2018-7489, GHSA-cggj-fvv3-cqwv]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2019-12086 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2019-12086, GHSA-5ww9-j83m-q7qx]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2019-12384 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2019-12384, GHSA-mph4-vhrx-mv67]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2019-12814 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2019-12814, GHSA-cmfg-87vq-g5g4]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2019-14379 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2019-14379, GHSA-6fpp-rgj9-8rwc]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2019-14439 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2019-14439, GHSA-gwp4-hfv6-p7hw]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2019-14540 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2019-14540, GHSA-h822-r4r5-v8jg]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2019-14892 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2019-14892, GHSA-cf6r-3wgc-h863]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2019-14893 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2019-14893, GHSA-qmqc-x3r4-6v39]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2019-16335 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2019-16335, GHSA-85cw-hj65-qqv9]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2019-16942 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2019-16942, GHSA-mx7p-6679-8g3q]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2019-16943 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2019-16943, GHSA-fmmc-742q-jg75]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2019-17267 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2019-17267, GHSA-f3j5-rmmp-3fc5]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2019-17531 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2019-17531, GHSA-gjmw-vf9h-g25v]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2019-20330 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2019-20330, GHSA-gww7-p5w4-wrfv]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-10650 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2020-10650, GHSA-rpr3-cw39-3pxh]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-10672 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2020-10672, GHSA-95cm-88f5-f2c7]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-10673 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2020-10673, GHSA-fqwf-pjwf-7vqv]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-10968 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2020-10968, GHSA-rf6r-2c4q-2vwg]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-10969 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2020-10969, GHSA-758m-v56v-grj4]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-11111 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2020-11111, GHSA-v3xw-c963-f5hc]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-11112 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2020-11112, GHSA-58pp-9c76-5625]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-11113 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2020-11113, GHSA-9vvp-fxw6-jcxr]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-11619 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2020-11619, GHSA-27xj-rqx5-2255]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-11620 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2020-11620, GHSA-h4rc-386g-6m85]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-14060 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2020-14060, GHSA-j823-4qch-3rgm]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-14061 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2020-14061, GHSA-c2q3-4qrh-fm48]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-14062 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2020-14062, GHSA-c265-37vj-cwcc]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-14195 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2020-14195, GHSA-mc6h-4qgp-37qh]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-24616 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2020-24616, GHSA-h3cw-g4mq-c5x2]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-24750 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2020-24750, GHSA-qjw2-hr98-qgfh]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-25649 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2020-25649, GHSA-288c-cq4h-88gq]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-35490 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2020-35490, GHSA-wh8g-3j2c-rqj5]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-35491 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2020-35491, GHSA-r3gr-cxrf-hg25]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-35728 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2020-35728, GHSA-5r5r-6hpj-8gg9]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-36179 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2020-36179, GHSA-9gph-22xh-8x98]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-36180 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2020-36180, GHSA-8c4j-34r4-xr8g]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-36181 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2020-36181, GHSA-cvm9-fjm9-3572]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-36182 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2020-36182, GHSA-89qr-369f-5m5x]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-36183 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2020-36183, GHSA-9m6f-7xcq-8vf8]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-36184 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2020-36184, GHSA-m6x4-97wx-4q27]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-36185 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2020-36185, GHSA-8w26-6f25-cm9x]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-36186 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2020-36186, GHSA-v585-23hc-c647]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-36187 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2020-36187, GHSA-r695-7vr9-jgc2]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-36188 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2020-36188, GHSA-f9xh-2qgp-cq57]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-36189 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2020-36189, GHSA-vfqx-33qm-g869]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-36518 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2020-36518, GHSA-57j2-w4cx-62h2]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-8840 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2020-8840, GHSA-4w82-r329-3q67]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-9546 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2020-9546, GHSA-5p34-5m6p-p58g]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-9547 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2020-9547, GHSA-q93h-jc49-78gg]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2020-9548 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2020-9548, GHSA-p43x-xfjf-5jhr]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2021-20190 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
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
[INFO]   - CVE-2021-46877 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
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
[INFO]   - CVE-2022-42003 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2022-42003, GHSA-jjjh-jjxp-wpff]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2022-42004 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2022-42004, GHSA-rgv9-q543-rqg4]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2022-42889 org.apache.commons:commons-text:jar:1.9 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2022-42889, GHSA-599f-7c49-w659]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: PLANNED_CODE_ABSENT; Analysis would remove declared code; the resulting archive has not been verified
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
[INFO]   - CVE-2025-48924 org.apache.commons:commons-lang3:jar:3.17.0 (compile) [PLANNED_UNVERIFIED]
[INFO]     Aliases: [CVE-2025-48924, GHSA-j288-q9x7-2f5v]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [CVE_LIST, OSV]
[INFO]   - CVE-2025-49128 com.fasterxml.jackson.core:jackson-core:jar:2.19.0 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2025-49128, GHSA-wf8f-6423-gfxg]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2025-52999 com.fasterxml.jackson.core:jackson-core:jar:2.19.0 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2025-52999, GHSA-h46c-h94j-95f3]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-10532 ch.qos.logback:logback-core:jar:1.5.18 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-10532, GHSA-jhq6-gfmj-v8fx]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-110879 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
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
[INFO]   - CVE-2026-18401 com.fasterxml.jackson.core:jackson-core:jar:2.19.0 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2026-18401, GHSA-72hv-8253-57qq]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Declared code: [src/main/java/com/fasterxml/jackson/core/json/async/NonBlockingUtf8JsonParserBase.java] RESOLVED; classes: [com.fasterxml.jackson.core.json.async.NonBlockingUtf8JsonParserBase]; reasons: []
[INFO]     Declared code: [NonBlockingUtf8JsonParserBase._finishNumberIntegralPart] RESOLVED; classes: [com.fasterxml.jackson.core.json.async.NonBlockingUtf8JsonParserBase]; reasons: []
[INFO]     Declared code: [NonBlockingUtf8JsonParserBase._valueComplete] UNRESOLVED; classes: []; reasons: [ROUTINE_METHOD_NOT_FOUND]
[INFO]     Sources: [CVE_LIST, OSV]
[INFO]   - CVE-2026-19032 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2026-19032, GHSA-wjgm-6hv5-3cvf]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
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
[INFO]   - CVE-2026-50193 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2026-50193, GHSA-3wrr-7qpf-2prh]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-54512 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2026-54512, GHSA-j3rv-43j4-c7qm]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-54513 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2026-54513, GHSA-rmj7-2vxq-3g9f]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-54514 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2026-54514, GHSA-hgj6-7826-r7m5]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-54515 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2026-54515, GHSA-5jmj-h7xm-6q6v]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-54516 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2026-54516, GHSA-9fxm-vc8v-hj55]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-54517 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2026-54517, GHSA-5hh8-q8hv-fr38]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-54518 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2026-54518, GHSA-rcqc-6cw3-h962]
[INFO]     Applicability: NO_AFFECTED_ASSERTION; intent: UNRESOLVED
[INFO]     Outcome: UNRESOLVED; Applicability or assessment intent is unresolved for this version
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-59888 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2026-59888, GHSA-3pjw-73gf-8qr5]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-59889 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2026-59889, GHSA-5gvw-p9qm-jgwh]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-68494 com.fasterxml.jackson.core:jackson-core:jar:2.19.0 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2026-68494, GHSA-r7wm-3cxj-wff9]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Declared code: [src/main/java/com/fasterxml/jackson/core/json/async/NonBlockingUtf8JsonParserBase.java] RESOLVED; classes: [com.fasterxml.jackson.core.json.async.NonBlockingUtf8JsonParserBase]; reasons: []
[INFO]     Declared code: [NonBlockingUtf8JsonParserBase._finishNumberIntegralPart] RESOLVED; classes: [com.fasterxml.jackson.core.json.async.NonBlockingUtf8JsonParserBase]; reasons: []
[INFO]     Declared code: [NonBlockingUtf8JsonParserBase._startNegativeNumber] RESOLVED; classes: [com.fasterxml.jackson.core.json.async.NonBlockingUtf8JsonParserBase]; reasons: []
[INFO]     Declared code: [NonBlockingUtf8JsonParserBase._startPositiveNumber] RESOLVED; classes: [com.fasterxml.jackson.core.json.async.NonBlockingUtf8JsonParserBase]; reasons: []
[INFO]     Declared code: [com.fasterxml.jackson.core.async.ByteArrayFeeder] REVIEW_LEAD; classes: []; reasons: [HEURISTIC_REQUIRES_REVIEW]
[INFO]     Declared code: [com.fasterxml.jackson.core.exc.StreamConstraintsException] REVIEW_LEAD; classes: []; reasons: [HEURISTIC_REQUIRES_REVIEW]
[INFO]     Heuristic leads: [com.fasterxml.jackson.core.async.ByteArrayFeeder, com.fasterxml.jackson.core.exc.StreamConstraintsException]
[INFO]     Sources: [CVE_LIST, OSV]
[INFO]   - CVE-2026-68497 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2026-68497, GHSA-q4xh-88c3-wmh7]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Declared code: [src/main/java/com/fasterxml/jackson/databind/ext/CoreXMLDeserializers.java] RESOLVED; classes: [com.fasterxml.jackson.databind.ext.CoreXMLDeserializers, com.fasterxml.jackson.databind.ext.CoreXMLDeserializers$Std]; reasons: []
[INFO]     Declared code: [com.fasterxml.jackson.databind.ext.CoreXMLDeserializers.Std._deserialize] UNRESOLVED; classes: []; reasons: [ROUTINE_OWNER_NOT_FOUND]
[INFO]     Sources: [CVE_LIST, OSV]
[INFO]   - CVE-2026-68498 com.fasterxml.jackson.core:jackson-core:jar:2.19.0 (compile) [PLANNED_TRIM]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Declared code: [src/main/java/com/fasterxml/jackson/core/json/ReaderBasedJsonParser.java] RESOLVED; classes: [com.fasterxml.jackson.core.json.ReaderBasedJsonParser]; reasons: []
[INFO]     Declared code: [ReaderBasedJsonParser._parseName2] RESOLVED; classes: [com.fasterxml.jackson.core.json.ReaderBasedJsonParser]; reasons: []
[INFO]     Sources: [CVE_LIST]
[INFO]   - CVE-2026-77310 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2026-77310, GHSA-vvgp-rfg2-7rr6]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - CVE-2026-83557 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2026-83557, GHSA-gx83-3vf8-gh7j]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Declared code: [src/main/java/com/fasterxml/jackson/databind/jsontype/DefaultBaseTypeLimitingValidator.java] RESOLVED; classes: [com.fasterxml.jackson.databind.jsontype.DefaultBaseTypeLimitingValidator, com.fasterxml.jackson.databind.jsontype.DefaultBaseTypeLimitingValidator$UnsafeBaseTypes]; reasons: []
[INFO]     Declared code: [com.fasterxml.jackson.databind.jsontype.DefaultBaseTypeLimitingValidator.isUnsafeBaseType] RESOLVED; classes: [com.fasterxml.jackson.databind.jsontype.DefaultBaseTypeLimitingValidator, com.fasterxml.jackson.databind.jsontype.DefaultBaseTypeLimitingValidator$UnsafeBaseTypes]; reasons: []
[INFO]     Sources: [CVE_LIST, OSV]
[INFO]   - CVE-2026-89407 com.fasterxml.jackson.core:jackson-core:jar:2.19.0 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2026-89407, GHSA-p6pp-m3f8-5c89]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Declared code: [com.fasterxml.jackson.core.io.NumberInput.looksLikeValidNumber] RESOLVED; classes: [com.fasterxml.jackson.core.io.NumberInput]; reasons: []
[INFO]     Declared code: [com.fasterxml.jackson.core.io.NumberInput] REVIEW_LEAD; classes: []; reasons: [HEURISTIC_REQUIRES_REVIEW]
[INFO]     Heuristic leads: [com.fasterxml.jackson.core.io.NumberInput]
[INFO]     Sources: [CVE_LIST, OSV]
[INFO]   - CVE-2026-89425 com.fasterxml.jackson.core:jackson-core:jar:2.19.0 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2026-89425, GHSA-7hhh-6rmp-j9qf]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Declared code: [com.fasterxml.jackson.core.json.UTF8DataInputJsonParser._reportInvalidToken] RESOLVED; classes: [com.fasterxml.jackson.core.json.UTF8DataInputJsonParser]; reasons: []
[INFO]     Sources: [CVE_LIST, OSV]
[INFO]   - CVE-2026-91776 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2026-91776, GHSA-wv8q-qhhj-9h54]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Declared code: [com.fasterxml.jackson.databind.jsontype.impl.TypeDeserializerBase._findDeserializer] RESOLVED; classes: [com.fasterxml.jackson.databind.jsontype.impl.TypeDeserializerBase]; reasons: []
[INFO]     Sources: [CVE_LIST, OSV]
[INFO]   - CVE-2026-91777 com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Aliases: [CVE-2026-91777, GHSA-cxp5-3px4-pw24]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Declared code: [com.fasterxml.jackson.databind.deser.std.CollectionDeserializer.CollectionReferringAccumulator.resolveForwardReference] UNRESOLVED; classes: []; reasons: [ROUTINE_OWNER_NOT_FOUND]
[INFO]     Declared code: [com.fasterxml.jackson.databind.deser.std.MapDeserializer.MapReferringAccumulator.resolveForwardReference] UNRESOLVED; classes: []; reasons: [ROUTINE_OWNER_NOT_FOUND]
[INFO]     Sources: [CVE_LIST, OSV]
[INFO]   - CVE-2026-9828 ch.qos.logback:logback-core:jar:1.5.18 (compile) [RETAINED_UNCHANGED]
[INFO]     Aliases: [CVE-2026-9828, GHSA-p47f-322f-whfh]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO]   - GHSA-mhm7-754m-9p8w com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) [PLANNED_TRIM]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; No complete physical proof was available for an effective declaration. No unique trimmed artifact is available for physical omission proof
[INFO]     Sources: [OSV]
[INFO] CVE Freshness: INCOMPLETE (partial or mixed source freshness; some sources failed or are incomplete)
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
[INFO] Mediated TEST dependency graph (captured and saved by the analyze goal):
[INFO]   - io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT {nodeId=n0} [RETAINED]
[INFO]   - io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT -> ch.qos.logback:logback-classic:jar:1.5.18 (compile) {nodeId=n3} [RETAINED]
[INFO]   - io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT -> com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) {nodeId=n2} [RETAINED, WOULD_TRIM]
[INFO]   - io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT -> org.apache.commons:commons-text:jar:1.9 (compile) {nodeId=n1} [RETAINED, WOULD_TRIM]
[INFO]   - io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT -> org.codehaus.janino:janino:jar:3.1.12 (compile) {nodeId=n4} [RETAINED, WOULD_TRIM]
[INFO]   - io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT -> org.junit.jupiter:junit-jupiter:jar:5.11.4 (test) {nodeId=n6} [RETAINED]
[INFO]   - io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT -> org.springframework:spring-context:jar:6.2.7 (compile) {nodeId=n5} [RETAINED]
[INFO]   - io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT -> ch.qos.logback:logback-classic:jar:1.5.18 (compile) -> ch.qos.logback:logback-core:jar:1.5.18 (compile) {nodeId=n10} [RETAINED]
[INFO]   - io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT -> ch.qos.logback:logback-classic:jar:1.5.18 (compile) -> org.slf4j:slf4j-api:jar:2.0.17 (compile) {nodeId=n11} [RETAINED, WOULD_TRIM]
[INFO]   - io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT -> com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) -> com.fasterxml.jackson.core:jackson-annotations:jar:2.19.0 (compile) {nodeId=n8} [RETAINED]
[INFO]   - io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT -> com.fasterxml.jackson.core:jackson-databind:jar:2.18.2 (compile) -> com.fasterxml.jackson.core:jackson-core:jar:2.19.0 (compile) {nodeId=n9} [RETAINED, WOULD_TRIM]
[INFO]   - io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT -> org.apache.commons:commons-text:jar:1.9 (compile) -> org.apache.commons:commons-lang3:jar:3.17.0 (compile) {nodeId=n7} [WOULD_DROP]
[INFO]   - io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT -> org.codehaus.janino:janino:jar:3.1.12 (compile) -> org.codehaus.janino:commons-compiler:jar:3.1.12 (compile) {nodeId=n12} [RETAINED, WOULD_TRIM]
[INFO]   - io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT -> org.junit.jupiter:junit-jupiter:jar:5.11.4 (test) -> org.junit.jupiter:junit-jupiter-api:jar:5.12.2 (test) {nodeId=n18} [RETAINED]
[INFO]   - io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT -> org.junit.jupiter:junit-jupiter:jar:5.11.4 (test) -> org.junit.jupiter:junit-jupiter-engine:jar:5.12.2 (test) {nodeId=n20} [RETAINED]
[INFO]   - io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT -> org.junit.jupiter:junit-jupiter:jar:5.11.4 (test) -> org.junit.jupiter:junit-jupiter-params:jar:5.12.2 (test) {nodeId=n19} [RETAINED]
[INFO]   - io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT -> org.springframework:spring-context:jar:6.2.7 (compile) -> io.micrometer:micrometer-observation:jar:1.15.0 (compile) {nodeId=n17} [RETAINED]
[INFO]   - io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT -> org.springframework:spring-context:jar:6.2.7 (compile) -> org.springframework:spring-aop:jar:6.2.7 (compile) {nodeId=n13} [RETAINED]
[INFO]   - io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT -> org.springframework:spring-context:jar:6.2.7 (compile) -> org.springframework:spring-beans:jar:6.2.7 (compile) {nodeId=n14} [RETAINED]
[INFO]   - io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT -> org.springframework:spring-context:jar:6.2.7 (compile) -> org.springframework:spring-core:jar:6.2.7 (compile) {nodeId=n15} [RETAINED]
[INFO]   - io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT -> org.springframework:spring-context:jar:6.2.7 (compile) -> org.springframework:spring-expression:jar:6.2.7 (compile) {nodeId=n16} [RETAINED]
[INFO]   - io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT -> org.junit.jupiter:junit-jupiter:jar:5.11.4 (test) -> org.junit.jupiter:junit-jupiter-api:jar:5.12.2 (test) -> org.apiguardian:apiguardian-api:jar:1.1.2 (test) {nodeId=n25} [RETAINED]
[INFO]   - io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT -> org.junit.jupiter:junit-jupiter:jar:5.11.4 (test) -> org.junit.jupiter:junit-jupiter-api:jar:5.12.2 (test) -> org.junit.platform:junit-platform-commons:jar:1.12.2 (test) {nodeId=n24} [RETAINED]
[INFO]   - io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT -> org.junit.jupiter:junit-jupiter:jar:5.11.4 (test) -> org.junit.jupiter:junit-jupiter-api:jar:5.12.2 (test) -> org.opentest4j:opentest4j:jar:1.3.0 (test) {nodeId=n23} [RETAINED]
[INFO]   - io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT -> org.junit.jupiter:junit-jupiter:jar:5.11.4 (test) -> org.junit.jupiter:junit-jupiter-engine:jar:5.12.2 (test) -> org.junit.platform:junit-platform-engine:jar:1.12.2 (test) {nodeId=n26} [RETAINED]
[INFO]   - io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT -> org.springframework:spring-context:jar:6.2.7 (compile) -> io.micrometer:micrometer-observation:jar:1.15.0 (compile) -> io.micrometer:micrometer-commons:jar:1.15.0 (compile) {nodeId=n22} [RETAINED]
[INFO]   - io.github.spockz:example-cve-unused-app:0.1.0-SNAPSHOT -> org.springframework:spring-context:jar:6.2.7 (compile) -> org.springframework:spring-core:jar:6.2.7 (compile) -> org.springframework:spring-jcl:jar:6.2.7 (compile) {nodeId=n21} [RETAINED]
[INFO]   JAR trim cache: unavailable (Analyze reports an in-memory prediction only)
[INFO]   Analysis report: <PROJECT_ROOT>/examples/example-cve-unused-app/target/dependency-elider-analysis-report.json
[INFO]   Class usage report: <PROJECT_ROOT>/.scratch/transcript-analysis/analyze-cve-unused-app-class-usage.json
[INFO]   Test view: unavailable: tests were not compiled during analyze
[INFO] ------------------------------------------------------------------------
[INFO] ------------------------------------------------------------------------
[INFO] Total time: <BUILD_TIME>
[INFO] Finished at: <TIMESTAMP>
[INFO] ------------------------------------------------------------------------
```

<!-- END:transcript:analyze-cve-unused-app -->

### Analysis Options

| Option | Default | Description |
| :--- | :--- | :--- |
| `-Delide.traceFiles` | *(none)* | Comma-separated paths to runtime telemetry traces (required). |
| `-Delide.trimJars` | `false` | When `true`, simulates intra-JAR trimming and evaluates CVE absence proofs without modifying files. |
| `-Delide.trimWorkers` | `4` | Maximum worker threads for JAR preparation, closure analysis, and archive sanitization. Actual concurrency is also capped by available processors and pending work; `1` runs sequentially. |
| `-Delide.retainedArtifacts` | *(empty)* | Comma-separated coordinates (`groupId:artifactId[:version[:type[:classifier]]]`) to retain regardless of trace evidence. |
| `-Delide.banishedDependencies` | *(empty)* | Comma-separated exact, trimmed `groupId:artifactId` requests; wildcards and version/type/classifier fields are unsupported. Matched or pre-resolution-excluded requests require `elide.productionClassesComplete=true` or a trusted `process-classes` lifecycle binding. A matching unsupported Maven scope or artifact type fails closed. Analyze predicts matched, pre-resolution-excluded, or unmatched outcomes and never applies them; Elide applies only a validated plan before publication. |
| `-Delide.failOnForbiddenCode` | `false` | Fail the goal when an explicit forbidden-code policy finds a violation. All outcomes are reported with either setting. |
| `-Delide.productionOutput` | *(empty)* | Path to compiled classes (e.g. `target/classes`) to enable static code reference scanning. |
| `-Delide.conservativeServiceLoaderRoots` | `true` | When `true`, retains unproven ServiceLoader SPI roots; when `false`, prunes unproven SPI roots. |
| `-Delide.reportFile` | `target/dependency-elider-class-usage.json` | Path for the class-usage analysis report. |

Only resolved regular JARs in `compile` and `runtime` scopes are considered for elision. Non-JAR artifacts and other dependency scopes are always retained.

---

## 4. Active Build Elision (`elide`)

The `elide` goal defaults to Maven's `process-classes` lifecycle phase, after production compilation and before tests and packaging. An explicit execution phase remains authoritative.

### Step 1: Enable the Core Extension

To enable whole-artifact dependency removal, declare the core extension in the consumer project's `.mvn/extensions.xml`:

```xml
<extensions>
  <extension>
    <groupId>io.github.spockz</groupId>
    <artifactId>dependency-elider-maven-plugin</artifactId>
    <version>0.1.0-SNAPSHOT</version>
  </extension>
</extensions>
```

> **Important**: Without this extension, ordinary trace-derived whole-artifact drops normally remain retained, though retained-JAR trimming still functions. When an explicit ban is requested, Elide uses isolated current-model Resolver planning and may also evaluate unrelated trace-derived drops; both ban-driven and ordinary drops require graph and retained-content closure before publication.

The persisted Elide summary records applied-ban outcomes in `appliedBans`: matched artifacts are `FORCED_ABSENT_AFTER_RESOLUTION`, declarations removed before resolution are `EXCLUDED_BEFORE_RESOLUTION`, and unmatched requests are `UNMATCHED`. Unmatched requests are not applied and do not prove absence. `rawDroppedCoordinates` excludes policy-forced absences, while total absent-artifact metrics include them.

### Step 2: Run the Elision Build

Invoke `elide` on the command line alongside your build goals:

```sh
mvn io.github.spockz:dependency-elider-maven-plugin:0.1.0-SNAPSHOT:elide package \
  -Delide.skip=false \
  -Delide.traceFiles=target/classes.log \
  -Delide.trimJars=true
```

Or configure the execution permanently in `pom.xml`:

```xml
<build>
  <plugins>
    <plugin>
      <groupId>io.github.spockz</groupId>
      <artifactId>dependency-elider-maven-plugin</artifactId>
      <version>0.1.0-SNAPSHOT</version>
      <executions>
        <execution>
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

### Elision Configuration Reference

| Option | Default | Description |
| :--- | :--- | :--- |
| `elide.skip` | `false` | Disables elision and trimming when set to `true`. |
| `elide.leafOnly` | `true` | Restricts dependency elision and intra-JAR trimming to leaf modules in multi-module Maven reactors. Intermediate modules with downstream reactor dependents or `pom` packaging skip elision, allowing internal libraries to build and test against standard dependencies and leaving definitive elision to final application packaging modules. Set to `false` to analyze every module. |
| `elide.traceFiles` | *(none)* | Comma-separated paths to runtime telemetry traces (required). |
| `elide.trimJars` | `false` | Enables ProGuard Core link closure to trim unreferenced classes from retained JARs. |
| `elide.trimWorkers` | `4` | Maximum worker threads for JAR preparation, closure analysis, and archive sanitization. Actual concurrency is also capped by available processors and pending work; `1` runs sequentially. |
| `elide.preconditionClassPathComplete` | `false` | Opts into exact prerequisite-class proof in Elide or physical current-inventory assessment in Analyze. The inventory contains production class/resource output and non-test-scoped effective dependency archives. Isolated test source, class, and resource outputs and test-scoped dependency archives are excluded; ordinary `testCompile` and `testResources` may run. Test output overlapping a production root, custom test compiler arguments or output directories that could redirect classes, and unmodeled production writers suppress proof. The compiler guard checks the production `compile` goal and production target; test-only compiler processing and target settings do not expand the runtime inventory. If Elide reaches tests, it requires the standard Surefire `default-test` execution with `-DskipTests=true` so tests cannot mutate production outputs after capture. |

Packaging is modeled only for maven-shade-plugin 3.6.0 with one `package`/`shade` execution and one built-in manifest transformer whose `mainClass` is resolved. The inherited signature-only resource exclusions in the examples are allowed. Other Shade filters, transformers, inputs, dependencies, source-JAR properties, or custom maven-jar-plugin configuration suppress proof.
If the requested lifecycle reaches `test`, the guard requires the standard Maven Surefire Plugin 3.5.2 `default-test` execution and explicit `-DskipTests=true`. Test compilation remains enabled, but isolated test output is excluded from runtime provider inventory; baseline fixture runs execute their tests normally.
| `elide.assumeConventionalJavaSourceLayout` | `true` | Allows the documented conventional Java source-root translation when exact-path lookup does not locate a structured source claim. Set `false` to require an exact archive path. It never waives complete bytecode attribution or verified artifact identity. The assumption is saved in proof/report provenance; `report` uses the value from the last successful elision snapshot. |
| `elide.productionClassesComplete` | `false` | Asserts that production output contains all compiled production classes. The default `elide` phase is `process-classes`; an explicit phase remains authoritative. Source-free modules may have absent or empty output, while projects with Java sources must have compiled classes. This assertion also allows direct `elide` and `analyze` goals to inspect current runtime inputs without lifecycle provenance. Analyze records physical prerequisite absence from those inputs when `elide.preconditionClassPathComplete=true`; planned removals remain forecasts. Production roots come from compiled bytecode; retain dependencies used only through inlined constants explicitly with `retainedArtifacts`. The legacy `elide.sourceRootsComplete=true` property is rejected with migration guidance.
| `elide.trimRoots` | *(none)* | Comma-separated additional root classes (e.g. `com.example.AppRoot`). |
| `elide.trimSkipArtifacts` | *(none)* | Comma-separated coordinates of retained JARs to keep byte-identical. Their classes serve as roots for sibling closure. |
| `elide.snykEnabled` | `false` | Query Snyk for project package findings during `analyze` and `elide`. Requires an authorized API account, `SNYK_TOKEN`, and an organization ID. |
| `elide.snykOrgId` | `SNYK_ORG_ID` | Snyk organization ID for the optional package-issues API. |
| `elide.snykApiBaseUri` | `https://api.snyk.io` | Snyk regional HTTPS API origin; only supported Snyk API hosts are accepted. |
| `elide.retainDuplicateClassOwners` | *(none)* | Comma-separated class names or globs (`*` within a package, `**` across packages, e.g. `org.example.**`). When a matching class is present in several dependency JARs, every owning JAR is retained whole and byte-identical, including owners that would otherwise be dropped. Unmatched duplicates still fail the build. |
| `elide.trimDuplicateClassOwners` | *(none)* | Comma-separated class names or globs with the same syntax. Every matching duplicate class is kept in every owning JAR, including owners that would otherwise be dropped; with `trimJars=true`, their other unused classes can still be trimmed. If both lists match a class, `retainDuplicateClassOwners` wins; the same pattern in both lists is rejected. |
| `elide.mrjarStrategy` | `vertical-shading` | With `trimJars=true`, `vertical-shading` elevates and trims the configured compiler release view. Higher-tier entries are preserved while their analyzed bodies retain sibling dependencies. Set to `pass-through` to preserve the entire multi-release input JAR byte-identically. When another dependency is trimmed, the unchanged MRJAR contributes closure for the selected runtime views. |
| `elide.failOnUnsupportedModuleInfo` | `false` | When `false`, JARs with root `module-info.class` pass through unchanged on the classpath. When `true`, they fail the build. |
| `elide.conservativeServiceLoaderRoots` | `true` | When `true`, retains unproven ServiceLoader dynamic roots declared in `META-INF/services/`. When `false`, unproven SPI roots are pruned. |
| `elide.summaryFile` | `target/dependency-elider-report.json` | Path for the persisted elision snapshot read by `report`. |
| `elide.testCompilationView` | `false` | Opts into the scoped original test compilation view and automatic test-only preparation. Requires the core extension, exactly one opted-in project, and a successful `elide` execution earlier in the same invocation. One opted-in leaf in a sequential reactor has been tested; parallel Maven reactor execution (`-T`) is unsupported. |
| `elide.testAdditionsJar` | *(none)* | Optional caller-supplied test runtime JAR. When set, it bypasses automatic analysis and the test report labels its contents unverified. |
| `elide.testViewReportFile` | `target/elider/test-view-report.json` | Separate saved test-view observation used by `report`; it does not change the production report, SBOM or VEX. |
| `elide.analysisSummaryFile` | `target/dependency-elider-analysis-report.json` | Path for the analysis summary. To replay it, pass this path as `elide.summaryFile` to `report`. |
| `elide.sbomFile` | `target/dependency-elider-sbom.cdx.json` | Path for the post-elision CycloneDX 1.6 SBOM. |
| `elide.baselineSbomFile` | `target/baseline-sbom.cdx.json` | Path for the pre-elision baseline CycloneDX 1.6 SBOM. |
| `elide.vexFile` | `target/dependency-elider.openvex.json` | Path for the OpenVEX document written when omission or precondition proof succeeds, whether or not physical JAR trimming is enabled. |

For example, accept duplicated `org.example.Shared` and keep every provider JAR whole with
`'-Delide.retainDuplicateClassOwners=org.example.Shared'`. To preserve duplicates throughout
a package while allowing unused sibling classes to be trimmed, use
`-Delide.trimJars=true '-Delide.trimDuplicateClassOwners=org.example.**'` instead.
Quote glob arguments so the shell passes them unchanged. The equivalent POM list is:

```xml
<configuration>
  <trimJars>true</trimJars>
  <trimDuplicateClassOwners>
    <className>org.example.**</className>
  </trimDuplicateClassOwners>
</configuration>
```

### Preserving Metadata and Special JARs

Set `-Delide.trimWorkers=2` to cap trimming at two workers. This setting limits the plugin's trimming concurrency; it does not reserve CPU cores or limit other Maven work. The JVM option `-XX:ActiveProcessorCount=N` changes the processor count reported to all Maven code, so it is a Maven-wide limit rather than a plugin-only setting.

* **Framework Roots**: Service providers (`META-INF/services`), Spring factories, and GraalVM native-image configs automatically protect declaring and provider JARs from whole-artifact removal.
* **ServiceLoader SPI Dynamic Roots**: Application bytecode is scanned for constant `ServiceLoader.load` invocations to prove SPI usage. When `conservativeServiceLoaderRoots` is `true` (default), unproven SPI providers are retained for runtime safety. Set it to `false` to permit pruning unproven providers when your application does not need them. Retained declared code prevents omission proof under the common finding checks.
* **Intra-JAR Trimming**: Trimmed JARs are written to `target/elided-artifacts/` with original JARs left untouched. Digital signatures are stripped to maintain archive validity, while resources, licenses, and SPI descriptors are preserved.
* **Multi-Release and Module Descriptors**. With JAR trimming enabled, Elider uses the effective compiler release, then target, then the Maven JVM's feature release as the output baseline. Elider elevates and trims the baseline view. Higher-tier entries remain byte-identical except versioned `module-info.class`, which Elider removes. Code selected by each supplied runtime release contributes to sibling closure using that image's class table. Set `elide.mrjarStrategy=pass-through` to preserve the whole source archive. Root module descriptors keep the classpath pass-through behavior.
* **Exact Pass-Through (`trimSkipArtifacts`)**: Pins specified dependencies byte-identical while allowing their classes to resolve external links into trimmed sibling dependencies. Missing references originating in the unchanged JAR are tolerated; reachable missing references from a sibling being transformed still fail analysis. This also applies to retained `provided` and `system` JARs and to dependencies that graph or bytecode reachability requires Elider to retain unchanged. Their resolved bytecode and dynamic roots contribute to sibling closure, including analyzed multi-release tiers. In an `unresolved references` error, the `analysis candidate` is the archive whose closure is being analyzed, while the class before `->` owns the unresolved reference and may be in a different JAR. Select the exact resolved coordinate of a compile/runtime owner for pass-through if it must remain unchanged. An absent dependency's own classes and outgoing references are outside the analyzed graph.
* **Tolerated duplicate classes**. By default duplicate class ownership fails analysis because class-loading order would be ambiguous. `retainDuplicateClassOwners` and `trimDuplicateClassOwners` let you accept specific duplicates explicitly, preserving all providers and the dependency closure of each implementation. Both policies cover the production analysis classpath, including `provided` and `system` owners, which remain untrimmed. Multi-release duplicates use the effective views of the selected runtimes. Tolerated duplicates are listed in the build log and under `toleratedDuplicates` in `dependency-elider-report.json` and the Analyze class-usage report (class name, action `RETAIN_JARS` or `TRIM_OTHER_CLASSES`, and owning coordinates). The saved `report` goal replays these findings.
* **Native-image argument policy**: Class roots, package roots, configuration references, and descriptor fields in the audited GraalVM Native Image 21.0.12+7.1 inventory are modeled. Invalid recognized inputs fail clearly. Other syntactically valid arguments are accepted without inferred roots; unknown future options are outside the completeness guarantee. See [ADR-0009](../../../../docs/adr/0009-permissive-graalvm-native-image-metadata-ingestion.md).

### Using Post-Compile Elision and Inspecting the Dependency Tree

For projects with source generators or annotation processors, enable the extension and set `elide.productionClassesComplete=true`, or bind `elide` to `process-classes`. The extension preserves explicit phases and assigns omitted phases before Maven creates the lifecycle plan. This is the normal way to ensure compilation and generation finish before capture. A direct `mvn dependency-elider:elide` does not run those lifecycle steps; it can still produce precondition proof when `elide.productionClassesComplete=true` asserts that the already compiled production output is complete. The direct goal then scans physical runtime inputs. Unknown production writers in a lifecycle run remain unsupported. Test compilation and resource processing may run because isolated test outputs are excluded. `skipTests=true` is required if test execution would follow capture.

In this mode, production roots come from emitted bytecode. Source files are not scanned; dependencies referenced only through compile-time-inlined constants may not appear in bytecode, so retain those dependencies explicitly with `elide.retainedArtifacts` when needed. The class-use report remains bytecode and runtime telemetry evidence; source files do not count as runtime reachability or VEX proof. Test-only output is outside this production scan. Source-free modules with absent or empty output are supported; if Java source files exist but no production class files were emitted, run compilation first or use the normal lifecycle.

With `.mvn/extensions.xml` and an active elider execution at its selected phase (process-classes by default), run `dependency:tree` to inspect the post-elision graph directly. A process-classes binding injects that phase before the tree request unless an equal or later lifecycle phase already appears before it:

```sh
mvn dependency:tree
```

### Isolated Test Compilation and Runtime View

In the tested Maven 3.9.11 classpath setup with one opted-in project, run
`mvn clean package -Delide.testCompilationView=true` with the core extension and an `elide` execution bound to
`process-classes` or `initialize`. The extension schedules `prepare-test-view` at
`process-test-classes`. The test compiler sees the original allowed mediated dependency files only
during its `testCompile` execution. Elider restores the effective production artifact view after
compilation, including on a handled compilation failure. The production resolver plan is not
switched to originals.

Preparation scans the compiled test roots, closes their static links across the allowed original
JARs, and adds missing classes to `target/elider/test-additions.jar`. Surefire receives that JAR
after the ordinary test classpath. Existing Surefire XML classpath elements and the
`maven.test.additionalClasspath` property are retained. A test may therefore pass using code that
is absent from the deployable package; check the packaged application with a separate production
classpath test when deployment behavior matters. Elider does not attach, install or deploy the
test addition.

Use `mvn clean` when test sources, compiled output, dependencies, compiler settings or runtime
options change. A build without `clean` requires a matching
`target/elider/test-view-freshness.json` manifest; changed inputs fail with a diagnostic to run
`mvn clean test`. Preparation clears the previous saved test report before checking freshness, so
failed preparation cannot leave a replayable result from the prior run. `-DskipTests` still compiles and prepares tests, while
`-Dmaven.test.skip=true` leaves test results unavailable. Direct goals need Elider earlier in the
same invocation, and automatic runtime delivery needs preparation after the last successful test
compiler execution. An explicit direct sequence can use
`compiler:testCompile dependency-elider:prepare-test-view surefire:test` after `process-classes` has run.

The current test addition is a class-only JAR. Tests continue to read resources from the
effective production JARs. A changed-path contributor whose resource entries or bytes differ
from the allowed original, or a selected signed, sealed, multi-release or modular archive or one
with classpath-relevant manifest fields, fails with an actionable error. Duplicate original class
owners, missing providers and unsupported module-path behavior also fail. The tested plugin
combination is Compiler 3.13.0, Surefire 3.5.2
and Shade 3.6.0. A single opted-in leaf in a sequential reactor is tested; multiple opted-in modules,
parallel Maven reactor execution (`-T`) and more complex reactor topologies remain outside the
verified boundary. An ordinary test annotation processor that generates a JUnit test has passed
the real Maven fixture. Maven 4, arbitrary runners, other annotation processor configurations,
unchecked callback failures and process interruption remain outside the verified boundary.
Allowed test inputs respect explicit bans; excluded or banned artifacts are not restored.
Production forbidden-code assessment, SBOM, OpenVEX and precondition-proof eligibility retain
their production scope. Running tests does not waive the precondition guard's `skipTests=true`
requirement when execution reaches Surefire.

Compiled tests and reached original classes are scanned for direct `Class.forName`,
`ClassLoader.loadClass`, `ServiceLoader.load` and `loadInstalled` calls. Literal class names become
test roots. If a call cannot be resolved, preparation conservatively includes every class missing
from the effective view in the test-only addition and reports `conservativeFallbackUsed=true`.
This can include classes not used by the test; it does not add them to the production package.
Custom loaders, method handles, resource-driven class names and dynamic classes outside the
scanned closure are not modeled.

---

## 5. Viewing Elision Reports (`report`)

The `report` goal displays the summary and mediated dependency graph from the last successful `elide` run without re-executing dependency analysis:

It also reads the separate `target/elider/test-view-report.json` when present. Its schema-1
payload records sorted original-versus-effective inputs, added classes, whether a conservative
fallback was used, and the SHA-256 of the production report it belongs to. Replay verifies the
project identity and production report binding without rescanning test or dependency files.
Analysis reports, absent test reports and reports from another production run display an explicit
unavailable test-view line. Malformed or incompatible test reports fail instead of being treated
as empty results. A caller-supplied additions JAR is labeled unverified. Test-only rows never
enter production omission proofs, SBOMs or VEX.

`exclusionReview` saves repeated exact exclusions observed on frozen pre-injection effective
dependency rows, including separate declaration and exclusion origins. Findings are advisory and
exclude wildcard coordinates; noncontributing management exclusions and incomplete provenance are
reported separately. An unavailable capture is explicit. Maven path exclusions affect collection
and mediation, while a global post-resolution ban affects project output and can remove content
needed by consumers. No POM edits or behavioral equivalence are implied. The Analyze class-usage
report contains the same review, and the `report` goal replays the saved elision review.

```sh
mvn io.github.spockz:dependency-elider-maven-plugin:0.1.0-SNAPSHOT:report
```

### Report Information

* **Dropped Artifacts**: Total count and original on-disk JAR bytes of elided dependencies.
* **Pruned Classes**: Count and uncompressed `.class` payload bytes removed from dropped JARs and retained JARs (metrics never overlap).
* **Vulnerability Status**: Separates common package/code findings and unresolved review claims from verified classifications. OSV, CVE List and manual inputs retain provenance for reporting and use the same effective-finding assessment. Automatic normalized code sets and affected-version coverage union, preserving version gaps and code applicability; explicit manual fields override within matching scope and omitted fields enrich. Severity is ignored. Manual `LOW`/`MEDIUM` retains review-only intent and cannot be bypassed by automatic enrichment. Verification requires exact version binding, attributable declared code and physical absence, or complete opted-in prerequisite inventory. Unsupported or ambiguous code remains visible rather than producing a proof. Removed, trimmed and unchanged are inventory facts, not mitigation. The saved `report` goal replays findings, attribution and assumptions without reassessment. Each output file is replaced atomically; the set is not all-or-nothing. With `elide.trimJars=false`, physical JAR replacement is disabled while report/SBOM/OpenVEX publication, prerequisite assessment, ownership recording and stale OpenVEX cleanup remain enabled. See [VEX Evidence Boundary](#vex-evidence-boundary).
* **Mediated Graph**: Visualizes shortest dependency paths with node dispositions: `[RETAINED]`, `[CLASS_TRIMMED]`, `[EFFECTIVE_DROP]`, or `[PROTECTED]`.
* **Format Versions**: Internal persisted report and cache formats use independent schema version 1; incompatible payloads fail fast with instructions to rerun `elide`. CycloneDX declares `specVersion` 1.6 and OpenVEX uses its 0.2.0 context URL. The top-level `version` in either generated security document is a document revision counter, not a schema version.

---

## 6. Vulnerability Intelligence & OpenVEX

Maven Dependency Elider syncs vulnerability metadata from the official OSV Maven snapshot (`-Delide.osvSnapshotUri`) and the CVEList v5 repository (`-Delide.cveListGitUri`).

Both inputs can independently produce Maven findings when their identity/version information is supported. Configured `<vulnerabilityMappings>` joins those findings for the current project; manual rows are not written to the shared external index. Automatic path/class/routine details normalize into sets, and affected versions union without filling gaps between disjoint ranges. A declared code path keeps its version scope even when package coverage is wider. Unsupported claims remain explicit and do not manufacture a Maven identity.

Manual supplied fields have higher priority for the same CVE, component and applicable version. An explicit manual code mapping replaces the automatic class/file/routine group; omitted fields are enriched. All effective values then use the same validation and verification. Source names are report attribution rather than proof authority; severity scores do not influence merging. See [ADR-0014](https://github.com/spockz/maven-dependency-elider/blob/main/docs/adr/0014-source-independent-vulnerability-findings.md).

### Optional Snyk package findings

To query Snyk during `analyze` or `elide`, configure `SNYK_TOKEN` and `SNYK_ORG_ID` in the environment and set `-Delide.snykEnabled=true`. Alternatively, pass the organization ID with `-Delide.snykOrgId=...`. Use the regional API origin for the organization if it is not hosted at the default endpoint. Enabling this option sends the project's queried Maven package coordinates to Snyk and requires an account entitled to use its package-issues API.

The API is queried for each supported concrete project artifact, including transitive dependencies present in the input inventory. Its findings apply only to the exact queried version, retain Snyk and CVE identifiers, and merge with other findings. This is a project-scoped lookup, not a download or local copy of Snyk's full database; the separately licensed Application Feed is not consumed by this option. Snyk observations are reported independently, including incomplete and failed queries. Their revision is a local fingerprint of the query results, not a Snyk database revision. Rate-limited or unauthorized requests leave the observation incomplete. Offline execution sends no requests and reports the enabled source as unavailable.

### Refreshing the Vulnerability Cache

Update the local vulnerability database on demand:

```sh
mvn io.github.spockz:dependency-elider-maven-plugin:0.1.0-SNAPSHOT:update-cve-index
```

* **Cache location**: Stored in the OS user cache directory (outside `~/.m2`); override via `-Delide.cveCacheDirectory=/path/to/cache`.
* **Freshness TTL**: Defaults to 24 hours (`-Delide.cveCacheTtlHours=24`). Use `-Delide.cveForceSync=true` to force synchronization.
* **Offline resilience**: Offline builds read a validated, producer-compatible generic cache without network access or CVE checkout scanning. Missing or invalid cache state is reported as unavailable, rather than successful empty coverage. Project-local manual mappings can still be assessed.

OSV and CVE List keep independent last-good observations. A failed refresh retains that source's last-good claims with a stale/error diagnostic while another source can advance. A successful empty source snapshot is distinct from a failure. A failed cache publication preserves the previous published generic snapshot. No project's manual mappings are written to this shared cache.

CVE List and OSV indexing skip malformed affected entries or records while keeping valid siblings from the same refresh. A source with skipped data is marked `PARTIAL`, with a skipped-row count and bounded diagnostic details, so its findings do not imply complete source coverage. An affected entry with an invalid version claim is skipped in full to avoid interpreting the remaining versions as a broader range. A later refresh can repair skipped data; OSV retries a full snapshot after a partial refresh. Unreadable files, damaged archives, an invalid OSV change index, and network or Git failures remain source refresh failures.

The following ZIP and CSV refresh rules describe OSV synchronization. CVE List separately reuses a current partition within its TTL, checks the Git revision when due, and reuses indexed contributions when that revision is unchanged. Offline assessment does not scan the checkout.

The 24-hour TTL measures time since the last successful local synchronization. On a due online refresh with a reusable cached snapshot, the plugin checks the OSV ZIP object's `Last-Modified` metadata with a HEAD request. It downloads the ZIP when source metadata is absent or incompatible, the source timestamp differs, the advertised ZIP timestamp is at least 24 hours old, or `-Delide.cveForceSync=true`; otherwise it reuses the cached snapshot. Any full download uses `Last-Modified` from its successful ZIP GET response as that snapshot's source timestamp, including cold and forced downloads. Each due refresh downloads the complete `Maven/modified_id.csv` and fetches records whose source `modified` value is newer than the staged owner record. Successful responses replace that OSV record's associations; explicit withdrawals remove that owner.

The ZIP timestamp, each OSV record's `modified` value, and local `lastSyncTimestamp` describe different clocks. OSV does not document a shared watermark or CSV deletion events, so synchronization is eventually consistent: upstream publication delay, races, offline builds, failed requests, and removals awaiting a later full ZIP can extend how long local data differs from the source. A successful local sync is not a zero-lag or completeness guarantee.

### Declaring Project Vulnerability Mappings

Map specific vulnerabilities to code symbols in `pom.xml`:

```xml
<configuration>
  <trimJars>true</trimJars>
  <vulnerabilityMappings>
    <vulnerabilityMapping>
      <cveId>CVE-2026-10001</cveId>
      <groupId>org.example</groupId>
      <artifactId>affected-library</artifactId>
      <version>1.2.3</version>
      <versionRangeSpec>[1.2.0,1.3.0)</versionRangeSpec>
      <vulnerableClasses>
        <vulnerableClass>org.example.affected.VulnerableHandler</vulnerableClass>
      </vulnerableClasses>
      <sourceAdvisoryUrl>https://example.invalid/advisory</sourceAdvisoryUrl>
      <confidenceLevel>HIGH</confidenceLevel>
    </vulnerabilityMapping>
  </vulnerabilityMappings>
</configuration>
```

### Runtime Inputs

List the deployment images that should provide platform linkage evidence. Supply installed
modular Java 9+ homes or ZIP, `tar.gz`, and `tgz` archives. Relative paths resolve from the
consuming Maven module. For direct goals, use a comma-separated list such as
`-Delide.runtimeInputs=/opt/jre-21,/opt/archives/jre-25.tar.gz`.

```xml
<configuration>
  <runtimeInputs>
    <runtimeInput>/opt/jre-21</runtimeInput>
    <runtimeInput>/opt/archives/jre-25.tar.gz</runtimeInput>
  </runtimeInputs>
</configuration>
```

To use the JDK that runs Maven, list `${java.home}` explicitly. Elider analyzes each selected
release view and retains the classes needed by their combined closure. The compiler target
still controls the MRJAR output baseline. A project targeting Java 21 can select only a Java
25 image. The report and its replay warn that Java 21 is outside the supplied coverage.
Required production classes and supertypes must resolve in each selected runtime and its
dependency view. This includes providers admitted through proven service loading.
Supported metadata retains classes conservatively without proving that the application
loads them, so their optional hierarchies do not require resolution.
Elider merges retained classes after checking the individual views.
The report lists inspected images and marks runtime releases as analyzed once linkage
analysis completes for all selected images.

Unavailable images block elision or trimming that requires their linkage evidence.
Independent JAR findings and direct forbidden invocations remain reportable. Runtime
inputs stay outside application dependencies and SBOMs. Elider uses a supported JRT
reader from the JDK running Maven and treats Java 8 `rt.jar` or unsupported modular
images as unavailable.

For named production output, Elider resolves module requirements and JPMS services from
the selected system modules. Classpath applications use the available system modules
conservatively. Application dependency module paths and deployment-specific module options
are outside this scope.
With one installed image, Elider uses `jdeps` for optional module advice when the tool can
read that image through the Maven JDK's JRT provider. A tool or linkage failure leaves the
advice unavailable.

#### Prepare a compressed runtime with Maven

The forbidden-code example includes an opt-in `prepare-forbidden-runtime` profile. Its
JReleaser JDKs Maven Plugin execution accepts a published archive URL and SHA-256,
keeps the runtime compressed, and checks the destination during `initialize`.
Supply the publisher's checksum and the archive's platform. A reference image represents
the deployment only if it is the deployment image.
[JDKs Maven Plugin documentation](https://jreleaser.org/guide/latest/tools/jdks-maven.html)

```sh
./mvnw -f examples/example-forbidden-code-app/pom.xml -Pprepare-forbidden-runtime \
  "-Delider.runtime.archiveUrl=$JRE_URL" "-Delider.runtime.archiveSha256=$JRE_SHA256" \
  "-Delider.runtime.platform=$JRE_PLATFORM" initialize
```

The profile hands Elider the path
`${elider.runtime.cacheDirectory}/elider-target-jre/${elider.runtime.archiveName}`.
The default name is `runtime.zip`. Set `-Delider.runtime.archiveName=runtime.tar.gz`
for a tarball. Choose a cache directory outside `target` to keep downloads across
`clean`. For offline use, leave acquisition inactive and pass the prepared path in
`elide.runtimeInputs`. A direct `analyze` or `elide` command requires prior preparation.

Activating both `prepare-forbidden-runtime` and `elide-forbidden-example` schedules
preparation before Elide at `process-classes`. The direct downloader execution
`org.jreleaser:jdks-maven-plugin:1.26.0:setup-jdks@prepare-elider-runtime` skips the
lifecycle and the Enforcer check. Configure acquisition on one reactor project and
list the shared archive path in each consuming module.

Key a CI download cache by the downloader goal and plugin version, archive URL,
publisher checksum, platform, and archive name. Elider stores derived indexes for
other runtime images under `.elider-runtime-index` in Maven's local repository.
The index key includes the module image bytes, inspected release metadata and reader
policy. Each goal validates the current image before reusing an index, including when a
reactor module replaces the archive at the same path. This directory survives `clean`
and can be removed to reclaim space.

### Forbidden Code Policy

Add `forbiddenSymbols` to an explicit POM mapping, or use `forbidDeclaredCode=true` to select
the mapping's own `vulnerableClasses`. Use one selector per mapping. A mapping using
`forbiddenSymbols` can also supply a separate `vulnerableClasses` group for CVE proof.
Without that group, the explicit symbols supply the declared code group for the Maven finding.
Downloaded findings and the current mapping catalog format supply advisory evidence.

This example uses an illustrative CVE and Maven identity. Use the advisory and symbols reviewed
for your artifact.

```xml
<configuration>
  <vulnerabilityMappings>
    <vulnerabilityMapping>
      <cveId>CVE-2026-10001</cveId>
      <componentKind>MAVEN_ARTIFACT</componentKind>
      <groupId>org.example</groupId>
      <artifactId>affected-library</artifactId>
      <versionRangeSpec>[1.2,1.3)</versionRangeSpec>
      <forbiddenSymbols>
        <symbol>org.example.affected.Parser#parse(byte[])</symbol>
      </forbiddenSymbols>
    </vulnerabilityMapping>
  </vulnerabilityMappings>
</configuration>
```

| Component kind | Identity |
| :--- | :--- |
| `MAVEN_ARTIFACT` (default) | Exact `groupId`, `artifactId`, `type` (default `jar`), and `classifier` (default empty) in the effective non-test dependency inventory. |
| `PROJECT_OUTPUT` | The current project's identity and version. Supply the version scope and omit dependency coordinates. |
| `JAVA_RUNTIME` | Each explicitly selected Java runtime image. Supply the version scope and omit dependency coordinates. |

A mapping requires an exact `version` or an explicit `versionRangeSpec`. Use `(,)` to cover all
versions of the selected component. The range controls policy scope. `assertsAffected=true`
separately asserts CVE affectedness for that scope. Runtime rules use each inspected image's
version and the multi-release view selected by its feature release. Numeric predicates compare
the resolved runtime version components. An unavailable image or unsupported runtime version
predicate leaves version applicability `UNKNOWN`. A direct method match can still violate policy.

| Example symbol | Selects |
| :--- | :--- |
| `org.example.Parser` | That class only. |
| `org.example.Parser#parse(byte[],java.lang.String)` | Only that parameter signature, including any corresponding compiler-generated bridge descriptors. |
| `org.example.Parser#Parser()` | The zero-argument constructor and any same-named method with that signature. |
| `org.example.*` / `org.example.**` | Top-level classes in that package / that package and its subpackages. |
| `org.example.Parser$*` / `org.example.Parser$**` | Direct / recursive member classes identified by class metadata. |

Exact methods require parentheses, including `()` for no arguments. Use primitive types or
fully qualified reference types and `[]` for arrays. Source-style nested names use metadata
for resolution. If a retained named class inherits the method from a declaration available in
the inspected provider, the report identifies that declaring owner. An unresolved hierarchy or
ambiguous owner yields `UNKNOWN` where it prevents a complete conclusion. Elide trims whole
classes. A retained forbidden method is a violation even when its body is never called.

The scope covers production output, admitted generated classes such as Spring AOT main
classes, and effective non-test dependencies at `process-classes`. Test output, plugin and
processor dependencies, and later package or deployment inputs are outside this scope. Direct
invocations use `elide.productionClassesComplete=true` to assert compiled production output
completeness. The JAR checks cover every retained physical release tier, including tiers above
the target and unmodified pass-through JARs.

* `PASS` means the selected symbol is absent from a complete scope.
* `VIOLATION` means the declaration survives in an inspected JAR or production output, or an
  exact runtime method invocation appears in the assessed bytecode.
* `UNKNOWN` means the available evidence cannot determine a result. A runtime rule with no
  direct match remains unknown. Independent JAR checks still produce their own results.
* `NOT_APPLICABLE` means the concrete component version is outside the configured scope.

`analyze` saves `PREDICTED` results. `elide` saves `OBSERVED` results after checking actual
bytes, including cache hits. Each summary stores them in `forbiddenCodeAssessments` with the
symbol, CVE, component, version and applicability, provenance, evidence, and enforcement setting.
The `report` goal displays the selected snapshot without rechecking outputs.

For `JAVA_RUNTIME` methods, Elide matches the instruction's symbolic owner, name, and parameter
types. It uses caller class metadata to resolve source-style nested names. It checks production
classes and the target release's view of effective non-test JARs. `DIRECT_RUNTIME_CALL` evidence
names the caller class entry and the full invoked descriptor. An exact match violates policy
even when runtime applicability is unknown. A known out-of-scope runtime version reports
`NOT_APPLICABLE`. Execution, runtime affectedness, and indirect reachability require separate
evidence.

Set `-Delide.failOnForbiddenCode=true` to make either goal fail on any violation. For example,
an applied failure logs `Forbidden code OBSERVED VIOLATION` with the matching symbol and
provider. The previous successful Elide report and VEX stay in place, and the rejected invocation
publishes no Maven artifact view. An observed pass can support omission VEX when the existing
CVE applicability, attribution and original-to-output proof checks all succeed. A symbol already
absent from the original artifact can pass policy, while omission proof requires original presence.

#### Runnable forbidden-code examples

The standalone fixture compiles one application variant per build directory. Its harness
captures class-load traces, runs Analyze and Elide, checks saved reports and effective JAR bytes,
and replays the reports. Both demonstrations use benign inputs. Their policy observations
describe the assessed scope and do not prove exploitability.

From the repository root, with `JAVA_HOME` set to a JDK 21 or newer:

```sh
./mvnw -pl dependency-elider-maven-plugin -am install -DskipTests
evidence=$(mktemp -d)
bash examples/verify-forbidden-code.sh "$evidence" "$PWD/mvnw" --batch-mode --no-transfer-progress
```

The runtime mapping selects `java.util.Base64.Decoder#decode(byte[])` for CVE-2026-114938
with the all-version policy scope `(,)`. One variant decodes a fixed Base64 value and one
uses the equivalent plain text. With enforcement enabled, Analyze and Elide fail on the
decoder variant's `VIOLATION`. The plain-text variant reports `UNKNOWN` and succeeds. The
fixture repeats both cases with a Java 17 compiler target and no matching runtime image. The same
policy results apply, with version applicability recorded as `UNKNOWN`. The public overload is an
illustrative entry point. Applying a fixed runtime remains the
remediation. [Apache Shiro advisory](https://shiro.apache.org/blog/2026/11/apache-shiro-java4shell.html)

Replay of the decoder variant's successful run with enforcement disabled shows the exact
call site and the independent Commons Compress pass.

<!-- BEGIN:transcript:report-forbidden-runtime -->

```text
$ ./mvnw \
  --batch-mode \
  --no-transfer-progress \
  --offline \
  -f \
  examples/example-forbidden-code-app/pom.xml \
  io.github.spockz:dependency-elider-maven-plugin:0.1.0-SNAPSHOT:report \
  -Delide.summaryFile=$TRANSCRIPT_EVIDENCE/forbidden-code/decode/build/dependency-elider-report.json \
  -Delide.failOnForbiddenCode=true
Process exit status: 0
[INFO] Loading cache configuration from <PROJECT_ROOT>/.mvn/maven-build-cache-config.xml
[INFO] Using SHA-256 hash algorithm for cache
[INFO]
[INFO] ------------< io.github.spockz:example-forbidden-code-app >-------------
[INFO] Building Example: Forbidden Code at the Production Boundary 0.1.0-SNAPSHOT
[INFO]   from pom.xml
[INFO] --------------------------------[ jar ]---------------------------------
[INFO]
[INFO] --- dependency-elider:0.1.0-SNAPSHOT:report (default-cli) @ example-forbidden-code-app ---
[INFO] Dependency Elider report JSON snapshot: <TEMP_DIR>/forbidden-code/decode/build/dependency-elider-report.json
[INFO] Dependency Elider report
[INFO] Project: io.github.spockz:example-forbidden-code-app:0.1.0-SNAPSHOT
[INFO] Snapshot: last successful elide run at <TIMESTAMP>
[INFO] Analysis target JDK release: <RUNTIME_RELEASE>
[INFO] Elider runtime JDK release: <RUNTIME_RELEASE>
[INFO] Analyzed runtime releases: [<RUNTIME_RELEASE>]
[INFO] Runtime input <RUNTIME_IMAGE>: Java <RUNTIME_VERSION> (<RUNTIME_IDENTITY>)
[INFO] Policy: retained=[], banished=[]
[INFO] The snapshot does not revalidate changed inputs when this goal runs.
[INFO] Conventional Java source layout assumption saved for this run: true
[INFO] Whole artifacts dropped: 0 / 1 (original JAR file bytes: 0 B)
[INFO] Program classes removed with dropped JARs: 0 (uncompressed .class entry payload bytes: 0 B; excludes module descriptors and archive sanitation metadata)
[INFO] Raw trace decision drops before graph safety: 0
[INFO] Applied bans: none
[INFO] Program classes pruned from retained JARs: 288 (uncompressed omitted .class payload bytes: 903.98 KiB; excludes module descriptors and archive metadata)
[INFO]   - org.apache.commons:commons-compress:jar:1.17 (compile): 288 classes, 903.98 KiB
[INFO] Vulnerability findings: 1
[INFO]   - CVE-2018-11771 org.apache.commons:commons-compress:jar:1.17 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: DECLARED_CODE_ABSENT; All effective declared code and its nested classes are absent from the trimmed artifact. This observation is limited to the declared code and does not establish declaration completeness.
[INFO]     Declared code: [org.apache.commons.compress.archivers.zip.ZipArchiveInputStream#read(byte[],int,int)] RESOLVED; classes: [org.apache.commons.compress.archivers.zip.ZipArchiveInputStream, org.apache.commons.compress.archivers.zip.ZipArchiveInputStream$1, org.apache.commons.compress.archivers.zip.ZipArchiveInputStream$BoundedInputStream, org.apache.commons.compress.archivers.zip.ZipArchiveInputStream$CurrentEntry]; reasons: []
[INFO]     Sources: [POM]
[INFO] CVE Freshness: UNAVAILABLE (vulnerability cache and refresh sources are unavailable)
[INFO] CVE Sources:
[INFO]   - CACHE UNAVAILABLE
[INFO]     Generic findings cache is unavailable offline
[INFO] Forbidden code overall: VIOLATION
[INFO] Forbidden code OBSERVED PASS: CVE-2018-11771 org.apache.commons.compress.archivers.zip.ZipArchiveInputStream#read(byte[],int,int) in MAVEN_ARTIFACT org.apache.commons:commons-compress:jar (Owner absent from provider; enforcement disabled)
[INFO]     scope=[1.7,1.18), version=1.17, targetRelease=<RUNTIME_RELEASE>, applicability=APPLICABLE, assertsAffected=true, evidence=STAGED_ARCHIVE_DECLARATIONS, complete=true, provider=<TEMP_DIR>/forbidden-code/decode/build/elided-artifacts/.generations/<TRIM_GENERATION>/org.apache.commons-commons-compress-1.17-trimmed.jar, provenance=effective-project-pom:vulnerabilityMappings[1], source=https://commons.apache.org/proper/commons-compress/security.html
[INFO] Forbidden code OBSERVED VIOLATION: CVE-2026-114938 java.util.Base64.Decoder#decode(byte[]) in JAVA_RUNTIME <RUNTIME_IDENTITY> (Exact invocation found in effective bytecode at <TEMP_DIR>/forbidden-code/decode/build/classes!io/github/spockz/example/forbidden/DecodeApplication.class; enforcement disabled)
[INFO]     scope=(,), version=<RUNTIME_VERSION>, targetRelease=<RUNTIME_RELEASE>, applicability=APPLICABLE, assertsAffected=false, evidence=DIRECT_RUNTIME_CALL, complete=false, provider=<RUNTIME_IMAGE>, provenance=effective-project-pom:vulnerabilityMappings[0], source=https://shiro.apache.org/blog/2026/11/apache-shiro-java4shell.html
[INFO]     provider=<TEMP_DIR>/forbidden-code/decode/build/classes, entry=io/github/spockz/example/forbidden/DecodeApplication.class, tier=0, owner=java.util.Base64$Decoder, descriptors=[([B)[B]
[INFO] POM exclusion review (advisory only):
[INFO]   Exclusion review unavailable: No pre-injection declaration capture is
[INFO]   available
[INFO] Mediated dependency graph unavailable: Maven resolver session is unavailable
[INFO] Test view: unavailable: no saved test preparation
[INFO] ------------------------------------------------------------------------
[INFO] ------------------------------------------------------------------------
[INFO] Total time: <BUILD_TIME>
[INFO] Finished at: <TIMESTAMP>
[INFO] ------------------------------------------------------------------------
```

<!-- END:transcript:report-forbidden-runtime -->

The dependency mapping covers `[1.7,1.18)` and selects
`ZipArchiveInputStream#read(byte[],int,int)`. The fixture checks the public `([BII)I`
descriptor in the actual 1.17 archive. In the safe variant, the library still supplies
`ZipArchiveEntry`, while the stream class is trimmed. The harness verifies the post-trim
artifact against the SBOM and OpenVEX hashes. [Apache Commons Compress advisory](https://commons.apache.org/proper/commons-compress/security.html)

<!-- BEGIN:transcript:analyze-forbidden-dependency -->

```text
$ ./mvnw \
  --batch-mode \
  --no-transfer-progress \
  --offline \
  -f \
  examples/example-forbidden-code-app/pom.xml \
  io.github.spockz:dependency-elider-maven-plugin:0.1.0-SNAPSHOT:analyze \
  -Dexample.buildDirectory=$TRANSCRIPT_EVIDENCE/forbidden-code/safe/build \
  -Delide.traceFiles=$TRANSCRIPT_EVIDENCE/forbidden-code/safe/trace.log \
  -Delide.cveCacheDirectory=$TRANSCRIPT_EVIDENCE/forbidden-code/safe/advisories \
  -Delide.reportFile=$TRANSCRIPT_EVIDENCE/forbidden-code/safe/transcript-classes.json \
  -Delide.analysisSummaryFile=$TRANSCRIPT_EVIDENCE/forbidden-code/safe/transcript-analysis.json \
  -Delide.productionClassesComplete=true \
  -Delide.trimJars=true \
  -Delide.failOnForbiddenCode=true
Process exit status: 0
[INFO] Loading cache configuration from <PROJECT_ROOT>/.mvn/maven-build-cache-config.xml
[INFO] Using SHA-256 hash algorithm for cache
[INFO]
[INFO] ------------< io.github.spockz:example-forbidden-code-app >-------------
[INFO] Building Example: Forbidden Code at the Production Boundary 0.1.0-SNAPSHOT
[INFO]   from pom.xml
[INFO] --------------------------------[ jar ]---------------------------------
[INFO]
[INFO] --- dependency-elider:0.1.0-SNAPSHOT:analyze (default-cli) @ example-forbidden-code-app ---
[WARNING] Generic findings cache is unavailable offline
[INFO] Dependency Elider report
[INFO] Project: io.github.spockz:example-forbidden-code-app:0.1.0-SNAPSHOT
[INFO] Snapshot: analysis prediction at <TIMESTAMP>
[INFO] Analysis target JDK release: <RUNTIME_RELEASE>
[INFO] Elider runtime JDK release: <RUNTIME_RELEASE>
[INFO] Analyzed runtime releases: [<RUNTIME_RELEASE>]
[INFO] Runtime input <RUNTIME_IMAGE>: Java <RUNTIME_VERSION> (<RUNTIME_IDENTITY>)
[INFO] Policy: retained=[], banished=[]
[INFO] The snapshot does not revalidate changed inputs when this goal runs.
[INFO] Conventional Java source layout assumption saved for this run: true
[INFO] Whole artifacts that would be dropped: 0 / 1 (original JAR file bytes: 0 B)
[INFO] Program classes that would be removed with dropped JARs: 0 (uncompressed .class entry payload bytes: 0 B; excludes module descriptors and archive sanitation metadata)
[INFO] Raw trace decision drops before graph safety: 0
[INFO] Planned bans: none
[INFO] Program classes that would be pruned from retained JARs: 288 (uncompressed omitted .class payload bytes: unknown; excludes module descriptors and archive metadata)
[INFO]   - org.apache.commons:commons-compress:jar:1.17 (compile): 288 classes, unknown
[INFO]     Classes that would be pruned from this JAR: [org.apache.commons.compress.MemoryLimitException, org.apache.commons.compress.PasswordRequiredException, org.apache.commons.compress.archivers.ArchiveException, org.apache.commons.compress.archivers.ArchiveInputStream, org.apache.commons.compress.archivers.ArchiveOutputStream, ... (+283 more in analysis report)]
[INFO] Analysis only: no trim proof or published changes
[INFO] Vulnerability findings: 1
[INFO]   - CVE-2018-11771 org.apache.commons:commons-compress:jar:1.17 (compile) [PLANNED_TRIM]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: PLANNED_CODE_ABSENT; Analysis would remove declared code; the resulting archive has not been verified
[INFO]     Declared code: [org.apache.commons.compress.archivers.zip.ZipArchiveInputStream#read(byte[],int,int)] RESOLVED; classes: [org.apache.commons.compress.archivers.zip.ZipArchiveInputStream, org.apache.commons.compress.archivers.zip.ZipArchiveInputStream$1, org.apache.commons.compress.archivers.zip.ZipArchiveInputStream$BoundedInputStream, org.apache.commons.compress.archivers.zip.ZipArchiveInputStream$CurrentEntry]; reasons: []
[INFO]     Sources: [POM]
[INFO] CVE Freshness: UNAVAILABLE (vulnerability cache and refresh sources are unavailable)
[INFO] CVE Sources:
[INFO]   - CACHE UNAVAILABLE
[INFO]     Generic findings cache is unavailable offline
[INFO] Forbidden code overall: UNKNOWN
[INFO] Forbidden code PREDICTED PASS: CVE-2018-11771 org.apache.commons.compress.archivers.zip.ZipArchiveInputStream#read(byte[],int,int) in MAVEN_ARTIFACT org.apache.commons:commons-compress:jar (Owner absent from provider; enforcement enabled)
[INFO]     scope=[1.7,1.18), version=1.17, targetRelease=<RUNTIME_RELEASE>, applicability=APPLICABLE, assertsAffected=true, evidence=PHYSICAL_DECLARATIONS, complete=true, provider=<TEMP_DIR>/maven-repository/org/apache/commons/commons-compress/1.17/commons-compress-1.17.jar, provenance=effective-project-pom:vulnerabilityMappings[1], source=https://commons.apache.org/proper/commons-compress/security.html
[INFO] Forbidden code PREDICTED UNKNOWN: CVE-2026-114938 java.util.Base64.Decoder#decode(byte[]) in JAVA_RUNTIME <RUNTIME_IDENTITY> (Available runtime evidence does not establish method or class reachability; enforcement enabled)
[INFO]     scope=(,), version=<RUNTIME_VERSION>, targetRelease=<RUNTIME_RELEASE>, applicability=APPLICABLE, assertsAffected=false, evidence=RUNTIME_REACHABILITY, complete=false, provider=<RUNTIME_IMAGE>, provenance=effective-project-pom:vulnerabilityMappings[0], source=https://shiro.apache.org/blog/2026/11/apache-shiro-java4shell.html
[INFO] POM exclusion review (advisory only):
[INFO]   Exclusion review unavailable: No pre-injection declaration capture is
[INFO]   available
[INFO] Mediated TEST dependency graph (captured and saved by the analyze goal):
[INFO]   - io.github.spockz:example-forbidden-code-app:0.1.0-SNAPSHOT {nodeId=n0} [RETAINED]
[INFO]   - io.github.spockz:example-forbidden-code-app:0.1.0-SNAPSHOT -> org.apache.commons:commons-compress:jar:1.17 (compile) {nodeId=n1} [RETAINED, WOULD_TRIM]
[INFO]   JAR trim cache: unavailable (Analyze reports an in-memory prediction only)
[INFO]   Analysis report: <TEMP_DIR>/forbidden-code/safe/transcript-analysis.json
[INFO]   Class usage report: <TEMP_DIR>/forbidden-code/safe/transcript-classes.json
[INFO]   Test view: unavailable: tests were not compiled during analyze
[INFO] ------------------------------------------------------------------------
[INFO] ------------------------------------------------------------------------
[INFO] Total time: <BUILD_TIME>
[INFO] Finished at: <TIMESTAMP>
[INFO] ------------------------------------------------------------------------
```

<!-- END:transcript:analyze-forbidden-dependency -->

The retained variant reads a generated ZIP through `InputStream`. Elide rejects the surviving
method with enforcement enabled and preserves the previous successful report and VEX. The
harness checks Maven's exit status of 1 and saves its output in
`$evidence/forbidden-code/retained/rejected.log`. With enforcement disabled, the violation is
saved and replayed below. Applying the safe variant without
trimming reports a violation even after a trim-enabled prediction passed. A separate 1.18
build reports `NOT_APPLICABLE`, since the version is
outside the configured range.

<!-- BEGIN:transcript:report-forbidden-retained -->

```text
$ ./mvnw \
  --batch-mode \
  --no-transfer-progress \
  --offline \
  -f \
  examples/example-forbidden-code-app/pom.xml \
  io.github.spockz:dependency-elider-maven-plugin:0.1.0-SNAPSHOT:report \
  -Delide.summaryFile=$TRANSCRIPT_EVIDENCE/forbidden-code/retained/build/dependency-elider-report.json \
  -Delide.failOnForbiddenCode=true
Process exit status: 0
[INFO] Loading cache configuration from <PROJECT_ROOT>/.mvn/maven-build-cache-config.xml
[INFO] Using SHA-256 hash algorithm for cache
[INFO]
[INFO] ------------< io.github.spockz:example-forbidden-code-app >-------------
[INFO] Building Example: Forbidden Code at the Production Boundary 0.1.0-SNAPSHOT
[INFO]   from pom.xml
[INFO] --------------------------------[ jar ]---------------------------------
[INFO]
[INFO] --- dependency-elider:0.1.0-SNAPSHOT:report (default-cli) @ example-forbidden-code-app ---
[INFO] Dependency Elider report JSON snapshot: <TEMP_DIR>/forbidden-code/retained/build/dependency-elider-report.json
[INFO] Dependency Elider report
[INFO] Project: io.github.spockz:example-forbidden-code-app:0.1.0-SNAPSHOT
[INFO] Snapshot: last successful elide run at <TIMESTAMP>
[INFO] Analysis target JDK release: <RUNTIME_RELEASE>
[INFO] Elider runtime JDK release: <RUNTIME_RELEASE>
[INFO] Analyzed runtime releases: [<RUNTIME_RELEASE>]
[INFO] Runtime input <RUNTIME_IMAGE>: Java <RUNTIME_VERSION> (<RUNTIME_IDENTITY>)
[INFO] Policy: retained=[], banished=[]
[INFO] The snapshot does not revalidate changed inputs when this goal runs.
[INFO] Conventional Java source layout assumption saved for this run: true
[INFO] Whole artifacts dropped: 0 / 1 (original JAR file bytes: 0 B)
[INFO] Program classes removed with dropped JARs: 0 (uncompressed .class entry payload bytes: 0 B; excludes module descriptors and archive sanitation metadata)
[INFO] Raw trace decision drops before graph safety: 0
[INFO] Applied bans: none
[INFO] Program classes pruned from retained JARs: 228 (uncompressed omitted .class payload bytes: 702.38 KiB; excludes module descriptors and archive metadata)
[INFO]   - org.apache.commons:commons-compress:jar:1.17 (compile): 228 classes, 702.38 KiB
[INFO] Vulnerability findings: 1
[INFO]   - CVE-2018-11771 org.apache.commons:commons-compress:jar:1.17 (compile) [RETAINED_AND_TRIMMED]
[INFO]     Applicability: AFFECTED; intent: AUTO_VERIFY
[INFO]     Outcome: NO_PROOF; A corresponding forbidden-code declaration lacks an observed pass
[INFO]     Declared code: [org.apache.commons.compress.archivers.zip.ZipArchiveInputStream#read(byte[],int,int)] RESOLVED; classes: [org.apache.commons.compress.archivers.zip.ZipArchiveInputStream, org.apache.commons.compress.archivers.zip.ZipArchiveInputStream$1, org.apache.commons.compress.archivers.zip.ZipArchiveInputStream$BoundedInputStream, org.apache.commons.compress.archivers.zip.ZipArchiveInputStream$CurrentEntry]; reasons: []
[INFO]     Sources: [POM]
[INFO] CVE Freshness: UNAVAILABLE (vulnerability cache and refresh sources are unavailable)
[INFO] CVE Sources:
[INFO]   - CACHE UNAVAILABLE
[INFO]     Generic findings cache is unavailable offline
[INFO] Forbidden code overall: VIOLATION
[INFO] Forbidden code OBSERVED VIOLATION: CVE-2018-11771 org.apache.commons.compress.archivers.zip.ZipArchiveInputStream#read(byte[],int,int) in MAVEN_ARTIFACT org.apache.commons:commons-compress:jar (Method declaration present; enforcement disabled)
[INFO]     scope=[1.7,1.18), version=1.17, targetRelease=<RUNTIME_RELEASE>, applicability=APPLICABLE, assertsAffected=true, evidence=STAGED_ARCHIVE_DECLARATIONS, complete=false, provider=<TEMP_DIR>/forbidden-code/retained/build/elided-artifacts/.generations/<TRIM_GENERATION>/org.apache.commons-commons-compress-1.17-trimmed.jar, provenance=effective-project-pom:vulnerabilityMappings[1], source=https://commons.apache.org/proper/commons-compress/security.html
[INFO]     provider=<TEMP_DIR>/forbidden-code/retained/build/elided-artifacts/.generations/<TRIM_GENERATION>/org.apache.commons-commons-compress-1.17-trimmed.jar, entry=org/apache/commons/compress/archivers/zip/ZipArchiveInputStream.class, tier=0, owner=org.apache.commons.compress.archivers.zip.ZipArchiveInputStream, descriptors=[([BII)I]
[INFO] Forbidden code OBSERVED UNKNOWN: CVE-2026-114938 java.util.Base64.Decoder#decode(byte[]) in JAVA_RUNTIME <RUNTIME_IDENTITY> (Available runtime evidence does not establish method or class reachability; enforcement disabled)
[INFO]     scope=(,), version=<RUNTIME_VERSION>, targetRelease=<RUNTIME_RELEASE>, applicability=APPLICABLE, assertsAffected=false, evidence=RUNTIME_REACHABILITY, complete=false, provider=<RUNTIME_IMAGE>, provenance=effective-project-pom:vulnerabilityMappings[0], source=https://shiro.apache.org/blog/2026/11/apache-shiro-java4shell.html
[INFO] POM exclusion review (advisory only):
[INFO]   Exclusion review unavailable: No pre-injection declaration capture is
[INFO]   available
[INFO] Mediated dependency graph unavailable: Maven resolver session is unavailable
[INFO] Test view: unavailable: no saved test preparation
[INFO] ------------------------------------------------------------------------
[INFO] ------------------------------------------------------------------------
[INFO] Total time: <BUILD_TIME>
[INFO] Finished at: <TIMESTAMP>
[INFO] ------------------------------------------------------------------------
```

<!-- END:transcript:report-forbidden-retained -->

### Overriding Conservative Multi-Symbol Mappings

When an upstream vulnerability advisory covers a wide version range and maps multiple classes across versions (for example, Jackson Core `CVE-2026-68494` mapping both `ByteArrayFeeder` and `StreamConstraintsException`), the elider's default proof engine conservatively fails closed if any mapped class does not exist in the original dependency JAR (such as versions prior to Jackson 2.15 where `StreamConstraintsException` had not yet been created).

If you inspect the upstream fix commit and determine that only a subset of the mapped classes applies to your specific version, you can declare an explicit POM override targeting your library version. POM overrides take precedence over the indexed mapping:

```xml
<configuration>
  <trimJars>true</trimJars>
  <vulnerabilityMappings>
    <!-- Jackson Core: override index mapping to only require ByteArrayFeeder for pre-2.15 versions -->
    <vulnerabilityMapping>
      <cveId>CVE-2026-68494</cveId>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-core</artifactId>
      <versionRangeSpec>[2.14.0,2.15.0)</versionRangeSpec>
      <vulnerableClasses>
        <vulnerableClass>com.fasterxml.jackson.core.async.ByteArrayFeeder</vulnerableClass>
      </vulnerableClasses>
      <!-- Point directly to the upstream fix commit showing the modified file diffs -->
      <sourceAdvisoryUrl>https://github.com/FasterXML/jackson-core/pull/1611</sourceAdvisoryUrl>
      <confidenceLevel>HIGH</confidenceLevel>
    </vulnerabilityMapping>
  </vulnerabilityMappings>
</configuration>
```

### VEX Evidence Boundary

Every source supplies common effective declarations to the same proof checks. Manual priority affects merging, not proof authority. Omitted-code proof requires exact candidate identity and version, attributable declared classes in the original artifact, and their physical absence from the resulting artifact. Configured manual `LOW`/`MEDIUM` is review-only even if automatic data fills missing fields. `HIGH` alone, a package-only match or a heuristic code name cannot establish proof.

Declared source paths and routines are attributed against the exact original JAR through the shared bytecode-based resolver. Path normalization preserves Java case and package identity; a basename alone is insufficient. Qualified routines retain their declaring owner and any supplied signature, and ambiguous ownership or unsupported attribution suppresses the corresponding proof. `elide.assumeConventionalJavaSourceLayout` controls the documented source-root translation, not evidence completeness. No particular JDK vendor/build or in-process recompilation of third-party source is required. The result is bounded to the verified declared code; it does not establish the vulnerability's independent truth or that every affected code path was declared. Unresolved claims remain visible for review.

The omitted-code proof also requires archive inspection to prove every affected class family absent from the retained candidate's trimmed JAR. A dependency removed entirely is reported as dropped from inventory, not as code-absence VEX.

Core mappings, complete-inventory proof, CycloneDX/OpenVEX serialization, and snapshot-aware assessment support precondition evidence. A mapping must name both the prerequisite Maven coordinate and exact prerequisite class; coordinate-only mappings cannot prove absence. Set `elide.preconditionClassPathComplete=true` to assert that the declared runtime inventory is complete, independent of `elide.trimJars`. The inventory includes production class/resource output and non-test-scoped effective dependency archives; isolated test roots and test-scoped archives are excluded. Normal `testCompile` and `testResources` may run. Custom test compiler arguments/output paths that could redirect providers into production roots still suppress proof. The compiler guard checks the production `compile` goal and production target; test-only processing and target settings do not expand the inventory. The guard also checks active and managed plugin configuration, processor and compiler plugin dependencies, interface assertions, custom production source/resource roots, filtered production resources, unresolved settings, and unmodeled production writers. Package-only profiles and unsupported packaging/extensions suppress proof. Direct `elide` and `analyze` may inspect current physical runtime inputs with `elide.productionClassesComplete=true`; lifecycle provenance is not required. Analyze may record physical prerequisite absence from that complete current inventory when the opt-in above is enabled. A prerequisite absent only from Analyze's predicted post-trim view remains a forecast. Analyze does not publish CycloneDX/OpenVEX; Elide's publisher revalidates provider membership and content before publishing. No inventory claim covers a later assembled package or external runtime mechanism. The default production generated-sources directory is inventoried; generated test source directories are not runtime providers. Pre-capture Enforcer rules are limited to verified built-ins. With `elide.trimJars=false`, archive replacement is disabled while inventory assessment remains enabled. See [ADR-0008](https://github.com/spockz/maven-dependency-elider/blob/main/docs/adr/0008-precondition-gated-vex-attestations.md) and [RQ-0013](https://github.com/spockz/maven-dependency-elider/blob/main/docs/research/RQ-0013-precondition-gated-vex-and-multi-artifact-exploitability.md).
The package guard supports `jar` and `pom` projects and accepts only maven-shade-plugin 3.6.0 with one `package`/`shade` execution and a built-in manifest transformer with a resolved `mainClass`. Any request that reaches a modeled JAR package execution must include `clean` first so the standard JAR plugin cannot reuse an older archive; Shade packaging is covered as an additional package path. Clean skip/exclusion/failure overrides and deferred clean modes suppress proof. It allows only the inherited signature-resource exclusions shown in the examples. `war` and `maven-plugin` packaging, other Shade filters, transformers, inputs, dependencies, source-JAR properties, custom maven-jar-plugin configuration, and resource-plugin dependencies suppress proof.

---

## 7. Comparing SBOMs with OSV-Scanner

To verify vulnerability reduction across baseline and post-elision inventories, run the automated comparison:

```sh
make scan-sbom
```

This runs OSV-Scanner offline against both `target/baseline-sbom.cdx.json` and `target/dependency-elider-sbom.cdx.json`, generating reports in `target/sbom-comparison/`:

* `baseline-scan.json`: Raw scanner findings on the untrimmed baseline inventory.
* `post-elision-scan.json`: Raw scanner findings on the post-elision inventory.
* `comparison-report.json`: Hash-verified summary of eliminated versus remaining package-level findings.
