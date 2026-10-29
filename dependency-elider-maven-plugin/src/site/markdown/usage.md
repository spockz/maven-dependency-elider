<!-- WHY: Documents the usable Maven goal and the lifecycle safety boundary for plugin consumers. -->
# Maven Plugin Usage

Maven Dependency Elider provides four primary goals:

* `analyze`: Dry-run that identifies removable dependencies and estimates size savings without changing dependency artifacts, classpaths, or packages. It may write the configured class-usage report.
* `elide`: Active build-time goal that prunes unneeded JARs and trims unreferenced classes during the `INITIALIZE` phase.
* `report`: Displays the persisted elision snapshot and mediated dependency graph from the last successful build.
* `update-cve-index`: Refreshes local vulnerability intelligence from OSV and CVEList v5.

For common questions, see the [User FAQ](https://github.com/spockz/maven-dependency-elider/blob/main/docs/faq.md) and [Contributor Decisions and FAQ](https://github.com/spockz/maven-dependency-elider/blob/main/docs/contributor-decisions-and-faq.md).

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

Run `analyze` to inspect potential dependency drops and byte savings without altering project artifacts, classpaths, or packaged outputs. The goal writes class-usage evidence to `elide.reportFile` (default `target/dependency-elider-class-usage.json`); choose a path under `.scratch` if the output should not be kept with build artifacts:

```sh
mvn io.github.spockz:dependency-elider-maven-plugin:0.1.0-SNAPSHOT:analyze \
  -Delide.traceFiles=target/classes.log
```

The repository's CVE fixture transcript includes its configured command, exit status, and captured analysis output. Its CVE findings use only the two mappings in the pinned [transcript fixture](https://github.com/spockz/maven-dependency-elider/blob/main/scripts/fixtures/transcript-vulnerability-cache/README.md), so they do not represent complete vulnerability coverage. `$PROJECT_ROOT` and `$TRANSCRIPT_EVIDENCE` stand for the repository and temporary trace directory created by `make update-transcripts`:

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
  -Delide.sourceRootsComplete=true \
  -Dmaven.compiler.proc=none \
  -Delide.trimSkipArtifacts=org.springframework:spring-context:6.2.7:jar:,org.springframework:spring-beans:6.2.7:jar:,org.springframework:spring-aop:6.2.7:jar:,org.springframework:spring-expression:6.2.7:jar:,org.springframework:spring-jcl:6.2.7:jar:,io.micrometer:micrometer-observation:1.15.0:jar:,io.micrometer:micrometer-commons:1.15.0:jar: \
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
[INFO] Dependency Elider analysis summary
[INFO]   Artifacts that would be elided by this analysis: 0 / 25 (0.0%)
[INFO]   Estimated original JAR bytes for those artifacts: 0 B (sum of original on-disk input JAR sizes; final package delta may differ)
[INFO]   Program class entries in JARs that would be dropped: 0 (uncompressed .class entry payload bytes: 0 B; excludes module descriptors and archive sanitation metadata)
[INFO]   JAR trim cache: 0 validated hit(s), 22 analysis run(s)
[INFO]   Avoided CVEs (artifacts that would be dropped): none matched the available vulnerability mappings
[INFO]   Mitigated CVEs (vulnerable code that would be pruned by trimming):
[INFO]     CVE-2022-42889 org.apache.commons:commons-text:jar:1.9
[INFO]   CVEs that would be inactive due to unmet prerequisite dependencies: none matched the available vulnerability mappings
[INFO]   CVEs that would be excluded due to conservative multi-symbol checks: none detected
[INFO]   Class usage report: <PROJECT_ROOT>/.scratch/transcript-analysis/analyze-cve-unused-app-class-usage.json
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
| `-Delide.excludedArtifacts` | *(empty)* | Comma-separated coordinates (`groupId:artifactId[:version[:type[:classifier]]]`) to retain regardless of trace evidence. |
| `-Delide.productionOutput` | *(empty)* | Path to compiled classes (e.g. `target/classes`) to enable static code reference scanning. |
| `-Delide.conservativeServiceLoaderRoots` | `true` | When `true`, retains unproven ServiceLoader SPI roots; when `false`, prunes unproven SPI roots. |
| `-Delide.reportFile` | `target/dependency-elider-class-usage.json` | Path for the class-usage analysis report. |

Only resolved regular JARs in `compile` and `runtime` scopes are considered for elision. Non-JAR artifacts and other dependency scopes are always retained.

---

## 4. Active Build Elision (`elide`)

The `elide` goal runs in Maven's `INITIALIZE` lifecycle phase, removing unused dependencies and trimming unreferenced classes before compilation and packaging plugins execute.

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

> **Important**: Without this extension, whole-artifact drops fail closed (all candidate JARs remain retained), though retained-JAR trimming still functions.

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
| `elide.traceFiles` | *(none)* | Comma-separated paths to runtime telemetry traces (required). |
| `elide.trimJars` | `false` | Enables ProGuard Core link closure to trim unreferenced classes from retained JARs. |
| `elide.trimWorkers` | `4` | Maximum worker threads for JAR preparation, closure analysis, and archive sanitization. Actual concurrency is also capped by available processors and pending work; `1` runs sequentially. |
| `elide.sourceRootsComplete` | `false` | Set `true` only if all production and generated sources exist before `INITIALIZE` with no downstream generation. When `false`, all compile-classpath JARs and classes are conservatively retained. |
| `elide.trimRoots` | *(none)* | Comma-separated additional root classes (e.g. `com.example.AppRoot`). |
| `elide.trimSkipArtifacts` | *(none)* | Comma-separated coordinates of retained JARs to keep byte-identical. Their classes serve as roots for sibling closure. |
| `elide.failOnUnsupportedMultiRelease` | `false` | When `false`, multi-release JARs pass through unchanged. When `true`, multi-release candidate JARs fail the build. |
| `elide.failOnUnsupportedModuleInfo` | `false` | When `false`, JARs with root `module-info.class` pass through unchanged on the classpath. When `true`, they fail the build. |
| `elide.conservativeServiceLoaderRoots` | `true` | When `true`, retains unproven ServiceLoader dynamic roots declared in `META-INF/services/`. When `false`, unproven SPI roots are pruned. |
| `elide.summaryFile` | `target/dependency-elider-report.json` | Path for the persisted elision snapshot read by `report`. |
| `elide.sbomFile` | `target/dependency-elider-sbom.cdx.json` | Path for the post-elision CycloneDX 1.6 SBOM. |
| `elide.baselineSbomFile` | `target/baseline-sbom.cdx.json` | Path for the pre-elision baseline CycloneDX 1.6 SBOM. |
| `elide.vexFile` | `target/dependency-elider.openvex.json` | Path for the generated OpenVEX document. |

### Preserving Metadata and Special JARs

Set `-Delide.trimWorkers=2` to cap trimming at two workers. This setting limits the plugin's trimming concurrency; it does not reserve CPU cores or limit other Maven work. The JVM option `-XX:ActiveProcessorCount=N` changes the processor count reported to all Maven code, so it is a Maven-wide limit rather than a plugin-only setting.

* **Framework Roots**: Service providers (`META-INF/services`), Spring factories, and GraalVM native-image configs automatically protect declaring and provider JARs from whole-artifact removal.
* **ServiceLoader SPI Dynamic Roots**: Application bytecode is scanned for constant `ServiceLoader.load` invocations to prove SPI usage. When `conservativeServiceLoaderRoots` is `true` (default), unproven SPI providers are retained for runtime safety, but any CVEs retained solely by unproven SPI entries are excluded from mitigation into `Potentially conservative CVE exclusions`. Set `conservativeServiceLoaderRoots` to `false` to prune unproven SPI entries.
* **Intra-JAR Trimming**: Trimmed JARs are written to `target/elided-artifacts/` with original JARs left untouched. Digital signatures are stripped to maintain archive validity, while resources, licenses, and SPI descriptors are preserved.
* **Multi-Release and Module Descriptors**: Multi-release implementation classes and root `module-info.class` entries pass through unchanged on the classpath by default.
* **Exact Pass-Through (`trimSkipArtifacts`)**: Pins specified dependencies byte-identical while allowing their classes to resolve external links into trimmed sibling dependencies.

### Inspecting the Post-Elision Dependency Tree

With `.mvn/extensions.xml` and an active initialize-bound elider execution, run `dependency:tree` to inspect the post-elision graph directly:

```sh
mvn dependency:tree
```

---

## 5. Viewing Elision Reports (`report`)

The `report` goal displays the summary and mediated dependency graph from the last successful `elide` run without re-executing dependency analysis:

```sh
mvn io.github.spockz:dependency-elider-maven-plugin:0.1.0-SNAPSHOT:report
```

### Report Information

* **Dropped Artifacts**: Total count and original on-disk JAR bytes of elided dependencies.
* **Pruned Classes**: Count and uncompressed `.class` payload bytes removed from dropped JARs and retained JARs (metrics never overlap).
* **Vulnerability Status**: Separates CVEs removed from inventory, proven absent by bytecode trimming, and coordinate-only prerequisite findings. The prerequisite category does not prove that the exact provider class is absent and is not VEX evidence; see [VEX Evidence Boundary](#vex-evidence-boundary).
* **Mediated Graph**: Visualizes shortest dependency paths with node dispositions: `[RETAINED]`, `[CLASS_TRIMMED]`, `[EFFECTIVE_DROP]`, or `[PROTECTED]`.
* **Format Versions**: Internal persisted report and cache formats use independent schema version 1; incompatible payloads fail fast with instructions to rerun `elide`. CycloneDX declares `specVersion` 1.6 and OpenVEX uses its 0.2.0 context URL. The top-level `version` in either generated security document is a document revision counter, not a schema version.

---

## 6. Vulnerability Intelligence & OpenVEX

Maven Dependency Elider syncs vulnerability metadata from the official OSV Maven snapshot (`-Delide.osvSnapshotUri`) and the CVEList v5 repository (`-Delide.cveListGitUri`).

### Refreshing the Vulnerability Cache

Update the local vulnerability database on demand:

```sh
mvn io.github.spockz:dependency-elider-maven-plugin:0.1.0-SNAPSHOT:update-cve-index
```

* **Cache location**: Stored in the OS user cache directory (outside `~/.m2`); override via `-Delide.cveCacheDirectory=/path/to/cache`.
* **Freshness TTL**: Defaults to 24 hours (`-Delide.cveCacheTtlHours=24`). Use `-Delide.cveForceSync=true` to force synchronization.
* **Offline resilience**: Normal builds skip network synchronization when offline, falling back safely to the local cache or bundled seed data.

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

The current omitted-code proof path can support VEX only when a high-confidence mapping matches a retained trim candidate and archive inspection proves every mapped vulnerable class and nested class absent from that candidate's trimmed JAR. A dependency removed entirely is reported as dropped from inventory, not as code-absence VEX.

Precondition-gated VEX is an accepted design that is not implemented yet. It will require both a prerequisite Maven coordinate and exact prerequisite class metadata. Users will have to set `elide.preconditionClassPathComplete=true` to assert that the declared Maven build inventory is complete. The proof will check application classes/resources and all effective post-elision dependency archives, bind the result to an inventory fingerprint and per-file digests, and suppress VEX if any inventory input or provider is unknown. The assertion will cover only that declared Maven inventory; it cannot prove absence of classes introduced by later packaging or external runtime mechanisms. The OpenVEX statement will use a free-form impact statement without a justification; this is less machine-readable, but no OpenVEX justification enum accurately describes the missing prerequisite. See [ADR-0008](https://github.com/spockz/maven-dependency-elider/blob/main/docs/adr/0008-precondition-gated-vex-attestations.md) and [RQ-0013](https://github.com/spockz/maven-dependency-elider/blob/main/docs/research/RQ-0013-precondition-gated-vex-and-multi-artifact-exploitability.md).

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
