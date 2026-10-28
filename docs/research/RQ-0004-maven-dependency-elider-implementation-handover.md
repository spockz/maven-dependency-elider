<!-- WHY: Provides the complete engineering handover, architectural invariants, track specifications, and multi-tier testing protocols for implementing the runtime telemetry-driven Maven Dependency Elider engine and plugin. -->
# RQ-0004: Maven Dependency Elider Engine and Plugin Implementation Handover

* **Status**: Open
* **Category**: Implementation Handover & Engineering Specifications
* **Date**: 2026-10-24
* **Last Updated**: 2026-10-25

Abbreviations: Architecture Decision Record (ADR), Abstract Syntax Tree (AST), Bytecode Manipulation (ASM), Central Directory (CEN), Class Data Sharing (CDS), Common Vulnerabilities and Exposures (CVE), Java Microbenchmark Harness (JMH), Java Virtual Machine (JVM), JDK Flight Recorder (JFR), Project Object Model (POM), Research Question (RQ), Software Bill of Materials (SBOM), Vulnerability Exploitability eXchange (VEX).

This document provides the complete engineering handover for a Luna agent to implement the runtime telemetry-driven dependency elision engine, the Maven 3.x/4.x plugin, and the empirical test harness for `maven-dependency-elider`.

Implementation snapshot (2026-10-25): the whole-artifact elision, evidence-reporting, and four-example lifecycle follow-ups are integrated. The original plan remains partially complete: Maven cache/provenance integration and Maven 4 verification remain pending. The [session closeout](../handovers/2026-10-25-session-closeout.md) records verified behavior, test evidence, and the next session's priorities; specification sketches below are not declarations that every feature is implemented.

Current report metric contract (2026-10-28): the persisted elision snapshot is schema v4. It reports whole-JAR drops with artifact count, original on-disk JAR bytes, program `.class` entry count, and uncompressed class-entry payload bytes. Retained-JAR class trimming has its own class and payload-byte totals; classes in whole-dropped JARs are never included in retained-JAR trim totals. Both class metrics exclude root/versioned `module-info.class` entries and archive metadata. Schema v3 and other unsupported report versions require rerunning `elide`; no migration is provided. `elide.reportFile` remains class-usage evidence, while `elide.summaryFile` is the elision snapshot consumed by `dependency-elider:report`. The current schema, rendering, and verification receipt is maintained in [RQ-0006](RQ-0006-maven-artifact-view-consistency-and-early-resolution-hooks.md#215-effective-output-and-resolver-projection-slices-32c32d).

---

## 1. Executive Summary & Non-Negotiable Invariants

### 1.1 Core Problem Statement

Traditional software composition analysis (SCA) and dependency management suffer from severe granularity and visibility mismatches:

1. **Distribution and Assessment Granularity**: Applications may require only part of their resolved dependencies. Removing unnecessary code can reduce distribution size, while vulnerability conclusions still require product-specific evidence; a coordinate-based finding is not automatically false because some code was unobserved.
2. **Static Analysis Blindness**: Static inspection (e.g., `mvn dependency:analyze`) cannot observe dynamic reflection, Spring Boot auto-configuration, or Java SPI (`ServiceLoader`).
3. **Classpath Mutation Timing**: Stripping dependencies during packaging (`prepare-package`) allows compilation and tests to execute against an artificially bloated classpath, introducing classpath collisions (split packages) and masking runtime missing-class failures until deployment.

The intended value is translating an external usage oracle into reduced dependencies used consistently by Maven compilation, testing, and packaging. `INITIALIZE` mutation is the proposed whole-artifact integration mechanism; it must be verified against later resolution and consumer classpaths. The differentiation is oracle integration and dependable orchestration, with prior art in Gradle transformations and DepTrim (ADR-0001).

### 1.2 Non-Negotiable Invariants

1. **Sub-10ms Fast-Path Invariant (ADR-0001, RQ-0003)**:
   On routine, cached Maven builds where dependencies and traces have not changed, the plugin overhead must be strictly **$< 10\text{ ms}$** (target: $\approx 1\text{ ms}$). Every routine build evaluates a fast fingerprint; full disk rescanning must occur only on cache misses.
2. **Runtime Telemetry Primacy (ADR-0001)**:
   Elision decisions use external evidence with an explicit coverage contract. Positive observations supply roots; absence alone does not prove non-use. Future source-aware trimming combines oracle, source compilation, and framework/resource roots with their required dependencies (RQ-0001 and RQ-0002).
3. **Fail-Fast Early Phase Execution (ADR-0001)**:
   The whole-artifact `elide` Mojo targets `INITIALIZE` with `requiresDependencyResolution = ResolutionScope.TEST`, before compilation and tests. Those checks expose missing dependencies on covered paths; they do not prove runtime completeness. Source-aware trimming requires a separate ordering decision for generated sources and processors.
4. **Transparent Downstream Packaging (ADR-0002)**:
   Avoiding custom downstream adapters is a design goal. Verify actual compile/test classpaths and packaged bytes for each supported integration. In-memory mutation alone does not establish support for every packager or scanner (ADR-0002).
5. **Dual Maven Compatibility (3.8+/3.9+ and 4.x)**:
   The codebase targets Java 21 LTS (`<maven.compiler.release>21</maven.compiler.release>`) and must build and execute cleanly on both Apache Maven 3.9.x and Maven 4.0.x.
6. **Clean `mvn verify` Gate**:
   All unit tests, JMH benchmark gates, and end-to-end integration tests on both example projects (`example-basic-app` and `example-spring-boot-app`) must pass cleanly.

---

## 2. Parallel Implementation Tracks & Ownership

| Track | Target Module / Packages | Responsibility | Prerequisite |
| :--- | :--- | :--- | :--- |
| **Track 1: Telemetry Ingestion Layer** | `elider-core/src/main/java/.../trace` | Multi-source trace readers (ClassLoader logs, CDS lists, JFR events, GraalVM JSON). | None |
| **Track 2: High-Performance ZIP Central Directory Indexer** | `elider-core/src/main/java/.../scanner` | Parallel virtual-thread scanner of JAR Central Directories (`CEN`) without entry inflation. | None |
| **Track 3: Graph Elision Engine & Sub-10ms Fingerprint Cache** | `elider-core/src/main/java/.../engine`, `.../cache` | 64-bit fingerprinting, cache storage/validation, dependency reachability graph pruning. | Tracks 1, 2 |
| **Track 4: Provenance Generators** | `elider-core/src/main/java/.../metadata` | Audit POM and CycloneDX 1.6 inventory first; OpenVEX and Dependency-Check outputs require explicit vulnerability evidence. | Track 3 |
| **Track 5: Early Lifecycle Maven Plugin Mojo** | `dependency-elider-maven-plugin` | `@Mojo(name="elide", defaultPhase=INITIALIZE)`, in-memory `project.getArtifacts()` mutator. | Tracks 3, 4 |
| **Track 6: Sub-Artifact Bytecode Slicing** | Deferred | No sub-artifact deletion in the current product scope. An observed class retains its entire owning dependency JAR. | Explicit future scope revision |
| **Track 7: JMH Benchmarking Suite** | `elider-benchmarks` | Microbenchmarks proving the $<10\text{ ms}$ invariant on cache-hit and parallel cold-path. | Tracks 2, 3 |
| **Track 8: End-to-End Verification Harness** | `examples/`, `elider-core/src/test` | 3-stage recording $\rightarrow$ elision $\rightarrow$ verification tests on basic app and Spring Boot. | Tracks 5, 7 |

---

## 3. Detailed Component Specifications

### 3.1 Track 1: Telemetry Ingestion Layer (`elider-core/trace`)

**Files to implement:**

* `io.github.spockz.elider.trace.RuntimeTraceReader` (interface)
* `io.github.spockz.elider.trace.ClassLoaderLogReader`
* `io.github.spockz.elider.trace.CdsClassListReader`
* `io.github.spockz.elider.trace.JfrTraceReader`
* `io.github.spockz.elider.trace.GraalVmConfigReader`
* `io.github.spockz.elider.trace.JaCoCoTraceReader`
* `io.github.spockz.elider.trace.CompositeTraceReader`

#### Implementation Details

1. **`RuntimeTraceReader` interface**:

   ```java
   public interface RuntimeTraceReader {
       boolean supports(Path path);
       TraceData read(Path path) throws IOException;
   }
   ```

2. **`ClassLoaderLogReader`**:
   * Parses logs from `-Xlog:class+load:file=classes.log` or console redirect.
   * Extracts class names from lines matching `[info][class,load] <classname> source: ...` or raw lines.
   * Converts slash/dot notation using `TraceData.normalizeToDot(name)` and `normalizeToSlash(name)`.
3. **`CdsClassListReader`**:
   * Parses HotSpot Class Data Sharing dumps (`-XX:DumpLoadedClassList=classes.lst`).
   * Ignores comment lines starting with `#` or `@`. Each line contains a loaded class name in slash format (e.g. `java/lang/Object`, `org/apache/commons/codec/binary/Base64`).
4. **`JfrTraceReader`**:
   * Uses the JDK 21 standard library `jdk.jfr.consumer.RecordingFile`.
   * Iterates through `jdk.ClassLoad` events.
   * Extracts the `loadedClass` field: `event.getClass("loadedClass").getName()`.
   * Filters out null or anonymous classes (`/0x...`).
5. **`GraalVmConfigReader`**:
   * Parses `reflect-config.json` via Jackson `JsonNode`.
   * Extracts the `"name"` property from each reflected class descriptor.
6. **`CompositeTraceReader`**:
   * Inspects candidate files, identifies applicable readers, and merges results into a single `TraceData` instance.
7. **Artifact attribution**:
   * Preserve defining-artifact information when a telemetry format provides it (for example, a class-loading record with a JAR source). Do not infer artifact identity from class name alone.
   * The pruning engine may use a reported origin to disambiguate duplicate classes only when the source identifies the artifact reliably. For class-only observations, retain every supplied artifact containing an observed duplicate class.
8. **Application bytecode evidence follow-up**:
   * Add a separate scanner for direct symbolic class references in compiled production application classes. Keep these references separate from runtime observations and artifact-origin evidence.
   * Record whether the application scan completed and which production class output was scanned. Missing or failed scans mean static evidence is unknown, never that a class is unreferenced.
   * Define direct references from bytecode structures; do not count class-name string literals, reflection configuration, dependency-to-dependency references, or test classes as direct application references unless a separately named input is added.

---

### 3.2 Track 2: High-Performance ZIP Central Directory Indexer (`elider-core/scanner`)

**Files to implement:**

* `io.github.spockz.elider.scanner.JarIndexScanner`
* `io.github.spockz.elider.scanner.ArtifactClassIndex`

#### Implementation Details

1. **Central Directory Only (No Entry Inflation)**:
   * Scanning 80+ JARs must not call `jarFile.getInputStream(entry)` or decompress bytecode.
   * Open using standard `new java.util.zip.ZipFile(file.toFile())`.
   * Iterate over `zipFile.entries()`: only read `entry.getName()`.
   * If name ends with `.class` and is not `module-info.class`:
     * Strip `.class` and normalize.
     * Add to `ArtifactClassIndex`.
2. **Java 21 Virtual Threads**:
   * Use `Executors.newVirtualThreadPerTaskExecutor()`:

     ```java
     try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
         List<Future<ArtifactScanResult>> futures = artifacts.stream()
             .map(a -> executor.submit(() -> scanSingleJar(a)))
             .toList();
         // gather results
     }
     ```

   * Benchmarking requirement: 100 dependency JARs indexed in $< 20\text{ ms}$ on NVMe SSD.

---

### 3.3 Track 3: Graph Elision Engine & Sub-10ms Fingerprint Cache (`elider-core/engine`, `.../cache`)

**Files to implement:**

* `io.github.spockz.elider.cache.FingerprintEngine`
* `io.github.spockz.elider.cache.ElisionCacheRecord`
* `io.github.spockz.elider.engine.DependencyPruner`
* `io.github.spockz.elider.engine.PruneConfig`

#### Implementation Details

1. **`FingerprintEngine`**:
   * Computes a 64-bit fingerprint from:
     * Sorted list of artifact coordinates (`groupId:artifactId:version:classifier:type`).
     * Filesystem timestamps and sizes (`lastModified` and `fileSize`) of each resolved artifact JAR.
     * Path, `lastModified`, and `fileSize` of each configured trace file.
     * Active configuration flags (`keepScopes`, `includes`, `excludes`).
   * Cache file: stored in `target/.elider-cache.bin` (compact binary format: 8-byte magic, 8-byte fingerprint, int count, UTF strings).
   * Validation time: $< 0.3\text{ ms}$.
2. **`DependencyPruner`**:
   * Inputs: `Collection<ArtifactFileRef> resolvedArtifacts`, `TraceData traceData`, `PruneConfig config`.
   * For each artifact:
     * If artifact is in `config.getKeepArtifacts()` or matches `config.getExcludedScopes()`: mark `RETAINED`.
     * Otherwise, cross-reference artifact's contained classes with `traceData`.
     * If count of loaded classes == 0: mark `ELIDED`.
     * If count of loaded classes > 0: mark `RETAINED`.
   * Returns `ElisionDecision` with retained artifacts, elided artifacts, and class breakdowns.
3. **Usage evidence classification follow-up**:
   * Join the dependency class inventory, complete application bytecode-reference scan, and runtime trace into distinct report groups: application-bytecode referenced; runtime-observed without an application-bytecode reference; and neither referenced nor observed.
   * Preserve the four underlying referenced/observed combinations and an explicit unknown state when the static scan is incomplete.
   * Report-only: direct references do not prove execution, and runtime-only observations do not identify why a framework loaded a class. The second group must not be labeled “framework loaded.”
   * Keep existing retention behavior: every runtime-observed class retains its owning dependency JAR. This classification adds no intra-JAR deletion and does not prove classes in the third group are universally unused.

---

### 3.4 Track 4: Provenance Generators (`elider-core/metadata`)

**Files to implement:**

* `io.github.spockz.elider.metadata.EffectivePomGenerator`
* `io.github.spockz.elider.metadata.CycloneDxSbomGenerator`
* `io.github.spockz.elider.metadata.OpenVexGenerator`
* `io.github.spockz.elider.metadata.DependencyCheckSuppressionGenerator`

#### Implementation Details

The initial provenance slice is a fresh CycloneDX 1.6 inventory for whole-artifact elision. It requires the root project identity, the applied retained-artifact inventory, the pruning decision, document metadata, and real artifact paths when hashes are emitted. It must not infer dependency edges from a flat artifact list. Deduplicate scope variants by artifact identity while preserving version, type, and classifier distinctions; represent Maven scopes as properties rather than CycloneDX scope values. Validate output against a pinned CycloneDX 1.6 schema in an offline test.

Later slices may add:

1. **`EffectivePomGenerator`**:
   * Takes the original effective model and resolved dependency paths as inputs and writes an audit POM. Removing direct dependency elements alone is insufficient because a retained dependency may bring an elided transitive back into resolution.
   * Do not emit a consumer POM that references an `elided` classifier until the companion artifact is actually installed/deployed and consumer resolution is verified. Changing an in-memory file pointer does not publish a new Maven coordinate.
2. **`CycloneDxSbomGenerator` slicing enrichment**:
   * Use actual SHA-256 values from on-disk original and sliced JARs.
   * CycloneDX 1.6 pedigree ancestors are complete component objects, including required `type` and `name` fields. Pedigree patches are objects with required `type`; use `pedigree.notes` for explanatory text rather than a patch `description` field.
   * Emit retained/removed class and symbol properties only from a slicing result that records those actual counts. An `ElisionDecision` class breakdown describes observed/unused classes and is not evidence of physically removed bytecode.
3. **`OpenVexGenerator`**:
   * Requires explicit product identity, vulnerability identifiers and mappings, issuer, timestamp, document ID/version, and evidence supporting each statement. Do not synthesize vulnerability statements from dependency pruning alone.
   * Use the specification’s `component_not_present` justification only when the identified product and vulnerability assessment support it. For sliced code, use `vulnerable_code_not_present`; do not use `code_not_present`.
4. **`DependencyCheckSuppressionGenerator`**:
   * Requires vulnerability-to-component evidence and writes narrowly scoped suppressions for legacy scanners. Do not infer vulnerability selectors from unused classes or generate broad suppressions without evidence.

---

### 3.5 Track 5: Early-Phase Maven Plugin Mojo (`dependency-elider-maven-plugin`)

**Files to implement:**

* `io.github.spockz.elider.plugin.ElideMojo`
* `io.github.spockz.elider.plugin.AnalyzeMojo`

#### Implementation Details

1. **`ElideMojo` Declaration**:

   ```java
   @Mojo(
       name = "elide",
       defaultPhase = LifecyclePhase.INITIALIZE,
       requiresDependencyResolution = ResolutionScope.TEST,
       threadSafe = true
   )
   public class ElideMojo extends AbstractMojo {
       @Parameter(defaultValue = "${project}", readonly = true, required = true)
       private MavenProject project;

       @Parameter(property = "elide.traceFiles")
       private List<File> traceFiles;

       @Parameter(property = "elide.skip", defaultValue = "false")
       private boolean skip;

       @Parameter(property = "elide.failOnUnused", defaultValue = "false")
       private boolean failOnUnused;

       @Parameter(property = "elide.excludedArtifacts")
       private List<String> excludedArtifacts;
       ...
   }
   ```

2. **Execution Logic**:
   * Check fingerprint cache: if valid, read cached decision, mutate `project.getArtifacts()`, and exit in $< 1.5\text{ ms}$.
   * If cache miss:
     1. Ingest `traceFiles` (auto-detecting `target/classes.log`, `target/*.jfr`, `target/classes.lst`).
     2. Scan Central Directory of all `project.getArtifacts()`.
     3. Execute `DependencyPruner.prune(...)`.
     4. Save decision to cache.
   * Pass plugin-user-configured `excludedArtifacts` into the pruning policy. Matching exclusions retain those dependencies globally, regardless of where they enter the dependency set; keep this distinct from exclusions scoped to an individual Maven dependency declaration. The default is empty, and coordinate matching must be documented and tested.
   * **In-Memory Mutation (ADR-0002)**:

     ```java
     Set<Artifact> allArtifacts = new LinkedHashSet<>(project.getArtifacts());
     Set<Artifact> retained = allArtifacts.stream()
         .filter(a -> decision.isRetained(toCoordinate(a)))
         .collect(Collectors.toCollection(LinkedHashSet::new));
     project.setArtifacts(retained);

     if (project.getDependencyArtifacts() != null) {
         Set<Artifact> directRetained = project.getDependencyArtifacts().stream()
             .filter(a -> decision.isRetained(toCoordinate(a)))
             .collect(Collectors.toCollection(LinkedHashSet::new));
         project.setDependencyArtifacts(directRetained);
     }
     ```

   * Emit only provenance artifacts supported by the available product, resolved-inventory, digest, slicing, and vulnerability evidence; report omitted unsupported formats explicitly.
   * Print a concise Maven build summary after every elision run, including cache hits. Report whole-artifact elisions as `elided / input dependency artifacts` and a percentage. For dropped JARs, separately report their artifact count, original on-disk bytes, number of program `.class` entries, and uncompressed class-entry payload bytes. For retained-JAR trimming, report program classes removed and uncompressed omitted `.class` entry payload bytes using only retained JARs; exclude whole-dropped JARs from both trim totals and any trim denominator. Do not combine the drop and trim class totals. Both categories exclude root/versioned `module-info.class` and archive sanitation metadata. Report bytecode symbols (methods and fields) removed / symbols considered, each with a percentage, only when that stage runs. When retained-JAR trimming is not run, report its counts as zero and mark that stage as not run; never present a missing denominator as 0%.

---

### 3.6 Track 6: Sub-Artifact Bytecode Slicing (Deferred)

Sub-artifact slicing is outside the current product scope. Runtime class observations map to their owning dependency artifact, and any observed class retains the entire JAR. Do not run intra-JAR link-closure analysis or delete individual class entries. Reopen this track only through an explicit scope revision.

**Historical proposal only:** The files and algorithm below are not current implementation tasks or acceptance criteria.

**Potential future files if the scope is explicitly reopened:**

* `io.github.spockz.elider.slicer.BytecodeSlicer`
* `io.github.spockz.elider.slicer.LinkClosureResolver`

#### Historical Implementation Proposal

1. **ASM Transitive Link Closure**:
   * For partially used dependencies, find root classes referenced by project or runtime traces.
   * Use ASM `ClassReader` to inspect instructions, field descriptors, method signatures, and exception types.
   * Expand iteratively: add internal classes in the same JAR until closure is fixed.
2. **Signature Stripping (`maven-shade-plugin` Standard)**:
   * Check if JAR contains `META-INF/*.SF`, `*.DSA`, `*.RSA`, or `META-INF/SIG-*`.
   * If signed and `stripSignatures=false`: skip slicing (retain whole JAR).
   * If `stripSignatures=true` (or unsigned):
     * Strip signature files from `META-INF/`.
     * Strip digest attributes from `META-INF/MANIFEST.MF`.
     * Create sliced JAR in `target/elided-artifacts/<artifact>-elided.jar`.
     * Swap in-memory pointer via `artifact.setFile(slicedJarPath)`.

---

### 3.7 Track 7: JMH Benchmarking Suite (`elider-benchmarks`)

**Files to implement:**

* `io.github.spockz.elider.benchmark.FastPathBenchmark`
* `io.github.spockz.elider.benchmark.ZipCenScannerBenchmark`
* `io.github.spockz.elider.benchmark.TraceReaderBenchmark`

#### Benchmarking Gates

* `FastPathBenchmark`: Measures fingerprint validation + in-memory `Set.retainAll()` mutation. **Gate: $< 0.5\text{ ms}$ average latency.**
* `ZipCenScannerBenchmark`: Compares sequential vs. virtual-thread parallel Central Directory scanning across 100 JARs. **Gate: $< 25\text{ ms}$ total scan time.**

---

### 3.8 Track 8: Integration Test Harness & Reference Projects (`examples/`)

#### 1. `examples/example-basic-app`

* Plain Java 21 app.
* Uses `jackson-databind` for simple JSON parsing.
* Declares unused `commons-codec:commons-codec:1.17.1`.
* Packaged with `maven-shade-plugin`.

#### 2. `examples/example-spring-boot-app`

* Spring Boot 3.3.5 web application.
* Uses `spring-boot-starter-web` for a REST endpoint `/api/hello`.
* Declares both unused BOM-managed Commons Codec and `spring-boot-starter-mail`. Baseline runtime telemetry observes mail classes even though application production bytecode does not directly reference them.
* Packaged with `spring-boot-maven-plugin:repackage`.

**Implementation follow-up (2026-10-25):** The repeatable lifecycle test declares both the unused,
BOM-managed `commons-codec` candidate and `spring-boot-starter-mail`. Before the active build runs
`clean`, the harness copies baseline `target/classes` outside the build directory and passes that
copy using `-Delide.productionOutput`. It also directs `-Delide.reportFile` outside `target`. The
report assertions require mail classes seen in runtime telemetry to be classified as
`runtimeObservedWithoutApplicationReference`, and require Commons Codec's `Hex` class to appear in
`neitherReferencedNorObserved`. The packaged Boot JAR omits Commons Codec while retaining the
complete mail artifacts, and `GET /api/hello` continues to return the expected response. This
classification does not establish why mail classes were loaded and does not change whole-JAR
retention. The elision goal remains in an opt-in profile activated by `-Delide.mode=elision`; the
baseline mode does not activate the profile.

#### 3. Integration Test Loop (Programmatic Test Case)

1. **Stage 1 (Recording)**:
   * Launch app / test with `-Xlog:class+load:file=target/classes.log` or CDS `-XX:DumpLoadedClassList=target/classes.lst`.
   * Execute integration test; shut down app; verify trace file exists.
2. **Stage 2 (Elision)**:
   * Preserve the baseline application production output outside `target`, then execute
     `./mvnw clean package` with elider active and the preserved output supplied for static scan.
   * Plugin runs at `INITIALIZE`, elides unobserved `commons-codec`, and retains runtime-observed mail artifacts while reporting mail classes separately from direct application bytecode references.
   * In-memory `project.getArtifacts()` is pruned.
   * Shade and Spring Boot repackage complete.
3. **Stage 3 (Dual Verification)**:
   * **Functional**: Start the resulting fat JAR (`java -jar target/*.jar`) and execute HTTP/integration tests. Must pass with zero errors.
   * **Physical**: Inspect the fat JAR entries:
     * `commons-codec` classes must be **100% absent** from `example-basic-app` shaded JAR.
     * The `spring-context-support`, `org.eclipse.angus:jakarta.mail`,
       `jakarta.activation-api`, and `angus-activation` JARs must remain in
       `example-spring-boot-app` `BOOT-INF/lib` when the runtime trace observes their classes, even
       if application bytecode has no direct reference to those classes.
   * **Security**: Validate CycloneDX against its pinned schema and ensure it matches the applied inventory. Emit VEX only for vulnerability assessments with required product identity and evidence; never treat a flat pruning decision as vulnerability proof.

---

## 4. Multi-Level Testing & Acceptance Strategy

### Level 1: Hermetic Unit Tests (`elider-core/src/test`)

* `ClassLoaderLogReaderTest`: Tests parsing standard `-Xlog:class+load` format, edge-case source strings, and class normalization.
* `CdsClassListReaderTest`: Tests parsing slash-separated HotSpot CDS class lists, ignoring comments and whitespace.
* `JarIndexScannerTest`: Tests parallel virtual-thread CEN scanning on fixture JARs.
* `FingerprintEngineTest`: Tests deterministic 64-bit hashing, cache hit/miss semantics, and file modification detection.
* `DependencyPrunerTest`: Tests whole-artifact elision with direct and transitive combinations.
* `ProvenanceGeneratorTest`: Tests CycloneDX `pedigree` and OpenVEX JSON structure.

### Level 2: JMH Microbenchmark Gates (`elider-benchmarks`)

* Execute JMH benchmarks to verify the fast-path latency boundary:
  $$\Delta t_{\text{fast-path}} < 1\text{ ms}$$

### Level 3: End-to-End Maven Verification Loop (`dependency-elider-maven-plugin/src/test`)

* Programmatic execution of the 3-stage loop against `example-basic-app` and `example-spring-boot-app`.
* Verifies physical absence of elided dependencies in packaged JARs and non-regression of runtime behavior.

---

## 5. Acceptance Verification Checklist

The follow-ups below qualify earlier implementation sketches. Deferred source-aware/member trimming is not activated by this handover update.

Before declaring implementation complete:

* [ ] **Compilation**: Root build `./mvnw clean compile` passes across all modules under Java 21.
* [ ] **Unit Tests**: All hermetic tests in `elider-core` pass cleanly.
* [ ] **JMH Invariant**: Fast-path cache validation benchmark measures $< 1\text{ ms}$ ($< 10\text{ ms}$ overhead gate satisfied).
* [ ] **Plugin Descriptor**: `dependency-elider-maven-plugin` generates valid plugin descriptors for Maven 3.x and 4.x.
* [ ] **Basic App Verification**: `commons-codec` is physically pruned from `example-basic-app` shaded JAR while Jackson-based execution continues to succeed.
* [ ] **Spring Boot Verification**: Unobserved Commons Codec is omitted from `BOOT-INF/lib`; runtime-observed mail classes without direct application references are classified in the report, and the exact mail runtime JAR bytes remain in `BOOT-INF/lib` while the web endpoint passes.
* [ ] **Provenance Output**: CycloneDX 1.6 inventory matches the applied retained-artifact set and validates against the pinned schema. Audit POM, OpenVEX, and Dependency-Check suppressions are emitted only when their required resolved-graph, product, vulnerability, digest, and slicing evidence is supplied.
* [ ] **Elision Summary**: Each run reports whole-artifact removals as a count and percentage of eligible artifacts, original on-disk JAR bytes, and the program `.class` entry count and uncompressed class-entry payload bytes discarded with those artifacts. It reports retained-JAR trimmed class counts and payload bytes separately. Dropped-artifact classes never enter retained-JAR trim totals or denominators; both class metrics exclude root/versioned `module-info.class` entries and archive sanitation metadata.
* [ ] **Documentation & Indexing**: ADR and RQ registers updated with completed checkpoints.

## 6. Design Follow-Ups and Unresolved Boundaries

| Area | Follow-up and evidence required | Owning work |
| :--- | :--- | :--- |
| Oracle contract | Specify observation versus completeness, member descriptors, attribution, instrumentation coverage, environment, workload, and stale-evidence handling. Class-only or partial method evidence must not enable arbitrary member deletion. | Track 1; RQ-0002 |
| Source compilation roots | Active whole-artifact correctness gap for the next user-defined work package: resolve original dependencies and retain artifacts required to compile current source, including constants and erased references. Cover generated sources and compiler settings; resolve lifecycle ordering. The negative javac probe proves classpath mutation, not correct retention. A source-required dependency absent from runtime telemetry must remain available with elision enabled. | Tracks 1, 3, 5, and 8; RQ-0001 §2.2; independent of deferred Track 6 |
| Closure and engine choice | Compare established engines against custom class filtering; retain supporting code across JARs. Decide integration mode, Java support, and distribution terms. Begin with separate dependency outputs and no renaming/aggressive optimization if this scope is reopened. | Deferred Track 6; RQ-0001 |
| Dynamic discovery and resources | Supply explicit/framework roots for services, Spring, reflection, serialization, and native code. Preserve or deliberately handle descriptors/resources and signed, modular, sealed, or multi-release inputs. | Tracks 1 and 8; RQ-0001 and RQ-0005 |
| Consumer consistency | Prove compiler, Surefire/Failsafe, runtime launches, and packagers consume the intended files after later resolution. Verify identities/hashes as well as physical omissions. Keep original repository artifacts immutable. | Tracks 5 and 8; ADR-0002 |
| Invocation and reactor behavior | Investigate inter-module outputs, dependency management/conflict mediation, parallel builds, Maven daemon reuse, offline builds, direct goal/IDE invocations, and test-only dependencies. State supported combinations explicitly. | Tracks 5 and 8 |
| Compile/runtime outputs | Decide whether a single superset suffices. Separate outputs need explicit classpaths and packaging exclusions; `provided` is not a compilation-only packaging policy. Do not split fields between duplicate class definitions. | Track 5; RQ-0001; ADR-0002 |
| Reproducibility and cache | Bind decisions to content/configuration/evidence identities; validate outputs, atomic writes, parallel access, and failed transformations. Measure cold and cached total build work. | Tracks 3 and 7; RQ-0003 |
| Publication and scope | Specialization is application-specific. Publishing a reusable library requires roots for downstream APIs and a separate identity/resolution policy. Verify consumer resolution rather than publish references to unavailable transformed artifacts. | Tracks 4 and 5; RQ-0001 |
| Validation and security reporting | Test actual transformed dependencies, positive/negative fixtures, packaged contents, and reasons for retention/removal. Separate package-size results, scanner results, and vulnerability assessments. | Tracks 4 and 8 |

The first source-aware trimming experiment, if approved as a scope revision, should compare oracle plus source/framework roots against a distribution-only shrinker baseline, preserve individual JAR boundaries and compilation metadata, retain members conservatively, and report package size, total build cost, and setup effort. This is a research candidate, not an implemented feature or a replacement for the current whole-artifact scope.
