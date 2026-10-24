<!-- WHY: Provides the complete engineering handover, architectural invariants, track specifications, and multi-tier testing protocols for implementing the runtime telemetry-driven Maven Dependency Elider engine and plugin. -->
# RQ-0004: Maven Dependency Elider Engine and Plugin Implementation Handover

* **Status**: Open
* **Category**: Implementation Handover & Engineering Specifications
* **Date**: 2026-10-24
* **Last Updated**: 2026-10-24

Abbreviations: Architecture Decision Record (ADR), Abstract Syntax Tree (AST), Bytecode Manipulation (ASM), Central Directory (CEN), Class Data Sharing (CDS), Common Vulnerabilities and Exposures (CVE), Java Microbenchmark Harness (JMH), Java Virtual Machine (JVM), JDK Flight Recorder (JFR), Project Object Model (POM), Research Question (RQ), Software Bill of Materials (SBOM), Vulnerability Exploitability eXchange (VEX).

This document provides the complete engineering handover for a Luna agent to implement the runtime telemetry-driven dependency elision engine, the Maven 3.x/4.x plugin, and the empirical test harness for `maven-dependency-elider`.

---

## 1. Executive Summary & Non-Negotiable Invariants

### 1.1 Core Problem Statement

Traditional software composition analysis (SCA) and dependency management suffer from severe granularity and visibility mismatches:

1. **False-Positive CVE Noise**: Empirical research proves that **57% of transitive library relationships in Maven are completely bloated** (zero classes ever loaded), and **92%–95% of package vulnerabilities in Java are unreachable at the function level**. Manifest-based scanners create overwhelming alert fatigue.
2. **Static Analysis Blindness**: Static inspection (e.g., `mvn dependency:analyze`) cannot observe dynamic reflection, Spring Boot auto-configuration, or Java SPI (`ServiceLoader`).
3. **Classpath Mutation Timing**: Stripping dependencies during packaging (`prepare-package`) allows compilation and tests to execute against an artificially bloated classpath, introducing classpath collisions (split packages) and masking runtime missing-class failures until deployment.

`maven-dependency-elider` solves this by binding automated elision to the early Maven `INITIALIZE` lifecycle phase, grounded in empirical runtime telemetry, mutating the in-memory `MavenProject.getArtifacts()` state so compiler, test runner, packagers (`maven-shade-plugin`, `spring-boot-maven-plugin:repackage`), and SBOM/CVE scanners transparently bundle and report only surviving code.

### 1.2 Non-Negotiable Invariants

1. **Sub-10ms Fast-Path Invariant (ADR-0001, RQ-0003)**:
   On routine, cached Maven builds where dependencies and traces have not changed, the plugin overhead must be strictly **$< 10\text{ ms}$** (target: $\approx 1\text{ ms}$). Every routine build evaluates a fast fingerprint; full disk rescanning must occur only on cache misses.
2. **Runtime Telemetry Primacy (ADR-0001)**:
   Elision decisions are grounded in runtime telemetry (CDS class lists, `-Xlog:class+load`, JFR, GraalVM config, JaCoCo). Static bytecode constant-pool scanning is rejected as a sole decision source.
3. **Fail-Fast Early Phase Execution (ADR-0001)**:
   The `elide` Mojo binds to `INITIALIZE` with `requiresDependencyResolution = ResolutionScope.TEST`. It mutates `project.getArtifacts()` *before* `compile` and *before* `test`. If an essential dependency is improperly elided, the build must fail immediately during `javac` or `surefire`.
4. **Transparent Downstream Packaging (ADR-0002)**:
   No custom adapters or modifications are permitted in downstream packaging plugins. Mutating `project.getArtifacts()` and `setFile()` in-memory must guarantee that `maven-shade-plugin`, `spring-boot-maven-plugin:repackage`, assembly, and container plugins bundle *only* surviving code.
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
| **Track 4: Three-Tier Provenance Generators** | `elider-core/src/main/java/.../metadata` | Effective/Consumer POM, CycloneDX 1.5+ SBOM (`pedigree`), OpenVEX JSON, Dependency-Check XML. | Track 3 |
| **Track 5: Early Lifecycle Maven Plugin Mojo** | `dependency-elider-maven-plugin` | `@Mojo(name="elide", defaultPhase=INITIALIZE)`, in-memory `project.getArtifacts()` mutator. | Tracks 3, 4 |
| **Track 6: Sub-Artifact Bytecode Symbol Slicing (Step 2)** | `elider-core/src/main/java/.../slicer` | ASM intra-JAR link closure, Shade signature-stripping, sliced companion JAR creation. | Track 5 |
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

---

### 3.4 Track 4: Three-Tier Provenance Generators (`elider-core/metadata`)

**Files to implement:**

* `io.github.spockz.elider.metadata.EffectivePomGenerator`
* `io.github.spockz.elider.metadata.CycloneDxSbomGenerator`
* `io.github.spockz.elider.metadata.OpenVexGenerator`
* `io.github.spockz.elider.metadata.DependencyCheckSuppressionGenerator`

#### Implementation Details

1. **`EffectivePomGenerator`**:
   * Writes `target/effective-pom-elided.xml`.
   * Strips `<dependency>` entries for elided artifacts.
   * For sliced dependencies (Step 2), attaches `<classifier>elided</classifier>` and XML comments documenting original SHA-256 and retained symbol counts.
2. **`CycloneDxSbomGenerator`**:
   * Generates/enriches `target/bom-elided.cdx.json` conforming to CycloneDX 1.5/1.6 schema.
   * Elided dependencies are excluded or tagged.
   * Sliced dependencies declare:
     * `hashes`: actual SHA-256 of the on-disk sliced JAR.
     * `pedigree.ancestors`: original Maven Central coordinate and original SHA-256 digest.
     * `pedigree.patches`: `"Debloated unused classes via maven-dependency-elider"`.
     * `properties`: `elider:status=sliced`, `elider:retainedClasses`, `elider:totalClasses`.
3. **`OpenVexGenerator`**:
   * Writes `target/elided.vex.json` conforming to the OpenVEX specification:
     * `status: "not_affected"`.
     * `justification: "component_not_present"` for whole-artifact elisions.
     * `justification: "code_not_present"` for sliced classes.
4. **`DependencyCheckSuppressionGenerator`**:
   * Writes `target/dependency-check-suppressions.xml` for legacy scanners lacking VEX support.

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

   * Emit provenance metadata files into `target/`.
   * Print a concise Maven build summary after every elision run, including cache hits. Report whole-artifact elisions as `elided / input dependency artifacts` and a percentage. Report surgical removals separately: classes removed / classes considered and bytecode symbols (methods and fields) removed / symbols considered, each with a percentage. Whole-artifact removals must not be double-counted in the surgical denominators. When slicing is not run, report surgical counts as zero and mark the stage as not run; never present a missing denominator as 0%.

---

### 3.6 Track 6: Sub-Artifact Bytecode Symbol Slicing (Step 2 Priority)

**Files to implement:**

* `io.github.spockz.elider.slicer.BytecodeSlicer`
* `io.github.spockz.elider.slicer.LinkClosureResolver`

#### Implementation Details

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
* Declares unused starter `spring-boot-starter-mail`.
* Packaged with `spring-boot-maven-plugin:repackage`.

#### 3. Integration Test Loop (Programmatic Test Case)

1. **Stage 1 (Recording)**:
   * Launch app / test with `-Xlog:class+load:file=target/classes.log` or CDS `-XX:DumpLoadedClassList=target/classes.lst`.
   * Execute integration test; shut down app; verify trace file exists.
2. **Stage 2 (Elision)**:
   * Execute `./mvnw clean package` with elider active.
   * Plugin runs at `INITIALIZE`, detects unused `commons-codec` (basic app) and unused mail transitives (Spring Boot app).
   * In-memory `project.getArtifacts()` is pruned.
   * Shade and Spring Boot repackage complete.
3. **Stage 3 (Dual Verification)**:
   * **Functional**: Start the resulting fat JAR (`java -jar target/*.jar`) and execute HTTP/integration tests. Must pass with zero errors.
   * **Physical**: Inspect the fat JAR entries:
     * `commons-codec` classes must be **100% absent** from `example-basic-app` shaded JAR.
     * `angus-mail` / `jakarta.mail` JARs must be **100% absent** from `example-spring-boot-app` `BOOT-INF/lib`.
   * **Security**: Verify `target/bom-elided.cdx.json` and `target/elided.vex.json` omit the elided dependencies.

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

Before declaring implementation complete:

* [ ] **Compilation**: Root build `./mvnw clean compile` passes across all modules under Java 21.
* [ ] **Unit Tests**: All hermetic tests in `elider-core` pass cleanly.
* [ ] **JMH Invariant**: Fast-path cache validation benchmark measures $< 1\text{ ms}$ ($< 10\text{ ms}$ overhead gate satisfied).
* [ ] **Plugin Descriptor**: `dependency-elider-maven-plugin` generates valid plugin descriptors for Maven 3.x and 4.x.
* [ ] **Basic App Verification**: `commons-codec` is physically pruned from `example-basic-app` shaded JAR while Jackson-based execution continues to succeed.
* [ ] **Spring Boot Verification**: Unused starter libraries are physically omitted from `BOOT-INF/lib` while Spring Boot web endpoint boots and tests cleanly.
* [ ] **Provenance Output**: `effective-pom-elided.xml`, `bom-elided.cdx.json`, and `elided.vex.json` are emitted with valid syntax and `pedigree`/`not_affected` statements.
* [ ] **Elision Summary**: Each run prints absolute counts and percentages for whole artifacts elided and, when slicing runs, classes and bytecode symbols removed; denominators are explicit and exclude whole-artifact removals from surgical metrics.
* [ ] **Documentation & Indexing**: ADR and RQ registers updated with completed checkpoints.
