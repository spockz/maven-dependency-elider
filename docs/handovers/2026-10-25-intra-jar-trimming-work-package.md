<!-- WHY: Provides the complete work package specification, track decomposition, and committable slices for implementing ProGuard Core-driven intra-JAR trimming, signature stripping, and CycloneDX 1.6 pedigree provenance. -->
# Work Package Handover: WP-TRIM-01 ProGuard Core-Driven Intra-JAR Trimming and Pedigree Provenance

* **Status**: Ready for Implementation
* **Owning Thread / Session**: Primary Coordinating Session
* **Date**: 2026-10-25
* **Target Branch / Base**: `main` (`4be38dc`)

---

## 1. Executive Summary & Non-Negotiable Invariants

### 1.1 Objective

Build upon the verified whole-artifact elision engine by introducing **intra-JAR dependency trimming**: selectively pruning unreferenced `.class` files from retained third-party dependency JARs down to what is strictly necessary for correct application compilation and execution, while preserving per-JAR archive boundaries, stripping invalidated digital signatures, and recording full provenance in **CycloneDX 1.6 SBOMs** via `pedigree.ancestors` and `pedigree.patches`.

### 1.2 Non-Negotiable Invariants

1. **Strict License Boundary**: Embed **only** `com.guardsquare:proguard-core:9.1.10` (licensed under **Apache License 2.0**). The GPL-licensed `proguard-base` must **never** be added as a project dependency (ADR-0003).
2. **Sub-10ms Fast-Path Invariant**: Cached Maven invocations must evaluate fingerprints and apply the in-memory decision in **$< 10\text{ ms}$** (target: $\approx 1\text{ ms}$). Trimming and link closure must execute strictly on cold cache misses and cache their outputs under `target/elided-artifacts/` (ADR-0001, RQ-0003).
3. **Link Closure Completeness**: Slicing must retain the transitive fixed-point closure of all referenced internal classes within that dependency (including superclasses, interfaces, field types, method parameter/return descriptors, exceptions, and annotations). Zero runtime `NoClassDefFoundError` or `VerifyError` permitted (ADR-0003, RQ-0001).
4. **Archive Sanitation & Signature Stripping**: Any trimmed JAR containing digital signature block files (`META-INF/*.SF`, `*.DSA`, `*.RSA`, `META-INF/SIG-*`) must have those files stripped and section digests removed from `META-INF/MANIFEST.MF` to prevent JVM `SecurityException` (ADR-0003).
5. **Per-JAR Boundary Preservation**: Each trimmed dependency must remain a distinct, individual JAR matching its Maven coordinate. Monolithic whole-program flattening or premature shading into a single jar is strictly prohibited (ADR-0002, ADR-0003).
6. **Transparent Downstream Packaging**: The in-memory artifact pointer is updated via `artifact.setFile(trimmedJar)` in `INITIALIZE`. Downstream packagers (`maven-shade-plugin`, `spring-boot-maven-plugin:repackage`, assembly) must transparently package trimmed bytes without custom plugin adapters (ADR-0002).
7. **Clean Verification Gates**: Every track and integrated slice must pass `make check` (formatting, Checkstyle, PMD, SpotBugs, Markdownlint, tests) and `make test-examples` cleanly.

---

## 2. Track Decomposition & Directed Acyclic Graph (DAG)

```text
┌────────────────────────────────────────────────────────┐
│ Track 1: Source Compilation Roots Protection (Prereq)  │
└──────────────────────────┬─────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│ Track 2: ProGuard Core Engine & Link Closure           │
└──────────────────────────┬─────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│ Track 3: Archive Sanitizer & Signature Stripping       │
└──────────────────────────┬─────────────────────────────┘
                           │
             ┌─────────────┴─────────────┐
             ▼                           ▼
┌──────────────────────────┐┌──────────────────────────┐
│ Track 4: CycloneDX 1.6   ││ Track 5: Maven Plugin    │
│ Pedigree Provenance      ││ Lifecycle Wiring & Swap  │
└────────────┬─────────────┘└────────────┬─────────────┘
             │                           │
             └─────────────┬─────────────┘
                           ▼
┌────────────────────────────────────────────────────────┐
│ Track 6: Fixtures, End-to-End Verification & JMH Gates │
└────────────────────────────────────────────────────────┘

Track 7 (Persisted Elision Report) depends on Tracks 3 and 5; Track 6's report examples depend on Track 7.
```

---

## 3. Detailed Track Specifications & Slices

### Track 1: Source Compilation Roots Protection (Prerequisite)

**Worktree**: `.scratch/worktrees/track-source-roots`  
**Owned Packages**: `elider-core/src/main/java/io/github/spockz/elider/scanner/`

* **Slice 1.1: Source Compilation Reference Scanner**
  * Implement `SourceCompilationReferenceScanner` to scan Java sources in `src/main/java`.
  * Extract: direct type references, inlined primitive/String constants (`static final` fields), erased type bounds, and compile-time annotations.
  * Tests: `SourceCompilationReferenceScannerTest` verifying extraction of inlined constant classes and generic bounds.
* **Slice 1.2: Pruner Integration & Negative Probe Guard**
  * Integrate source roots into `DependencyPruner` so dependencies required for source compilation are never elided, even if unobserved at runtime.
  * Verify that the negative compiler probe in `make test-examples` continues to cleanly enforce compiler visibility.

**INITIALIZE source-completeness contract (implementation deviation):** `elide.sourceRootsComplete` defaults to `false`; the plugin then skips source attribution and conservatively pins every effective compile-classpath JAR and all indexed classes for later trimming. Users may set it to `true` only when all production and generated sources are already present before `INITIALIZE` and no later processor or generator introduces compile references. That mode resolves supported effective compiler settings and fails closed on unsupported modes or uncertain source generation. Both modes preserve the independent runtime-trace match requirement. This bounded contract replaces any assumption that roots present at `INITIALIZE` are complete by default.

---

### Track 2: ProGuard Core Engine & Link Closure (`elider-core`)

**Worktree**: `.scratch/worktrees/track-proguard-engine`  
**Owned Packages**: `elider-core/src/main/java/io/github/spockz/elider/trimmer/`, `elider-core/pom.xml`

* **Slice 2.1: ProGuard Core Dependency & ClassPool Ingestion**
  * Add `com.guardsquare:proguard-core:9.1.10` to `elider-core/pom.xml`.
  * Create `io.github.spockz.elider.trimmer.DependencyJarTrimmer`:
    * Ingest candidate dependency JAR into `ProgramClassPool`.
    * Ingest classpath (JDK classes + sibling dependencies) into `LibraryClassPool`.
* **Slice 2.2: Transitive Link Closure Visitor**
  * Initialize the root set from: runtime telemetry (CDS, logs, JFR, JaCoCo) + source compilation roots + SPI/GraalVM dynamic roots.
  * Execute ProGuard Core's `ClassReferenceInitializer` and reachability visitors to traverse all referenced internal types, superclasses, interfaces, method descriptors, and field types.
* **Slice 2.3: Link Closure Unit Test Suite**
  * Create `DependencyJarTrimmerTest` verifying:
    * Root class `A` referencing internal class `B` retains both `A` and `B`.
    * Unreferenced class `C` in the same JAR is omitted.
    * Complex JVM structures (inner classes, invokedynamic, exceptions, generics) are retained in closure.

---

### Track 3: Archive Sanitizer & Signature Stripping (`elider-core`)

**Worktree**: `.scratch/worktrees/track-archive-sanitizer`  
**Owned Packages**: `elider-core/src/main/java/io/github/spockz/elider/trimmer/`

* **Slice 3.1: Output JAR Generation**
  * Implement `ArchiveSanitizer` streaming only retained classes and non-class resources into `target/elided-artifacts/<artifactId>-<version>-trimmed.jar`.
  * Preserve `META-INF/services/`, license and NOTICE files (`LICENSE*`, `NOTICE*`), and property descriptors.
* **Slice 3.2: Signature Stripping & Manifest Cleansing**
  * Strip signature files (`META-INF/*.SF`, `META-INF/*.DSA`, `META-INF/*.RSA`, `META-INF/SIG-*`).
  * Cleanse `META-INF/MANIFEST.MF` by removing section digest blocks.
* **Slice 3.3: Hash Provenance & ArtifactTrimRecord**
  * Compute SHA-256 and SHA-1 digests of original and trimmed JARs.
  * Return immutable `ArtifactTrimRecord(coordinate, originalPath, originalSha256, trimmedPath, trimmedSha256, totalClasses, retainedClasses)`.

---

### Track 4: CycloneDX 1.6 Pedigree Emission (`elider-core`)

**Worktree**: `.scratch/worktrees/track-cdx-pedigree`  
**Owned Packages**: `elider-core/src/main/java/io/github/spockz/elider/metadata/`

* **Slice 4.1: Pedigree & Patch Metadata Generation**
  * Update `CycloneDxSbomGenerator`:
    * Populate `component.hashes` with the trimmed JAR's actual SHA-256.
    * Populate `component.pedigree.ancestors` with the original Maven Central coordinate and original SHA-256.
    * Populate `component.pedigree.patches` with description: `"Trimmed X unreferenced classes via ProGuard Core link closure"`.
    * Add properties: `elider:status=trimmed`, `elider:retainedClasses`, `elider:totalClasses`.
* **Slice 4.2: Pinned Schema Validation Tests**
  * Update `CycloneDxSbomGeneratorTest` validating generated trimmed components against `schema/bom-1.6.schema.json`.

---

### Track 5: Maven Plugin Lifecycle Wiring & In-Memory Redirection (`dependency-elider-maven-plugin`)

**Worktree**: `.scratch/worktrees/track-plugin-trimming`  
**Owned Packages**: `dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/`

* **Slice 5.1: Plugin Parameter & Lifecycle Trigger**
  * Add `@Parameter(property = "elide.trimJars", defaultValue = "false") private boolean trimJars;` to `ElideMojo`.
  * Invoke `DependencyJarTrimmer` during `INITIALIZE` on retained dependencies when active.
* **Slice 5.2: In-Memory File Pointer Redirection**
  * For each trimmed dependency: call `artifact.setFile(trimmedJarPath)` on the in-memory `Artifact` object.
* **Slice 5.3: Fingerprint & Output Caching**
  * Cache trimmed JARs keyed by original SHA-256 + root set fingerprint, ensuring trimming executes only once per dependency version.
  * Ensure fast-path cache hit executes in $< 1.5\text{ ms}$.

**Track 5 implementation note:** JAR trimming is opt-in (`elide.trimJars=false` by default). A global cache manifest binds ordered candidate and sibling JAR content digests, sorted roots, the selected platform signature digest, engine/schema versions, and trimmed output digests. It is checked before platform-pool construction and ProGuard analysis; warm hits return the stored trim records without running the closure analysis. Cross-artifact link closure is propagated to a fixed point before outputs are accepted. Repeated single-artifact lifecycle tests measured 95.2 to 99.1 ms for exact-validation cache hits under GraalVM JDK 21, so the 1.5 ms target is unmet. Validation remains content-based because Maven snapshots and local artifacts can change while filesystem metadata stays the same. Trimming emits a CycloneDX SBOM at `target/dependency-elider-sbom.cdx.json` by default when enabled; `elide.sbomFile` overrides the path.

---

### Track 6: Reference App Fixtures & Verification Loop (`examples/`)

**Worktree**: `.scratch/worktrees/track-fixtures-verification`  
**Owned Packages**: `examples/`, `elider-benchmarks/`

* **Slice 6.1: Basic App Trimming Verification**
  * In `example-basic-app`, trim `commons-compress` down to used classes.
  * Verify that the shaded fat JAR shrinks in byte size and executes successfully.
* **Slice 6.2: Spring Boot Trimming Verification**
  * In `example-spring-boot-app`, verify that partially used starters package trimmed JARs into `BOOT-INF/lib` and pass HTTP integration tests.
* **Slice 6.3: JMH Benchmark Gate**
  * Run JMH benchmarks in `elider-benchmarks` to assert that the $< 10\text{ ms}$ fast-path overhead invariant holds with trimming cache enabled.

* **Slice 6.5: Named Baseline and Elision Modes**
  * Select fixture behavior from one POM with `-Delide.mode=baseline` or `-Delide.mode=elision`; the `elision` value activates a named Maven profile.
  * Verify that `make test-examples` builds and compares both modes without parallel POM definitions.

### Track 7: Persisted Elision Report Goal and Example Output (`dependency-elider-maven-plugin`, `examples/`)

**Worktree**: `.scratch/worktrees/track-elision-report`
**Dependencies**: Tracks 3 and 5; Track 6 example reporting depends on Track 7.

* **Slice 7.1: Exact Pruned-Class Payload Accounting**
  * Record the uncompressed byte size of omitted program `.class` entries in each `ArtifactTrimRecord` while the sanitizer reads the source archive; class counts and bytes exclude module descriptors and archive sanitation metadata.
  * Preserve the value in the trim cache so cache hits produce identical report totals without reopening JARs.
  * Test that an omitted class's recorded payload bytes equal its uncompressed input ZIP entry size.
* **Slice 7.2: Persisted Snapshot and `report` Goal**
  * Have a successful `elide` execution atomically persist the pre-mutation whole-artifact removals and trim records under the Maven build directory.
  * Add `dependency-elider:report`, which reads that snapshot without re-running analysis or relying on mutated Maven artifact views.
  * Report whole artifacts dropped by count and sum of their original on-disk JAR sizes. Report program classes pruned from retained JARs by count and sum of uncompressed omitted `.class` entry payload bytes, excluding module descriptors and archive sanitation metadata; label the byte basis explicitly and use binary `KiB`/`MiB` units.
  * Identify the snapshot's project GAV, canonical project directory, and successful-run timestamp. Fail clearly if no successful snapshot exists or it belongs to a different project checkout. A failed or skipped `elide` must not publish a new snapshot; if an earlier successful snapshot remains, `report` must describe it as the last successful run. The report does not revalidate changed dependencies, sources, or traces when displaying that saved result.
  * Test exact counts/bytes, stable formatting, cache-hit equivalence, no re-analysis, missing snapshots, and failed/skipped-run freshness semantics.
* **Slice 7.3: Report Every Example**
  * Invoke the report goal after successful elision for Basic, Spring Boot, CVE-unused, and CVE-safe-class examples.
  * Capture representative goal output for each example in the README.
* **Slice 7.4: Report Trim Results During Elision**
  * When `elide.trimJars=true`, report program classes pruned from retained JARs and the sum of uncompressed omitted `.class` entry payload bytes from `analysis.trimRecords()` in the `elide` summary.
  * Label the payload-byte basis and state that module descriptors and archive sanitation metadata are excluded.
  * Keep the stage-not-run class summary for `analyze` and trim-disabled `elide`; methods and fields remain stage-not-run.
  * Update plugin usage documentation and test the visible trim-enabled summary using the Maven Mojo trimming fixture.

---

## 4. Verification Protocol

1. **Initial Baseline Gate**:

   ```sh
   test -z "$(git status --porcelain)" && make check
   ```

2. **Per-Slice Verification**:
   * Surgical unit tests for the modified component.
   * Project-wide sweep: `make check`.
3. **Track Wrap-Up & Integration Sweep**:
   * `make check` (zero lint, checkstyle, or test errors).
   * `make test-examples` (passes all baseline and elided lifecycle tests across basic and Spring Boot fixtures).
4. **Final Acceptance Gate**:
   * Trimmed JARs are physically present in `target/elided-artifacts/`.
   * Signatures stripped and digests cleansed.
   * Repackaged fat JARs and Spring Boot JARs boot and pass integration tests.
   * CycloneDX 1.6 SBOM validates against official schema.
   * Each example documents the report goal output for whole-artifact and class-pruning counts and byte totals, with GAV and snapshot freshness visible.
