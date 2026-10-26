<!-- WHY: Defines performance and cache-correctness investigations so build overhead targets and reduction benefits can be evaluated with reproducible evidence. -->
# RQ-0003: Sub-10ms Maven Fast-Path Invariant and Benchmarking Methodology

* **Status**: Open
* **Category**: Performance & Benchmarking
* **Date**: 2026-10-24
* **Last Updated**: 2026-10-26

Abbreviations: Java Microbenchmark Harness (JMH), Solid State Drive (SSD), Non-Volatile Memory Express (NVMe), Central Directory (CEN), Virtual Threads (Loom), Central Processing Unit (CPU).

---

## 1. Context & Research Questions

When bound and active, the plugin executes on Maven lifecycle invocations that reach `INITIALIZE` (e.g. `mvn compile`, `mvn test`, `mvn package`); standalone goals need not run that phase. If the plugin adds noticeable latency to local developer builds, developer adoption drops.

A hard non-negotiable invariant is established:
$$\Delta t_{\text{overhead}} < 10\text{ ms on cached/routine builds}$$

### Primary Research Questions

* **RQ-0003.1**: What is the most efficient, allocation-free fingerprinting scheme to detect whether dependencies or trace files have changed?
* **RQ-0003.2**: On cache hits, can reading the precomputed pruning decision and mutating `project.getArtifacts()` execute in $< 1\text{ ms}$?
* **RQ-0003.3**: On cold cache misses (when dependencies change), what is the minimal latency achievable for scanning the ZIP Central Directory of 50–100 JAR files using Java 21 Virtual Threads?
* **RQ-0003.4**: How should automated CI benchmarks be structured to fail the build if fast-path overhead exceeds 10ms?
* **RQ-0003.5**: What size reduction and configuration-effort savings justify the added source analysis, shrinking, archive rewriting, and cache validation costs compared with a distribution-only shrinker?

---

## 2. Technical Design & Performance Budget

### Latency Budget Allocation (Total: 10 ms)

| Component | Fast-Path (Cache Hit) | Cold-Path (Cache Miss) | Implementation Technique |
| :--- | :--- | :--- | :--- |
| **Fingerprint Check** | $< 0.3\text{ ms}$ | $< 0.3\text{ ms}$ | Hash of artifact keys + trace `mtime`/`size` |
| **Pruning Mutation** | $< 0.1\text{ ms}$ | $< 0.1\text{ ms}$ | In-memory `Set.retainAll()` over ~100 elements |
| **Decision Load / Deserialization** | $< 0.5\text{ ms}$ | N/A | Memory-mapped or compact binary cache file |
| **ZIP Central Directory Scan** | $0\text{ ms}$ (Skipped) | $10\text{--}25\text{ ms}$ | JDK 21 Virtual Threads reading CEN headers |
| **Trace Ingestion** | $0\text{ ms}$ (Skipped) | $1\text{--}5\text{ ms}$ | Memory-mapped buffer newline scanning |
| **Total Expected Latency** | **$< 1.0\text{ ms}$** | **$15\text{--}30\text{ ms}$** | Strict pass of $< 10\text{ ms}$ budget on fast-path |

---

## 3. Benchmarking Suite Design

To prove the invariant empirically, we establish a dedicated benchmark module (`elider-benchmarks`):

1. **JMH Microbenchmarks**:
   * `FastPathBenchmark`: Measures fingerprint verification and in-memory set mutation in isolation under realistic multi-core load.
   * `ZipCenScannerBenchmark`: Measures reading Central Directory headers across 100 dependency JARs with:
     * Sequential `ZipFile`
     * Parallel streams
     * Virtual thread per task executor (`Executors.newVirtualThreadPerTaskExecutor()`)
   * `TraceParserBenchmark`: Measures parsing throughput across CDS class lists, `-Xlog:class+load` text files, and GraalVM JSON.

2. **Integration Verification Harness**:
   * Executes real Maven processes against `example-basic-app` with and without the plugin:
     $$\Delta t = t_{\text{plugin}} - t_{\text{baseline}}$$
   * Measure paired baseline/plugin runs with controlled daemon state, warmup, filesystem cache, and identical workload. Record distributions and uncertainty; whole-process timing noise can exceed 10ms, so ten differences alone do not establish the target. Combine this with lifecycle instrumentation of plugin work.

### Total Cost and Cache Correctness

The fast-path target is a budget, not a measured guarantee or a claim that builds become faster. Separately measure source resolution/analysis, processors/generators, engine work, archive rewriting, report generation, and validation. Compare cold builds, no-op cached builds, source-only edits, trace changes, dependency upgrades, and changed compiler/framework settings. Report packaged bytes, elapsed time, peak memory, output/cache storage, and reproducible configuration effort.

For future trimming, a cache entry must bind to sources and generated-source inputs, dependency content identities, ordered class/module paths, toolchain/release/compiler settings, processor paths/options, framework resources, oracle coverage, engine version/configuration, and output inventory. Metadata-only `mtime`/size validation has limitations when content changes without those metadata changing. Compare stronger identity checks and their cost explicitly.

Investigate atomic output publication, partial/corrupt cache recovery, parallel reactor/daemon access, and whether output digests still match cached decisions. A fast lookup of a stale or incomplete transformation is not a valid cache hit. Core microbenchmarks do not establish integration latency or net build savings.

---

## 4. 2026-10-26 Source and Profile Investigation

This investigation ran two tracks before changing cache behavior: a read-only source audit and JFR profiles of Basic Shade, Spring Boot, and the warm Maven trim-cache JMH operation. No source algorithm or cache implementation changed.

### Warm cache operation

The no-JFR JMH control measured **92.860 ±0.223 ms/op** (one fork, five 1-second warmups, ten 1-second measurements). The matching normal JFR run measured **93.996 ±0.665 ms/op**, about 1.2% slower, so the normal profile did not materially distort this timing. The fixture is only a 695-byte input JAR, 363-byte trimmed output, and roughly 773-byte manifest. The GraalVM 21 `lib/ct.sym` input is 11,302,308 bytes.

JFR's hottest Java samples were `ZipFile.Source.checkAndAddEntry` (26.4%), `ArrayList.SubList.toArray` (15.1%), and `ZipEntryIterator.next` (9.4%). The warm cache path calls `platformInputs` on every operation; that method opens and enumerates `ct.sym` to find the selected release, then `fingerprintForInputs` hashes the complete archive. The cache path also hashes the candidate input in the fingerprint and again while validating the cache entry, and hashes the trimmed output. JFR therefore points to repeated ZIP central-directory work and file reads, rather than work proportional to the tiny candidate JAR. SHA-256 compression was not a leading CPU sample.

A targeted JFR profile with file-read threshold set to zero recorded 167.4 MB of `ct.sym` reads over the fork. That run includes JMH setup's cold analysis and JMOD reads, so it cannot attribute an exact number of bytes to each measured operation. Its measured time was 110.309 ±4.119 ms/op, about 18.8% slower than control; use it for I/O attribution only, not the latency result. JFR artifacts are temporary under `/tmp/elider-jfr` and are not committed.

### Example Maven profiles

The unprofiled `make test-examples` run measured Basic at 2.256 s baseline and 4.218 s with elision, and Spring Boot at 4.072 s baseline and 75.933 s with elision. JFR runs used GraalVM 21.0.12 and plain Maven 3.9.16 to record separate Maven and Surefire processes. Basic's elided Maven build took 3.813 s and produced only 62 execution samples, too few to quantify its hot methods. Spring's elided Maven build took 77 s; the elider phase occupied nearly all the extra time before Surefire began.

Spring's profile was CPU and allocation heavy: `TreeMap.getEntry` accounted for 15.6% of execution samples, ProGuard `DescriptorClassEnumeration.nextFluff` and `nextClassName` about 10% each, and `AbstractStringBuilder.append` 10.7%. Sampled allocation events were led by buffered reads, ZipFile inflater creation, `DataInputStream.readFully`, and `String.substring`. RSS reached about 1.8 GB during trimming. GC pauses totaled about 0.78 s over 77 s, with about 11.2 s of GC user CPU; no contention-by-site events were recorded. This is allocation/CPU churn, not lock waiting. JFR adds profiling overhead, so use the earlier unprofiled timings for build-time comparisons.

### Source-level repeated work and order of attack

`DependencyJarTrimmer.analyzeInternal` validates and reads the candidate JAR and every sibling JAR into ProGuard class pools on each call. `MavenDependencyTrimmer.trim` calls that analysis per candidate and repeats all candidates until cross-artifact roots stop changing. This repeats validation, class-byte reads, pool construction, descriptor traversal, and reference initialization. It creates an avoidable classpath-wide repeated-work pattern before any persistent cache can help.

The dynamic-root scanner also runs before trimming and again inside trimming for retained libraries. Cache hits are checked only after source attribution, class indexing, and dynamic-root scans have already run. Exact content validation further hashes each retained JAR for the fingerprint and rehashes candidate inputs and outputs during cache-entry validation.

Prioritize investigation and implementation in this order:

1. Reduce algorithmic repetition first: construct one invocation-level class/reference graph and propagate owner roots over it, or at minimum parse and validate each archive once per invocation rather than once per candidate per propagation pass.
2. Pass per-JAR dynamic-root scan results and class-entry indexes through the request instead of reopening archives in both services. This reuse is scoped to one invocation and needs no persistent invalidation policy.
3. Deduplicate exact digest work: compute each candidate/input digest once per invocation and reuse the verified value in the fingerprint and cache-entry validation. Preserve content-based validation; file size and modification time alone are not a safe replacement.
4. Preserve exact JDK platform identity per trim invocation. The selected `ct.sym` or JMOD files are hashed once while computing that invocation's fingerprint. Do not memoize only the digest across Maven projects: platform analysis still reads the files directly, so a changed file could pair a stale identity with new analysis bytes. Reuse requires one immutable platform snapshot shared by fingerprinting and analysis.
5. Revisit persistent transformation-cache placement only after the preceding costs are reduced. A cache lookup moved earlier must bind every source/generated-source, trace, metadata, ordered dependency, compiler/runtime, engine, root, and output input that can change the result.

The profiles show what to investigate first; they do not prove that every listed optimization is safe. No persistent-cache weakening, ProGuard-pool sharing, or source changes were made as part of this investigation.

## 5. Next Steps & Decision Checkpoints

* [ ] Checkpoint 1: Create `elider-benchmarks` module with JMH harness.
* [ ] Checkpoint 2: Benchmark sequential vs. virtual-thread ZIP Central Directory reader across 100 real JARs.
* [ ] Checkpoint 3: Validate $< 1\text{ ms}$ fast-path execution in real Maven lifecycle execution.
* [ ] Checkpoint 4: Define a statistically defensible lifecycle overhead measurement and compare total build cost, package size, and setup effort with baseline workflows.
* [ ] Checkpoint 5: Specify complete transformation cache keys, output validation, and concurrent/partial-write behavior before caching source-aware trimming.

### 5.1 Follow-up Implementation Slices (2026-10-26)

The source audit and JFR findings are assigned to the Maven-trimming, ProGuard-engine, cache, and fixture-verification tracks. Work proceeds in dependency order; reference reuse remains gated on exact parity and earlier cache lookup remains gated on a complete identity contract. None of these slices alone establishes the sub-10 ms Maven invariant. Keep JMH cache-operation timing separate from elider-phase and paired end-to-end Maven measurements.

| Slice | Track | Scope and acceptance criteria | Depends on | State |
| :--- | :--- | :--- | :--- | :--- |
| **5.4 Invocation scan reuse** | Maven plugin trimming | Pass `DependencyDynamicRoots.RootScan` results through the trimming request and reuse the `ArtifactClassIndex` only where it has matching archive semantics. Scan each retained JAR's dynamic metadata once per invocation; preserve roots, pruning, pass-through decisions, projected multi-release behavior, and output bytes. | None | Implemented, reviewed, integrated as `e7c0a69` |
| **2.4 Per-invocation archive snapshot reuse** | ProGuard Core engine | Cache each archive's validated direct class-entry bytes once per trim invocation, but rebuild per-candidate ProGuard pools. Preserve ordered classpath precedence, cross-artifact links, pass-through unresolved references, signature-polymorphic references, and failure behavior. Do not share initialized mutable `ClassPool` instances. | 5.4 integration; cache reader precursor is independent | Approved and integrated as `01e2f98`; stale-analysis protection is included in 7.1 |
| **2.5 Context-scoped immutable reference graph** | ProGuard Core engine + Maven plugin trimming | Freeze edges and unresolved-link evidence once per exact candidate, ordered-sibling, platform, and program/library-role context. Reuse that context through monotonic root growth; keep candidate closures separate. Preserve candidate-first lookup, sibling order, platform fallback, reachable-only errors, and pass-through policies. Compare exact results with the current engine on context-role, precedence, failures, metadata, cycles, and multi-artifact propagation cases; measure traversal reductions on the Spring-sized fixture. A single global graph is not parity-safe because sibling classes are analyzed as `LibraryClass` and candidates as `ProgramClass`. | 2.4 parity | Approved and integrated as `3e79c59`, with review fixups `2e9eeed` and `b5cd879` |
| **2.6a Release prepared graph builders after materialization** | ProGuard Core engine | Clear the graph supplier only after successful graph construction so a failed build remains retryable. Verify prepared analysis retains only the immutable reference graph and closure state after success, without changing empty-root laziness, fixed-point results, or failure recovery. Reprofile retained heap/RSS. | 2.5, 6.4 | Architect-approved; implementation assigned |
| **2.6b Reuse immutable library class templates per archive** | ProGuard Core engine + Maven plugin trimming | Parse each sibling archive's `LibraryClass` declarations once per invocation/archive snapshot, freeze symbolic hierarchy and member declarations, then materialize fresh mutable classes for each exact graph context. Defer resolution, edges, and diagnostics to each context. Platform snapshots must preserve preparation-time isolation without caching caller-owned mutable pools. Preserve role, precedence, reachable-only errors, and outputs; prove parse-once/fresh-context behavior and measure CPU, allocations, and peak RSS on Basic/Spring. | 2.5, 2.6a, 6.4 | Architect-approved design; implementation follows 2.6a |
| **7.1 Exact digest deduplication and mutation guard** | Cache + Maven plugin trimming | Compute each distinct retained dependency input SHA-256 once per invocation and reuse it for fingerprinting and cache-entry validation; continue validating trimmed output bytes on hits. On a cold miss, verify inputs before staging and again after every output is published, aborting if any input changed or disappeared since analysis began. Test same-size content changes with restored mtimes, missing/corrupt outputs, candidate replacement before staging/publication, symlink retargeting, and mutation during sequential multi-output publication. | 5.4 and 2.4 | Approved and integrated as `01bb9f7` |
| **7.2 Maven-session platform identity** | Cache | Evaluate reuse of selected-release detection and exact `ct.sym`/JMOD identity across projects in one Maven session. Preserve exact platform content identity and use the same bytes for fingerprinting and analysis; verify distinct JDK content and releases. | 7.1 | Investigated; no safe memoization without a shared immutable platform snapshot |
| **7.3 Earlier persistent-cache lookup** | Cache + Maven plugin trimming | Move lookup earlier only after specifying and testing all result-affecting key dimensions: sources/generated sources, traces, metadata, ordered dependency bytes, roots, compiler/toolchain/runtime settings, processors, pass-through policy, engine/schema, destination, and inventory. Preserve output digest validation, atomic publication, and safe corrupt/concurrent recovery; prove each key change misses. | 5.4, 2.4, 2.5, 2.6a, 2.6b, 7.1, 7.2 | Deferred until graph memory/parsing work is evaluated and the full identity contract is specified |
| **6.4 Post-optimization example profiling** | Fixtures and verification | Run matched baseline and elision `clean verify` measurements for Basic and Spring Boot, then profile elided Maven processes separately with JFR. Report timing distributions, process RSS, allocation/CPU hotspots, and artifact-size effects; distinguish JFR overhead from unprofiled timing. | 2.4, 2.5, 5.4, 7.1, 7.2 | Complete; three matched cycles per example, plus separate Basic/Spring JFR profiles |

The pre-existing cache-reader allocation change is reviewed and integrated as `113705a`; it reduces decoding allocations but does not remove exact content hashing. Its receipt is `.scratch/reviews/track-cache-reader.md`. Slice 7.1 and 2.4 are now integrated. The 7.2 review found no safe cross-project digest memoization without a shared immutable platform snapshot; 7.3 remains gated on the complete transformation identity contract.

#### Slice 6.4 post-optimization evidence

The integration branch passed `make test-examples` for Basic Shade, Spring Boot, and both CVE fixtures. Three full example cycles measured paired `clean verify` calls without JFR; each pair ran baseline first with the same local dependencies already warm. Median baseline/elision/delta was **2.241/4.269/+2.032 s** for Basic (ranges 2.237–2.278 / 4.260–4.348 / +1.982–2.107 s) and **4.061/32.413/+28.341 s** for Spring (ranges 4.040–4.072 / 32.198–34.720 / +28.137–30.680 s). The earlier single Spring observation was +71.861 s. Several optimization slices landed between those observations, so the reduction cannot be attributed to one slice. Treat the three baseline-first cycles as descriptive warm-dependency measurements, not statistically robust estimates.

The Basic shaded package shrank from 2,738,745 to 1,360,150 bytes; its Commons Compress input JAR shrank from 1,117,221 to 110,843 bytes. The Spring Boot package shrank from 34,588,443 to 29,427,062 bytes, removing 5,161,381 bytes. The nested `spring-webmvc` JAR shrank from 1,048,416 to 807,364 bytes and from 526 to 379 classes.

Separate JFR profiles used GraalVM 21.0.12 and the repository Maven wrapper; do not compare their elapsed times with unprofiled measurements. The Spring Maven process ran for 32 s, peaked at **3,135,084 KiB process RSS** (forked Surefire RSS is not included), and produced 1,446 execution samples and 7,029 allocation samples. Top execution frames were `TreeMap.getEntry` (227 samples, 15.7%), `AbstractStringBuilder.append` (198, 13.7%), and ProGuard `DescriptorClassEnumeration.nextClassName` (133, 9.2%) / `nextFluff` (68, 4.7%). **506 of 1,446** execution stacks included elider frames. Allocation sample weights were led by `DataInputStream.readFully`, ProGuard `StringUtil.getString`, and descriptor enumeration; they point to repeated class parsing and signature processing, not lock contention. Source inspection confirms each candidate context reparses cached sibling class bytes with `ArchiveSnapshot.newClassPool` and copies the full platform class pool in `PlatformClassSnapshot.copyOf`; the fixed-point loop retains all candidate contexts at once. The architect also found that `PreparedAnalysisState` retains its graph-supplier lambda after materialization, keeping the builder and its platform copies reachable. Proposed slices 2.6a and 2.6b address builder lifetime and repeated library parsing before persistent caching.

The Basic JFR profile ran for 4 s, peaked at 1,230,628 KiB Maven-process RSS, and yielded only 62 execution samples, so its method-level CPU ranking is low confidence. Its allocation samples include ASM parsing, ZIP inflater setup, and the new platform signature snapshot copier. The RSS monitor sampled the Maven process's `VmHWM`; it did not measure aggregate process-tree memory. JFR artifacts and raw logs remain in `/tmp/elider-postopt-jfr` and are not committed.

#### Slice 7.2 evidence and decision

Each `MavenDependencyTrimmer.trim` call opens `ct.sym` to check selected-release signatures, then hashes the selected platform archive once when building the fingerprint. `loadCache` consumes that fingerprint without hashing `ct.sym` again. The remaining repeated work is across separate trim calls, such as projects in a reactor. The warm-cache JFR profile sampled `ZipFile` central-directory work and recorded 167.4 MB of file reads across a fork, but the read recording includes setup and JMOD loading and cannot isolate a per-call saving.

Reusing a digest across Maven projects is unsafe with the current reader boundary: later analyses open the current `ct.sym` or JMOD files directly. If a platform file changes mid-session, a reused digest would identify earlier bytes while analysis reads later bytes. The project therefore assumes the selected JDK platform files remain stable during each trim invocation and keeps exact hashing for each invocation. Session reuse needs a shared immutable platform snapshot consumed by both fingerprinting and ProGuard analysis. The regression test verifies that distinct release values and different JDK platform bytes produce distinct fingerprints, and that changing `ct.sym` content with the same size and restored modification time still changes its identity.

#### Slice 2.4 review finding and 7.1 guard

* **2.4 implementation**: commit `01e2f98` caches validated direct class-entry bytes per normalized path for one trim invocation while constructing fresh ProGuard pools for each analysis. This removes repeated ZIP-entry reads and ASM validation, but still parses class bytes into fresh pools and repeats closure traversal. Its uncompressed class-byte memory cost remains unmeasured and belongs in 6.4.
* **7.1 review and fix**: the first review found that an earlier source could mutate during a later output's publication after its per-output check. The final full-snapshot verification after all publications closes that gap. A deterministic regression changes input 1 during output 2 publication. The approved, autosquashed slice is `01bb9f7`; its post-merge Java 21 `make check` passed with 121 core and 65 plugin tests, formatting, static analysis, and Markdown lint.
* **2.5 architecture constraint**: the critical architect rejected a single global graph for parity. Candidate classes are ProGuard `ProgramClass` nodes while sibling classes are `LibraryClass` nodes; class edges and unresolved links can differ by role. Maven also uses separate compiler and runtime platform contexts. The safe first slice freezes a graph per exact analysis context and reuses it only as roots grow, preserving each candidate's closure and reachable-only errors. A broader shared graph is a separate later optimization.

#### Existing cache-reader allocation change

* **Track / commits**: cache; `21bdc90` (strict GraalVM JFR hidden-class name handling) and `1f95d36` (bounded cache decoding allocation reuse), integrated as `113705a`.
* **Review**: approved; receipt: `.scratch/reviews/track-cache-reader.md`.
* **Verification**: rebased and post-merge `make check` passed with GraalVM 21, 117 core tests and 64 plugin tests, static analysis, formatting, and Markdown lint. This work does not address repeated input/output digests or JDK platform identity.

#### Slice 5.4 evidence and review

* **Implementer / reviewed commit**: Maven trimming track; `8b3c4c4` (`Reuse Maven invocation dependency scans`), rebased without code changes and integrated as `e7c0a69`.
* **Focused and full verification**: post-merge `make check` passed with repository GraalVM 21; 116 core tests, 64 plugin tests, static analysis, formatting, and Markdown lint passed. The trim-boundary test verifies supplied dynamic roots affect output and missing scan evidence fails explicitly. The JMH benchmark computes dynamic-root input inside each measured operation, preserving its previous measurement boundary.
* **Review verdict**: approved after the initial reviewer model hit capacity; replacement review accepted the complete implementation. Receipt: `.scratch/reviews/track-plugin-trimming-performance.md`.
