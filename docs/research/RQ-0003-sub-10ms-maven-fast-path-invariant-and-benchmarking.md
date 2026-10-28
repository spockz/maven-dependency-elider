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
* **RQ-0003.6**: How can concurrent execution across CPU cores (e.g., using Java 21 Virtual Threads or bounded worker pools) be applied to CPU-intensive and I/O-bound phases—such as concurrent intra-JAR trimming across candidate dependencies, parallel ZIP entry decompression, parallel SHA-256 digesting, and concurrent archive rewriting—to drastically reduce end-to-end wall-clock time without thrashing disk I/O, breaking deterministic build outputs, or exceeding process memory caps in large reactor builds?

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

### 2.2 Parallel Work Scheduling for Wall-Clock Time Reduction

While the `< 10 ms` invariant governs cached and fast-path execution, non-cached execution and large-scale intra-JAR trimming (e.g. on Spring Boot, currently measuring $+20.4\text{ s}$ overhead) must minimize wall-clock latency through parallelization across available CPU cores:

1. **Concurrent Candidate JAR Trimming**:
   * *Opportunity*: In `MavenDependencyTrimmer.trim`, candidate dependencies are currently evaluated and trimmed sequentially. Because each candidate JAR's link-closure analysis, bytecode rewriting, and output packaging operate on disjoint input and output paths, candidate trimming tasks are embarrassingly parallel.
   * *Objective*: Transform candidate loop execution from linear sum latency $\sum_{i=1}^n t_i$ toward the single largest candidate latency $\max_{1 \le i \le n}(t_i)$, dramatically dropping wall-clock duration on multi-core systems.

2. **Parallel I/O, Decompression, and Hashing Pipeline**:
   * *Opportunity*: Reading Central Directory headers across $50\text{--}100$ dependency JARs, decompressing bytecode, computing SHA-256 digests for platform/dependency archives, and re-packing sanitized output archives can saturate high-throughput NVMe SSDs when executed via Java 21 Virtual Threads (`Executors.newVirtualThreadPerTaskExecutor()`).
   * *Objective*: Decouple I/O wait states from CPU-bound link-closure analysis.

3. **Concurrency Constraints & Resource Bounding**:
   * *Memory Bounding (Heap/RSS Ceiling)*: ProGuard `ClassPool` instances and in-memory archive buffers consume significant memory (Spring Boot elision already peaks at $\approx 3.1\text{ GB}$ RSS). Unbounded concurrency risks JVM OutOfMemory errors. Concurrency must be bounded via worker limits (e.g. `Math.min(availableProcessors, 4)`) or memory-sensitive semaphores.
   * *Maven Reactor Coordination (`mvn -T`)*: When Maven builds multi-module reactor projects in parallel, intra-plugin parallelism must avoid thread oversubscription and thrashing.
   * *Strict Determinism*: Regardless of thread scheduling, candidate output files, cache manifest entries, SBOM component arrays, and log traces must maintain strictly deterministic order (e.g. sorted by canonical coordinate).

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

The unprofiled `make test-examples` run measured Basic at 2.256 s baseline and 4.218 s with elision, and Spring Boot at 4.072 s baseline and 75.933 s with elision. JFR runs used GraalVM 21.0.12 and the repository Maven wrapper; the wrapper in this checkout resolves Apache Maven 3.9.11. Basic's elided Maven build took 3.813 s and produced only 62 execution samples, too few to quantify its hot methods. Spring's elided Maven build took 77 s; the elider phase occupied nearly all the extra time before Surefire began.

Spring's profile was CPU and allocation heavy: `TreeMap.getEntry` accounted for 15.6% of execution samples, ProGuard `DescriptorClassEnumeration.nextFluff` and `nextClassName` about 10% each, and `AbstractStringBuilder.append` 10.7%. Sampled allocation events were led by buffered reads, ZipFile inflater creation, `DataInputStream.readFully`, and `String.substring`. RSS reached about 1.8 GB during trimming. GC pauses totaled about 0.78 s over 77 s, with about 11.2 s of GC user CPU; no contention-by-site events were recorded. This is allocation/CPU churn, not lock waiting. JFR adds profiling overhead, so use the earlier unprofiled timings for build-time comparisons.

### Source-level repeated work and order of attack

The initial audit found `DependencyJarTrimmer.analyzeInternal` validating and reading each candidate and sibling JAR into ProGuard class pools for each candidate analysis. `MavenDependencyTrimmer.trim` repeated candidate analyses until cross-artifact roots stopped changing. Slice 2.4 removed repeated ZIP entry reads by keeping validated class bytes per invocation; slice 2.6b now captures immutable sibling declarations once per archive snapshot and materializes fresh ProGuard classes per graph context. Context-local linking and descriptor traversal still run for each exact graph.

The dynamic-root scanner also runs before trimming and again inside trimming for retained libraries. Cache hits are checked only after source attribution, class indexing, and dynamic-root scans have already run. Exact content validation further hashes each retained JAR for the fingerprint and rehashes candidate inputs and outputs during cache-entry validation.

Prioritize investigation and implementation in this order:

1. Reduce algorithmic repetition first: construct one invocation-level class/reference graph and propagate owner roots over it, or at minimum parse and validate each archive once per invocation rather than once per candidate per propagation pass.
2. Pass per-JAR dynamic-root scan results and class-entry indexes through the request instead of reopening archives in both services. This reuse is scoped to one invocation and needs no persistent invalidation policy.
3. Deduplicate exact digest work: compute each candidate/input digest once per invocation and reuse the verified value in the fingerprint and cache-entry validation. Preserve content-based validation; file size and modification time alone are not a safe replacement.
4. Preserve exact JDK platform identity per Maven invocation. Under ADR 0004, selected platform inputs (`ct.sym`, `release` metadata, and selected JMODs) are assumed stable during the invocation. Capture normalized paths, release/selection evidence, deterministic module inventory, and exact SHA-256 values once; deferred analysis opens those recorded paths without rehashing or rerunning selection. Fresh invocations recompute identity, including detection of same-size content changes with restored mtimes.
5. Revisit persistent transformation-cache placement only after the preceding costs are reduced. A cache lookup moved earlier must bind every source/generated-source, trace, metadata, ordered dependency, compiler/runtime, engine, root, and output input that can change the result.

The profiles show what to investigate first; they do not prove that every listed optimization is safe. No persistent-cache weakening, ProGuard-pool sharing, or source changes were made as part of this investigation.

## 5. Next Steps & Decision Checkpoints

* [ ] Checkpoint 1: Create `elider-benchmarks` module with JMH harness.
* [ ] Checkpoint 2: Benchmark sequential vs. virtual-thread ZIP Central Directory reader across 100 real JARs.
* [ ] Checkpoint 3: Validate $< 1\text{ ms}$ fast-path execution in real Maven lifecycle execution.
* [ ] Checkpoint 4: Define a statistically defensible lifecycle overhead measurement and compare total build cost, package size, and setup effort with baseline workflows.
* [ ] Checkpoint 5: Specify complete transformation cache keys, output validation, and concurrent/partial-write behavior before caching source-aware trimming.
* [ ] Checkpoint 6: Benchmark and implement bounded parallel candidate trimming and archive I/O using Java 21 Virtual Threads to reduce non-cached wall-clock time on multi-core builds.

### 5.1 Follow-up Implementation Slices (2026-10-26)

The source audit and JFR findings are assigned to the Maven-trimming, ProGuard-engine, cache, and fixture-verification tracks. Work proceeds in dependency order; reference reuse remains gated on exact parity and earlier cache lookup remains gated on a complete identity contract. None of these slices alone establishes the sub-10 ms Maven invariant. Keep JMH cache-operation timing separate from elider-phase and paired end-to-end Maven measurements.

| Slice | Track | Scope and acceptance criteria | Depends on | State |
| :--- | :--- | :--- | :--- | :--- |
| **5.4 Invocation scan reuse** | Maven plugin trimming | Pass `DependencyDynamicRoots.RootScan` results through the trimming request and reuse the `ArtifactClassIndex` only where it has matching archive semantics. Scan each retained JAR's dynamic metadata once per invocation; preserve roots, pruning, pass-through decisions, projected multi-release behavior, and output bytes. | None | Implemented, reviewed, integrated as `e7c0a69` |
| **2.4 Per-invocation archive snapshot reuse** | ProGuard Core engine | Cache each archive's validated direct class-entry bytes once per trim invocation, but rebuild per-candidate ProGuard pools. Preserve ordered classpath precedence, cross-artifact links, pass-through unresolved references, signature-polymorphic references, and failure behavior. Do not share initialized mutable `ClassPool` instances. | 5.4 integration; cache reader precursor is independent | Approved and integrated as `01e2f98`; stale-analysis protection is included in 7.1 |
| **2.5 Context-scoped immutable reference graph** | ProGuard Core engine + Maven plugin trimming | Freeze edges and unresolved-link evidence once per exact candidate, ordered-sibling, platform, and program/library-role context. Reuse that context through monotonic root growth; keep candidate closures separate. Preserve candidate-first lookup, sibling order, platform fallback, reachable-only errors, and pass-through policies. Compare exact results with the current engine on context-role, precedence, failures, metadata, cycles, and multi-artifact propagation cases; measure traversal reductions on the Spring-sized fixture. A single global graph is not parity-safe because sibling classes are analyzed as `LibraryClass` and candidates as `ProgramClass`. | 2.4 parity | Approved and integrated as `3e79c59`, with review fixups `2e9eeed` and `b5cd879` |
| **2.6a Release prepared graph builders after materialization** | ProGuard Core engine | Clear the graph supplier only after successful graph construction so a failed build remains retryable. Verify prepared analysis retains only the immutable reference graph and closure state after success, without changing empty-root laziness, fixed-point results, or failure recovery. Reprofile retained heap/RSS. | 2.5, 6.4 | Approved and integrated as `53c1121` |
| **2.6b Reuse immutable library class templates per archive** | ProGuard Core engine + Maven plugin trimming | Parse each sibling archive's `LibraryClass` declarations once per invocation/archive snapshot, freeze symbolic hierarchy and member declarations, then materialize fresh mutable classes for each exact graph context. Defer resolution, edges, and diagnostics to each context. Platform snapshots must preserve preparation-time isolation without caching caller-owned mutable pools. Preserve role, precedence, reachable-only errors, and outputs; prove parse-once/fresh-context behavior and measure CPU, allocations, and peak RSS on Basic/Spring. | 2.5, 2.6a, 6.4 | Approved as `6a1bcac` and integrated as `a83649b`; post-merge `make check` and example verification passed; see remeasurement below |
| **2.6c Frozen graph-pool lookup index** | ProGuard Core engine | After candidate and merged library membership/precedence are final, expose the same `Clazz` objects through a frozen hash lookup while preserving the underlying `ClassPool` sorted storage and traversal. Keep program and library pools separate so ProGuard still performs program-first lookup and per-owner unresolved callbacks. Do not memoize member resolution or diagnostics. Prove same lookup results/identity, unchanged iteration, fail-closed mutation, precedence, cross-pool resolution, reachable-only errors, retry behavior, output parity, then measure JFR lookups, allocation, and RSS. | 2.6b | Approved and integrated as `ed6a33d`; semantic and full-check evidence passed |
| **7.1 Exact digest deduplication and mutation guard** | Cache + Maven plugin trimming | Compute each distinct retained dependency input SHA-256 once per invocation and reuse it for fingerprinting and cache-entry validation; continue validating trimmed output bytes on hits. On a cold miss, verify inputs before staging and again after every output is published, aborting if any input changed or disappeared since analysis began. Test same-size content changes with restored mtimes, missing/corrupt outputs, candidate replacement before staging/publication, symlink retargeting, and mutation during sequential multi-output publication. | 5.4 and 2.4 | Initially integrated as `01bb9f7`; publication-time source rehashes were later removed under ADR 0004 and slice 7.3 |
| **7.2 Maven-session platform identity** | Cache | Evaluate reuse of selected-release detection and exact `ct.sym`/JMOD identity across projects in one Maven session. Preserve exact platform content identity and use the same bytes for fingerprinting and analysis; verify distinct JDK content and releases. | 7.1 | Investigated; no safe memoization without a shared immutable platform snapshot |
| **7.3 Reuse captured input provenance under Maven invocation stability** | Cache + Maven plugin trimming | Compute SHA-256 and SHA-1 together once per distinct normalized retained input and carry path-bound immutable provenance through fingerprinting and staging. Assume resolved inputs remain stable during one Maven invocation; remove publication-time source rehashes while retaining output validation, temporary staging, atomic moves, and standalone API checks. | 5.4, 2.4, 7.1, 7.2 | Implemented, reviewed, and integrated as `dbf7214` with path-binding fix `c49fe04` |
| **7.4 Capture platform sources for exact deferred parsing** | Core platform reader | Capture selected platform bytes and digest identity together so fingerprinting and deferred analysis consume the same sources. Keep platform classes and pools context-local. | 7.3 | Implemented and reviewed as `61cf010`, with cleanup fix `9f86967`; superseded by 7.6 after 7.5 memory/latency measurements |
| **7.5 Request-owned platform byte snapshots** | Plugin/cache performance | Reuse complete snapshots through Maven request data with atomic same-key publication, retry after failed capture, and fresh mutable pools. | 7.4 | Implemented; review pending; design superseded by 7.6. Warm/fresh JMH and end-to-end evidence below |
| **7.6 Digest-only invocation-owned platform identity** | Core platform reader + Maven plugin cache | Record normalized selected paths, effective releases, selection evidence, sorted JMOD inventory, and one exact SHA-256 per selected source. Use central-directory selection, parse recorded live paths on misses, and rely on ADR 0004's stable-platform-input assumption. Do not retain archive bytes, compute platform SHA-1, or rescan JMOD declarations for cache identity. | 7.5 | Implemented and reviewed as `4cc9a7b`/`5b5edd2`; `make fmt check` passed (149 core, 72 plugin); fresh and warmed JMH/JFR and memory evidence below |
| **7.7 Bounded parallel platform-digest experiment** | Plugin/cache performance | Measure sequential against CPU-bounded 2/4/8-worker hashing of independent selected platform files, including executor construction in fresh-context latency and separate invocation-scoped reuse. Measure digest time separately from source discovery, inventory, cache validation, and executor cost; cover warm, controlled cold/less-cached, and parallel reactor workloads. Preserve deterministic identity assembly, same-key single-owner capture, failure propagation, and retry in any prototype. | 7.6 | Deferred until feature acceptance is complete. Performance improvements are lower priority than completing and verifying product behavior. Keep this experiment as a revisit candidate; proceed only for ≥20% fresh-context latency reduction with separated confidence intervals and ≤10% aggregate-throughput regression under representative reactor concurrency. |
| **7.8 Parallel candidate trimming & archive pipeline** | Maven plugin trimming + engine | Evaluate bounded concurrent candidate JAR analysis, parallel bytecode extraction/writing, and asynchronous hashing. Benchmark wall-clock reduction on Spring Boot fixture; enforce memory upper bound (max concurrent workers) and verify strict output determinism. | Feature completeness / WP-RESOLVE-01 & WP-VEX-01 | Open investigation candidate |
| **6.4 Post-optimization example profiling** | Fixtures and verification | Run matched baseline and elision `clean verify` measurements for Basic and Spring Boot, then profile elided Maven processes separately with JFR. Report timing distributions, process RSS, allocation/CPU hotspots, and artifact-size effects; distinguish JFR overhead from unprofiled timing. | 2.4, 2.5, 5.4, 7.1, 7.2 | Complete; three matched cycles per example, plus separate Basic/Spring JFR profiles |
| **6.6 Post-2.6c and 7.3 example profiling** | Fixtures and verification | Repeat three matched warm-dependency baseline-first `clean verify` cycles for Basic and Spring Boot after 2.6c and 7.3; run JFR/RSS separately and retain runtime/package checks. | 2.6c, 7.3 | Complete; see post-2.6c/7.3 evidence below |

The pre-existing cache-reader allocation change is reviewed and integrated as `113705a`; it reduces decoding allocations but does not remove exact content hashing. Its receipt is `.scratch/reviews/track-cache-reader.md`. Slices 7.1, 2.4, 2.6b, 2.6c, and 7.3 are integrated. Slice 7.6 reuses invocation-owned path-bound platform identities under ADR 0004's stable-input contract; it does not share ProGuard pools or move persistent cache lookup earlier.

#### Slice 6.4 post-optimization evidence

The integration branch passed `make test-examples` for Basic Shade, Spring Boot, and both CVE fixtures. Three full example cycles measured paired `clean verify` calls without JFR; each pair ran baseline first with the same local dependencies already warm. Median baseline/elision/delta was **2.241/4.269/+2.032 s** for Basic (ranges 2.237–2.278 / 4.260–4.348 / +1.982–2.107 s) and **4.061/32.413/+28.341 s** for Spring (ranges 4.040–4.072 / 32.198–34.720 / +28.137–30.680 s). The earlier single Spring observation was +71.861 s. Several optimization slices landed between those observations, so the reduction cannot be attributed to one slice. Treat the three baseline-first cycles as descriptive warm-dependency measurements, not statistically robust estimates.

The Basic shaded package shrank from 2,738,745 to 1,360,150 bytes; its Commons Compress input JAR shrank from 1,117,221 to 110,843 bytes. The Spring Boot package shrank from 34,588,443 to 29,427,062 bytes, removing 5,161,381 bytes. The nested `spring-webmvc` JAR shrank from 1,048,416 to 807,364 bytes and from 526 to 379 classes.

Separate JFR profiles used GraalVM 21.0.12 and the repository Maven wrapper; do not compare their elapsed times with unprofiled measurements. The Spring Maven process ran for 32 s, peaked at **3,135,084 KiB process RSS** (forked Surefire RSS is not included), and produced 1,446 execution samples and 7,029 allocation samples. Top execution frames were `TreeMap.getEntry` (227 samples, 15.7%), `AbstractStringBuilder.append` (198, 13.7%), and ProGuard `DescriptorClassEnumeration.nextClassName` (133, 9.2%) / `nextFluff` (68, 4.7%). **506 of 1,446** execution stacks included elider frames. Allocation sample weights were led by `DataInputStream.readFully`, ProGuard `StringUtil.getString`, and descriptor enumeration; they point to repeated class parsing and signature processing, not lock contention. Source inspection confirmed candidate analyses reparsed sibling class bytes and copied the full platform class pool in `PlatformClassSnapshot.copyOf`; the fixed-point loop retained all candidate contexts at once. Slice 2.6a releases the graph supplier after successful construction, and 2.6b removes repeated sibling declaration parsing while retaining context-local resolution.

The Basic JFR profile ran for 4 s, peaked at 1,230,628 KiB Maven-process RSS, and yielded only 62 execution samples, so its method-level CPU ranking is low confidence. Its allocation samples include ASM parsing, ZIP inflater setup, and the new platform signature snapshot copier. The RSS monitor sampled the Maven process's `VmHWM`; it did not measure aggregate process-tree memory. JFR artifacts and raw logs remain in `/tmp/elider-postopt-jfr` and are not committed.

#### Slice 2.6b post-optimization evidence

After integrating `a83649b` (engine-track commit `6a1bcac`), three baseline-first cycles with warm local Maven dependencies measured Basic baseline/elision/delta at **2.244/4.286/+2.038 s** median (ranges 2.231–2.263 / 4.269–4.300 / +2.037–2.042 s) and Spring at **4.090/26.752/+22.716 s** (ranges 4.036–4.117 / 26.717–26.995 / +22.627–22.878 s). The Spring elision median is 5.661 s lower than the earlier 6.4 measurement of 32.413 s; this is a descriptive before/after observation, not a guaranteed or isolated causal effect. Basic and Spring package sizes, retained Spring mail artifacts, and runtime checks remained the same.

A separate post-change Spring JFR recording covered a 27 s Maven process and produced 1,141 execution samples and 4,652 allocation samples. `TreeMap.getEntry` was the top first execution frame (256 samples, 22.4%); 148 samples came through `ClassReferenceInitializer.findClass -> ClassPool.getClass`, 61 through `ReferenceGraphIndexer.EdgeCollector`, and 35 through `ClassSuperHierarchyInitializer`. ProGuard `DescriptorClassEnumeration.nextFluff` and `nextClassName` contributed 193 (16.9%) and 149 (13.1%) first frames. 358 of 1,141 execution stacks included elider frames. Allocation weights are sampled estimates, not exact totals; the largest first-frame weights were `String.substring`, descriptor enumeration, and `LibraryClass.methodsAccept`. This motivates slice 2.6c: a frozen per-context lookup index can leave resolution and missing-reference callbacks in ProGuard while replacing repeated TreeMap lookups. Descriptor traversal remains another hot path, but precomputation would require replacing private ProGuard reference-initializer operations and has a wider parity burden. A separate profiled run measured **3,269,272 KiB Maven-process peak RSS** using `/proc/<pid>/status` `VmHWM`; it excludes forked Surefire RSS, and the RSS figure does not establish retained heap or aggregate process-tree memory. The same recording sampled 48 post-GC heap summaries; the last reported post-GC heap use was about 1.0 GiB, which is not a retained-object attribution. The profiler run's timing is not included in the unprofiled timing comparison. JFR and run logs are in `/tmp/elider-post-2.6b-*` and are not committed.

#### Slice 6.6 post-2.6c and 7.3 evidence

The timing environment was GraalVM JDK 21.0.12+7.1, repository `./mvnw` (Apache Maven 3.9.11), `--batch-mode --no-transfer-progress`, and the already-warm local Maven repository. The command was `JAVA_HOME=/workspace/sources/maven-dependency-elider/.scratch/toolchains/graalvm-jdk-21.0.12+7.1 MAVEN=./mvnw make test-examples`. It ran baseline and elision modes in separate `clean verify` Maven processes for each fixture, captured the baseline runtime trace between modes, then checked runtime behavior and package contents. Three additional runs of that same target produced these baseline/elision/delta values:

| Fixture | Baseline, median (range) | Elision, median (range) | Added time, median (range) |
| --- | ---: | ---: | ---: |
| Basic Shade | 2.251 s (2.227–2.293) | 4.236 s (4.199–4.271) | +1.972 s (+1.943–+2.020) |
| Spring Boot | 4.087 s (4.053–4.148) | 24.424 s (24.177–24.506) | +20.337 s (+20.029–+20.453) |

All three cycles passed all four fixtures, including Basic compiler-visibility and runtime checks, Spring endpoint/package checks, and both CVE fixtures. Basic's shaded package was **2,738,745 → 1,360,150 bytes** and Commons Compress was **1,117,221 → 110,843 bytes**. Spring's package was **34,588,443 → 29,427,062 bytes**, a reduction of **5,161,381 bytes**; nested `spring-webmvc` was **1,048,416 → 807,364 bytes** and **526 → 379 classes**. The latest medians are 0.066 s lower for Basic and 2.379 s lower for Spring than the post-2.6b medians above. The prior and current measurements straddle 2.6c `ed6a33d` and 7.3 `dbf7214` (path-binding follow-up `c49fe04`); these descriptive cycles do not isolate either change's causal effect.

Separate JFR profiles used fresh baseline runtime traces, the same wrapper/JDK and elision options, and `MAVEN_OPTS=-XX:StartFlightRecording=filename=…,settings=profile,dumponexit=true`. The profiling runs are not included in timing results. Basic's recording lasted 4 s and had 75 execution samples and 773 allocation samples; its first-frame samples were sparse, led by `DescriptorClassEnumeration.nextClassName` (6), `ImmutableCollections$MapN.probe` (4), and `DescriptorClassEnumeration.nextFluff` (3). This is too few execution samples for a reliable method ranking. Spring's recording lasted 24 s and had 1,121 execution samples and 4,381 allocation samples. Its top first frames were ProGuard `DescriptorClassEnumeration.nextFluff` (186, 16.6%), `nextClassName` (150, 13.4%), `ImmutableCollections$MapN.probe` (144, 12.8%), and `HashMap.resize` (42, 3.7%); `TreeMap.getEntry` had 27 samples (2.4%) and `FrozenClassPool.getClass` had 12. **534 of 1,121** execution stacks contained an elider frame. Spring allocation samples were weighted most heavily at `String.substring` (940 samples; 3,927,863,296 estimated bytes), `DescriptorClassEnumeration.nextFluff` (479; 2,031,663,624), and `nextClassName` (236; 995,728,352). These weights are sampling estimates, not exact allocation totals or retained heap.

Separate `/proc/<pid>/status` `VmHWM` sampling every 50 ms measured **940,252 KiB** peak RSS for the Basic Maven process and **2,924,512 KiB** for Spring. The profiler-run elapsed times were 4.369 s and 24.808 s respectively and are not comparable with unprofiled cycle timings. RSS is for the Maven process only; it excludes forked Surefire/application processes and does not measure aggregate process-tree memory or identify retained heap. JFR files, JSON summaries, RSS stats, and raw cycle logs are under `/tmp/elider-6.6-jfr` and `/tmp/elider-6.6-cycle-*.log`; they are not committed.

#### Slice 7.2 evidence and decision

Each `MavenDependencyTrimmer.trim` call opens `ct.sym` to check selected-release signatures, then hashes the selected platform archive once when building the fingerprint. `loadCache` consumes that fingerprint without hashing `ct.sym` again. The remaining repeated work is across separate trim calls, such as projects in a reactor. The warm-cache JFR profile sampled `ZipFile` central-directory work and recorded 167.4 MB of file reads across a fork, but the read recording includes setup and JMOD loading and cannot isolate a per-call saving.

The stable-input contract in ADR 0004 includes selected JDK platform files. A mid-invocation edit is unsupported and can make that invocation nondeterministic; a fresh invocation recomputes and recognizes changed content. Slice 7.6 shares path-bound identities and source-selection evidence through the Maven request while parsing recorded live paths on a cache miss. Fingerprinting does not claim those live paths are immutable snapshots. Tests verify distinct JDK/release/source-mode identities and detect same-size content changes with restored mtimes in a fresh context.

#### Slice 7.6 digest-only platform identity and performance evidence

Slice 7.5's warmed-request trim-cache operation measured **0.094 ±0.001 ms/op**, below the warmed repeated-request target of **<10 ms**. A fresh request with an existing output cache measured **1,172.372 ±12.433 ms/op** and retained **130,382,660 bytes** of selected `ct.sym`, release metadata, and 79 JMODs. Those byte arrays made one-project Maven builds slower than the 6.6 checkpoint; the implementation also computed both SHA-256 and SHA-1 for platform archives.

Slice 7.6 replaces byte snapshots with a request-owned identity of normalized source paths, effective releases, selection evidence, sorted JMOD inventory, and one SHA-256 per selected source. It uses `ZipFile` central-directory inspection and does not retain archive bytes, calculate platform SHA-1, or enumerate each JMOD's class names for identity. A cache miss parses the selected live paths directly without rehashing or rerunning selection. The stable-input ADR explicitly covers `ct.sym`, release metadata, and selected JMODs. Corrupt selected sources fail during miss-path parsing before a success manifest or output can be published; a new invocation recomputes content identity.

The timing environment was GraalVM JDK 21.0.12+7.1 with the repository wrapper (Apache Maven 3.9.11). Unprofiled JMH used JMH 1.37, two forks, three 1 s warmups, and five 1 s measurement iterations. One op calls production `MavenDependencyTrimmer.trim` for one tiny candidate, including dynamic roots, dependency digests, platform identity, cache-manifest validation, and cached-output hashing. Fresh request/cache-hit timing was **93.465 ±0.391 ms/op** (range 92.999–94.012), about 9.3× above the <10 ms fast-path budget; warmed same-request/cache-hit timing was **0.093 ±0.001 ms/op** (range 0.093–0.094). The warmed result measures reuse after invocation-owned platform identity is available; fresh-context cache hits remain above budget. Compared descriptively with 7.5, fresh capture dropped from 1,172 ms to 93 ms while warm latency remained about 0.094 ms; 7.6 changed byte retention, digest algorithms, and archive selection behavior together, so this is not an isolated causal estimate.

Separate JFR runs used one fork, one 1 s warmup, and two 2 s measurements. The fresh run measured 94.377 ms/op and produced 44 execution samples; six samples each were in SHA-256 compression, `ZipFile$Source.checkAndAddEntry`, and `ZipEntryIterator.next`. JMOD central-directory preflight had been removed; remaining ZIP samples cover selected archive inspection and operation work. Fresh allocation samples were weighted toward ZIP entry iteration (16.73%), ASM class reads (12.12%), digest setup (11.18%), and path/string processing. The warmed run measured 0.096 ms/op and produced 38 execution samples; it had no direct `jdk.FileRead` events. JFR includes setup/warmup, uses sampled execution/allocation, and does not report exact total CPU or allocation.

On this GraalVM JDK 21 installation, the identity contains 81 sources (ct.sym, release metadata, and 79 JMODs), 17,805 characters in the serialized identity, and 14,336 path-plus-digest characters. It retains no archive byte arrays; these character counts are not a heap-size measurement. A targeted unprofiled Spring elision run selected the single Maven Launcher PID by command line (PID 835033), sampling `/proc/<pid>/status` `VmHWM` every 50 ms for 485 samples. Its peak was **3,119,312 KiB RSS**; child processes were excluded. The earlier multi-PID aggregate was discarded. This differs from 7.5's one-process 3,106,188 KiB by about 13 MiB, which is within run variability; no RSS improvement is claimed. The 7.5 and 7.6 RSS/JMH measurements are descriptive and do not isolate a single change.

The three matched post-7.6 example cycles measured median added time of **+1.977 s** for Basic and **+20.417 s** for Spring Boot; all four fixtures passed. These cycles included the 79-JMOD fallback identity. Removing the redundant JMOD central-directory preflight changed fresh JMH by about 3 ms/op (96.488 to 93.465 ms/op), small compared with the end-to-end cycle ranges, so the examples were not rerun. The measured Maven overhead remains above baseline, and the <10 ms target remains unmet for fresh-context work. Further performance optimization is deferred while feature completeness and correctness take priority. The bounded parallel-digest experiment remains a revisit candidate after feature acceptance. See the [performance follow-up handover](../handovers/2026-10-26-performance-follow-up.md) for the slice history and review status.

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
