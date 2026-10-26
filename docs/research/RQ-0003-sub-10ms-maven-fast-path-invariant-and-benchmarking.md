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
4. Reuse the JDK platform identity for the Maven session. Hash `ct.sym` exactly once per session after reading its content, keyed by the normalized JDK path and release; if a longer-lived cache is considered, preserve exact content identity. Consider immutable platform-signature templates keyed by JDK content and release, but do not share mutable initialized ProGuard pools without proving that is safe.
5. Revisit persistent transformation-cache placement only after the preceding costs are reduced. A cache lookup moved earlier must bind every source/generated-source, trace, metadata, ordered dependency, compiler/runtime, engine, root, and output input that can change the result.

The profiles show what to investigate first; they do not prove that every listed optimization is safe. No persistent-cache weakening, ProGuard-pool sharing, or source changes were made as part of this investigation.

## 5. Next Steps & Decision Checkpoints

* [ ] Checkpoint 1: Create `elider-benchmarks` module with JMH harness.
* [ ] Checkpoint 2: Benchmark sequential vs. virtual-thread ZIP Central Directory reader across 100 real JARs.
* [ ] Checkpoint 3: Validate $< 1\text{ ms}$ fast-path execution in real Maven lifecycle execution.
* [ ] Checkpoint 4: Define a statistically defensible lifecycle overhead measurement and compare total build cost, package size, and setup effort with baseline workflows.
* [ ] Checkpoint 5: Specify complete transformation cache keys, output validation, and concurrent/partial-write behavior before caching source-aware trimming.

### 5.1 Follow-up Implementation Slices (2026-10-26)

The source audit and JFR findings are assigned to the existing Maven-trimming, ProGuard-engine, and cache tracks. Work proceeds in dependency order; the shared-reference-graph refactor and earlier cache lookup remain gated on parity and complete identity contracts. None of these slices alone establishes the sub-10 ms Maven invariant. Keep JMH cache-operation timing separate from elider-phase and paired end-to-end Maven measurements.

| Slice | Track | Scope and acceptance criteria | Depends on | State |
| :--- | :--- | :--- | :--- | :--- |
| **5.4 Invocation scan reuse** | Maven plugin trimming | Pass `DependencyDynamicRoots.RootScan` results through the trimming request and reuse the `ArtifactClassIndex` only where it has matching archive semantics. Scan each retained JAR's dynamic metadata once per invocation; preserve roots, pruning, pass-through decisions, projected multi-release behavior, and output bytes. | None | Implemented, reviewed, integrated as `e7c0a69` |
| **2.4 Per-invocation archive parse reuse** | ProGuard Core engine | Validate and parse each original or projected archive once per trim invocation while retaining per-candidate initialization and closure behavior. Prove fewer archive reads and exact retained/reachable-set parity, including ordered classpath precedence, cross-artifact links, pass-through unresolved references, signature-polymorphic references, and failures. Do not share initialized mutable `ClassPool` instances. | 5.4 review; may proceed independently if interfaces do not overlap | In progress |
| **2.5 Immutable invocation reference graph** | ProGuard Core engine + Maven plugin trimming | Derive immutable per-class edges and unresolved-link evidence once, then propagate roots over that graph. Preserve candidate-first lookup, sibling order, platform fallback, reachable-only errors, and pass-through rules. Compare exact retained and reachable sets against the existing engine on multi-artifact chains and cycles; measure traversal reductions on the Spring-sized fixture. | 2.4 parity | Deferred until 2.4 passes |
| **7.1 Exact digest deduplication** | Cache | Compute each distinct retained input SHA-256 once per invocation and reuse the verified digest for fingerprint and entry validation; continue validating trimmed output bytes on cache hits. Test same-size content changes with restored mtimes, missing/corrupt outputs, and define behavior for inputs changed mid-invocation. | 5.4 and 2.4 | Assigned after cache track is available |
| **7.2 Maven-session platform identity** | Cache | Reuse selected-release detection and exact `ct.sym` identity per normalized JDK path and release for one Maven session; include ordered JMOD names and exact content digests on fallback. Verify multiple JDKs/releases and do not share identities across sessions. State and test the file-change-during-session assumption. | 7.1 | Assigned after 7.1 |
| **7.3 Earlier persistent-cache lookup** | Cache + Maven plugin trimming | Move lookup earlier only after specifying and testing all result-affecting key dimensions: sources/generated sources, traces, metadata, ordered dependency bytes, roots, compiler/toolchain/runtime settings, processors, pass-through policy, engine/schema, destination, and inventory. Preserve output digest validation, atomic publication, and safe corrupt/concurrent recovery; prove each key change misses. | 5.4, 2.4, 2.5, 7.1, 7.2 | Deferred pending identity contract |

The retained `track/cache` worktree currently contains uncommitted cache-reader changes. Preserve those edits and finish their existing review before starting slices 7.1–7.3 there. Do not mix cache-reader allocation work into digest identity or platform identity slices.

#### Slice 5.4 evidence and review

* **Implementer / reviewed commit**: Maven trimming track; `8b3c4c4` (`Reuse Maven invocation dependency scans`), rebased without code changes and integrated as `e7c0a69`.
* **Focused and full verification**: post-merge `make check` passed with repository GraalVM 21; 116 core tests, 64 plugin tests, static analysis, formatting, and Markdown lint passed. The trim-boundary test verifies supplied dynamic roots affect output and missing scan evidence fails explicitly. The JMH benchmark computes dynamic-root input inside each measured operation, preserving its previous measurement boundary.
* **Review verdict**: approved after the initial reviewer model hit capacity; replacement review accepted the complete implementation. Receipt: `.scratch/reviews/track-plugin-trimming-performance.md`.
