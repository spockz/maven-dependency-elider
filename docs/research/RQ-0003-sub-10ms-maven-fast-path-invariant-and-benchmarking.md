<!-- WHY: Defines performance and cache-correctness investigations so build overhead targets and reduction benefits can be evaluated with reproducible evidence. -->
# RQ-0003: Sub-10ms Maven Fast-Path Invariant and Benchmarking Methodology

* **Status**: Open
* **Category**: Performance & Benchmarking
* **Date**: 2026-10-24
* **Last Updated**: 2026-10-25

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

## 4. Next Steps & Decision Checkpoints

* [ ] Checkpoint 1: Create `elider-benchmarks` module with JMH harness.
* [ ] Checkpoint 2: Benchmark sequential vs. virtual-thread ZIP Central Directory reader across 100 real JARs.
* [ ] Checkpoint 3: Validate $< 1\text{ ms}$ fast-path execution in real Maven lifecycle execution.
* [ ] Checkpoint 4: Define a statistically defensible lifecycle overhead measurement and compare total build cost, package size, and setup effort with baseline workflows.
* [ ] Checkpoint 5: Specify complete transformation cache keys, output validation, and concurrent/partial-write behavior before caching source-aware trimming.
