<!-- WHY: Investigates the engineering constraints and performance benchmarks required to guarantee <10ms overhead during routine Maven invocations. -->
# RQ-0003: Sub-10ms Maven Fast-Path Invariant and Benchmarking Methodology

* **Status**: Open
* **Category**: Performance & Benchmarking
* **Date**: 2026-10-24
* **Last Updated**: 2026-10-24

Abbreviations: Java Microbenchmark Harness (JMH), Solid State Drive (SSD), Non-Volatile Memory Express (NVMe), Central Directory (CEN), Virtual Threads (Loom), Central Processing Unit (CPU).

---

## 1. Context & Research Questions

Because the `dependency-elider-maven-plugin` binds to the early `INITIALIZE` lifecycle phase, it executes on **every single Maven invocation** (e.g. `mvn compile`, `mvn test`, `mvn package`). If the plugin adds noticeable latency to local developer builds, developer adoption drops.

A hard non-negotiable invariant is established:
$$\Delta t_{\text{overhead}} < 10\text{ ms on cached/routine builds}$$

### Primary Research Questions

* **RQ-0003.1**: What is the most efficient, allocation-free fingerprinting scheme to detect whether dependencies or trace files have changed?
* **RQ-0003.2**: On cache hits, can reading the precomputed pruning decision and mutating `project.getArtifacts()` execute in $< 1\text{ ms}$?
* **RQ-0003.3**: On cold cache misses (when dependencies change), what is the minimal latency achievable for scanning the ZIP Central Directory of 50–100 JAR files using Java 21 Virtual Threads?
* **RQ-0003.4**: How should automated CI benchmarks be structured to fail the build if fast-path overhead exceeds 10ms?

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
   * Fails test execution if $\Delta t \ge 10\text{ ms}$ across 10 consecutive cached runs.

---

## 4. Next Steps & Decision Checkpoints

* [ ] Checkpoint 1: Create `elider-benchmarks` module with JMH harness.
* [ ] Checkpoint 2: Benchmark sequential vs. virtual-thread ZIP Central Directory reader across 100 real JARs.
* [ ] Checkpoint 3: Validate $< 1\text{ ms}$ fast-path execution in real Maven lifecycle execution.
