<!-- WHY: Defines the work package specification for comprehensive test suite velocity optimizations, shared fixture caching, parallel test execution, and concurrent verification tooling. -->
# Work Package Handover: WP-TEST-01 Comprehensive Test Suite Velocity & Verification Optimization

* **Status**: Ready for Implementation
* **Owning Thread / Session**: Primary Coordinating Session
* **Date**: 2026-10-30
* **Target Branch / Base**: `main`
* **Related Research Questions**:
  * [RQ-0016: GraalVM Native-Image Metadata Ingestion and Permissive Argument Taxonomy](../research/RQ-0016-graalvm-native-image-metadata-ingestion-and-permissive-argument-taxonomy.md)
* **Related Architecture Decisions**:
  * [ADR-0003: ProGuard Core-Driven Intra-JAR Trimming and CycloneDX Pedigree](../adr/0003-proguard-core-intra-jar-trimming-and-cyclonedx-pedigree.md)
  * [ADR-0008: Evidence-Gated VEX Attestation and Precondition Proof Generation](../adr/0008-evidence-gated-vex-attestation-and-precondition-proof-generation.md)

---

## 1. Executive Summary & Problem Statement

### 1.1 Context

As the project evolved to support comprehensive bytecode analysis, multi-module reactors, dynamic root extraction, and VEX attestation, test execution times have steadily increased:

* `make test-plugin` takes ~45 seconds due to nested Maven lifecycle builds and 40+ extensive Mojo unit tests.
* `make test-examples` (`examples/run-elision-cycle.sh`) takes over 70 seconds to sequentially run baseline builds, trace generation, and elision cycles across multiple standalone fixture apps.
* `make update-transcripts` / `make check-transcripts` takes over 60 seconds because `scripts/update-transcripts.go` runs each fixture Maven command sequentially.
* Unit test suites repeatedly synthesize JARs, ClassPools, and byte arrays on every single test method rather than sharing immutable fixtures.

### 1.2 Objectives

1. **Shared Fixture Setup & In-Memory Re-use**: Share expensive immutable test fixtures (pre-built synthetic JARs, parsed class models) across assertions instead of reconstructing zip archives and ASM bytecodes per test method.
2. **JUnit 5 Parallelization & Surefire Tuning**: Enable concurrent execution for isolated unit tests using JUnit 5 parallel execution (`junit.jupiter.execution.parallel.enabled=true`) and tuned Surefire forks.
3. **Fast Inner Loop via Failsafe Separation**: Formalize the separation between sub-second unit tests (`*Test.java`) and slow nested Maven invocations (`*IT.java` via `maven-failsafe-plugin`), allowing instant local feedback.
4. **Parallel Execution of Example Fixtures (`run-elision-cycle.sh`)**: Execute independent fixture app builds (`example-basic-app`, `example-spring-boot-app`, CVE fixtures) concurrently in parallel subshells with isolated temporary targets.
5. **Concurrent Transcript Processing (`scripts/update-transcripts.go`)**: Refactor the Go transcript updater/checker to run independent fixture commands in parallel goroutines with a bounded worker pool.

---

## 2. Invariants & Guardrails

1. **Strict Test Isolation**: Parallel test execution must never produce test collisions. Tests mutating file systems or Maven sessions must use isolated temporary directories (`@TempDir`) or distinct reactor worktrees.
2. **Determinism & Reproducibility**: Parallelizing fixture execution must produce identical transcripts, digests, and VEX attestations. Output ordering in transcripts must remain strictly deterministic.
3. **No Flaky Timing Dependencies**: Tests must not rely on `Thread.sleep` or arbitrary timing windows; synchronizations must rely on deterministic file or process state.
4. **Language & Tooling Boundary (AGENTS.md)**: New tooling must remain Java, Bash, or Go. The existing Node.js Markdown linter and SBOM verification scripts are the narrow exception for repository verification; do not add Node.js implementation tooling. Do not use Python.
5. **Zero PMD / Checkstyle Suppressions**: Any test refactoring or fixture sharing must adhere strictly to zero-warning quality gates without `@SuppressWarnings("PMD...")`.

---

## 3. Technical Specification & Work Breakdown

### 3.1 Track 1: Shared Fixture Setup & In-Memory Pre-computation

#### Problem

In `PreconditionClassInventoryTest`, `ElideMojoTest`, `DependencyDynamicRootsTest`, and `MavenDependencyTrimmerTest`, dozens of test methods construct identical dummy `.class` files, zip them into temporary `.jar` archives, and construct new ClassPools.

#### Implementation

1. **Static / Class-Level Fixtures**:
   * For read-only JAR fixtures (e.g. standard synthetic libraries with `used/Sample.class` and `unused/Dead.class`), create immutable template archives once per test class lifecycle (`@BeforeAll` or static holder) in `@TempDir(cleanup = CleanupMode.ALWAYS)`.
   * Test methods requiring mutated JARs copy or derive from the template rather than rewriting from scratch.
2. **Shared ClassPool Cache**:
   * Preload immutable JDK and common mock library classes into a shared, read-only `ClassPool` or class inventory template, avoiding repeated JRT filesystem traversal.

---

### 3.2 Track 2: Test Lifecycle Separation & Surefire/Failsafe Tuning

#### Problem

Currently, `make test-plugin` uses brittle CLI exclusions (`-Dtest='!DependencyContextLifecycleIntegrationTest'`) to prevent concurrency conflicts with nested Maven installations.

#### Implementation

1. **Formal Unit vs. Integration Separation**:
   * Rename `DependencyContextLifecycleIntegrationTest` to `DependencyContextLifecycleIT` and bind it to `maven-failsafe-plugin`.
   * Configure `maven-surefire-plugin` for fast unit tests with `forkCount=1C` and `reuseForks=true`.
   * Configure `maven-failsafe-plugin` with isolated user home and repository directories for nested Maven invocations:

     ```xml
     <systemPropertyVariables>
       <maven.repo.local>${project.build.directory}/it-repo</maven.repo.local>
     </systemPropertyVariables>
     ```

2. **JUnit 5 Parallel Execution**:
   * Enable concurrent method execution for purely functional tests (e.g., `ClassUsageAnalysisTest`, `NativeImageDynamicRootsTest`, `PomTransformerTest`, `VexSerializerSupportTest`) via `junit-platform.properties`:

     ```properties
     junit.jupiter.execution.parallel.enabled = true
     junit.jupiter.execution.parallel.mode.default = concurrent
     junit.jupiter.execution.parallel.mode.classes.default = concurrent
     ```

---

### 3.3 Track 3: Parallel Execution of Example Fixtures (`run-elision-cycle.sh`)

#### Problem

`examples/run-elision-cycle.sh` builds and tests four standalone example fixtures sequentially:

1. `example-basic-app`
2. `example-spring-boot-app`
3. `example-cve-unused-app`
4. `example-cve-safe-class-app`

Each fixture executes clean, compile, trace, analyze, and elide in sequence, taking ~15–20s each, totaling ~70s.

#### Implementation

1. Refactor `run-elision-cycle.sh` to execute the four independent fixture lifecycles in parallel background jobs:

   ```bash
   run_fixture "examples/example-basic-app" &
   run_fixture "examples/example-spring-boot-app" &
   run_fixture "examples/example-cve-unused-app" &
   run_fixture "examples/example-cve-safe-class-app" &
   wait
   ```

2. Capture logs to dedicated per-fixture log files (`target/fixture-<name>.log`) and stream or aggregate them upon completion so output is not interleaved.
3. Expected execution time drops from ~70s to ~20s (governed by the longest single fixture, Spring Boot).

---

### 3.4 Track 4: Concurrent Transcript Tooling (`scripts/update-transcripts.go`)

#### Problem

`scripts/update-transcripts.go` processes markdown transcript blocks one by one. For each block, it shells out to Maven, waits for completion, strips ANSI codes, and compares or writes output. With 8+ transcript blocks, this takes 60–80 seconds.

#### Implementation

1. Parse all transcript manifest entries and group them by independent target fixtures.
2. Use a Go worker pool with `runtime.NumCPU()` (or bounded concurrency) to execute independent command blocks concurrently.
3. For blocks targeting the same fixture directory, serialize execution using directory-keyed mutexes to avoid build directory contention.
4. Collect results and assemble the final markdown documents deterministically in manifest order.
5. Expected execution time drops from ~60s to ~18s.

---

## 4. Track Decomposition & Committable Slices

```text
┌────────────────────────────────────────────────────────────────────────┐
│                   WP-TEST-01 Track Decomposition                       │
├───────────────┬────────────────────────────────────────────────────────┤
│ Slice 1       │ Shared Fixtures & ClassPool In-Memory Caching          │
├───────────────┼────────────────────────────────────────────────────────┤
│ Slice 2       │ Failsafe Separation & JUnit 5 Concurrency              │
├───────────────┼────────────────────────────────────────────────────────┤
│ Slice 3       │ Parallel Example Fixture Runner (run-elision-cycle.sh) │
├───────────────┼────────────────────────────────────────────────────────┤
│ Slice 4       │ Concurrent Go Transcript Engine (update-transcripts)   │
└───────────────┴────────────────────────────────────────────────────────┘
```

### Slice 1: Shared Fixtures in Plugin & Core Unit Tests

* Identify duplicate JAR creation in `DependencyDynamicRootsTest`, `ElideMojoTest`, and `PreconditionClassInventoryTest`.
* Extract static fixture factory / `@BeforeAll` helpers to build base JARs once.
* Verify unit tests pass with zero PMD suppressions and measure velocity improvements.

### Slice 2: JUnit 5 Concurrency & Failsafe Integration

* Add `junit-platform.properties` to `elider-core` and `dependency-elider-maven-plugin`.
* Rename lifecycle integration test to `*IT.java` and bind to Failsafe.
* Update `Makefile` test targets (`test-core`, `test-plugin`) to leverage native concurrent execution.

### Slice 3: Parallel Shell Execution in `run-elision-cycle.sh`

* Implement subshell backgrounding with `wait` and per-fixture log redirection.
* Verify single-project and reactor modes run cleanly under `make test-examples`.

### Slice 4: Concurrent Go Transcript Engine

* Refactor `scripts/update-transcripts.go` to use goroutines, worker pool, and deterministic document assembly.
* Verify `make check-transcripts` and `make update-transcripts` produce byte-identical output with zero drift.

---

## 5. Verification & Acceptance Gates

Execute the full repository verification suite:

```bash
JAVA_HOME=$(pwd)/.scratch/toolchains/graalvm-jdk-21.0.12+7.1 make check
```

Invariants:

* `make check` wall-clock execution time reduced significantly (target: >40% overall reduction).
* All unit, integration, and example tests pass deterministically.
* 0 Spotless violations, 0 Checkstyle violations, 0 PMD violations, 0 SpotBugs warnings.
* 0 Markdownlint violations (`make lint-markdown`).
* `make check-transcripts` confirms zero drift.
