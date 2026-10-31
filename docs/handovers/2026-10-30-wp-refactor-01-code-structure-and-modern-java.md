<!-- WHY: Defines the work package specification for decomposing monolithic God-classes, adopting modern Java 21 idioms, and eliminating widespread PMD suppressions across core and plugin modules. -->
# Work Package Handover: WP-REFACTOR-01 Code Structure Decomposition & Modern Java 21 Refactoring

* **Status**: Implemented; full `make check` and example checks passed.
* **Owning Thread / Session**: Primary Coordinating Session
* **Date**: 2026-10-30
* **Target Branch / Base**: `main`
* **Related Architecture Decisions**:
  * [ADR-0003: ProGuard Core-Driven Intra-JAR Trimming and CycloneDX Pedigree](../adr/0003-proguard-core-intra-jar-trimming-and-cyclonedx-pedigree.md)
  * [ADR-0008: Evidence-Gated VEX Attestation and Precondition Proof Generation](../adr/0008-evidence-gated-vex-attestation-and-precondition-proof-generation.md)

---

## 1. Executive Summary & Problem Statement

### 1.1 Context & Problem

As features were iteratively implemented, several core orchestration classes accumulated excessive responsibilities, resulting in monolithic "God Classes" with heavy PMD suppressions:

* [`MavenDependencyTrimmer.java`](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenDependencyTrimmer.java): **3,562 lines long**, containing **18 class-level PMD suppressions** (`GodClass`, `TooManyMethods`, `CouplingBetweenObjects`, `ExcessiveImports`, `CognitiveComplexity`, `CyclomaticComplexity`, `NcssCount`, etc.). It bundles ProGuard execution, multi-release JAR handling, ZIP stream sanitization, digest generation, parallel thread management, and disk caching into one class.
* [`MavenElisionService.java`](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenElisionService.java): **1,948 lines long**, containing **10 class-level PMD suppressions**. It bundles configuration canonicalization, dynamic root scanning coordination, graph traversal, reachability analysis, VEX evidence collection, and artifact plan resolution.
* Multiple helper routines use pre-Java 17 imperative patterns, complex nested conditionals, and mutable collections where Java 21 features (records, pattern matching, sealed interfaces, sequenced collections) enable concise, type-safe, and self-documenting code.

Per repository policy, **PMD exclusions are a last resort and must not be used to mask architectural bloat**.

### 1.2 Objectives

1. **Deconstruct `MavenDependencyTrimmer` into Focused Collaborators**: Extract discrete, single-responsibility components with zero class-level PMD suppressions.
2. **Deconstruct `MavenElisionService`**: Separate graph reachability, VEX attestation collection, and plan resolution into distinct services.
3. **Adopt Modern Java 21 Idioms**: Replace legacy boilerplate with records, pattern matching (`switch` and `instanceof`), sealed hierarchies, and sequenced collections.
4. **Eliminate Class-Level PMD Suppressions**: Systematically reduce and eliminate suppressions for `GodClass`, `TooManyMethods`, `CouplingBetweenObjects`, `ExcessiveImports`, and `CyclomaticComplexity`.

---

## 2. Non-Negotiable Invariants & Guardrails

1. **Strict Behavioral Equivalence**: Zero alteration to elision plans, intra-JAR trimming results, SBOM generation, or VEX attestation outputs.
2. **Deterministic Outputs & Digests**: All byte sanitization, entry sorting, and manifest normalization must remain byte-identical across refactorings.
3. **Zero New Suppressions & Elimination of Existing Suppressions**: Refactoring must eliminate class-level PMD suppressions rather than renewing or relocating them.
4. **Language & Tooling Boundary (AGENTS.md)**: Strictly Java, Bash, or Go. No Python or Node.js.
5. **Clean Verification Gates**: All refactorings must pass `make check` (Spotless, Checkstyle, PMD 7.28.0, SpotBugs, Markdownlint, and all tests).

---

## 3. Architecture & Decomposition Specification

### 3.1 Decomposition of `MavenDependencyTrimmer` (3,562 lines $\to$ Focused Collaborators)

```text
┌────────────────────────────────────────────────────────────────────────┐
│                      MavenDependencyTrimmer Facade                     │
├───────────────────┬───────────────────┬────────────────────────────────┤
│ JarTrimCache      │ ProGuardTrimEngine│ MultiReleaseJarTrimmer         │
│ Probing, hashing, │ ProGuard Core     │ MR-JAR version directories &   │
│ hit/miss metadata │ intra-JAR trimming│ module-info preservation       │
├───────────────────┴───────────────────┴────────────────────────────────┤
│ JarArchiveSanitizer                   │ ParallelTrimExecutor           │
│ Signature stripping, manifest cleanup │ Thread-safe bounded worker     │
│ and deterministic zip assembly        │ execution & lifecycle control  │
└───────────────────────────────────────┴────────────────────────────────┘
```

1. **`JarTrimCache`**:
   * Responsibilities: Cache directory resolution, two-phase key validation (size/timestamp then SHA-256), reading/writing cached `.jar` files and sidecar metadata.
2. **`ProGuardTrimEngine`**:
   * Responsibilities: Constructing ProGuard `ClassPool`, seeding entry-point rules, executing intra-JAR trimming, and emitting pruned class lists.
3. **`MultiReleaseJarTrimmer`**:
   * Responsibilities: Scanning and sanitizing `META-INF/versions/**` entries, ensuring consistency across Java version-specific bytecode overlays.
4. **`JarArchiveSanitizer`**:
   * Responsibilities: Stripping digital signatures (`META-INF/*.SF`, `*.DSA`, `*.RSA`), cleaning `MANIFEST.MF`, normalizing zip timestamps, and writing deterministic output archives.
5. **`ParallelTrimExecutor`**:
   * Responsibilities: Managing worker threads, task distribution, and error aggregation without triggering concurrency linter suppressions.

---

### 3.2 Decomposition of `MavenElisionService` (1,948 lines $\to$ Focused Collaborators)

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        MavenElisionService Facade                      │
├────────────────────────────────┬───────────────────────────────────────┤
│ ElisionReachabilityEngine      │ VexAttestationService                 │
│ Reachability graph traversal & │ Precondition proof aggregation,       │
│ retained artifact calculation  │ component hashing & VEX generation    │
├────────────────────────────────┴───────────────────────────────────────┤
│ DynamicRootOrchestrator        │ ArtifactPlanPublisher                 │
│ Dynamic roots resolution across│ Session-level and build-directory     │
│ SPI, native-image, and Spring  │ plan publication                      │
└────────────────────────────────┴───────────────────────────────────────┘
```

1. **`ElisionReachabilityEngine`**:
   * Responsibilities: Core BFS/DFS reachability traversal across the artifact graph, evaluating compile/runtime scopes and transitive linkages.
2. **`VexAttestationService`**:
   * Responsibilities: Aggregating precondition proofs, calculating artifact digests, evaluating CVE mitigations, and generating typed VEX attestations.
3. **`DynamicRootOrchestrator`**:
   * Responsibilities: Coordinating discovery and aggregation of dynamic roots across SPI, native-image descriptors, and Spring configuration.

---

### 3.3 Modern Java 21 Modernization Matrix

| Modern Java 21 Feature | Current Legacy Pattern | Modernized Target Pattern |
| :--- | :--- | :--- |
| **Records** | Mutable POJOs, static inner classes with custom getters/equals/hashcode | Immutable domain records (`TrimTask`, `CacheMetadata`, `ElisionCandidate`). |
| **Pattern Matching for Switch** | Long chains of `if-else` using `instanceof` and manual type casting | Type-safe exhaustive `switch (obj)` with record deconstruction. |
| **Sealed Types** | Open abstract classes or loose interfaces with unchecked implementations | Sealed interfaces (`sealed interface TrimOutcome permits TrimSuccess, TrimSkipped, TrimFailed`). |
| **Sequenced Collections** | `iterator().next()`, index tracking, manual list reversal | Sequenced collection methods (`collection.getFirst()`, `collection.reversed()`). |
| **Compact Stream Pipelines** | Nested loops with manual accumulator lists | Stream methods (`toList()`, `mapMulti()`, grouping collectors). |

---

## 4. Track Decomposition & Committable Slices

```text
┌────────────────────────────────────────────────────────────────────────┐
│                  WP-REFACTOR-01 Track Decomposition                    │
├───────────────┬────────────────────────────────────────────────────────┤
│ Slice 1       │ Extract JarArchiveSanitizer & JarTrimCache             │
├───────────────┼────────────────────────────────────────────────────────┤
│ Slice 2       │ Extract ProGuardTrimEngine & MultiReleaseJarTrimmer    │
├───────────────┼────────────────────────────────────────────────────────┤
│ Slice 3       │ Decompose MavenElisionService Collaborators            │
├───────────────┼────────────────────────────────────────────────────────┤
│ Slice 4       │ Modern Java 21 Idiom Modernization & Cleanup           │
└───────────────┴────────────────────────────────────────────────────────┘
```

### Slice 1: Extract `JarArchiveSanitizer` and `JarTrimCache`

* Extract zip sanitization, manifest cleaning, and signature removal from `MavenDependencyTrimmer` into `JarArchiveSanitizer`.
* Extract cache directory management, key generation, and cache probing into `JarTrimCache`.
* Eliminate associated PMD suppressions in `MavenDependencyTrimmer`.
* Verify all unit and integration tests pass with 0 regressions.

### Slice 2: Extract `ProGuardTrimEngine` and `MultiReleaseJarTrimmer`

* Extract core ProGuard configuration and execution into `ProGuardTrimEngine`.
* Extract versioned multi-release directory processing into `MultiReleaseJarTrimmer`.
* Reduce `MavenDependencyTrimmer` to a thin orchestration coordinator under 400 lines.
* Eliminate `GodClass`, `TooManyMethods`, and `ExcessiveImports` suppressions.

### Slice 3: Decompose `MavenElisionService` Collaborators

* Extract `ElisionReachabilityEngine` and `VexAttestationService`.
* Decouple plan calculation from Maven session state publishing.
* Eliminate class-level suppressions on `MavenElisionService`.

### Slice 4: Modern Java 21 Idioms & Quality Verification

* Migrate internal data structures to records and sealed hierarchies.
* Refactor complex conditional ladders to pattern-matching switches.
* Run full verification suite (`make check`, `make fmt lint-java test-all`).

---

## 5. Verification & Acceptance Gates

Execute the full repository verification suite:

```bash
JAVA_HOME=$(pwd)/.scratch/toolchains/graalvm-jdk-21.0.12+7.1 make fmt lint-java test-core test-plugin test-all
```

Invariants:

* `MavenDependencyTrimmer.java` line count reduced by >70% (target: < 500 lines).
* `MavenElisionService.java` line count reduced by >60% (target: < 500 lines).
* Class-level PMD suppressions (`GodClass`, `TooManyMethods`, `CouplingBetweenObjects`, `ExcessiveImports`) completely eliminated from refactored classes.
* 0 Spotless violations, 0 Checkstyle violations, 0 PMD violations, 0 SpotBugs warnings.
* 0 Markdownlint violations (`make lint-markdown`).
* 100% of unit, integration, and example tests pass deterministically.

## 6. Implementation & Verification Closeout

### Implementation

* `MavenDependencyTrimmer.java` is 208 lines; archive staging, cache, candidate planning, ProGuard execution,
  multi-release analysis, output publication, and parallel scheduling now live in focused collaborators.
* `MavenElisionService.java` is 165 lines; reachability, dynamic-root discovery, artifact planning, and
  effective-output publication are delegated to focused services.
* `MultiReleaseTierAnalyzer.java` is a 28-line entry point over ordered tier-analysis phases.
* Shared immutable request, result, evidence, policy, and analysis values use records. `TrimRequestFactory` keeps
  the two trim entry points aligned while preserving their distinct roots and retained inputs.
* Removed the class-level complexity, coupling, and import suppressions from the refactored facades and tier
  analyzer. No new class-level suppressions were added to those classes.

### Verification (2026-10-30)

* `JAVA_HOME=.scratch/toolchains/graalvm-jdk-21.0.12+7.1 make fmt` passed.
* `JAVA_HOME=.scratch/toolchains/graalvm-jdk-21.0.12+7.1 make lint-java` passed on the final tree. Spotless was
  clean, Checkstyle reported 0 violations, PMD reported no violations, and SpotBugs reported no warnings.
* `make test-core`, `make test-plugin`, and `make test-all` passed. The full reactor reports 679 tests with no
  failures, errors, or skips; the isolated lifecycle target also passed all 16 tests.
* After the final empty-result cleanup, focused service and trimmer tests passed: 29 tests, 0 failures.
* `make test-examples` passed for five standalone fixtures and the multi-module reactor, including sequential
  and `-T 4` builds, package/runtime checks, SBOM checks, and MRJAR tier checks.
* `git diff --check` passed, and searches found no test or benchmark callers of the removed nested facade APIs.
* `JAVA_HOME=.scratch/toolchains/graalvm-jdk-21.0.12+7.1 make check` passed, including Markdownlint, the Node-based
  SBOM comparison tests, the full Java test suite, lifecycle integration tests, and command transcript checks.
