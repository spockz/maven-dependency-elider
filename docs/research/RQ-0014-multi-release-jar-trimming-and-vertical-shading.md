<!-- WHY: Investigates intra-JAR trimming for Multi-Release JARs (JEP 238), vertical shading (baseline elevation), cross-tier reachability, and safe upper-tier pass-through. -->
# RQ-0014: Multi-Release JAR Trimming, Vertical Shading, and Cross-Tier Reachability

## Status

Open

## Date

2026-10-29

## Category

Bytecode Slicing & Multi-Release Optimization

## 1. Context & Current Boundary

Multi-Release JARs (MRJARs; [JEP 238](https://openjdk.org/jeps/238)) allow third-party libraries to bundle multiple class-file versions within a single archive: a base version compiled for a legacy baseline (typically Java 8 or Java 6) in the archive root, and specialized class overrides under `META-INF/versions/<N>/` (e.g., `META-INF/versions/9/`, `META-INF/versions/11/`, `META-INF/versions/17/`, `META-INF/versions/21/`).

Currently, `maven-dependency-elider` adopts a **conservative pass-through policy** for retained MRJAR dependencies:

1. **Candidate Exclusion**: [`MultiReleaseLibraryProjection.hasUnsupportedVersionedClasses`](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MultiReleaseLibraryProjection.java) detects versioned implementation classes. [`MavenDependencyTrimmer.buildPassThroughPlan`](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenDependencyTrimmer.java) removes the MRJAR from the candidate trim set and retains its original bytes byte-identically.
2. **Analysis-Only Library Projection**: For sibling resolution, [`MultiReleaseLibraryProjection.create`](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MultiReleaseLibraryProjection.java) extracts the effective classes for the executing runtime release into an ephemeral analysis JAR. The MRJAR's classes are then rooted to protect outgoing links to other trimmed dependencies.
3. **Core Engine Fail-Closed Invariants**:
   * [`ArchiveSnapshot.read`](../../elider-core/src/main/java/io/github/spockz/elider/trimmer/ArchiveSnapshot.java) explicitly refuses candidate MRJARs (`"Cannot safely resolve a multi-release candidate JAR"`).
   * [`ArchiveSanitizer.sanitize`](../../elider-core/src/main/java/io/github/spockz/elider/trimmer/ArchiveSanitizer.java) throws on any entry under `META-INF/versions/`.
   * [`OmittedCodeProof.readClasses`](../../elider-core/src/main/java/io/github/spockz/elider/model/OmittedCodeProof.java) throws `"Ambiguous duplicate class entry"` if a class exists in both base and versioned directories.

### The Problem

Pass-through prevents runtime classloading errors but leaves significant vulnerabilities and bloat in place:

* **Dormant CVE Gadgets Persist**: High-profile libraries (`log4j-core`, `netty-*`, `commons-compress`, `jackson-core`, `bouncycastle`) are MRJARs. If dormant, unreferenced classes in these libraries contain CVE gadgets (e.g., deserialization chains or obsolete protocol parsers), pass-through leaves them untouched in the packaged artifact, defeating elider's core value proposition.
* **Distribution Bloat**: Terminal distributions (Spring Boot fat JARs, shaded archives, Docker container images) bundle redundant bytecode for obsolete JVMs (e.g. Java 8 fallbacks) that will never be executed by the target runtime environment.

---

## 2. Core Architectural Dynamics

### 2.1 The Asymmetry: Application Target ($T$) vs. Dependency Tiers vs. Runtime JRE ($R$)

Let $T$ be the application's bytecode compilation target (e.g. `--release 17` or `maven.compiler.release = 17`), and $R$ be the executing JRE at runtime.

1. **Forward Runtime Compatibility ($R \ge T$)**:
   Java bytecode is forward-compatible. An application compiled for Java 17 will never run on Java 11 (the JVM immediately throws `UnsupportedClassVersionError: 61.0`), but it frequently runs on **higher JRE versions** (e.g., JRE 21 or JRE 25).
2. **Dependency Target $\neq$ Application Target**:
   Third-party dependencies maintain their own tier structure independently of the consuming application. A library often provides a Java 8 base and a `versions/9/` override, with **no `versions/17/` directory at all**.
3. **Descending Runtime Search**:
   Under JEP 238, when running on JRE 21, the JVM searches descending from 21 down to 9, and then base:
   $$21 \longrightarrow 20 \longrightarrow \dots \longrightarrow 17 \longrightarrow \dots \longrightarrow 9 \longrightarrow \text{Base (Root)}$$
   Therefore, if a library defines `StackLocator` in `versions/9/` and nothing higher, **JRE 21 loads the `versions/9/` implementation**. Whole-tier directories cannot be deleted simply because their version number is lower than $T$.

---

### 2.2 Vertical Shading (Baseline Elevation)

To eliminate obsolete bytecode without violating JEP 238 tooling constraints, we introduce **Vertical Shading (Baseline Elevation)**:

For an application targeting Java $T$:

1. **Determine the Effective Baseline**: For each active class $C$, determine its highest available version that is $\le T$:
   $$V_{\text{base}}(C) = \max \{ v \in S(C) \mid v \le T \}$$
   *(where $S(C)$ is the set of versions defining $C$, with base treated as $\le 8$)*.
2. **Elevate to Root**: Move the bytecode of $V_{\text{base}}(C)$ to the archive root (`C.class`), replacing the obsolete Java 8/6 bytecode.
3. **Excise Dead Lower Tiers**: Permanently purge all bytecodes of $C$ compiled for versions $< V_{\text{base}}(C)$.
4. **Remove Promoted Versioned Entry**: Remove `META-INF/versions/<V_base>/C.class` since it now resides in the root.
5. **Zero-Warning Spec Compliance**: Because $C$ is present in the root base layer, `jar --validate` detects a valid base entry for any higher override (e.g. in `versions/21/`), avoiding the `"contains a new public class not found in base entries"` advisory warning.

---

### 2.3 Upper-Tier ($> T$) Handling & Compiler Ceilings

When a dependency contains versioned classes or version-specific helpers for runtimes higher than the current compiler/build platform (e.g., `META-INF/versions/21/` when building on Java 17):

1. **Missing Platform APIs**: Classes in `versions/21/` may reference APIs introduced after Java 17 (Virtual Threads, `SequencedCollection`, Vector API). Linking these classes against a Java 17 platform pool triggers `UnresolvedReferenceException` under ProGuard Core.
2. **Absence of Runtime Telemetry**: Telemetry captured on Java 17 contains zero evidence of what executes on Java 21.
3. **Policy: Conservative Upper-Tier Pass-Through**:
   * If a class is active, its higher-tier override (`versions/21/Foo.class`) and all associated internal helpers (`versions/21/Helper21.class`) **pass through untouched**.
   * We do not attempt ProGuard closure analysis inside tiers $> T$; they are carried forward intact to guarantee forward execution safety on newer JREs.

---

### 2.4 Horizontal Trimming (Unreferenced Dead Code)

If an entire logical class $C$ is unreferenced anywhere in the application's link-closure roots:

* $C$ is pruned from **Base** AND from **every `META-INF/versions/*/` tier**.
* Pruning the class across all tiers leaves no orphaned versioned entry and completely eradicates dormant CVE gadgets across all potential runtime versions.

---

## 3. Comprehensive Multi-Release Trimming Rule Table

The following matrix governs trimming decisions for any class $C$ in a dependency MRJAR, assuming application compilation target $T = 17$ and runtime execution $R \ge 17$:

| Scenario for Class `Foo` | Original Layout in Dependency | Effective Baseline ($\le 17$) | Trimmed & Shaded Output Layout | Pruned Entries | Specification & Runtime Impact |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1. Dead Class** (Unreferenced by application) | Base (Java 8), `versions/9`, `versions/17`, `versions/21` | *None* | **Completely Omitted** | Pruned from all 4 locations | **100% Dead Code & CVE Eradication**. Safe under JEP 238. |
| **2. Active Class** (Base only) | Base (Java 8) | Java 8 | **Root**: Java 8 bytecode | *None* | Valid base class; runs on all JREs. |
| **3. Active Class** (Updated in 9 only) | Base (Java 8), `versions/9` | **Java 9** | **Root**: Java 9 bytecode (Elevated) | Base (Java 8), `versions/9` (Promoted) | **Zero warnings**. Obsolete Java 8 bytecode deleted; JRE $\ge 17$ loads Java 9 from root. |
| **4. Active Class** (Updated in 9 and 17) | Base (Java 8), `versions/9`, `versions/17` | **Java 17** | **Root**: Java 17 bytecode (Elevated) | Base (Java 8), `versions/9`, `versions/17` (Promoted) | **Zero warnings**. Java 8 and 9 deleted; JRE $\ge 17$ loads Java 17 from root. |
| **5. Active Class** (Updated in 9 and 21) | Base (Java 8), `versions/9`, `versions/21` | **Java 9** | **Root**: Java 9 bytecode (Elevated); **`versions/21/`**: Java 21 override (Pass-through) | Base (Java 8), `versions/9` (Promoted) | **Zero warnings**. JRE 17–20 loads root (Java 9); JRE 21+ loads `versions/21`. |
| **6. Active Class** (Updated in 9, 17, and 21) | Base (Java 8), `versions/9`, `versions/17`, `versions/21` | **Java 17** | **Root**: Java 17 bytecode (Elevated); **`versions/21/`**: Java 21 override (Pass-through) | Base (Java 8), `versions/9`, `versions/17` (Promoted) | **Zero warnings**. Java 8 and 9 deleted. JRE 17–20 loads root (Java 17); JRE 21+ loads `versions/21`. |
| **7. Version-Specific Helper** (Internal class in 21 only) | `versions/21/Helper21.class` | *None* | **`versions/21/`**: `Helper21.class` (Pass-through) | *None* | Exceeds compiler platform pool ceiling. Passed through verbatim to preserve forward-runtime execution. |

---

## 4. Research Questions & Implementation Tracks

### RQ-0014.1: ArchiveSanitizer Elevation and Filtering Protocol

How should `ArchiveSanitizer` in `elider-core` be refactored to support vertical elevation and multi-tier filtering?

* Support accepting an elevation map: `Map<String, String> sourceEntryToRoot` indicating which versioned entries must be written to root.
* Ensure manifest handling cleanses digest headers while retaining `Multi-Release: true` if and only if entries remain under `META-INF/versions/`. If all versioned entries were elevated or pruned, strip `Multi-Release: true` to produce a clean single-release archive.

### RQ-0014.2: OmittedCodeProof Multi-Tier Verification

How should `OmittedCodeProof` verify class omission across multiple version tiers?

* Fix `readClasses` to index classes by `(tier, className)` rather than throwing on duplicate logical names.
* To attest `vulnerable_code_not_present` for a CVE mapped to `com.foo.VulnerableGadget`, prove that `VulnerableGadget` is absent from the root base layer AND absent from all `META-INF/versions/*/` directories in the trimmed JAR.

### RQ-0014.3: CycloneDX 1.6 Pedigree Provenance Accounting

How should class metrics be reported for trimmed MRJARs?

* Distinguish physical ZIP class entries (`elider:totalZipEntries`, `elider:retainedZipEntries`) from unique logical binary classes (`elider:totalLogicalClasses`, `elider:retainedLogicalClasses`).
* Record `elider:mrjarStatus` with values `elevated_and_trimmed` or `passed_through`.

### RQ-0014.4: Cache Fingerprinting & Performance Fast Path

How does vertical shading affect the $<10\text{ ms}$ fast-path cache invariant ([RQ-0003](RQ-0003-sub-10ms-maven-fast-path-invariant-and-benchmarking.md))?

* Incorporate the target release ($T$) and MRJAR trimming strategy into `FingerprintSnapshot`.
* Reusing the analysis projection for candidate trimming ensures that multi-release analysis adds zero additional ProGuard traversal passes beyond standard single-release candidates.

---

## 5. Architectural Decision Record (ADR) Impact & Update Instructions

### Affected ADRs

* **[ADR-0003: ProGuard Core-Driven Intra-JAR Trimming and CycloneDX Pedigree](../adr/0003-proguard-core-intra-jar-trimming-and-cyclonedx-pedigree.md)**: Directly affected. ADR-0003 defines the intra-JAR trimming engine, archive sanitization, link closure completeness, and pedigree provenance. Its current invariants assume flat single-release archives and fail-closed behavior on `META-INF/versions/`.
* **[ADR-0002: In-Memory Artifact Mutation for Downstream Packaging Transparency](../adr/0002-in-memory-artifact-mutation-for-downstream-packaging-transparency.md)**: Contextually resolved. ADR-0002 explicitly identified multi-release entries as an open transformation requirement deferred to RQ-0001; ADR-0003 updates resolve that limitation.

### Detailed Instructions to Update ADR-0003

When the implementation prototype and test verification for RQ-0014 are accepted, apply the following updates to **ADR-0003**:

1. **Update Section 3 (`Archive Sanitization & Signature Stripping`)**:
   * Add a subsection for **Multi-Release Archive Sanitization and Vertical Shading**:
     * For any retained candidate containing `META-INF/versions/`:
       * Calculate the effective base version $V_{\text{base}} = \max \{ v \in S(C) \mid v \le T \}$.
       * Elevate $V_{\text{base}}$ to the archive root (`C.class`), replacing obsolete lower-version bytecode.
       * Strip all entry bytecodes where $v < V_{\text{base}}$.
       * Pass through active higher-tier overrides ($v > T$) and higher-tier internal helper classes verbatim under `META-INF/versions/<v>/`.
       * Retain `Multi-Release: true` in `META-INF/MANIFEST.MF` if and only if entries remain under `META-INF/versions/`; otherwise remove it to emit a standard single-release archive.
2. **Update Section 5 (`CycloneDX 1.6 Pedigree Provenance`)**:
   * Update the structured component properties definition to distinguish physical vs. logical class counts:
     * `elider:mrjarStatus`: `elevated_and_trimmed` vs `passed_through`.
     * `elider:retainedClasses` and `elider:totalClasses` based on unique logical classes, with optional `elider:retainedZipEntries` and `elider:totalZipEntries` for physical archive tracking.
3. **Update Section 6 (`Invariants`)**:
   * Add **JEP 238 Multi-Release Structural Integrity**: Output trimmed multi-release archives must pass `jar --validate` without missing-base warnings by ensuring every surviving higher-tier public override has its baseline equivalent elevated to root.
   * Add **Upper-Tier Forward-Execution Preservation**: Tiers exceeding the platform compiler ceiling ($v > T$) must not be pruned via incomplete link closure; their overrides and internal helpers must pass through to guarantee execution safety when running on newer JREs.
4. **Update Section 7 (`Consequences`)**:
   * Document that dormant CVE gadgets in multi-release libraries (such as `log4j-core`, `netty-*`, `commons-compress`) are physically omitted from distributions without regressing runtime compatibility on newer JREs.
