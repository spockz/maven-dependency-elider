<!-- WHY: Investigates sub-artifact bytecode symbol slicing, constant-pool link closure, signature handling for signed JARs, and recording provenance across audit POMs, CycloneDX 1.6 SBOMs, and evidence-backed OpenVEX. -->
# RQ-0001: Sub-Artifact Bytecode Symbol Slicing and Multi-Tier Provenance

* **Status**: Open
* **Category**: Bytecode Slicing & Provenance Metadata
* **Date**: 2026-10-24
* **Last Updated**: 2026-10-30

Abbreviations: Architecture Decision Record (ADR), Abstract Syntax Tree (AST), Bytecode Manipulation (ASM), Common Vulnerabilities and Exposures (CVE), Software Bill of Materials (SBOM), Vulnerability Exploitability eXchange (VEX), Project Object Model (POM), Secure Hash Algorithm (SHA).

---

## 1. Context & Research Questions

When an application uses only a small fraction of a library, removing unnecessary classes can reduce distribution size and code exposed to execution. Vulnerability outcomes require separate evidence: coordinate-based scanners may still report the original component, and absence of a finding does not prove that a product is unaffected.

However, slicing a third-party JAR introduces three unresolved challenges:

1. **Link Closure**: Retaining only project-referenced classes can break internal references within the JAR, causing `NoClassDefFoundError` or `VerifyError` at runtime.
2. **Signature Invalidation**: Slicing an artifact modifies its byte stream and invalidates any cryptographic signatures (`META-INF/*.SF`, `*.RSA`).
3. **Provenance & Hash Mismatch**: A sliced JAR's SHA-256 no longer matches the official Maven Central release. Without explicit metadata, downstream consumers and scanners may reject the artifact as corrupt or misattribute findings.

### Primary Research Questions

* **RQ-0001.1**: Which established shrinker can compute required dependencies of retained code across JARs while preserving the compilation contract and separate output artifacts?
* **RQ-0001.2**: What is the safest policy for signed JARs (e.g., skip slicing by default vs. strip signatures following `maven-shade-plugin` conventions)?
* **RQ-0001.3**: How should sliced artifacts be represented across:
  * The **Effective / Consumer POM** (Maven 3 flattened POM vs. Maven 4 Consumer POM)?
  * **CycloneDX 1.6 SBOMs** using schema-valid `pedigree` and `properties` data?
  * **OpenVEX and CycloneDX VEX** documents using vulnerability-to-product evidence and valid status justifications?
* **RQ-0001.4**: What Kotlin/JVM metadata, source semantics, and unresolved optional-link cases must be modeled before the trimmer can claim equivalent reachability safety for Kotlin libraries and applications?

---

## 2. Capability Inventory & Options Analysis

### 2.1 Engine Evaluation: ProGuard Core vs. Google R8

We evaluated two premier established shrinking and bytecode analysis engines for per-dependency intra-JAR trimming:

| Dimension | `com.guardsquare:proguard-core:9.4.0` | `com.android.tools:r8` |
| :--- | :--- | :--- |
| **Licensing** | **Apache 2.0** (`proguard-core` is licensed under Apache 2.0; distinct from GPL `proguard-base`). Perfectly compatible with project's Apache 2.0 license. | **BSD 3-Clause** (Apache compatible). |
| **Distribution** | Hosted directly on **Maven Central**. | Hosted on Google Maven repository (`maven.google.com`), not on Central. |
| **Per-JAR Boundary Preservation** | **Native**: Class pool and visitor architecture operates seamlessly on individual dependency JARs (`ProgramClassPool` for target JAR, `LibraryClassPool` for classpath). | **Poor**: Monolithic whole-program AOT compiler designed to flatten and merge all inputs into a single output archive/directory. |
| **JVM Bytecode Target** | Native standard JVM class file reader/writer (Java 8–25+). | Primarily Android DEX compiler with secondary `--classfile` support. |
| **Reachability Analysis** | Explicit dependency and link-closure visitor graphs without forced bytecode optimizations. | Heavy optimizations and inlining by default. |

**Selected Engine**: **`com.guardsquare:proguard-core`** is selected as the primary engine for intra-JAR dependency trimming. It satisfies technical suitability, per-JAR boundary preservation, Maven Central availability, and strict Apache 2.0 license compatibility.

### 2.2 Source-Aware Trimming and Root Discovery Requirements

To guarantee application correctness and avoid breaking compilation or runtime execution, the root set $R$ for a dependency must combine:

1. **Positive Runtime Telemetry**: Classes loaded or executed in CDS (`-XX:DumpLoadedClassList`), ClassLoader logs (`-Xlog:class+load`), JFR (`jdk.ClassLoad`), and JaCoCo (`jacoco.exec`).
2. **Source Compilation Roots**: Direct type references in application sources, including:
   * Inlined primitive and String constants (`static final` fields) whose declaring classes must remain for client compilation.
   * Erased type bounds, generic type arguments, and thrown exceptions.
   * Compile-time (`RetentionPolicy.CLASS`) and runtime (`RUNTIME`) annotations.
3. **Dynamic Entry Points**: SPI providers declared in `META-INF/services/*`, reflection targets in GraalVM `reflect-config.json`, and Spring auto-configuration condition classes.
4. **Intra-JAR Link Closure**: For every class in $R$ belonging to dependency $J$, ProGuard Core's visitor graph resolves all referenced types, superclasses, interfaces, method descriptors, and field types internal to $J$, computing the transitive fixed-point closure.

### 2.3 Archive Integrity and Signature Policy

Modifying a signed JAR invalidates cryptographic signatures (`META-INF/*.SF`, `*.DSA`, `*.RSA`). Slicing a signed JAR without altering signature manifests causes `java.lang.SecurityException: SHA-256 digest error` during JVM class loading.

**Standard Policy (following `maven-shade-plugin`)**:

1. Strip signature block files (`META-INF/*.SF`, `META-INF/*.DSA`, `META-INF/*.RSA`, `META-INF/SIG-*`).
2. Purge individual section digest headers from `META-INF/MANIFEST.MF`.
3. Preserve all non-class resources (`META-INF/services/`, license and NOTICE files, properties).
4. Output the trimmed JAR to `target/elided-artifacts/<artifactId>-<version>-trimmed.jar`.

### 2.4 Provenance Models Across Standards

#### 1. Effective / Consumer POM

* In-place swapping via `artifact.setFile(trimmedJar)` is applied during the build for self-contained application packaging.
* For published libraries, the trimmed artifact is attached with `<classifier>trimmed</classifier>`.

#### 2. CycloneDX 1.6 SBOM

CycloneDX provides first-class support for modified components via `pedigree`. Sliced dependencies record their actual on-disk SHA-256 hash in `component.hashes`, and point to the upstream official Maven Central release in `pedigree.ancestors`:

```json
{
  "type": "library",
  "group": "org.apache.commons",
  "name": "commons-compress",
  "version": "1.21",
  "hashes": [{ "alg": "SHA-256", "content": "<sha256-of-trimmed-jar>" }],
  "pedigree": {
    "ancestors": [
      {
        "type": "library",
        "group": "org.apache.commons",
        "name": "commons-compress",
        "version": "1.21",
        "hashes": [{ "alg": "SHA-256", "content": "<original-central-sha256>" }]
      }
    ],
    "patches": [
      {
        "type": "unofficial",
        "description": "Trimmed unreferenced classes using ProGuard Core link closure"
      }
    ]
  },
  "properties": [
    { "name": "elider:status", "value": "trimmed" },
    { "name": "elider:retainedClasses", "value": "18" },
    { "name": "elider:totalClasses", "value": "160" }
  ]
}
```

#### 3. OpenVEX

The trimmer records class-removal provenance but has no CVE knowledge and does not generate VEX. A vulnerability/SBOM-aware scanner may emit an OpenVEX statement with `vulnerable_code_not_present` only when vulnerability data maps the CVE to omitted code with sufficient precision. A package/version finding or unused-artifact result alone does not establish that mapping:

```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "urn:uuid:<document-id>",
  "author": "io.github.spockz:dependency-elider-maven-plugin",
  "timestamp": "2026-10-25T16:00:00Z",
  "version": 1,
  "statements": [
    {
      "vulnerability": { "name": "<CVE-ID>" },
      "products": [{ "@id": "pkg:maven/org.apache.commons/commons-compress@1.21" }],
      "status": "not_affected",
      "justification": "vulnerable_code_not_present",
      "impact_statement": "The vulnerability-mapped class was omitted during intra-JAR link closure trimming."
    }
  ]
}
```

---

### 2.5 Kotlin/JVM Support Boundary

Kotlin support is partial. The user-facing [Kotlin support matrix](../faq.md#what-kotlin-features-are-supported) defines the current limits; this section records the remaining bytecode-analysis and source-analysis work for this research question.

| Kotlin input or feature | Current behavior | Gap before broader support |
| :--- | :--- | :--- |
| Kotlin-compiled library bytecode | Analyzed as ordinary JVM bytecode. Class references present in class-file structures and instructions participate in reachability. | Verify the stated boundary with compiler-produced fixtures across a declared Kotlin compiler/JDK matrix. |
| `kotlin.Metadata` on sibling library classes | Parsed and validated; metadata-bearing classes are reparsed per analysis context because ProGuard may mutate metadata. Metadata is not itself a reachability source. | Add metadata-aware reference traversal where Kotlin metadata contains class links absent from ordinary JVM references. |
| References encoded only in Kotlin metadata | Not followed for candidate or sibling-library closure. Candidate classes are read without Kotlin metadata initialization, and the reference visitor does not visit Kotlin metadata. | Initialize supported metadata on candidate classes and use ProGuard's Kotlin reference visitor, with context isolation and fail-closed behavior for unsupported or malformed metadata. |
| Application `.kt` and `.kts` sources | Not scanned. `elide.sourceRootsComplete=true` rejects Kotlin files; with the default `false`, compile-visible artifacts are retained conservatively. | Use Kotlin compiler semantic analysis to derive source roots and honor compiler version, classpath, plugins, source sets, and generated-source inputs before accepting source completeness. |
| Missing optional Kotlin/coroutine references | A reachable unresolved reference in a candidate being transformed fails closed. An unchanged owner can be retained with `trimSkipArtifacts`; MRJAR owners also have `mrjarStrategy=pass-through`. Resolved sibling links still contribute roots. | Define and test a narrow pass-through policy for owners with genuinely optional links. Do not globally ignore unresolved references, since that would hide required links. |
| Kotlin metadata in supplied platform classes | Unsupported; the internal platform snapshot rejects metadata-bearing classes. | Either add metadata-aware platform-pool support with isolation tests or retain an explicit unsupported boundary. |

Current evidence is narrow: `ArchiveSnapshotTemplateTest` uses a real Kotlin class resource to verify metadata parsing and per-context isolation, not metadata-only reachability. The Spring regression uses synthetic Java bytecode with an absent `kotlin.coroutines.Continuation`; it tests the fail-closed/pass-through policy, not Kotlin compiler output. Kotlin compiler and plugin-version combinations have not been independently verified.

Broader Kotlin support requires separate proof for three behaviors: (1) metadata-only links retain the referenced class and its transitive closure; (2) Kotlin source declarations retain the same compile-visible classes that Kotlin compilation requires; and (3) optional unresolved links preserve the owner safely without suppressing required references into sibling trim candidates. Tests must use compiler-produced `.class` files and real `.kt`/`.kts` sources, include positive and fail-closed cases, and record the compiler/plugin/JDK combinations actually exercised.

---

## 3. Evidence & Experimental Plan

1. Benchmark `com.guardsquare:proguard-core:9.4.0` class pool loading and reachability traversal latency across 50 dependency JARs.
2. Verify that trimming `commons-compress` in `example-basic-app` retains only required archive classes while preserving JVM class verification under Java 21+.
3. Ingest generated CycloneDX 1.6 SBOM into schema validators and downstream scanners to confirm valid `pedigree` ingestion.

---

## 4. Decision Checkpoints

* [x] **Checkpoint 1 (Engine Selection)**: Select `com.guardsquare:proguard-core:9.4.0` under Apache 2.0 license over Google R8 for per-JAR boundary preservation and Maven Central availability.
* [x] **Checkpoint 2 (Archive Sanitation)**: Adopt Shade signature-stripping conventions (`META-INF/*.SF`, `*.RSA`) and manifest digest cleansing.
* [x] **Checkpoint 3 (CycloneDX Provenance)**: Model trimmed artifact provenance via CycloneDX 1.6 `pedigree.ancestors` (Central SHA-256) and `pedigree.patches`.
* [ ] **Checkpoint 4 (Source-Root Protection)**: Implement source compilation reference scanner to protect compile-time dependencies.
* [ ] **Checkpoint 5 (Integration & Verification)**: Wire `DependencyJarTrimmer` into Maven plugin and verify on example fixtures.
