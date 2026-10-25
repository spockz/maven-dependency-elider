<!-- WHY: Investigates sub-artifact bytecode symbol slicing, constant-pool link closure, signature handling for signed JARs, and recording provenance across audit POMs, CycloneDX 1.6 SBOMs, and evidence-backed OpenVEX. -->
# RQ-0001: Sub-Artifact Bytecode Symbol Slicing and Multi-Tier Provenance

* **Status**: Deferred
* **Category**: Bytecode Slicing & Provenance Metadata
* **Date**: 2026-10-24
* **Last Updated**: 2026-10-25

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

---

## 2. Capability Inventory & Options Analysis

### 2.1 Sub-Artifact Slicing & Link Closure

This research remains deferred from the current product scope. Runtime observations map classes to owning dependency artifacts, and an observed class retains its entire JAR. The current implementation does not perform intra-JAR link-closure analysis, delete class entries, or rewrite methods, fields, or instructions. Reopen this work only through an explicit scope revision.

The remaining options below preserve the earlier research context; they are not active implementation instructions.

* **Approach A: Static ASM Call-Graph Closure**:
  Starting from the set of classes $R_{\text{used}}$ referenced by the application in artifact $A$, parse the bytecode of each $c \in R_{\text{used}}$ to identify referenced types $t \in A$. Add $t$ to $R_{\text{used}}$ recursively until fixed-point closure is achieved.
* **Approach B: Shade Plugin Filter Delegation**:
  Translate runtime traces and closure sets into `<filter>` definitions for `maven-shade-plugin`.
* **Approach C: Established Shrinker Integration**:
  Translate external oracle, source compilation, and framework/resource roots into an established engine's retention configuration. Compare this with custom closure work before selecting an engine. [ProGuard's shrinking contract](https://www.guardsquare.com/manual/configuration/usage) retains roots and their direct and indirect dependencies; its metadata controls also illustrate the compilation contract that must be preserved.

### 2.2 Source-Aware Trimming Requirements

Source compilation roots are also required for current whole-JAR elision. Their protection is an active correctness gap routed through RQ-0004's telemetry, pruning, Maven, and verification tracks, independently of this RQ's deferred intra-JAR/member-trimming scope. The user will define the next work package for that gap.

This proposal remains research, with no selected engine or active member-removal track. The initial experiment should preserve individual dependency JARs, disable renaming and aggressive optimization, and retain members conservatively when oracle coverage is incomplete.

| Concern | Required investigation and observable proof |
| :--- | :--- |
| Inlined constants | Resolve application sources against original dependencies before compilation erases field identity. Retain each referenced constant, its original value, declaring class, and required types; do not retain every constant indiscriminately. |
| Other erased references | Capture the full source compilation dependency set, including source-retained annotations and references in branches such as `if (false)`. Constant-access scanning alone is insufficient. |
| Compilation metadata | Preserve relevant `Signature`, `Exceptions`, `InnerClasses`, `EnclosingMethod`, annotations/type annotations, and enclosing types. Test client compilation, including records, sealed types, and generic nested types, rather than only JVM loading. |
| Generated sources and processors | Analyze the actual main/test sources with matching release/toolchain, module/class paths, processor paths/options, and compiler configuration. Investigate analysis after generation with original dependencies and avoid duplicate processor side effects. |
| Source prepass | Evaluate [JavacTask analysis separately from generation](https://docs.oracle.com/en/java/javase/21/docs/api/jdk.compiler/com/sun/source/util/JavacTask.html). This API does not itself solve Maven phase ordering or establish parity with other compilers and source languages. |
| Dependencies of retained code | Treat oracle entries as roots, not an exact copy list. Include supporting types/members, constructors, hierarchy, class initialization, and dependencies in other JARs. Compare established engine behavior before implementing custom closure. |
| Dynamic discovery | Add explicit or framework/resource-derived roots for reflection, service providers, Spring configuration, serialization, and native entry points. Source analysis does not establish arbitrary dynamic usage. |
| Resources and descriptors | Preserve, rewrite, or deliberately reject unsupported service/framework descriptors and referenced resources. Unknown formats must not be silently discarded. [Shade transformers](https://maven.apache.org/plugins/maven-shade-plugin/examples/resource-transformers.html) illustrate format-specific merging requirements if merging is later introduced. |
| Archive structure | Define handling for signatures and manifest digests, module descriptors, package sealing, multi-release layouts, and duplicate entries. Preserve boundaries initially; explicitly handle or reject unsupported inputs and retain required license/NOTICE resources. |
| Output identity | Keep originals immutable; record coordinates, original/output hashes, engine version, roots, configuration, and transformation result. Verify consumers receive the output associated with the decision. |
| Compile/runtime split | Compare a shared superset with separate outputs. A shared set retains compilation-only declarations; a split adds classpath, test, packaging, and publication policy. A companion JAR cannot merge additional fields into an existing class. |

### 2.3 Engine Selection and Distribution Terms

Compare engine capabilities separately from distribution terms. [ProGuard](https://github.com/Guardsquare/proguard/blob/master/LICENSE) uses GPL terms with a documented [integration exception](https://www.guardsquare.com/manual/license); [R8's license](https://r8.googlesource.com/r8/+/refs/heads/main/LICENSE) has BSD-style terms. Inspect the exact selected release and transitive components before deciding between embedding an engine and generating configuration for a separately invoked tool. Also verify ordinary JVM class-file output, supported Java constructs, diagnostics, and preservation of per-dependency boundaries; licensing alone does not establish technical suitability.

The project's Apache 2.0 license does not settle engine distribution obligations or the terms attached to transformed dependencies. Engine selection and integration mode need an explicit architecture decision before implementation.

### 2.4 Provenance Models Across Standards

#### 1. Effective / Consumer POM

* **Maven 4**: Investigate `ConsumerModelSource` only after dependency-resolution semantics are proven for the emitted model.
* **Maven 3**: Initially write `target/effective-pom-elided.xml` as an audit report. Removing direct dependency elements alone cannot stop a retained dependency from resolving an elided transitive again.
* Do not emit a consumer POM that names an `elided` classifier until the companion artifact is actually installed/deployed and consumer resolution is verified. An in-memory file pointer does not publish a new Maven coordinate.

#### 2. CycloneDX 1.6 SBOM

CycloneDX provides first-class support for modified components via `pedigree`. The following is a shape example only; emit it only when an actual slicing result provides the original/output files and hashes:

```json
{
  "type": "library",
  "group": "org.apache.commons",
  "name": "commons-compress",
  "version": "1.21",
  "hashes": [{ "alg": "SHA-256", "content": "<sha256-of-sliced-jar>" }],
  "pedigree": {
    "ancestors": [
      {
        "type": "library",
        "group": "org.apache.commons",
        "name": "commons-compress",
        "version": "1.21",
        "hashes": [{ "alg": "SHA-256", "content": "<central-sha256>" }]
      }
    ],
    "patches": [
      {
        "type": "unofficial"
      }
    ],
    "notes": "Elided unreferenced classes using maven-dependency-elider link closure."
  },
  "properties": [
    { "name": "elider:status", "value": "sliced" },
    { "name": "elider:retainedClasses", "value": "12" }
  ]
}
```

#### 3. OpenVEX

OpenVEX statements require an identified product and vulnerability plus issuer/document metadata. Do not infer a vulnerability assessment from an elision decision. The schema example below uses placeholders and is emitted only when a vulnerability-to-component mapping and evidence prove the stated outcome. For removed vulnerable code in a sliced component, the valid justification is `vulnerable_code_not_present`; `code_not_present` is not a valid label.

```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "urn:uuid:<document-id>",
  "author": "<issuer>",
  "timestamp": "<RFC-3339 timestamp>",
  "version": 1,
  "statements": [
    {
      "vulnerability": { "name": "<CVE-ID>" },
      "products": [{ "@id": "<product-purl>" }],
      "status": "not_affected",
      "justification": "vulnerable_code_not_present",
      "impact_statement": "The vulnerability-mapped code was omitted from the sliced component."
    }
  ]
}
```

---

## 3. Evidence & Experimental Plan

1. Compare an established shrinker adapter with custom class filtering on fixtures containing constants, erased references, generated sources, service providers, metadata, and cross-JAR dependencies. Keep class-entry filtering distinct from optional member-level shrinking.
2. Compile main and test clients, execute workloads, and inspect packages against the actual transformed dependencies. Assert both required contents and intended omissions, including negative fixtures that must fail when a necessary root is omitted.
3. Verify resources, archive structure, deterministic output, and original/output provenance. Test scanner behavior independently from vulnerability assessments; accepted SBOM pedigree and altered hashes do not imply suppression of a coordinate-based finding.

---

## 4. Next Steps & Decision Checkpoints

The slicing checkpoints below are deferred and inactive under the current whole-artifact retention scope. Reopen them only through an explicit scope revision.

* [ ] Checkpoint 1: Finalize link closure traversal algorithm and benchmark cold-path overhead.
* [ ] Checkpoint 2: Validate CycloneDX `pedigree` acceptance with Trivy and Grype.
* [ ] Checkpoint 3: Propose draft ADR on sub-artifact symbol slicing once Step 1 (whole-dependency elision) is fully implemented.
* [ ] Checkpoint 4: Resolve source-analysis ordering, compilation metadata preservation, and compile/runtime output policy before activating source-aware trimming.
* [ ] Checkpoint 5: Select an engine and integration mode with documented capability and license evaluation; compare [DepTrim](https://github.com/ASSERT-KTH/deptrim) and a distribution-only shrinker workflow.
* [ ] Checkpoint 6: Measure packaged size, cold/cached build cost, and configuration effort under RQ-0003, with per-class/member decision explanations matching actual transformations.
