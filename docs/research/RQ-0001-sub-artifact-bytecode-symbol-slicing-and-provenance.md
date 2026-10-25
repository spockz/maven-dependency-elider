<!-- WHY: Investigates sub-artifact bytecode symbol slicing, constant-pool link closure, signature handling for signed JARs, and recording provenance across audit POMs, CycloneDX 1.6 SBOMs, and evidence-backed OpenVEX. -->
# RQ-0001: Sub-Artifact Bytecode Symbol Slicing and Multi-Tier Provenance

* **Status**: Open
* **Category**: Bytecode Slicing & Provenance Metadata
* **Date**: 2026-10-24
* **Last Updated**: 2026-10-24

Abbreviations: Architecture Decision Record (ADR), Abstract Syntax Tree (AST), Bytecode Manipulation (ASM), Common Vulnerabilities and Exposures (CVE), Software Bill of Materials (SBOM), Vulnerability Exploitability eXchange (VEX), Project Object Model (POM), Secure Hash Algorithm (SHA).

---

## 1. Context & Research Questions

When an application uses only a small fraction of classes in a large library (e.g., 10 classes out of 200 in `commons-compress` or `netty`), stripping unused `.class` files eliminates vulnerable classes (such as deserialization gadgets or obsolete protocol parsers) that would otherwise trigger false-positive CVE alerts.

However, slicing a third-party JAR introduces three unresolved challenges:

1. **Link Closure**: Retaining only project-referenced classes can break internal references within the JAR, causing `NoClassDefFoundError` or `VerifyError` at runtime.
2. **Signature Invalidation**: Slicing an artifact modifies its byte stream and invalidates any cryptographic signatures (`META-INF/*.SF`, `*.RSA`).
3. **Provenance & Hash Mismatch**: A sliced JAR's SHA-256 no longer matches the official Maven Central release. Without explicit metadata, downstream consumers and scanners may reject the artifact as corrupt or misattribute findings.

### Primary Research Questions

* **RQ-0001.1**: How can ASM-based link closure be computed efficiently to guarantee intra-JAR constant-pool and type closure?
* **RQ-0001.2**: What is the safest policy for signed JARs (e.g., skip slicing by default vs. strip signatures following `maven-shade-plugin` conventions)?
* **RQ-0001.3**: How should sliced artifacts be represented across:
  * The **Effective / Consumer POM** (Maven 3 flattened POM vs. Maven 4 Consumer POM)?
  * **CycloneDX 1.6 SBOMs** using schema-valid `pedigree` and `properties` data?
  * **OpenVEX and CycloneDX VEX** documents using vulnerability-to-product evidence and valid status justifications?

---

## 2. Capability Inventory & Options Analysis

### 2.1 Sub-Artifact Slicing & Link Closure

* **Approach A: Static ASM Call-Graph Closure**:
  Starting from the set of classes $R_{\text{used}}$ referenced by the application in artifact $A$, parse the bytecode of each $c \in R_{\text{used}}$ to identify referenced types $t \in A$. Add $t$ to $R_{\text{used}}$ recursively until fixed-point closure is achieved.
* **Approach B: Shade Plugin Filter Delegation**:
  Translate runtime traces and closure sets into `<filter>` definitions for `maven-shade-plugin`.

### 2.2 Provenance Models Across Standards

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

1. Implement intra-JAR ASM link closure analyzer on test fixture libraries (`commons-codec`, `commons-compress`).
2. Test JVM verification on sliced JARs with and without link closure under Java 21 to confirm zero `VerifyError` or `NoClassDefFoundError`.
3. Ingest generated CycloneDX SBOM into Dependency-Track and Grype to verify that `pedigree` and new SHA-256 digests are accepted without warnings.

---

## 4. Next Steps & Decision Checkpoints

* [ ] Checkpoint 1: Finalize link closure traversal algorithm and benchmark cold-path overhead.
* [ ] Checkpoint 2: Validate CycloneDX `pedigree` acceptance with Trivy and Grype.
* [ ] Checkpoint 3: Propose draft ADR on sub-artifact symbol slicing once Step 1 (whole-dependency elision) is fully implemented.
