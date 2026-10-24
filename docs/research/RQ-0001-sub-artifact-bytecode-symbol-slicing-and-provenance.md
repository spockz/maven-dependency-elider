<!-- WHY: Investigates sub-artifact bytecode symbol slicing, constant-pool link closure, signature handling for signed JARs, and recording provenance across Effective POMs, CycloneDX 1.5+ SBOMs, and OpenVEX. -->
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
  * **CycloneDX 1.5+ SBOMs** using the standard `pedigree` and `properties` schemas?
  * **OpenVEX and CycloneDX VEX** documents using `status: not_affected` and `justification: code_not_present`?

---

## 2. Capability Inventory & Options Analysis

### 2.1 Sub-Artifact Slicing & Link Closure

* **Approach A: Static ASM Call-Graph Closure**:
  Starting from the set of classes $R_{\text{used}}$ referenced by the application in artifact $A$, parse the bytecode of each $c \in R_{\text{used}}$ to identify referenced types $t \in A$. Add $t$ to $R_{\text{used}}$ recursively until fixed-point closure is achieved.
* **Approach B: Shade Plugin Filter Delegation**:
  Translate runtime traces and closure sets into `<filter>` definitions for `maven-shade-plugin`.

### 2.2 Provenance Models Across Standards

#### 1. Effective / Consumer POM

* **Maven 4**: Hook into `ConsumerModelSource` to emit an updated consumer POM. Sliced dependencies can be tagged or carry a `<classifier>elided</classifier>`.
* **Maven 3**: Write `target/effective-pom-elided.xml` with dependencies updated and attach or set as the project POM file.

#### 2. CycloneDX 1.5+ SBOM

CycloneDX provides first-class support for modified components via `pedigree`:

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
        "group": "org.apache.commons",
        "name": "commons-compress",
        "version": "1.21",
        "hashes": [{ "alg": "SHA-256", "content": "<central-sha256>" }]
      }
    ],
    "patches": [
      {
        "type": "unofficial",
        "description": "Elided unreferenced classes via maven-dependency-elider link closure"
      }
    ]
  },
  "properties": [
    { "name": "elider:status", "value": "sliced" },
    { "name": "elider:retainedClasses", "value": "12" }
  ]
}
```

#### 3. OpenVEX

```json
{
  "status": "not_affected",
  "justification": "code_not_present",
  "impact_statement": "The vulnerable class was omitted during bytecode symbol slicing."
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
