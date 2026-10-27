<!-- WHY: Evaluates non-intrusive lifecycle hooks and enrichment bridges to carry elider liveness, class-trimming pedigree, and VEX evidence into user-configured third-party SBOM plugins (e.g., cyclonedx-maven-plugin). -->
# RQ-0010: Third-Party SBOM Plugin Integration and In-Flight Liveness Enrichment

* **Status**: Open
* **Category**: SBOM & Lifecycle Integration
* **Date**: 2026-10-27
* **Related Research Questions**:
  * [RQ-0001: Sub-Artifact Bytecode Symbol Slicing and Multi-Tier Provenance](RQ-0001-sub-artifact-bytecode-symbol-slicing-and-provenance.md)
  * [RQ-0006: Maven Artifact-View Consistency and Early Resolution Hooks](RQ-0006-maven-artifact-view-consistency-and-early-resolution-hooks.md)
  * [RQ-0008: OSV SBOM Comparison and VEX Evidence](RQ-0008-osv-sbom-comparison-and-vex-evidence.md)
* **Related Architecture Decisions**:
  * [ADR-0002: In-Memory Artifact Mutation for Downstream Packaging Transparency](../adr/0002-in-memory-artifact-mutation-for-downstream-packaging-transparency.md)
  * [ADR-0003: ProGuard Core-Driven Intra-JAR Trimming and CycloneDX Pedigree](../adr/0003-proguard-core-intra-jar-trimming-and-cyclonedx-pedigree.md)

Abbreviations: Abstract Syntax Tree (AST), Build Extension (BE), Common Vulnerabilities and Exposures (CVE), Core Extension (CE), Execution Listener (EL), Project Object Model (POM), Software Bill of Materials (SBOM), Software Composition Analysis (SCA), Vulnerability Exploitability eXchange (VEX).

---

## 1. Context & Research Problem

The current implementation of `dependency-elider` provides a standalone SBOM generator (`CycloneDxSbomGenerator`) executed during `ElideMojo` that outputs `target/dependency-elider-sbom.cdx.json`. While this produces an authoritative, post-elision CycloneDX 1.6 document with pedigree diffs, enterprise repositories typically already declare and configure an official SBOM plugin in their `pom.xml`, such as:

* `org.cyclonedx:cyclonedx-maven-plugin` (with goals `makeBom`, `makeAggregateBom`, or `makePackageBom`, customized with specific schema versions, XML/JSON formats, license policies, organization metadata, and output destinations).
* `org.spdx:spdx-maven-plugin`.

If an engineer configures `cyclonedx-maven-plugin` to run during the `package` or `verify` phase:

1. **Whole-Artifact Elision is Automatically Reflected**: Because `dependency-elider` mutates `project.setArtifacts(...)` ([ADR-0002](../adr/0002-in-memory-artifact-mutation-for-downstream-packaging-transparency.md)) and decorates `ProjectDependenciesResolver` ([WP-RESOLVE-01](../handovers/2026-10-27-wp-resolve-01-maven-lifecycle-and-graph-consistency.md)), downstream SBOM plugins querying `DependencyGraphBuilder` or `project.getArtifacts()` naturally omit wholly elided JARs.
2. **Cryptographic Hashes Reflect Trimmed JARs**: Because `artifact.setFile(trimmedJar)` replaces the archive on disk, third-party SBOM plugins automatically hash the trimmed archive, accurately reporting the actual deployed artifact's SHA-256 hash.
3. **The Liveness & VEX Gap**: Standard third-party SBOM plugins have no awareness of class-level reachability, pruned symbols, intra-JAR pedigree ancestors, or VEX justifications. Consequently, they generate a standard inventory lacking:
   * `pedigree.ancestors` linking the trimmed component to the original upstream Maven coordinate and original SHA-256 digest.
   * `component.properties` or `evidence` describing surviving vs. pruned class metrics.
   * `vulnerabilities[]` (CycloneDX VEX) or standalone OpenVEX asserting `vulnerable_code_not_present` when verified symbol purging neutralizes a CVE.

Forcing users to disable their existing SBOM plugin or duplicate configuration into `dependency-elider-maven-plugin` violates the product goal of seamless lifecycle integration. We must evaluate whether a non-intrusive hook can carry over elider liveness analysis and pedigree into the user's configured SBOM plugin without disrupting its lifecycle phase or configuration.

---

## 2. Primary Research Questions

* **RQ-0010.1**: Which Maven lifecycle hook or extension mechanism allows detecting when a third-party SBOM plugin completes execution without altering the user's `pom.xml` plugin bindings?
* **RQ-0010.2**: Can a post-execution listener (`ExecutionListener.mojoSucceeded` or `EventSpy`) intercept the third-party SBOM output file, parse it, and enrich it in-place with liveness metrics, pedigree ancestors, and VEX statements?
* **RQ-0010.3**: What state-transfer mechanism (e.g., `MavenProject.setContextValue`, Maven Session user properties, or filesystem staging in `target/dependency-elider-class-usage.json`) is most resilient across multi-module reactor builds?
* **RQ-0010.4**: Can embedding metadata directly inside the trimmed JAR (e.g., `META-INF/elider/liveness.json` or `META-INF/sbom/component.cdx.json`) enable third-party plugins and container packagers (Spring Boot, Quarkus) to discover trim provenance automatically?
* **RQ-0010.5**: What failure and offline policy should apply if the user-configured SBOM plugin uses an unsupported format (e.g., SPDX instead of CycloneDX) or schema version?

---

## 3. Evaluated Hook & Integration Mechanisms

### Mechanism A: Maven Lifecycle Interceptor (`ExecutionListener` / `EventSpy`)

Maven core provides `org.apache.maven.execution.ExecutionListener` and `org.apache.maven.eventspy.EventSpy`.

* **Operation**:
  * During build initialization (`ElideMojo` or a Maven Core/Build Extension), the elider registers a decorating `ExecutionListener` on `MavenSession.getRequest().getExecutionListener()`.
  * The listener monitors `ExecutionEvent.Type.MojoSucceeded`.
  * When `event.getMojoExecution().getPlugin().getArtifactId()` matches `cyclonedx-maven-plugin` (or configured SBOM plugins):
    1. The listener inspects the Mojo's configured output directory and filename (or default `target/bom.json` / `target/bom.xml`).
    2. It reads the newly generated SBOM file.
    3. It enriches each trimmed component with its `pedigree.ancestors` (upstream coordinate + original SHA-256) and liveness properties.
    4. If evidence-backed VEX is enabled, it appends verified `vulnerabilities[]` records asserting `not_affected` / `vulnerable_code_not_present`.
    5. It writes the enriched SBOM back to disk before downstream packaging or publishing goals execute.
* **Trade-offs**:
  * *Pros*: Completely non-intrusive. The user configures `cyclonedx-maven-plugin` with their own flags, schema version, license filters, and goals. No duplicate configuration needed.
  * *Cons*: Requires JSON/XML mutation of third-party output files. Must handle schema variations gracefully.

### Mechanism B: Pre-Generation Dependency Graph & Session State Injection

* **Operation**:
  * `ElideMojo` runs in `INITIALIZE` or `PROCESS_CLASSES` and performs static liveness analysis and JAR trimming.
  * `WP-RESOLVE-01` decorates `ProjectDependenciesResolver` and `project.setArtifacts(...)`.
  * When `cyclonedx-maven-plugin` executes `DependencyGraphBuilder.buildDependencyGraph(buildingRequest)`:
    * The SBOM plugin sees only the surviving direct and transitive dependencies.
    * The physical files referenced by `artifact.getFile()` point to the trimmed JARs in `target/elided-jars/`.
  * *Enrichment Bridge*: The elider stores `ArtifactTrimRecord` and `ClassUsageReport` into `MavenProject.setContextValue("io.github.spockz.elider.provenance", trimContext)`.
* **Trade-offs**:
  * *Pros*: Already partially proven by ADR-0002 and WP-RESOLVE-01. Guarantees inventory reduction in third-party SBOMs with zero extra code.
  * *Cons*: Third-party plugins ignore `MavenProject.getContextValue()` unless specifically patched; does not inject `pedigree` or `VEX` into their output without Mechanism A.

### Mechanism C: In-Archive Embedded Pedigree (`META-INF/` Carrier)

* **Operation**:
  * When `DependencyJarTrimmer` writes a trimmed JAR, it writes an embedded manifest or CycloneDX component fragment inside the archive:
    * `META-INF/elider/liveness.json`
    * `META-INF/sbom/component.cdx.json` (recording `pedigree.ancestors` and pruned classes).
  * Frameworks like Spring Boot 3.3+ and Quarkus, or container scanners (Syft, Trivy), automatically inspect archive `META-INF/sbom/` directories to assemble composite application SBOMs.
* **Trade-offs**:
  * *Pros*: Self-contained within the artifact file. Survives across builds, local repository caches, and standalone container packaging.
  * *Cons*: Standard `cyclonedx-maven-plugin` does not unpack dependency JARs to merge embedded component SBOMs during `makeBom` (it only analyzes POM metadata and file hashes).

---

## 4. Architectural Synthesis & Proposed Strategy

To achieve transparent, zero-friction SBOM integration without interfering with user plugin lifecycles, a **two-tier bridge** is recommended:

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        Maven Build Lifecycle                           │
├────────────────────────────────────────────────────────────────────────┤
│ 1. Phase: INITIALIZE / PROCESS_CLASSES                                 │
│    dependency-elider:elide                                             │
│    ├── Liveness & Reachability Analysis                                │
│    ├── Whole-Artifact Pruning (ProjectDependenciesResolver / ADR-0002)│
│    ├── Intra-JAR Trimming & Local Hash Computation (ADR-0003)          │
│    └── Staging: target/dependency-elider-class-usage.json              │
│                                                                        │
│ 2. Phase: PACKAGE / VERIFY (User-Configured Plugin)                   │
│    cyclonedx-maven-plugin:makeBom                                      │
│    ├── Queries ProjectDependenciesResolver -> sees pruned graph        │
│    ├── Hashes trimmed JARs on disk -> accurate physical SHA-256        │
│    └── Writes target/bom.json (user's schema, licenses, formatting)   │
│                                                                        │
│ 3. Phase: POST-EXECUTION HOOK (ExecutionListener.mojoSucceeded)        │
│    EliderExecutionListener                                             │
│    ├── Intercepts cyclonedx-maven-plugin completion                    │
│    ├── Ingests target/bom.json + target/dependency-elider-*.json       │
│    ├── Injects pedigree.ancestors (upstream SHA-256)                   │
│    ├── Injects VEX not_affected / vulnerable_code_not_present          │
│    └── Rewrites target/bom.json in-place                               │
└────────────────────────────────────────────────────────────────────────┘
```

1. **Tier 1 (Passive Baseline via WP-RESOLVE-01)**: `ProjectDependenciesResolver` decoration ensures any third-party SBOM plugin automatically inherits whole-artifact elision and accurate physical hashes of trimmed JARs.
2. **Tier 2 (In-Flight Post-Mojo Enrichment Hook)**: An `ExecutionListener` hook intercepts `cyclonedx-maven-plugin` completion, non-intrusively enriching the generated document with `pedigree` and evidence-backed VEX.
3. **Fallback Standalone Mode**: If no third-party SBOM plugin is configured in the POM, `dependency-elider-maven-plugin` falls back to its standalone `CycloneDxSbomGenerator` to ensure users always receive an SBOM.

---

## 5. Next Steps

1. Prototype `EliderExecutionListener` in `dependency-elider-maven-plugin` to verify event capture on `cyclonedx-maven-plugin:makeBom`.
2. Test in-place enrichment of `target/bom.json` without invalidating CycloneDX 1.6 schema conformance.
3. Integrate this bridge as an optional track within `WP-VEX-01` (Track 4 / Track 5).
