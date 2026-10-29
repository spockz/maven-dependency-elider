<!-- WHY: Explains the empirical and architectural rationale for the Maven Dependency Elider project based on research into SCA granularity mismatch and the vulnerability reduction funnel. -->
# Project Rationale: The Granularity Impedance Mismatch in Dependency Security

Traditional Software Composition Analysis (SCA) suffers from a fundamental impedance mismatch between how security vulnerabilities are catalogued, how build systems resolve dependencies, and how the Java Virtual Machine executes bytecode.

Empirical research confirms that **only 1% to 3% of reported Common Vulnerabilities and Exposures (CVEs) represent genuine, exploitable risks** in production Java applications. The remaining 97% to 99% generate alert fatigue, costly manual triage, and fragile `<exclusion>` lists.

---

## 1. The Core Problem: Multi-Level Granularity Mismatch

Modern Java dependency security breaks down across four mismatched abstraction layers:

1. **Product-Level CPE Over-Matching (The "Netty" Problem)**:
   Coarse Common Platform Enumeration (CPE) strings (e.g. `cpe:2.3:a:netty:netty`) cause scanners to flag *every* `io.netty:netty-*` module on the classpath, even when a vulnerability exists solely in `netty-codec-http2` and the application only imports `netty-buffer`.
2. **Artifact-Level Coordinate Coarseness**:
   Maven resolves and packages dependencies strictly at the `groupId:artifactId` boundary. A single dormant, uncalled utility class inside a multi-megabyte JAR marks the entire artifact as vulnerable.
3. **Compound Exploitability & Gadget Chains**:
   Severe vulnerabilities (such as Jackson polymorphic deserialization) typically require compound conditions: a carrier library, secondary gadget classes, and specific runtime configuration. Absent these prerequisites, the flaw cannot be exploited.
4. **Class & Method Execution Reality**:
   The JVM loads individual `.class` files on demand. Entire transitive JARs—and large portions of direct dependencies—remain completely unloaded during application execution.

---

## 2. The Vulnerability Reality: The 1%–3% Exploitability Funnel

Telemetry and academic studies (KTH CASTOR, SAP Security Research, Snyk, Endor Labs, CISA) reveal how software bloat and coarse matching inflate vulnerability findings:

```text
[Stage 1: Raw Baseline (100%)]
       │
       ▼  Eliminate broad CPE product collisions across modular frameworks (-35% to -55%)
[Stage 2: CPE Disambiguation (45%–65% remaining)]
       │
       ▼  Prune unobserved, completely bloated transitive dependencies (-57% of transitive edges)
[Stage 3: Unused Dependency Pruning (20%–35% remaining)]
       │
       ▼  Verify function and class-level call-graph reachability (-90% to -95%)
[Stage 4: Function & Class Reachability (3%–8% remaining)]
       │
       ▼  Evaluate compound conditions, dormant paths, and configuration flags (-50% to -70%)
[Stage 5: Compound & Runtime Context (1%–3% remaining)]
```

### Empirical Research Breakdown

| Stage | Finding / Metric | Empirical Evidence & Academic Source |
| :--- | :--- | :--- |
| **Stage 1: Raw Baseline** | **100%** | Starting corpus of all reported CVE alerts produced by manifest and CPE scanners. |
| **Stage 2: CPE Disambiguation** | **45%–65% remaining** | Ponta et al. (SAP Research / ICSME 2018) showed 88.8% of findings for code-covered CVEs were false positives driven by coarse CPE matching. Dann et al. (ICSE-SEIP 2021) identified package identity mapping as the primary bottleneck in SCA accuracy. |
| **Stage 3: Unused Dependency Pruning** | **20%–35% remaining** | Soto-Valero et al. (KTH / EMSE 2021) analyzed 9,639 Maven Central artifacts (723,444 dependency relationships) and proved that 57% of transitive dependencies and 75.1% of all dependency relationships in Maven are completely bloated (zero classes loaded). |
| **Stage 4: Function Reachability** | **3%–8% remaining** | Snyk Enterprise Telemetry and Endor Labs benchmarked that function-level reachability eliminates 92%–95% of package-level alerts. Sonatype documented that only ~11% of vulnerable library downloads have reachable execution paths. |
| **Stage 5: Compound Context** | **1%–3% remaining** | FIRST.org EPSS and CISA KEV confirm < 0.5% of CVEs are actively exploited in the wild, with only 2%–5% having realistic exploit probability. USENIX Security 2022 (Cao et al.) showed over half of statically reachable gadget chains fail at runtime due to missing companion libraries or inactive configurations. |

---

## 3. Build-Time Elision vs. Downstream Suppression

Organizations typically attempt to handle vulnerability noise through downstream suppression files or Vulnerability Exploitability eXchange (VEX) documents. Here is how build-time elision compares:

| Dimension | Downstream Suppression / VEX | Build-Time Elision (`maven-dependency-elider`) |
| :--- | :--- | :--- |
| **Scanner Compatibility** | Fragmented; many enterprise scanners ignore inbound VEX or suppression files. | Universal; vulnerable code is physically removed, so all scanners report clean. |
| **Maintenance Burden** | Ongoing; compliance teams must periodically review and defend hundreds of open alerts. | Zero recurring triage; dead dependencies are automatically dropped during the build. |
| **Attack Surface** | Residual code remains packaged in containers and JARs, susceptible to future gadget reuse. | Eliminated; dormant classes are stripped from the final shipped archive. |
| **Supply Chain Provenance** | Vulnerability metadata sits outside build artifacts in separate manifests. | Schema-valid CycloneDX 1.6 SBOM records original component digests and trimming pedigree. |

### The Elision Workflow

1. **Ground in Concrete Telemetry**: Ingest real JVM execution evidence (HotSpot `-Xlog:class+load`, CDS lists, JFR events, GraalVM reflection configs, JaCoCo execs).
2. **Whole-Artifact Pruning**: Mutate Maven's in-memory artifact views at `INITIALIZE` to drop unobserved transitive dependencies before packaging.
3. **Bytecode Trimming**: Use ProGuard Core link closure on retained JARs to strip unreferenced classes while preserving resources, licenses, and SPI descriptors.
4. **Transparent Downstream Packaging**: Standard packaging plugins (`maven-shade-plugin`, `spring-boot-maven-plugin`) and scanners consume the clean, minimized classpath without bespoke glue code.

---

## 4. References & Academic Citations

* **[1]** Ponta, S. E., Plate, H., & Sabetta, A. (SAP Security Research / Eclipse Steady), *"Beyond Metadata: Code-Centric and Usage-Based Analysis of Known Vulnerabilities in Open-Source Software,"* 2018 IEEE International Conference on Software Maintenance and Evolution (ICSME), pp. 449–460: [arXiv:1806.05893](https://arxiv.org/abs/1806.05893).
* **[2]** Dann, A., Plate, H., Hermann, B., Serena, P. E., & Bodden, E., *"Identifying Challenges in Software Composition Analysis: An Industrial Perspective,"* 2021 IEEE/ACM International Conference on Software Engineering: Software Engineering in Practice (ICSE-SEIP): [arXiv:2103.05436](https://arxiv.org/abs/2103.05436).
* **[3]** Soto-Valero, C., Harrand, N., Monperrus, M., & Baudry, B. (KTH Royal Institute of Technology, CASTOR Group), *"A Comprehensive Study of Bloated Dependencies in the Maven Ecosystem,"* Empirical Software Engineering (EMSE), Vol. 26, No. 3, 2021: [arXiv:2001.07808](https://arxiv.org/abs/2001.07808).
* **[4]** Soto-Valero, C., Durieux, T., & Monperrus, M., *"A Longitudinal Analysis of Bloated Dependencies in Java Applications,"* 2021 29th ACM Joint European Software Engineering Conference and Symposium on the Foundations of Software Engineering (ESEC/FSE): [arXiv:2105.10186](https://arxiv.org/abs/2105.10186).
* **[5]** Cao, Y., et al., *"Towards Automated and Precise Java Deserialization Gadget Chain Mining,"* 31st USENIX Security Symposium (USENIX Security 22), pp. 1319–1336: [USENIX Security 2022](https://www.usenix.org/conference/usenixsecurity22/presentation/cao).
* **[6]** Jacobs, J., Romanosky, S., Edwards, B., & Adjerid, I., *"Exploit Prediction Scoring System (EPSS),"* ACM Digital Threats: Research and Practice, Vol. 2, No. 3, 2021: [doi:10.1145/3436242](https://doi.org/10.1145/3436242).
