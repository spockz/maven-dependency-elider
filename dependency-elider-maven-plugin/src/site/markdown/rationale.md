<!-- WHY: Explains the empirical and architectural rationale for the Maven Dependency Elider project based on research into SCA granularity mismatch and the vulnerability reduction funnel. -->
# Project Rationale: The Granularity Impedance Mismatch in Dependency Security

The primary motivation behind `maven-dependency-elider` is the realization that traditional Software Composition Analysis (SCA) suffers from a fundamental impedance mismatch between how security vulnerabilities are catalogued, how build systems resolve dependencies, and how the Java Virtual Machine executes bytecode.

Empirical research across academia and industry demonstrates that **on average, only 1% to 3% of reported Common Vulnerabilities and Exposures (CVEs) represent genuine, exploitable risks** in a given production application. Yet, developers spend countless hours triaging false positives, maintaining fragile XML `<exclusion>` rules, and fighting compliance alarms.

---

## 1. The Core Problem: Multi-Level Granularity Impedance Mismatch

Modern Java dependency security operates across four mismatched levels of abstraction:

1. **Product-Level CPE Over-Matching (The "Netty" Problem)**:
   The National Vulnerability Database (NVD) historically catalogues vulnerabilities using coarse Common Platform Enumeration (CPE) strings (e.g., `cpe:2.3:a:netty:netty`). Security scanners matching these strings flag *every* `io.netty:netty-*` sub-module on the classpath, even when the underlying flaw exists solely in `netty-codec-http2` and the application only depends on `netty-buffer`.
2. **Artifact-Level Coordinate Coarseness**:
   Apache Maven resolves, compiles, and packages dependencies strictly at the `groupId:artifactId` boundary. A single vulnerable, uncalled utility class inside a large multi-megabyte JAR marks the entire artifact as vulnerable in downstream reports.
3. **Compound Exploitability & Gadget Chains**:
   Many high-severity CVEs (such as FasterXML Jackson polymorphic deserialization) require compound co-occurrence: a carrier library, a secondary gadget artifact (e.g. specific Spring or Commons Collections classes), and an active vulnerable configuration. Absent any of these elements, the flaw is unexploitable.
4. **Class & Method Execution Reality**:
   The JVM loads individual `.class` files dynamically. Whole transitive JARs—and vast portions of directly imported libraries—remain completely quiescent during runtime execution.

---

## 2. The Vulnerability Reality: The 1%–3% Exploitability Funnel

Extensive empirical research from academic institutions (KTH CASTOR, SAP Security Research) and industrial security telemetry (Snyk, Sonatype, Endor Labs, CISA) reveals that software bloat and coarse matching account for up to 99% of all reported dependency vulnerabilities:

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
| **Stage 2: CPE Disambiguation** | **45%–65% remaining** | Ponta et al. (SAP Research / ICSME 2018) proved that 88.8% of findings for code-covered CVEs were false positives driven by coarse CPE matching. Dann et al. (ICSE-SEIP 2021) identified package identity mapping as the primary bottleneck in SCA accuracy. |
| **Stage 3: Unused Dependency Pruning** | **20%–35% remaining** | Soto-Valero et al. (KTH / EMSE 2021) analyzed 9,639 Maven Central artifacts (723,444 dependency relationships) and proved that 57% of transitive dependencies and 75.1% of all dependency relationships in Maven are completely bloated (zero classes loaded). Soto-Valero et al. (ESEC/FSE 2021) showed that 89.2% of bloated dependencies remain bloated across subsequent releases. |
| **Stage 4: Function Reachability** | **3%–8% remaining** | Snyk Enterprise Telemetry and Endor Labs benchmarked that function-level reachability cuts 92%–95% of package-level alerts. Sonatype State of the Software Supply Chain documented that only ~11% of vulnerable library downloads have reachable execution paths. |
| **Stage 5: Compound Context** | **1%–3% remaining** | FIRST.org EPSS and CISA KEV confirm that < 0.5% of CVEs are actively exploited in the wild, with only 2%–5% having realistic exploit probability. USENIX Security 2022 (Cao et al.) confirmed that over half of statically reachable gadget chains fail at runtime due to missing secondary companion libraries or dormant configurations. |

---

## 3. Why Build-Time Maven Elision Beats Downstream Administrative Suppression

When organizations attempt to manage vulnerability noise downstream using Vulnerability Exploitability eXchange (VEX) documents or scanner-specific suppression XML files:

* **Asymmetric Scanner Support**: Open-source scanners like Trivy and Grype natively ingest VEX, but commercial enterprise scanners and older tools (e.g. legacy OWASP Dependency-Check) ignore inbound VEX files or treat them purely as manual export formats.
* **Persistent Compliance Overhead**: Even with VEX, compliance teams must periodically review and defend hundreds of open alerts.
* **Residual Attack Surface**: Dormant code left on the disk or inside a container image remains susceptible to future zero-day discoveries or gadget chain re-purposing.

### The Elider Approach: Physical Removal at Build Time

`maven-dependency-elider` solves the problem upstream within the Maven lifecycle:

1. **Grounded Runtime Telemetry**: Ingests verifiable JVM execution evidence (HotSpot `-Xlog:class+load`, CDS dumps, JFR recordings, GraalVM reflection configuration, and JaCoCo coverage).
2. **Whole-Artifact Dynamic Pruning**: Safely mutates Maven's in-memory artifact views at the `INITIALIZE` phase, stripping unobserved transitive JARs before downstream packaging (Shade, Spring Boot repackaging) or SBOM generation occurs.
3. **Sub-Artifact Bytecode Slicing**: For retained dependencies, intra-JAR symbol slicing removes unreferenced classes while strictly preserving constant-pool link closure and stripping invalidated JAR signatures.
4. **Transparent Packaging & Clean Scans**: Downstream packaging plugins, scanners, and CycloneDX SBOM generators see only the reduced, actively needed dependency graph. Vulnerabilities in elided code are physically absent from the shipped artifact, eliminating false positives at the root.

---

## 4. References & Academic Citations

* **[1]** Ponta, S. E., Plate, H., & Sabetta, A. (SAP Security Research / Eclipse Steady), *"Beyond Metadata: Code-Centric and Usage-Based Analysis of Known Vulnerabilities in Open-Source Software,"* 2018 IEEE International Conference on Software Maintenance and Evolution (ICSME), pp. 449–460: [arXiv:1806.05893](https://arxiv.org/abs/1806.05893).
* **[2]** Dann, A., Plate, H., Hermann, B., Serena, P. E., & Bodden, E., *"Identifying Challenges in Software Composition Analysis: An Industrial Perspective,"* 2021 IEEE/ACM International Conference on Software Engineering: Software Engineering in Practice (ICSE-SEIP): [arXiv:2103.05436](https://arxiv.org/abs/2103.05436).
* **[3]** Soto-Valero, C., Harrand, N., Monperrus, M., & Baudry, B. (KTH Royal Institute of Technology, CASTOR Group), *"A Comprehensive Study of Bloated Dependencies in the Maven Ecosystem,"* Empirical Software Engineering (EMSE), Vol. 26, No. 3, 2021: [arXiv:2001.07808](https://arxiv.org/abs/2001.07808).
* **[4]** Soto-Valero, C., Durieux, T., & Monperrus, M., *"A Longitudinal Analysis of Bloated Dependencies in Java Applications,"* 2021 29th ACM Joint European Software Engineering Conference and Symposium on the Foundations of Software Engineering (ESEC/FSE): [arXiv:2105.10186](https://arxiv.org/abs/2105.10186).
* **[5]** Cao, Y., et al., *"Towards Automated and Precise Java Deserialization Gadget Chain Mining,"* 31st USENIX Security Symposium (USENIX Security 22), pp. 1319–1336: [USENIX Security 2022](https://www.usenix.org/conference/usenixsecurity22/presentation/cao).
* **[6]** Jacobs, J., Romanosky, S., Edwards, B., & Adjerid, I., *"Exploit Prediction Scoring System (EPSS),"* ACM Digital Threats: Research and Practice, Vol. 2, No. 3, 2021: [doi:10.1145/3436242](https://doi.org/10.1145/3436242).
