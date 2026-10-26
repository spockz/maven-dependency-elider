# Research Questions (RQs)

This directory tracks open investigations, capability comparisons, empirical benchmarks, and architectural explorations for the `maven-dependency-elider` project.

For user configuration and compatibility answers, see the [User FAQ](../faq.md). For implementation choices and engineering questions, see the [Contributor Decision Register and Engineering FAQ](../contributor-decisions-and-faq.md). Detailed unresolved investigations remain in the RQ documents below.

## Research Register

| RQ | Title | Date | Status | Category | Summary |
| :--- | :--- | :--- | :--- | :--- | :--- |
| [RQ-0001](RQ-0001-sub-artifact-bytecode-symbol-slicing-and-provenance.md) | Sub-Artifact Bytecode Symbol Slicing and Multi-Tier Provenance | 2026-10-24 | Open | Bytecode Slicing & Provenance Metadata | Evaluates ProGuard Core (Apache 2.0) for intra-JAR link closure, archive signature stripping, and provenance recording via CycloneDX 1.6 pedigree. |
| [RQ-0002](RQ-0002-runtime-sensor-fidelity-and-framework-autoconfiguration-quiescence.md) | Runtime Sensor Fidelity and Framework Auto-Configuration Quiescence | 2026-10-24 | Open | Runtime Telemetry & Framework Probing | Investigates the fidelity of runtime telemetry sources (ClassLoader logs, CDS, JFR, GraalVM, JaCoCo) and framework auto-configuration (@ConditionalOnClass probing vs. real execution). |
| [RQ-0003](RQ-0003-sub-10ms-maven-fast-path-invariant-and-benchmarking.md) | Sub-10ms Maven Fast-Path Invariant and Benchmarking Methodology | 2026-10-24 | Open | Performance & Benchmarking | Investigates cache correctness, the <10ms overhead target, total build cost, packaged size, configuration effort, and statistically defensible benchmarks. |
| [RQ-0004](RQ-0004-maven-dependency-elider-implementation-handover.md) | Maven Dependency Elider Engine and Plugin Implementation Handover | 2026-10-24 | Open | Implementation Handover & Engineering Specifications | Complete engineering handover, architectural invariants, track specifications, and multi-tier testing protocols for implementing the runtime telemetry-driven Maven Dependency Elider. |
| [RQ-0005](RQ-0005-spring-bean-request-evidence-and-autoconfiguration-recommendations.md) | Spring Bean Request Evidence and Auto-Configuration Recommendations | 2026-10-25 | Open | Framework Evidence & Recommendations | Investigates observing bean requests and dependency chains to recommend testable Spring Boot auto-configuration exclusions without treating one workload as proof that code is unused. |
| [RQ-0006](RQ-0006-maven-artifact-view-consistency-and-early-resolution-hooks.md) | Maven Artifact-View Consistency and Early Resolution Hooks | 2026-10-25 | Open | Maven Lifecycle & Resolver Integration | Measures when Maven consumers see inconsistent direct/resolved views, when resolution restores original artifacts, and whether an earlier resolver hook is worth its lifecycle cost. |
| [RQ-0007](RQ-0007-maven-plugin-site-and-github-pages.md) | Maven Plugin Documentation Site and GitHub Pages Publishing | 2026-10-26 | Open | Documentation & Publishing | Evaluates Maven-generated plugin documentation reports, hand-written guides, and GitHub Actions/GitHub Pages publishing, including versioning and validation. |
