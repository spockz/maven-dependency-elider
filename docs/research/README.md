# Research Questions (RQs)

This directory tracks open investigations, capability comparisons, empirical benchmarks, and architectural explorations for the `maven-dependency-elider` project.

## Research Register

| RQ | Title | Date | Status | Category | Summary |
| :--- | :--- | :--- | :--- | :--- | :--- |
| [RQ-0001](RQ-0001-sub-artifact-bytecode-symbol-slicing-and-provenance.md) | Sub-Artifact Bytecode Symbol Slicing and Multi-Tier Provenance | 2026-10-24 | Open | Bytecode Slicing & Provenance Metadata | Investigates ASM link closure, signature handling on signed JARs, and recording provenance across Effective POMs, CycloneDX 1.5+ SBOMs, and OpenVEX. |
| [RQ-0002](RQ-0002-runtime-sensor-fidelity-and-framework-autoconfiguration-quiescence.md) | Runtime Sensor Fidelity and Framework Auto-Configuration Quiescence | 2026-10-24 | Open | Runtime Telemetry & Framework Probing | Investigates the fidelity of runtime telemetry sources (ClassLoader logs, CDS, JFR, GraalVM, JaCoCo) and framework auto-configuration (@ConditionalOnClass probing vs. real execution). |
| [RQ-0003](RQ-0003-sub-10ms-maven-fast-path-invariant-and-benchmarking.md) | Sub-10ms Maven Fast-Path Invariant and Benchmarking Methodology | 2026-10-24 | Open | Performance & Benchmarking | Investigates the caching architecture, virtual-thread Central Directory ZIP scanning, and JMH test harness required to guarantee <10ms overhead during routine Maven invocations. |
| [RQ-0004](RQ-0004-maven-dependency-elider-implementation-handover.md) | Maven Dependency Elider Engine and Plugin Implementation Handover | 2026-10-24 | Open | Implementation Handover & Engineering Specifications | Complete engineering handover, architectural invariants, track specifications, and multi-tier testing protocols for implementing the runtime telemetry-driven Maven Dependency Elider. |
