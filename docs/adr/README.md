# Architecture Decision Records (ADRs)

This directory contains Architecture Decision Records (ADRs) for the `maven-dependency-elider` project.

## Accepted Decisions

| ADR | Title | Date | Role | Scope | Area | Summary |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| [ADR-0001](0001-runtime-telemetry-driven-dependency-elision-at-maven-initialize-phase.md) | Runtime Telemetry-Driven Dependency Elision at Maven INITIALIZE Phase | 2026-10-24 | architecture | build-lifecycle | plugin-core | Combine external usage evidence with compilation and dynamic-discovery requirements; target early execution with explicit coverage and ordering limits. |
| [ADR-0002](0002-in-memory-artifact-mutation-for-downstream-packaging-transparency.md) | In-Memory Artifact Mutation for Downstream Packaging Transparency | 2026-10-24 | contract | build-lifecycle | plugin-core | Target in-memory dependency replacement; verify consumer inventories, preserve originals, and track transformed artifact identities. |
| [ADR-0003](0003-proguard-core-intra-jar-trimming-and-cyclonedx-pedigree.md) | ProGuard Core-Driven Intra-JAR Trimming and CycloneDX Pedigree | 2026-10-25 | architecture | build-lifecycle | plugin-core | Use ProGuard Core to trim unreferenced classes from retained dependency JARs, sanitize signatures, and record provenance via CycloneDX 1.6 pedigree. |
| [ADR-0004](0004-assume-resolved-inputs-stable-during-build.md) | Assume Resolved Inputs Stay Stable During a Maven Invocation | 2026-10-26 | contract | cache-publication | plugin-core | Assume dependency archives and selected JDK platform sources (`ct.sym`, release metadata, and JMODs) remain stable for an invocation; use exact digest identities without repeated input reads while retaining cache/output integrity checks and atomic publication. |
| [ADR-0005](0005-released-format-versioning.md) | Versioning Released Persisted Formats | 2026-10-28 | policy | persisted-formats | repository | Keep unreleased persisted formats at version 1; increment a format's independent version only after its released representation changes. |
| [ADR-0006](0006-dual-source-vulnerability-advisory-ingestion-from-cvelist-v5-and-osv-maven.md) | Dual-Source Vulnerability Advisory Ingestion from CVEList v5 and OSV Maven | 2026-10-29 | architecture | vulnerability-assessment | plugin-core | Ingest vulnerability-to-symbol evidence using an offline-first pipeline combining the OSV Maven database snapshot for GAV coordinate and version range resolution with CVEList v5 for CVE provenance and class-level enrichment. |
