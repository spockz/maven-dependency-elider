# Architecture Decision Records (ADRs)

This directory contains Architecture Decision Records (ADRs) for the `maven-dependency-elider` project.

## Accepted Decisions

| ADR | Title | Date | Role | Scope | Area | Summary |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| [ADR-0001](0001-runtime-telemetry-driven-dependency-elision-at-maven-initialize-phase.md) | Runtime Telemetry-Driven Dependency Elision at Maven INITIALIZE Phase | 2026-10-24 | architecture | build-lifecycle | plugin-core | Combine external usage evidence with compilation and dynamic-discovery requirements; target early execution with explicit coverage and ordering limits. |
| [ADR-0002](0002-in-memory-artifact-mutation-for-downstream-packaging-transparency.md) | In-Memory Artifact Mutation for Downstream Packaging Transparency | 2026-10-24 | contract | build-lifecycle | plugin-core | Target in-memory dependency replacement; verify consumer inventories, preserve originals, and track transformed artifact identities. |
| [ADR-0003](0003-proguard-core-intra-jar-trimming-and-cyclonedx-pedigree.md) | ProGuard Core-Driven Intra-JAR Trimming and CycloneDX Pedigree | 2026-10-25 | architecture | build-lifecycle | plugin-core | Use ProGuard Core to trim unreferenced classes from retained dependency JARs, sanitize signatures, and record provenance via CycloneDX 1.6 pedigree. |
