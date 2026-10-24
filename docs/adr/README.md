# Architecture Decision Records (ADRs)

This directory contains Architecture Decision Records (ADRs) for the `maven-dependency-elider` project.

## Accepted Decisions

| ADR | Title | Date | Role | Scope | Area | Summary |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| [ADR-0001](0001-runtime-telemetry-driven-dependency-elision-at-maven-initialize-phase.md) | Runtime Telemetry-Driven Dependency Elision at Maven INITIALIZE Phase | 2026-10-24 | architecture | build-lifecycle | plugin-core | Ground dependency elision in multi-source runtime telemetry and execute during the early INITIALIZE lifecycle phase with dependency resolution. |
| [ADR-0002](0002-in-memory-artifact-mutation-for-downstream-packaging-transparency.md) | In-Memory Artifact Mutation for Downstream Packaging Transparency | 2026-10-24 | contract | build-lifecycle | plugin-core | Mutate MavenProject.getArtifacts() and dependencyArtifacts in-memory to purge unused dependencies and swap sliced JAR references. |
