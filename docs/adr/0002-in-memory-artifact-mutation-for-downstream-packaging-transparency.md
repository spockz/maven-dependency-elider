<!-- WHY: Records the contract for mutating MavenProject artifact sets in-memory so downstream packaging plugins and CVE scanners observe only surviving dependencies without custom integrations. -->
# ADR-0002: In-Memory Artifact Mutation for Downstream Packaging Transparency

* **Status**: Accepted
* **Date**: 2026-10-24

<!-- semedit-adr-metadata:v1 keys=summary,description,role,scope,area,languages; do not change key names or order. -->
| Key | Value |
| :--- | :--- |
| summary | Mutate MavenProject.getArtifacts() and dependencyArtifacts in-memory to purge unused dependencies and swap sliced JAR references. |
| description | Mutate the in-memory dependency sets during the early build phase so downstream packagers (Shade, Spring Boot, Assembly) and scanner plugins automatically package and audit only the retained code without requiring bespoke plugin integrations. |
| role | contract |
| scope | build-lifecycle |
| area | plugin-core |
| languages | java |

## Context

Standard packaging plugins (`maven-shade-plugin`, `spring-boot-maven-plugin:repackage`, `maven-assembly-plugin`, `jib-maven-plugin`) and SBOM generators (`cyclonedx-maven-plugin`) query `project.getArtifacts()` to discover what dependencies to package and analyze. If a pruning tool only generates an external report or rewrites static files on disk without updating the active `MavenProject` state, downstream packagers continue bundling bloated dependencies, and security scanners continue reporting false-positive CVEs.

## Decision

Prune dependencies directly within the active `MavenProject` model during Mojo execution:

1. **Whole-Artifact Elision**: Remove completely unused dependencies from `project.setArtifacts(...)` and `project.setDependencyArtifacts(...)`.
2. **Sub-Artifact Bytecode Slicing**: For partially used dependencies that undergo symbol slicing, update the in-memory artifact file pointer via `artifact.setFile(slicedJarFile)`.

Because downstream packaging and analysis plugins operate on the updated `project.getArtifacts()` collection:

* `maven-shade-plugin` and `spring-boot-maven-plugin` automatically exclude elided JARs from fat JARs and `BOOT-INF/lib`.
* SBOM generators and security scanning tools querying the project model or inspecting the packaged output automatically omit elided components.

## Invariants

* **In-Memory State Consistency**: Any artifact purged from `project.getArtifacts()` must also be purged from `project.getDependencyArtifacts()` if it was a direct dependency.
* **Deterministic Filtering**: Given identical runtime traces and dependency sets, the mutated artifact set must be strictly deterministic across builds.
* **Transitive Safety**: Slicing an artifact file in-place or via `artifact.setFile()` must preserve file accessibility throughout subsequent build phases.
* **Dual Maven Compatibility**: Artifact mutation logic must function identically on Maven 3.8+/3.9+ and Maven 4.0+.

## Consequences

Downstream packaging and scanning plugins require zero custom adapters or code modifications; they transparently bundle and report only what remains in the in-memory project model. Local repository caches (`~/.m2/repository`) remain untampered, while build outputs (`target/`) reflect the minimized attack surface.
