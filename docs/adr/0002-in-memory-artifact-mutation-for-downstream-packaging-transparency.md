<!-- WHY: Records the contract for mutating MavenProject artifact sets in-memory so downstream packaging plugins and CVE scanners observe only surviving dependencies without custom integrations. -->
# ADR-0002: In-Memory Artifact Mutation for Downstream Packaging Transparency

* **Status**: Accepted
* **Date**: 2026-10-24
* **Last Updated**: 2026-10-28

<!-- semedit-adr-metadata:v1 keys=summary,description,role,scope,area,languages; do not change key names or order. -->
| Key | Value |
| :--- | :--- |
| summary | Target in-memory dependency replacement; verify consumer inventories, preserve originals, and track transformed artifact identities. |
| description | Target in-memory dependency replacement and verify each supported compiler, test runner, packager, and scanner consumes the applied inventory; keep originals immutable and transformed outputs traceable. |
| role | contract |
| scope | build-lifecycle |
| area | plugin-core |
| languages | java |

## Context

Maven consumers may obtain dependencies from project artifact collections, cached classpaths, or fresh resolution. Updating one collection does not establish that compiler, test runner, packager, or scanner uses the reduced inventory. Tests can pass against originals while the packaged application fails against transformed dependencies. The integration must verify actual consumer inputs and packaged contents.

## Decision

Apply validated effective decisions during Mojo execution:

1. **Whole-Artifact Elision**: Filter the resolved artifact view using graph-backed effective decisions. Preserve direct dependency-artifact membership and POM declarations. A core extension applies exact validated graph projections to compatible later resolver calls.
2. **Retained Artifact Replacement**: Write separate transformed JARs and update retained artifact file pointers. Publish validated replacement paths for later compatible resolution without modifying repository originals.

For each supported plugin/version combination, verify the intended outcomes:

* Compilation and test execution consume the intended reduced artifacts, including when later plugins perform dependency resolution.
* Shade and Boot package the reduced inventory; Boot receives ordinary dependency JARs before it builds `BOOT-INF/lib`.
* SBOMs describe actual packaged components and transformed hashes. Coordinate-based scanners may still report vulnerabilities for a partially trimmed component; scanner silence is not evidence of non-exploitability.

## Invariants

* **Explicit View Semantics**: Preserve direct dependency membership while applying effective decisions to resolved artifacts and compatible resolver graphs. Verify each consumer independently; the direct view is not an effective-inventory guarantee.
* **Deterministic Filtering**: Given identical runtime traces and dependency sets, the mutated artifact set must be strictly deterministic across builds.
* **Original Immutability**: Never modify original artifacts in the shared Maven repository. Write outputs under the build directory or an isolated transformation cache with traceable input/output identities and hashes.
* **Consumer Consistency**: Verify compile, test, runtime, packaging, and reporting inventories independently; mutation surviving one consumer does not prove the others.
* **Compilation Contract**: A single compile/runtime output must retain all compilation requirements. Separate compilation/runtime outputs are an unresolved design option, not an implicit optimization.
* **Compatibility Evidence**: Limit compatibility claims to verified Maven, JDK, consumer-plugin, and project configurations. Maven CLI 3.9.11 single-project fixtures are verified; other Maven releases and active multi-module consumer reactors remain unverified.

## Consequences

Avoiding bespoke downstream adapters is a design goal, conditional on lifecycle integration evidence. If a consumer re-resolves originals, record the limitation and resolve the integration boundary rather than claim transparent support. Reactor builds, parallel execution, IDE/direct goal invocations, and publication of specialized artifacts need explicit investigation in RQ-0004.

A second JAR cannot supplement individual fields of an existing class: classpath selection chooses a class definition and does not merge members. Source-driven constant retention should preserve the required fields in their owning transformed classes. Any future compilation-only artifacts need explicit execution and packaging policy. Maven scope alone is insufficient: [Boot includes `provided` dependencies by default](https://docs.spring.io/spring-boot/maven-plugin/packaging.html), and they are available to tests.

Preserving individual JAR boundaries reduces resource collisions and identity changes but does not solve signatures, modules, package sealing, multi-release entries, or resource descriptors. RQ-0001 records these transformation requirements and the unresolved engine/licensing decision. The plugin's Apache 2.0 license does not determine third-party engine redistribution or transformed-library obligations.
