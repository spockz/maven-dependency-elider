<!-- WHY: Records the contract for mutating MavenProject artifact sets in-memory so downstream packaging plugins and CVE scanners observe only surviving dependencies without custom integrations. -->
# ADR-0002: In-Memory Artifact Mutation for Downstream Packaging Transparency

* **Status**: Accepted
* **Date**: 2026-10-24
* **Last Updated**: 2026-11-13

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
* **Compilation Contract**: Under default `process-classes` execution ([ADR-0010](0010-process-classes-lifecycle-and-bytecode-completeness.md)), production compilation uses the original resolved dependency graph while `testCompile` and downstream consumers observe the elided view. Any future separate compilation-only vs runtime outputs require explicit execution and packaging policy.
* **Publication Decoupling**: SBOM, baseline SBOM, summary report, and precondition-gated VEX publication are decoupled from `trimJars`; setting `trimJars=false` leaves dependency archives byte-identical while still running full assessment and report/VEX publication.
* **Compatibility Evidence**: Limit compatibility claims to verified Maven, JDK, consumer-plugin, and project configurations. Maven CLI 3.9.11 single-project fixtures and the strict three-module reactor chain are verified on compliant JDK 21+ installations ([ADR-0013](0013-compiler-decoupling-multi-jdk-portability-and-report-driven-liveness.md)), including sequential and `-T 4` builds. The reactor chain has no independent siblings, so arbitrary multi-module concurrency remains unverified; other Maven releases are also unverified.

## Consequences

The consumer verification contract here does not imply that a ban rewrites a consumer POM or changes every Resolver request. Those boundaries for `banishedDependencies` are defined in [ADR-0012](0012-dual-layer-ban-policy-and-retention-naming.md).

Avoiding bespoke downstream adapters is a design goal, conditional on lifecycle integration evidence. If a consumer re-resolves originals, record the limitation and resolve the integration boundary rather than claim transparent support. Broader reactor topologies, independent-module concurrency, IDE/direct goal invocations, and publication of specialized artifacts need explicit investigation in RQ-0012 and RQ-0004.

A second JAR cannot supplement individual fields of an existing class: classpath selection chooses a class definition and does not merge members. Compile-time inlined constants that leave no bytecode reference require explicit `elide.retainedArtifacts` ([ADR-0013](0013-compiler-decoupling-multi-jdk-portability-and-report-driven-liveness.md)). Maven scope alone is insufficient: [Boot includes `provided` dependencies by default](https://docs.spring.io/spring-boot/maven-plugin/packaging.html), and they are available to tests.

Preserving individual JAR boundaries reduces resource collisions and identity changes but does not solve signatures, modules, package sealing, multi-release entries, or resource descriptors; [ADR-0003](0003-proguard-core-intra-jar-trimming-and-cyclonedx-pedigree.md) defines the ProGuard Core transformation engine and archive-sanitization rules. The plugin's Apache 2.0 license does not determine third-party engine redistribution or transformed-library obligations.
