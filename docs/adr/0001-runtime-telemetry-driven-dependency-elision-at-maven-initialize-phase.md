<!-- WHY: Records the evidence and lifecycle boundaries needed to integrate dependency reduction into Maven compilation and testing. -->
# ADR-0001: Runtime Telemetry-Driven Dependency Elision at Maven INITIALIZE Phase

* **Status**: Accepted (Runtime Oracle & Multi-Format Ingestion); Superseded on Lifecycle Phase and Source Attribution by [ADR-0010](0010-process-classes-lifecycle-and-bytecode-completeness.md) and [ADR-0013](0013-compiler-decoupling-multi-jdk-portability-and-report-driven-liveness.md)
* **Date**: 2026-10-24
* **Last Updated**: 2026-11-13

<!-- semedit-adr-metadata:v1 keys=summary,description,role,scope,area,languages; do not change key names or order. -->
| Key | Value |
| :--- | :--- |
| summary | Combine external usage evidence with compilation and dynamic-discovery requirements; target early execution with explicit coverage and ordering limits. |
| description | Use external usage evidence with compilation and dynamic-discovery requirements; target early Maven execution while proving source-analysis ordering and consistent consumer classpaths. |
| role | architecture |
| scope | build-lifecycle |
| area | plugin-core |
| languages | java |

## Context

Static dependency analysis (such as `maven-dependency-plugin:analyze`) relies on bytecode scanning of compiled classes. It routinely fails to capture reflection, dynamic proxies, Java SPI (`ServiceLoader`), and framework dependency injection (e.g., Spring Boot auto-configuration), resulting in false-positive removals or manual whitelist burdens. Furthermore, deferring dependency stripping to packaging phases (like `prepare-package`) allows code and tests to execute against an artificially bloated classpath, introducing classpath collisions (split packages, duplicate classes) and obscuring whether the application can safely boot without the pruned libraries.

## Decision

Ground automated dependency elision in an external usage oracle, including runtime telemetry and explicit retention configuration. Supported evidence sources include JVM unified class loading logs (`-Xlog:class+load`), HotSpot Class Data Sharing dumps (`-XX:DumpLoadedClassList`), JDK Flight Recorder (`jdk.ClassLoad` and execution events), GraalVM metadata, and JaCoCo execution data (`jacoco.exec`). These sources have different semantics: observation, sampling, and declared reachability are not interchangeable completeness guarantees.

> **Supersession Note**: The original `2026-10-24` decision bound `elide` to `INITIALIZE`, introduced `elide.sourceRootsComplete` for Java source attribution, and cited `GraalVM JDK 21.0.12`. Those parts are superseded:
>
> * Default lifecycle execution is `process-classes` ([ADR-0010](0010-process-classes-lifecycle-and-bytecode-completeness.md)).
> * Source attribution and `sourceRootsComplete=true` are removed/rejected in favor of compiled bytecode link-closure and `elide.productionClassesComplete` ([ADR-0013](0013-compiler-decoupling-multi-jdk-portability-and-report-driven-liveness.md)).
> * Execution is decoupled to any compliant JDK 21+ runtime ([ADR-0013](0013-compiler-decoupling-multi-jdk-portability-and-report-driven-liveness.md)).

## Invariants

* **Evidence Contract**: Positive oracle evidence supplies retention roots. Missing classes or methods are not proof of non-use without an explicit coverage/completeness contract (e.g., `closedWorld=true` under [ADR-0013](0013-compiler-decoupling-multi-jdk-portability-and-report-driven-liveness.md)). Class-level evidence must not silently authorize member removal.
* **Post-Compile Default Execution**: Default `elide` execution runs at `process-classes` ([ADR-0010](0010-process-classes-lifecycle-and-bytecode-completeness.md)); explicit phase bindings remain user configuration.
* **Validation Boundary**: Compiler and test failures must propagate. Runtime-only dependencies on unexercised paths may still be missing after a passing build.
* **Multi-Format Ingestion**: The runtime ingestion layer must accept plain class lists, JFR recordings, JaCoCo `.exec` data, and GraalVM JSON files through a unified abstraction.

## Consequences

Strict dependency-removal requests have a separate collection, verification, and publication contract; see [ADR-0012](0012-dual-layer-ban-policy-and-retention-naming.md). Runtime evidence and artifact-elision evidence remain distinct from an explicit ban policy.

Executing at `INITIALIZE` with dependency resolution requires evidence generated before the elided build. Record the application/dependency versions, environment, workload, and instrumentation coverage to detect stale or mismatched evidence. Source-aware analysis adds its own inputs and ordering constraints.

Early transformation has prior art in [Gradle artifact transforms](https://docs.gradle.org/current/userguide/artifact_transforms.html) and [DepTrim](https://github.com/ASSERT-KTH/deptrim). The product value is oracle integration, dependable Maven orchestration, and explainable validation. A distribution-only shrinker may be sufficient when users do not need reduced dependencies in their normal compile/test lifecycle.

The build can test the intended reduced dependency set only after consumer classpaths and packaged bytes are verified under ADR-0002. A smaller classpath does not establish a faster build; total analysis, transformation, and cache costs require measurement under RQ-0003.

## Dated Amendment: 2026-11-08 Default Lifecycle Phase

[ADR-0010](0010-process-classes-lifecycle-and-bytecode-completeness.md) supersedes this ADR's
`INITIALIZE` integration target and pre-compile invariant. The default `elide` execution now runs
at `process-classes`, after production bytecode exists and before test compilation and packaging.
This moves the default pruning point later in the Maven lifecycle: production compilation uses
the original resolved dependency graph, while subsequent lifecycle consumers receive the validated
elided view. Existing explicit phase bindings remain user configuration. The saved report, final
package, and prerequisite proof continue to require their respective evidence contracts.
