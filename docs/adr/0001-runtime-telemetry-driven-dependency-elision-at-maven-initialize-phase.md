<!-- WHY: Records the evidence and lifecycle boundaries needed to integrate dependency reduction into Maven compilation and testing. -->
# ADR-0001: Runtime Telemetry-Driven Dependency Elision at Maven INITIALIZE Phase

* **Status**: Accepted
* **Date**: 2026-10-24
* **Last Updated**: 2026-10-25

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

For source-aware trimming, combine oracle roots, resolved source compilation roots, and framework/resource roots, then compute their required dependency closure. Static analysis complements external evidence; neither source references nor observed execution alone establish arbitrary dynamic usage. Source-aware trimming remains deferred under RQ-0001; this clarification does not activate member deletion.

Bind the core `elide` Mojo to the Maven `INITIALIZE` lifecycle phase (supporting Maven 3.x and 4.x), declaring `requiresDependencyResolution = ResolutionScope.TEST`. By resolving the dependency graph at `INITIALIZE`:

1. All direct and transitive JARs are downloaded and present in the local repository for indexing.
2. Unused dependencies are purged before `maven-compiler-plugin:compile` and `maven-surefire-plugin:test` assemble their classpaths.
3. Compilation and testing expose missing dependencies on the source and execution paths they cover. Passing them is useful validation, not a proof of completeness for unexercised paths.

`INITIALIZE` is the current whole-artifact integration target. A source-aware prepass must see generated sources and annotation-processor output with the original dependency classpath and matching compiler settings. The final phase ordering is unresolved: generators may run after `INITIALIZE`, and processors must not be run twice without accounting for their side effects. Investigate this ordering before promising that all source-aware reduction can finish at `INITIALIZE` (RQ-0001 and RQ-0004).

## Invariants

* **Evidence Contract**: Positive oracle evidence supplies retention roots. Missing classes or methods are not proof of non-use without an explicit coverage/completeness contract. Class-level evidence must not silently authorize member removal.
* **Pre-Compile Execution**: The `elide` Mojo must execute prior to `compile` and `test` phases whenever elision is active.
* **Validation Boundary**: Compiler and test failures must propagate. Runtime-only dependencies on unexercised paths may still be missing after a passing build.
* **Multi-Format Ingestion**: The runtime ingestion layer must accept plain class lists, JFR recordings, and GraalVM JSON files through a unified abstraction.

## Consequences

Executing at `INITIALIZE` with dependency resolution requires evidence generated before the elided build. Record the application/dependency versions, environment, workload, and instrumentation coverage to detect stale or mismatched evidence. Source-aware analysis adds its own inputs and ordering constraints.

Early transformation has prior art in [Gradle artifact transforms](https://docs.gradle.org/current/userguide/artifact_transforms.html) and [DepTrim](https://github.com/ASSERT-KTH/deptrim). The product value is oracle integration, dependable Maven orchestration, and explainable validation. A distribution-only shrinker may be sufficient when users do not need reduced dependencies in their normal compile/test lifecycle.

The build can test the intended reduced dependency set only after consumer classpaths and packaged bytes are verified under ADR-0002. A smaller classpath does not establish a faster build; total analysis, transformation, and cache costs require measurement under RQ-0003.
