<!-- WHY: Records the evidence and lifecycle boundaries needed to integrate dependency reduction into Maven compilation and testing. -->
# ADR-0001: Runtime Telemetry-Driven Dependency Elision at Maven INITIALIZE Phase

* **Status**: Accepted
* **Date**: 2026-10-24
* **Last Updated**: 2026-10-28

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

For source-aware trimming, combine oracle roots, resolved source compilation roots, and framework/resource roots, then compute their required dependency closure. Static analysis complements external evidence; neither source references nor observed execution alone establish arbitrary dynamic usage. Current source attribution covers Java type references, constant owners, generic bounds, and annotation types when the user explicitly asserts complete source availability. It does not activate member deletion.

Bind the core `elide` Mojo to the Maven `INITIALIZE` lifecycle phase, declaring `requiresDependencyResolution = ResolutionScope.TEST`. Current end-to-end evidence covers single-project Maven CLI 3.9.11 builds. Other Maven 3 releases, Maven 4, and active multi-module consumer reactors remain unverified. By resolving the dependency graph at `INITIALIZE`:

1. Maven resolves the project's TEST dependency context before the goal indexes eligible local JAR files.
2. The goal publishes validated decisions before compilation and testing. Each downstream consumer's actual inputs require independent verification.
3. Compilation and testing expose missing dependencies on the source and execution paths they cover. Passing them is useful validation, not a proof of completeness for unexercised paths.

`INITIALIZE` is the current whole-artifact integration target. Generated-source completeness cannot generally be established before lifecycle generators and compiler processors run. The plugin therefore exposes `elide.sourceRootsComplete`, defaulting to `false`. In that mode it skips source attribution and retains all effective compile-classpath JARs and their indexed classes, so those artifacts remain available for later intra-JAR trimming. Setting it to `true` is an explicit assertion that all production and generated sources are present before `INITIALIZE` and no later processor or generator adds compile references. With that assertion, the plugin uses supported effective Maven compiler settings and fails closed on unsupported compiler/toolchain modes, unknown source-generation executions, and missing or empty source roots. Runtime evidence still must match at least one supplied dependency class; source-only matches cannot authorize pruning. The conservative default can limit elision, but avoids treating current roots as proof that future generated sources do not exist.

## Invariants

* **Evidence Contract**: Positive oracle evidence supplies retention roots. Missing classes or methods are not proof of non-use without an explicit coverage/completeness contract. Class-level evidence must not silently authorize member removal.
* **Pre-Compile Execution**: The `elide` Mojo must execute prior to `compile` and `test` phases whenever elision is active.
* **Validation Boundary**: Compiler and test failures must propagate. Runtime-only dependencies on unexercised paths may still be missing after a passing build.
* **Multi-Format Ingestion**: The runtime ingestion layer must accept plain class lists, JFR recordings, and GraalVM JSON files through a unified abstraction.

## Consequences

Executing at `INITIALIZE` with dependency resolution requires evidence generated before the elided build. Record the application/dependency versions, environment, workload, and instrumentation coverage to detect stale or mismatched evidence. Source-aware analysis adds its own inputs and ordering constraints.

Early transformation has prior art in [Gradle artifact transforms](https://docs.gradle.org/current/userguide/artifact_transforms.html) and [DepTrim](https://github.com/ASSERT-KTH/deptrim). The product value is oracle integration, dependable Maven orchestration, and explainable validation. A distribution-only shrinker may be sufficient when users do not need reduced dependencies in their normal compile/test lifecycle.

The build can test the intended reduced dependency set only after consumer classpaths and packaged bytes are verified under ADR-0002. A smaller classpath does not establish a faster build; total analysis, transformation, and cache costs require measurement under RQ-0003.
