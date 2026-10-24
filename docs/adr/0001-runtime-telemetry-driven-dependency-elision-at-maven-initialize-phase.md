<!-- WHY: Records the architectural boundary for grounding dependency elision in runtime telemetry rather than static analysis, and binding execution to the early Maven INITIALIZE lifecycle phase. -->
# ADR-0001: Runtime Telemetry-Driven Dependency Elision at Maven INITIALIZE Phase

* **Status**: Accepted
* **Date**: 2026-10-24

<!-- semedit-adr-metadata:v1 keys=summary,description,role,scope,area,languages; do not change key names or order. -->
| Key | Value |
| :--- | :--- |
| summary | Ground dependency elision in multi-source runtime telemetry and execute during the early INITIALIZE lifecycle phase with dependency resolution. |
| description | Reject static bytecode inspection as insufficient for dynamic JVM execution; bind elision to INITIALIZE with requiresDependencyResolution=ResolutionScope.TEST so compiler, test runner, and packager execute exclusively against surviving dependencies. |
| role | architecture |
| scope | build-lifecycle |
| area | plugin-core |
| languages | java |

## Context

Static dependency analysis (such as `maven-dependency-plugin:analyze`) relies on bytecode scanning of compiled classes. It routinely fails to capture reflection, dynamic proxies, Java SPI (`ServiceLoader`), and framework dependency injection (e.g., Spring Boot auto-configuration), resulting in false-positive removals or manual whitelist burdens. Furthermore, deferring dependency stripping to packaging phases (like `prepare-package`) allows code and tests to execute against an artificially bloated classpath, introducing classpath collisions (split packages, duplicate classes) and obscuring whether the application can safely boot without the pruned libraries.

## Decision

Ground all automated dependency elision in runtime telemetry rather than static bytecode inspection. Supported runtime sources include JVM unified class loading logs (`-Xlog:class+load`), HotSpot Class Data Sharing dumps (`-XX:DumpLoadedClassList`), JDK Flight Recorder (`jdk.ClassLoad` and execution events), GraalVM reachability configuration (`reflect-config.json`), and JaCoCo execution data (`jacoco.exec`).

Bind the core `elide` Mojo to the Maven `INITIALIZE` lifecycle phase (supporting Maven 3.x and 4.x), declaring `requiresDependencyResolution = ResolutionScope.TEST`. By resolving the dependency graph at `INITIALIZE`:

1. All direct and transitive JARs are downloaded and present in the local repository for indexing.
2. Unused dependencies are purged before `maven-compiler-plugin:compile` and `maven-surefire-plugin:test` assemble their classpaths.
3. Compilation and testing serve as an immediate, automated fail-fast verification that the elided dependency tree contains all necessary symbols.

## Invariants

* **Runtime Telemetry Primacy**: Dependency elision decisions must be supported by empirical runtime execution data; the plugin will not guess reachability based purely on static constant-pool scans.
* **Pre-Compile Execution**: The `elide` Mojo must execute prior to `compile` and `test` phases whenever elision is active.
* **Fail-Fast Boundary**: If an essential dependency is improperly elided, the build must fail at `compile` or `test` time before any artifact or container image is packaged or published.
* **Multi-Format Ingestion**: The runtime ingestion layer must accept plain class lists, JFR recordings, and GraalVM JSON files through a unified abstraction.

## Consequences

Executing at `INITIALIZE` with dependency resolution requires that runtime traces be generated prior to the elided build (e.g., via a recording test run, integration test run, or committed baseline trace file). In return, the compiler and test harness validate the exact pruned dependency set, completely eliminating runtime surprises and packaging discrepancies.
