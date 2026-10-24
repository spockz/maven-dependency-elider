<!-- WHY: Investigates the fidelity of runtime telemetry sources (ClassLoader logs, CDS, JFR, GraalVM, JaCoCo) and resolves the impact of framework auto-configuration (e.g. Spring Boot @ConditionalOnClass) on dependency reachability. -->
# RQ-0002: Runtime Sensor Fidelity and Framework Auto-Configuration Quiescence

* **Status**: Open
* **Category**: Runtime Telemetry & Framework Probing
* **Date**: 2026-10-24
* **Last Updated**: 2026-10-24

Abbreviations: Java Virtual Machine (JVM), Class Data Sharing (CDS), JDK Flight Recorder (JFR), Abstract Syntax Tree (AST), Aspect-Oriented Programming (AOP), Inversion of Control (IoC), Spring Boot (SB).

---

## 1. Context & Research Questions

In modern enterprise applications (particularly Spring Boot 3+), framework auto-configuration probes classpath availability using conditional checks such as `@ConditionalOnClass(Foo.class)` or `ClassUtils.isPresent("foo.Bar", classLoader)`.

Calling `Class.forName(name, false, classLoader)` causes the JVM to define and load the probed class, even if:

1. The corresponding bean is never instantiated (e.g., guarded by missing `@ConditionalOnProperty`).
2. No code inside that class is ever executed.
3. The remaining 95% of transitive JARs brought in by that starter remain completely quiescent.

### Primary Research Questions

* **RQ-0002.1**: Which runtime telemetry sources accurately reflect loaded classes versus actively executed code?
  * ClassLoader logging (`-Xlog:class+load`)
  * HotSpot CDS dump (`-XX:DumpLoadedClassList` and `-XX:ArchiveClassesAtExit`)
  * JFR class loading and execution sampling events (`jdk.ClassLoad`, `jdk.ExecutionSample`)
  * GraalVM reachability metadata (`reflect-config.json`)
  * JaCoCo execution probes (`jacoco.exec`)
* **RQ-0002.2**: To what extent do unused Spring Boot starters load transitive classes during startup versus leaving them quiescent?
* **RQ-0002.3**: Can execution probes (JaCoCo/JFR) be used to distinguish between probe-only classes and real execution, allowing safe elision of conditionally skipped starters?

---

## 2. Experimental Setup: Two Reference Projects

We establish two reference projects that serve as permanent integration test fixtures:

### 1. `example-basic-app`

* Plain Java 21 application (no heavy reflection framework).
* Direct dependencies with bloated, unused transitive relationships (e.g., HTTP client and Jackson with unreferenced codec modules).
* Verified with and without `maven-shade-plugin`.

### 2. `example-spring-boot-app`

* Spring Boot 3.x+ web application on Java 21.
* Core starter: `spring-boot-starter-web`.
* Injected extra unused starter (e.g., `spring-boot-starter-mail` or `spring-boot-starter-validation`).
* Test harness:
  1. **Phase 1 (Recording)**: Start application under test with sensor attached; exercise REST endpoints via integration test; shutdown application; capture trace.
  2. **Phase 2 (Elision)**: Re-run build with elision active; inspect which starter dependencies are elided.
  3. **Phase 3 (Verification)**: Re-run the application fat JAR and execute integration tests to ensure 100% functional integrity.

---

## 3. Findings & Evidence (Pending Investigation)

| Sensor | Class Probing (`Class.forName(false)`) | Instruction Execution | Reflection Coverage | Test Exclusion Ease |
| :--- | :--- | :--- | :--- | :--- |
| `-Xlog:class+load` | Yes (Logged) | No | Yes | Medium (Text filter) |
| CDS Class List | Yes (Dumped) | No | Yes | High (Format is pure names) |
| JFR `jdk.ClassLoad` | Yes (Captured) | No | Yes | High (Structured events) |
| JFR Execution Sampling | No | Yes | No | High (Event filtering) |
| JaCoCo `jacoco.exec` | No | Yes | Indirect | High (Class/method probe bitmask) |

---

## 4. Next Steps & Decision Checkpoints

* [ ] Checkpoint 1: Construct `example-basic-app` and execute baseline recording with `-Xlog:class+load` and CDS dumps.
* [ ] Checkpoint 2: Construct `example-spring-boot-app` with an unused starter and measure which transitive dependencies are probed vs. untouched.
* [ ] Checkpoint 3: Document whether Spring Boot starter auto-configurations back off cleanly when secondary transitives are elided.
