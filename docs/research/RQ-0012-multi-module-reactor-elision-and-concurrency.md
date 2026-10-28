<!-- WHY: Investigates cross-module dependency elision, reactor-level state coordination, and concurrent multi-module builds under mvn -T. -->
# RQ-0012: Multi-Module Reactor Elision and Concurrency

## Status

Open

## Current boundary

Current end-to-end evidence covers single-project Maven CLI 3.9.11 builds across four fixtures (`example-basic-app`, `example-spring-boot-app`, `example-cve-unused-app`, and `example-cve-safe-class-app`). ADR-0001 and ADR-0002 explicitly state:
> *"Current end-to-end evidence covers single-project Maven CLI 3.9.11 builds. Other Maven 3 releases, Maven 4, and active multi-module consumer reactors remain unverified."*

In multi-module reactors (`pom` packaging aggregator with child modules), Maven may execute builds sequentially or concurrently via `mvn -T` (multi-threaded builder). Furthermore, downstream reactor modules frequently depend on upstream reactor modules (`<groupId>${project.groupId}</groupId><artifactId>child-core</artifactId>`). When an upstream submodule undergoes dependency elision or intra-JAR trimming, the downstream consumer module must observe consistent compiler classpath, dependency trees, and packaging inputs without race conditions, corrupted cross-process state, or classpath divergence.

## Research questions

1. **Reactor Graph Propagation**: How does an elided or trimmed upstream reactor module propagate its transformed artifact to downstream sibling modules in the same Maven execution session without relying on installed `~/.m2` repository artifacts?
2. **Concurrent Reactor Execution (`mvn -T`)**: When Maven executes independent reactor modules in parallel across worker threads, does `MavenElisionService`, `MavenDependencyTrimmer`, or `ElisionCache` exhibit race conditions, lock contention, or thread-safety hazards?
3. **Cross-Module Intra-JAR Trimming**: Can intra-JAR trimming safely prune dead code across reactor boundaries (e.g., pruning classes from upstream submodule JARs based on downstream application link closure), or must each reactor module's elision and trimming boundary remain strictly encapsulated within its own module scope?
4. **Clean vs. Incremental Reactor Invocations**: How do incremental builds within a reactor handle partial module execution (e.g., `mvn test -pl :submodule-b -am`) when upstream module elision artifacts reside under their respective `target/` directories?

## Options

1. **Encapsulated Per-Module Elision Boundary (Recommended Baseline)**:
   - Each module independently executes `elide` at `INITIALIZE` phase against its resolved dependencies.
   - Upstream reactor dependencies are resolved from reactor output directories (`target/classes` or `target/*.jar`).
   - The shared `ElisionCache` handles concurrent multi-threaded access using file locks on per-fingerprint lockfiles without cross-module memory sharing.
2. **Whole-Reactor Global Elision Coordinator**:
   - A root aggregator Mojo collects telemetry across all submodules, resolves a global cross-module graph, and orchestrates unified trimming.
   - High complexity: Requires custom Maven lifecycle participants and violates standard Maven module independence invariants.

## Evidence gates

- Build a dedicated reference reactor fixture (`examples/example-multi-module-reactor`) featuring at least three tiers:
  - `reactor-common`: Shared utility library with both used and unused external dependencies.
  - `reactor-service`: Business logic layer consuming `reactor-common`.
  - `reactor-app`: Executable application packaging the final distribution.
- Verify sequential execution (`mvn clean verify`).
- Verify parallel multi-threaded execution (`mvn -T 4 clean verify`).
- Verify graph isolation and deterministic `dependency-elider:report` snapshots per submodule.
- Prove that reactor submodule trims do not corrupt the shared OS user cache directory.

## Implementation Work Package

This investigation is realized in work package [WP-REACTOR-01](../handovers/2026-10-28-wp-reactor-01-multi-module-reactor-fixture.md).
