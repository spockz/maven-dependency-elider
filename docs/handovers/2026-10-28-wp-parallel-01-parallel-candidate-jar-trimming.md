<!-- WHY: Defines engineering work package WP-PARALLEL-01 for parallel candidate JAR trimming under RQ-0003 Slice 7.8. -->
# WP-PARALLEL-01: Parallel Candidate JAR Trimming (RQ-0003 Slice 7.8)

## Status

Approved for Implementation

## Context

[RQ-0003](../research/RQ-0003-sub-10ms-maven-fast-path-invariant-and-benchmarking.md) establishes the performance investigation for dependency elision.
In non-cached builds with intra-JAR trimming enabled (`elide.trimJars=true`), multiple candidate dependency JARs (e.g. 10 to 50+ candidates in Spring Boot applications) are currently prepared and analyzed sequentially in `MavenDependencyTrimmer.java`.

On multi-core systems, sequential candidate analysis is the dominant contributor to wall-clock time. For Spring Boot 3, trimming overhead currently accounts for $\approx 20\text{ s}$ of added build time.

## Objective

Implement **Slice 7.8: Parallel Candidate Trimming**:

1. Parallelize candidate preparation and link-closure analysis across available cores using a bounded executor or virtual thread pool.
2. Parallelize candidate archive sanitization (`ArchiveSanitizer.prepareWithProvenance`).
3. Bound concurrency to avoid thread thrashing and heap exhaustion (e.g. `Math.min(Runtime.getRuntime().availableProcessors(), 4)` workers or memory-sensitive bounding).
4. Maintain **strict determinism**: Collate output records, published manifests, SBOM component arrays, and logs in canonical coordinate order regardless of task completion order.

## Invariants & Guardrails

- **Thread-Safety**: ProGuard `ClassPool` instances for candidate programs are isolated per worker thread. Platform context pools (`FrozenClassPool`) must be read-only / safely shared across threads.
- **Fail-Closed Failure Handling**: Any worker exception immediately cancels remaining parallel tasks and bubbles up as a single deterministically wrapped `IOException` or `MojoExecutionException`.
- **Reproducible Bit-Exact Output**: Parallel trimming must produce identical output archives and hashes as sequential trimming.
