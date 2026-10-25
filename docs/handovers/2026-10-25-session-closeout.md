<!-- WHY: Carries the session's integration decisions, verification boundaries, and remaining work into the next session without treating the original handover as complete. -->
# Session Closeout: Maven Dependency Elider

Date: 2026-10-25. Status: approved whole-artifact implementation integrated and verified; original RQ-0004 plan remains partially complete.

## Scope and decisions

The original RQ-0004 plan remains open. This closeout integrates the independently reviewed whole-artifact elision and usage-evidence follow-ups, updates the value proposition and caveats, preserves deferred work, and establishes the next session's starting point. Gemini review was omitted at the user's explicit request because the bridge is unavailable.

Current behavior maps observed classes to their dependency artifacts and retains whole owning JARs. The optional production-bytecode scan is report-only; it does not supply source compilation roots or enable member/class deletion inside JARs. No intra-JAR engine is selected. Source-aware trimming remains deferred under RQ-0001; Spring bean usage recommendations are future research under RQ-0005.

The intended product value is external-oracle integration and consistent Maven compilation, testing, and packaging. Pre-compilation timing alone is not claimed as novel. Positive evidence supplies roots; incomplete method coverage does not authorize deleting every unlisted member. Compiler/test success validates covered behavior and is not a universal reachability proof.

## Track status

| Track | Integrated capability | Remaining work |
| :--- | :--- | :--- |
| 1: Telemetry and evidence | Class-load, CDS, JFR, GraalVM reflection metadata, JaCoCo readers; reliable JAR origins; conservative merging; optional production-bytecode reference scanner. | A fuller oracle completeness contract and deployment/workload identity; source analysis is separate deferred research. |
| 2: ZIP index | Central-directory class index and parallel scanner, with behavioral tests. | Broader real-world archive/performance coverage as needed. |
| 3: Pruner and cache | Whole-artifact pruning, user retention exclusions, origin-aware duplicates, evidence classification, fingerprint and complete-decision cache APIs. | Maven plugin cache integration, invalidation/recheck orchestration, and lifecycle hit-path verification. |
| 4: Provenance | Core CycloneDX 1.6 retained-inventory generator and pinned-schema tests. | Plugin emission wiring, audit/consumer POM semantics, and vulnerability-evidence-backed VEX/suppressions. |
| 5: Maven plugin | Nonmutating analyze; explicit-trace INITIALIZE elide; artifact-view validation; counts/percentages; deterministic class-usage JSON report. | Maven 4, other consumer plugins/invocation modes, cache integration, and provenance integration. |
| 6: Intra-JAR trimming | Deferred; prototype is excluded from integration. | Explicit scope revision and RQ-0001 decisions before any implementation resumes. |
| 7: Benchmarks | ZIP sequential/parallel comparison and core cache benchmarks. | Lifecycle measurements and broader cold/representative measurements; cache-load component budget remains missed. |
| 8: Examples | Basic Shade, Spring Boot, and two opt-in CVE fixtures; record/elide/package/run loop; runtime-only mail classification and byte-for-byte retained mail JAR comparisons. | OSV-Scanner outcomes remain unverified; original code-specific CVE removal demonstration remains constrained by whole-JAR scope. |

The negative compiler probe must show an application source referencing Commons Codec fails specifically in javac when the unchanged baseline trace elides Codec, while the same source compiles when elision is skipped. This closes the gap between package/test checks and actual compiler dependency visibility.

## Verification

Source integration: `efd5a265c1cc44b72cf813c30424e4b0978816b2` on local `main`. Documentation/research and agent-roster changes were committed first as `752378b`. The approved chain was rebased, its scanner fixup autosquashed, and integrated by fast-forward; no prototype code was merged. Independent [integration review](2026-10-25-integration-review.md) approved this bounded delivery.

The integrated tree passed a clean build, `make check` (21.305 seconds), and `make test-examples` (16.551 seconds). Surefire reports contain 88 core tests and 27 plugin tests, with no failures, errors, or skips. Each baseline and elided example cycle passed 9 fixture tests (2 basic, 3 Spring Boot, and 2 in each CVE fixture), alongside the compiler negative/control probe, archive/report checks, retained mail byte comparisons, and packaged application/HTTP checks. These durations are observed build measurements, not claimed speed improvements.

Verification used the selected Oracle GraalVM JDK 25.0.5 and Maven Daemon 1.0.6 (embedded Maven 3.9.16):

```sh
export JAVA_HOME="$PWD/.scratch/toolchains/graalvm-jdk-25.0.5+1.1"
export PATH="$JAVA_HOME/bin:$PATH"
make check MAVEN="$PWD/.scratch/toolchains/maven-mvnd-1.0.6/bin/mvnd" \
  MAVEN_ARGS='--batch-mode --no-transfer-progress -q'
make test-examples MAVEN="$PWD/.scratch/toolchains/maven-mvnd-1.0.6/bin/mvnd" \
  MAVEN_ARGS='--batch-mode --no-transfer-progress -q'
```

Local compilation targets Java 21 through the configured release setting; this closeout uses JDK 25 for execution as requested. Maven 4, a local JDK 21 execution matrix, OSV-Scanner results, native-image behavior, and new JMH measurements are not established by these checks. Existing GitHub Actions runs `make check` on Java 21; the example lifecycle target is currently separate from that CI job.

Prior measured cache results were fingerprint 0.221 ± 0.043 ms/op, complete-decision load 0.722 ± 0.011 ms/op, and combined lookup 1.078 ± 0.302 ms/op. The load misses its 0.5 ms component budget, and these core measurements do not prove the Maven fast-path target. ZIP fixture and environment limits remain recorded in the README and RQ-0003.

## Specification deviations and caveats

* Keep traces and preserved production output outside `target` when the next invocation runs `clean`; otherwise the evidence is deleted before INITIALIZE.
* Spring mail classes were observed during baseline execution and remain retained. The report distinguishes runtime observations without direct application-bytecode references; it does not prove Spring auto-configuration caused those observations. The Spring unused-artifact fixture uses Commons Codec instead.
* `excludedArtifacts` excludes dependencies from elision and therefore retains them across the current graph. Spring auto-configuration exclusions and Maven dependency exclusions have different meanings.
* Disabling an auto-configuration and removing a starter are separate experiments because classpath changes alter conditions and discovery.
* A separate distribution module/shrinker may suffice for users who need only a smaller packaged application. Measure added build work and configuration effort before making speed or convenience claims.
* Source-aware trimming must preserve constants and erased source references, generated-source/processor parity, compilation metadata, transitive supporting code, dynamic roots, resources/descriptors, archive structure, and output identity. Engine capability/licensing and compile/runtime output policy remain decisions to make under RQ-0001.
* A separate JAR cannot add fields to another definition of the same class. Maven `provided` scope alone cannot implement a compilation-only packaging policy.
* Application-specific specialization does not preserve a reusable library's unknown downstream consumers automatically.
* Removing code and suppressing a scanner finding are separate outcomes; vulnerability statements require explicit evidence.

## Preservation and tool evidence

The uncommitted four-file slicing prototype is preserved at `.scratch/deferred/track-bytecode-slicer-2026-10-25.tar.gz` with its manifest. SHA-256: `cdef9031a15ee940e415f1c30d848f399be65a03254c7c529608f6de6f16cfa2`. It must not be merged or treated as current implementation. Original track branches and the pre-rebase reference branch remain available for audit.

The transcript extractor inspected 39 retained root/child logs. It found zero executed semantic tools and four command candidates; manual inspection identifies only shell downloads/documentation mentions. Historical completeness outside retained logs is unknown. No semantic-versus-built-in runtime ratio or savings can be calculated. Existing track receipts describe built-in search/patch, formatter, analyzer, test, and reviewer workflows; exact historical per-agent wall-clock durations were not captured.

Track reviews and wrap-up receipts are under `.scratch/reviews/`; manual-edit records are under `.scratch/manual-edits/`. Versioned [tool assessments](../SUBOPTIMAL_TOOLS.md), [manual edit records](../MANUAL_EDITS.md), and this handover preserve the conclusions. Review and wrap-up receipts are also bundled in `.scratch/closeout-review-evidence.tar.gz`. Successful verification output is captured in `.scratch/closeout-*.log` and `.scratch/verification/`; the final integration review is `.scratch/reviews/closeout-integration.md`.

## Worktree cleanup and preserved unfinished work

Eight completed track worktrees were removed after independent integration approval. The primary checkout and all original branch refs remain. For branches whose approved commits were rebased, the old ref was preserved and the clean worktree detached at integrated `main` before removal. The pre-rebase reference branch is `codex/closeout-reference-before-rebase`.

The cache worktree at `.scratch/worktrees/track-cache` on `track/cache` was intentionally retained. It has five unreviewed, uncommitted edits affecting `ElisionCache`, its codec/reader, `ElisionDecision`, and cache tests. These changes are outside the integrated result and were neither modified nor approved during closeout. Its base is `eb4af735efd87a41ec23b6c2e05e93b1e88306d9`; a binary patch backup is `.scratch/deferred/track-cache-unreviewed-2026-10-25.patch`, SHA-256 `4ba411edd7dce5a99e907fdbf375ba82e0fe3dc619b9143edc1eeee3482d9bc2`. Inspect and review this candidate before continuing cache work; do not assume it is verified or silently discard it.

The removed slicing worktree's four prototype files were verified against their archive hashes before removal. The prototype archive, cache patch, and all evidence remain under the primary checkout's `.scratch`; they are workspace-local, ignored artifacts, not published source. Retain them if moving the repository to another machine. No branches were deleted and nothing was pushed.

## Next session

1. Read this handover, the current README, ADR-0001/0002, RQ-0004's follow-up table, and the relevant RQ before editing.
2. Inspect the retained unreviewed cache worktree and its patch backup first. Review/adopt or explicitly retire that candidate before Maven cache integration and its invalidation/lifecycle proof. Keep performance claims separate until measured.
3. Then address provenance integration and the documented Maven compatibility gaps in bounded follow-up slices, reusing track roles.
4. Keep source-aware/intra-JAR trimming and the Spring helper as separately approved research scopes rather than silently expanding artifact elision.
5. Preserve the distinction between verified example package behavior and the unrun vulnerability scanner expectations.
