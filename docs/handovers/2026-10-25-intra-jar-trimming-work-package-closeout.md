<!-- WHY: Hands off the verified WP-TRIM-01 result, remaining integration blockers, evidence, decisions, and research scope to a later session. -->
# WP-TRIM-01 Work-Package Closeout

## Identity and verdict

- Source handover: [WP-TRIM-01 specification](2026-10-25-intra-jar-trimming-work-package.md).
- Worktree/branch: `.scratch/worktrees/wp-trim-baseline`, `work-package/wp-trim-01`.
- Rebase base: committed `main` at `e893087`.
- Owning coordinator/session identifier: the coordinating thread that dispatched WP-TRIM-01; a thread UUID was unavailable in this delegated worktree context.
- Verdict: **The work package is incomplete against its original acceptance criteria.** Functional and reporting slices have been implemented and approved on the WP branch, but the exact-content warm-cache target (<10 ms) and per-artifact fast-path target (<1.5 ms) remain unmet and are deferred. Final integration into `main` is separately blocked by pre-existing dirty main paths. Preserve this branch and worktree until performance follow-up and path reconciliation are addressed.

The work package adds opt-in ProGuard Core class closure, source and dynamic roots, archive sanitation, CycloneDX pedigree, Maven lifecycle integration, fixtures, cache work, and persisted reports. All functional tracks received approval and the integrated branch passed the recorded Java 21 gates. Main was not edited, stashed, or committed during this closeout.

## Scope and acceptance

| Area | Outcome | Evidence |
| :--- | :--- | :--- |
| Source compilation roots | Implemented with fail-closed compiler settings and the explicit `elide.sourceRootsComplete` completeness contract. Default false pins compile-visible JARs/classes; runtime telemetry match remains independent. | [Source-roots receipt](../../.scratch/reviews/track-source-roots.md) and handover implementation note. |
| ProGuard Core closure | Cross-JAR fixed-point closure, signature-polymorphic references, dynamic roots, metadata, and retained pass-through roots are handled with fail-closed candidate behavior. | [Engine receipt](../../.scratch/reviews/track-proguard-engine.md). |
| Archive sanitation | Trimmed output is separately written; invalidated signatures and manifest digests are removed; original archives remain unchanged. | [Sanitizer receipt](../../.scratch/reviews/track-archive-sanitizer.md). |
| CycloneDX pedigree | Trimmed bytes and digest, original Maven ancestor and digest, patch metadata, and class counts are emitted and pinned-schema tested. No CVE mapping or VEX statement is inferred. | [Pedigree receipt](../../.scratch/reviews/track-cdx-pedigree.md). |
| Maven lifecycle and cache | Trimming is opt-in, outputs are validated, artifact views are updated under the documented Maven 3 boundary, and warm hits skip ProGuard closure. Exact validation remains content-based. | [Plugin receipt](../../.scratch/reviews/track-plugin-trimming.md), [cache review receipts](../../.scratch/reviews/track-cache-slice-7.1.md). |
| Examples and packaging | Basic Shade and Spring Boot nested-JAR paths plus two CVE package fixtures were verified; the generated packages execute and the Spring endpoint passes. | [Fixture mode receipt](../../.scratch/reviews/track-fixtures-mode-slice-6.5.md), [example checks](../../.scratch/verification/track8-javac-probe-test-examples.log), and [orchestration status](../../.scratch/orchestration-status.md). |
| Persisted reports | `elide` persists the last-success snapshot; the `report` goal only reads and renders that snapshot. Analyze reports estimated original JAR bytes for predicted elisions and omits trim-stage rows. The report still lacks original mediated graph paths. | [Track 7 integration receipt](../../.scratch/reviews/elision-report-integration.md), RQ-0006. |

## Verification and measured limits

- The final Java 21 `make check` for this closeout is recorded in `.scratch/verification/wp-trim-wrap-up-final-check.log`. It includes formatting, Java lint/static analysis, core and plugin tests, and Markdown lint.
- Earlier post-integration Java 21 `make test-examples` passed Basic, Spring Boot, CVE-unused, and CVE-safe-class fixtures, including package/runtime checks. The work package did not rerun examples during this documentation closeout.
- The exact-content warm trim-cache path is about 93 ms in the latest JMH evidence, above the <10 ms target; the per-artifact fast-path target of <1.5 ms is also unmet. Performance acceptance is deferred despite approval of the functional and reporting slices. The repeated same-request cache hit can be below the target; fresh-context validation is not. See [RQ-0003](../research/RQ-0003-sub-10ms-maven-fast-path-invariant-and-benchmarking.md) and the [performance follow-up](2026-10-26-performance-follow-up.md).
- Example Maven elision overhead is descriptive, not a stable guarantee: the latest paired medians are about +1.977 s for Basic and +20.417 s for Spring Boot. See [RQ-0003](../research/RQ-0003-sub-10ms-maven-fast-path-invariant-and-benchmarking.md).

## Decisions, deviations, and open questions

- `elide.sourceRootsComplete=false` is the safe default. Setting it true asserts all production/generated sources exist before `INITIALIZE` and no later processor/generator adds references.
- The Maven 3.9.9 direct dependency-artifact set is preserved to avoid triggering re-resolution. Resolved/project views and matching direct object file pointers are changed. Maven 4 and unrelated downstream mojos remain unverified.
- Retained multi-release and root-module-info classpath JARs pass through unchanged by default with warnings and conservative effective-class roots. This does not establish JPMS module-path closure or deployments on a different runtime feature.
- Explicit pass-through JARs tolerate only their own unresolved external links; normal candidates remain strict. Unsupported compiler settings and archive layouts fail closed.
- The exact-content cache validation target remains unmet; no metadata-only cache shortcut was adopted.
- OSV-Scanner invocation, CVE-to-class mapping, and VEX generation are not implemented. RQ-0008 evaluates package-level SBOM comparison separately from evidence-gated code absence.
- Example transcript generation/update/check is not implemented. RQ-0009 evaluates the user-provided Draft/open [PR #651](https://github.com/tetratelabs/built-on-envoy/pull/651) as a proposal for configured invocations, transcript capture, conservative normalization, explicit update/check targets, and CI; its exact implementation has not been independently established here.
- Session procedure now requires a supplied or prompt-snapshotted handover and a sibling `-closeout.md` artifact. This requirement was added during this closeout.
- RQ-0006 remains open: `dependency-elider:report` does not retain original Maven-mediated dependency graph paths. RQ-0007 covers plugin-site publication.

The complete specification deviation log is in [the work-package status ledger](../../.scratch/orchestration-status.md), with accepted architecture in [the ADR index](../adr/README.md), contributor decisions in [the contributor register](../contributor-decisions-and-faq.md), and unresolved investigations in [the RQ index](../research/README.md).

## Commit history and change size

The complete ordered branch log is available with `git log --oneline --reverse e893087..HEAD`. Slice 7.5 source commits `a0bbe6d` and `baaf345` were integrated before rebase as `323fcde` and `6a3f210`; their current rebased integrations are `cb65adc` and `6e4704e`. Report and documentation follow-ups include `c9027a5`, `21124df`, and `2120b9f`; this closeout is committed separately.

Cumulative diff statistics against base `e893087` are 115 files, 16,635 insertions, and 573 deletions, including this closeout sibling and the final session documentation. Reproduce them with `git diff --stat e893087..HEAD` after the documentation commit. The complete ordered integration log is available with `git log --oneline --reverse e893087..HEAD`; selected implementation/report milestones are listed above and in the orchestration status ledger.

## Remaining integration action

The current main worktree has uncommitted or untracked changes at paths that overlap the WP branch. Do not overwrite or merge until they are reconciled with their owner. The known overlaps are:

- `.agents/skills/skills/orchestrate-and-implement/SKILL.md`
- `README.md`
- `docs/adr/0003-proguard-core-intra-jar-trimming-and-cyclonedx-pedigree.md`
- `docs/adr/0004-assume-resolved-inputs-stable-during-build.md`
- `docs/adr/README.md`
- `docs/handovers/2026-10-25-intra-jar-trimming-work-package.md`
- `docs/research/README.md`
- `docs/research/RQ-0001-sub-artifact-bytecode-symbol-slicing-and-provenance.md`
- `examples/run-elision-cycle.sh`
- `examples/support/run_spring_boot_endpoint.py`
- `examples/support/verify_class_usage_report.py`
- `examples/support/verify_spring_mail_artifacts.py`

Other dirty main files did not overlap the WP branch at assessment time. The assessment is read-only; confirm main status immediately before any future integration. No worktree was removed and no chat archive was attempted.

## Tool-use and manual-edit assessment

See [semantic-tool assessment](../SUBOPTIMAL_TOOLS.md) and [manual-edit record](../MANUAL_EDITS.md). No semantic operation was invoked in this delegated closeout turn; the assessment is explicitly limited to the visible turn because a transcript identifier was unavailable. Repository-native reads/patches, Git, Markdownlint, and Java 21 `make check` were used. No source-code fallback was needed.
