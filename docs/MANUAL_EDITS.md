<!-- WHY: Records source-edit methods and verified fallbacks so future sessions can distinguish ordinary repository edits from unsupported semantic-tool claims. -->
# Manual Edit Records

## 2026-10-29: WP-REACTOR-01 implementation and wrap-up

This wrap-up updated the tooling assessment and manual-edit log with repository-native patches. No source files were edited in this turn and the transcript extractor found no semantic editing operation across the retained root and three child logs; its two command candidates were reviewed and classified as an `rg` search and the helper invocation. The earlier task summary does not preserve individual source-edit invocations, so it is not used to claim a semantic edit fallback or its absence. The Python transcript helper was run with the user's wrap-up authorization; app history lookup still returned `No handler registered`. The Java-only `make java-check` gate passed in 171 seconds with 195 core tests, 267 plugin tests, 15 lifecycle tests, and Java lint checks. The first full `make check` attempt ran for 200 seconds and stopped because the configured Markdown linter was missing from this worktree. Retrying with the existing main-checkout linter executable passed the complete check in 182 seconds, including Java lint/tests, Markdownlint, and 8 SBOM comparison tests; a final-state rerun after the last log edit also completed every check successfully. Spotless changed no tracked files.

## 2026-10-25: Initial implementation session closeout

No semantic editing operation was attempted in the retained session evidence. Repository-native patches and direct file edits were the normal workflow, followed by Spotless, Checkstyle, PMD, SpotBugs, and behavioral tests. Documentation edits used the Markdown linter. This is not recorded as a semantic-tool failure or a measured performance improvement.

Historical track records describe direct edits to the cache implementation/tests, benchmark Java/POM/README files, and the truncated JaCoCo-input fixture after review. Other records report implementer changes in isolated worktrees without coordinator source-edit fallback. These records are preserved with the review evidence archive; exact per-edit wall-clock comparisons are unavailable.

During closeout, the coordinator rebased the approved implementation chain, autosquashed its scanner fixup, and integrated it by fast-forward. The existing Track 8 implementer/reviewer pair added and approved the isolated javac visibility probe. No intra-JAR prototype code was integrated. Its four uncommitted files were archived with per-file hashes before worktree cleanup; see the [session handover](handovers/2026-10-25-session-closeout.md).

The final terminology follow-up edited the orchestration skill and its two references with repository-native patches. It defines work package → tracks → slices, ownership by one coordinating thread/session, and separate completion and session-closeout verdicts. No semantic tools or manual source-code fallbacks were needed; validation uses the skill validator and repository checks.

The final handover correction distinguishes the compiler probe's classpath-integration proof from correct source-dependency retention. README, RQ-0001, RQ-0004, and the handover now route whole-JAR source-root protection to the next user-defined work package; no implementation was added during this correction.

## 2026-10-26: WP report and vulnerability-assessment documentation closeout

This turn updated README, FAQ, research-register/RQs, orchestration skill, work-package closeout, and integration-receipt documentation with repository-native patches. No source-code edits or semantic editing operations were used, so there was no manual source-edit fallback or semantic-tool failure to record. Assessment coverage is limited to the visible delegated work-package turn; no transcript identifier was available for broader history extraction.

## 2026-10-27: WP-TRIM-01 final integration wrap-up

The closeout was updated with repository-native `apply_patch`; no source-code file was changed and no manual source-edit fallback was needed. No semantic editing operation was invoked. The wrap-up command history available to this delegated turn contains only repository reads, Git inspection, and documentation/check commands; earlier package implementation edits are covered by existing session and track records.

## 2026-10-28: WP-RESOLVE-01 implementation and README rerun

Implementation and documentation edits used repository-native `apply_patch` and file reads because no semantic editing or refactoring operation was available/invoked in this session. The lifecycle participant was split into focused package helpers, tests were expanded for bare-tree ordering and fail-fast boundaries, persisted report formats and docs were updated, and the README's Quick Start was replaced with commands executed against `example-basic-app`. The original README elide command did not include the fixture's source-completeness, annotation-processing, and excluded-artifact settings; a run against Basic failed on unresolved optional XZ references. The documented fixture settings now match the successful example invocation. Spotless, Java checks, lifecycle tests, example verification, and Markdownlint were used to validate edits.

No semantic edit failure or automated-edit fallback is recorded. This is a workflow/capability note, not evidence that repository-native edits were inferior; no equivalent semantic workflow was run.

## 2026-10-28: WP-VEX-01 implementation and wrap-up

The vulnerability assessment, SBOM/VEX publishing, Analyze summary, tests, and example-gate corrections were edited with repository-native `apply_patch`, then checked with Maven and the complete example runner. No semantic editing operation was invoked, so these edits were the normal repository workflow rather than a fallback from a failed semantic edit. The example assertions were revised from observed report/archive behavior after integration failures; `make test-examples` passed after correction. No semantic edit failure or unrecorded source-edit workaround occurred in the retained transcript evidence.

## 2026-10-29: Automated command-transcript tooling wrap-up

The available task summary reports repository-native Go, shell, Make, and documentation edits for transcript generation and output elision. No semantic editing operation was attempted, so these were the normal project workflow rather than a fallback from a failed semantic edit. The full earlier thread transcript and child-agent tool logs were unavailable; no additional source-edit failure or workaround can be established from the retained evidence.

## 2026-10-29: WP-TRANSCRIPT-01 post-rebase verification

Repository-native `apply_patch` sorted conservative ServiceLoader root names before rendering advisory reasons and added a regression test for reverse-insertion input. The first post-rebase `make check` hit an intermittent parallel-trimming worker null dereference; a setup rerun passed, and the next full check exposed unstable root ordering in the generated report. After the ordering fix, a full `make check` passed with 195 core tests, 267 plugin tests, 15 lifecycle tests, 8 SBOM comparison tests, Java and Markdown lint, and transcript drift verification. A later rerun after wrap-up log edits failed during fixture setup with `NoSuchMethodError`: the installed plugin expected `JdkApiClassPoolReader.readFrozen`, while the worktree's installed core artifact lacked that method. The worktree target JAR had the method, so the local snapshot artifacts were inconsistent; the mismatch's origin is unknown. No source changes resulted from that failure. The next full `make check` passed with the same suites and transcript gate; no code change was needed between the failed and passing runs. No semantic editing operation was invoked; repository-native patches were the normal method, not a fallback from a rejected semantic edit. The earlier full thread transcript and child-agent logs were unavailable, so this records only the visible wrap-up work.

## 2026-10-30: WP-NATIVE-01 final integration

The native-image/MRJAR integration and its documentation used repository-native `apply_patch`, Git, Make, and Maven. No semantic edit operation was available or used, and no manual source-edit fallback followed a failed semantic edit.
