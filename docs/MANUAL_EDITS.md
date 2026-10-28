<!-- WHY: Records source-edit methods and verified fallbacks so future sessions can distinguish ordinary repository edits from unsupported semantic-tool claims. -->
# Manual Edit Records

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
