<!-- WHY: Records the reviewed implementation, verification evidence, timing limits, and integration outcome for WP-Test01. -->
# Work Package Closeout: WP-Test01 Test Suite and Verification Velocity

## Outcome

WP-Test01 is complete. The implementation was rebased onto the current local `main`, passed the full post-rebase `make check`, and was approved by the dedicated track reviewers and the whole-system architect. The checked integration branch is the tree to fast-forward to local `main` as the final wrap-up step.

The package did not establish the handover's target of a greater than 40% reduction in overall `make check` time. We preserve measured per-track results and avoid attributing a speedup to overlapping or uncontrolled runs.

## Implemented tracks

| Track | Rebased commits | Result |
| :--- | :--- | :--- |
| Shared fixtures and global test state | `f7954cc` | Reused immutable test JAR bytes and JDK API templates while materializing fresh mutable class models. Isolated global-property writers and restored prior property state. |
| Test lifecycle and bounded test concurrency | `5804062` | Moved the nested Maven lifecycle test to Failsafe, separated unit and integration targets, bounded Maven/JUnit concurrency, and isolated nested Maven state. |
| Example fixture scheduling | `eaaee5e`, `68336ea` | Extracted the standalone fixture worker and added two-worker scheduling for five standalone fixtures. Shared setup/MRJAR and reactor join barriers remain serial; logs are ordered and failures retain per-fixture evidence. |
| Transcript scheduling | `7c50803`, `88c7fc7` | Added a four-worker Go pool grouped by normalized Maven `-f`/`--file` target. Commands for one fixture remain serial. Results and all independent fixture errors preserve manifest order. Documentation reconciliation starts only after every command and marker validation succeeds. |

## User-facing guidance

Root `AGENTS.md` and `.agents/skills/skills/wrap-up/SKILL.md` already direct contributors to refresh generated examples with `make update-transcripts` and verify with `make check-transcripts`. This guidance was checked and retained without adding duplicate instructions. The contributor FAQ, RQ-0003, and RQ-0009 describe the implementation and its limits.

## Verification

The pre-closeout post-rebase full `make check` exited 0 at integration commit `bc08bb9`. It passed 246 core tests, 445 plugin tests, 16 lifecycle integration tests, Java static checks, Markdownlint, SBOM comparison tests, the Go transcript behavior tests, scheduler synchronization tests, and transcript drift verification. The generated command transcripts were up to date. Log: `/tmp/wp-test01-post-main-rebase-check.log`.

After adding this closeout document and recording its verification, the final full `make check` also exited 0 before the local-main fast-forward. It passed the same suites and confirmed `Configured command transcripts are up to date.` Log: `/tmp/wp-test01-final-closeout-check.log`.

The example gates also passed: serial `EXAMPLE_JOBS=1 make test-examples` in 194.019 seconds, two-worker `EXAMPLE_JOBS=2 make test-examples` in 124.045 seconds, `make test-reactor-example`, and `make check-transcripts`. The serial/parallel measurements were taken while another worktree ran a full check; they are indicative only and do not establish a speedup. The strict reactor lifecycle remains sequential, with `-T 4` retained as a separate threaded-builder verification.

The initial transcript-tool check stopped before formatting because `JAVA_HOME` was unset. The configured retry passed using the repository-managed Java 21 toolchain, existing Markdown linter, and isolated Maven repository. No generated transcript blocks changed.

## Reviews and compatibility

Each track received dedicated implementation and independent review. Whole-system review approved the rebased tree at `bc08bb9`; it confirmed the cross-track test isolation, bounded workers, setup/join barriers, fixture grouping, ordered output/error handling, and writer boundary.

The work changes no persisted data format, protocol, plugin compatibility promise, or schema version. No ADR or migration was added.

## Integration and cleanup

The verified integration branch was rebased onto local `main` at `fb2ade3`. The main checkout's two untracked handover documents were preserved and were not staged, overwritten, or removed. After this closeout document, the full check is rerun; the checked tree is then fast-forwarded to local `main`. Track worktrees and temporary integration worktrees are removed only after the final fast-forward, with needed review/verification receipts preserved in the coordinator scratch area.
