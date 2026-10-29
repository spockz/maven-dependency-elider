<!-- WHY: Preserves the transcript tooling work-package outcome and remaining verification gate beside its source handover. -->
# WP-TRANSCRIPT-01 Closeout: Automated Command Transcripts and README Drift

## Work package and verdict

- **Owner:** Codex coordinating session.
- **Source handover:** [`2026-10-28-wp-transcript-01-automated-command-transcripts-and-readme-drift.md`](2026-10-28-wp-transcript-01-automated-command-transcripts-and-readme-drift.md), plus the original user request in `.scratch/handover.md`.
- **Base:** `a1f9f3bc6bc89e22dfa8051faf7d606d4f879e5f`.
- **Track:** `track/command-transcripts` in `.scratch/worktrees/track-command-transcripts`.
- **Verdict:** **INCOMPLETE pending rebase.** Implementation and independent review are complete in the isolated worktree. The full `make check` passed on the track at base `a1f9f3b`. Local `main` advanced to `8d5c9a69` during wrap-up and has unrelated dirty and untracked research documents, so the track must be rebased and checked again before commit and integration.

## Acceptance criteria

1. **Manifest and command contract: implemented.** `scripts/transcripts-manifest.json` records the setup command and six exact Maven invocations, working directories, arguments, expected codes, target docs, expected CVE evidence, and graph limits.
2. **Capture, normalization, and elision: implemented and reviewed.** The Go runner captures command output and failures, normalizes only named Maven timing/PID fields and exact project/evidence roots, validates markers, and elides report graph rows after three with a count and SHA-256 digest. Rerunning the displayed `report` command prints the full graph; a separate expansion target remains deferred.
3. **Explicit update/check modes: implemented and drift-checked.** `make update-transcripts` is the only mode that writes documentation. `make check-transcripts` has a separate compare-only code path; after setting the repository-managed Java 21 `JAVA_HOME`, it passed twice and reported that transcripts are up to date. The first attempt exited before setup because `JAVA_HOME` was unset.
4. **Examples, contributor docs, and research: implemented.** README and plugin usage contain generated regions. Contributor guidance documents the manifest, placeholders, normalization, output elision, pinned cache limitations, workflow, and side effects. RQ-0009 records design/evidence/open limits; RQ-0011 corrects the persisted report behavior.
5. **CI wiring: implemented.** GitHub Actions installs Go 1.24.4. `make check` runs `check-transcripts` after parallel Maven work to avoid concurrent fixture writes. The local full check passed; the hosted workflow was not run.

## Implementation and evidence

- Added a standard-library Go manifest runner, test-free fixture preparation script, and a two-record pinned CVE cache. Analyze/elide use Maven offline mode with this copied cache; baseline dependency provisioning may use configured repositories.
- The Spring trace is accepted only after `/api/hello` returns HTTP 200 with the expected body.
- Updated README, plugin usage, contributor decisions, RQ-0009, and RQ-0011. The report snapshots contain persisted vulnerability groups, so RQ-0011 now documents that `report` replays the last snapshot rather than rescanning advisories.
- Ran `make update-transcripts` twice. Both completed; the final run using the narrowed normalizer reported `Configured command transcripts are up to date.`
- Before the wrap-up assessment edits, static checks passed: `gofmt`, Go build, `bash -n`, `jq empty` for both JSON files, `git diff --check`, and Markdown lint (46 files, zero issues). After those edits, `make check-transcripts` passed again and `git diff --check` passed. Markdown lint was not rerun because the configured linter uses Node.js.
- No tests were added. The first full `make check` attempt stopped because this linked worktree lacked the local Markdownlint executable. Retrying with the existing executable from the main clone passed: Markdownlint covered 47 files with zero issues; 195 core tests, 267 plugin tests, 15 lifecycle integration tests, and 8 SBOM comparison Node tests passed; the transcript drift gate reported that examples are up to date. The CI workflow was not run. Cold dependency resolution and repeated CI behavior remain unverified.

## Review and diff

- Dedicated track reviewer: **APPROVED**. Receipt: `.scratch/reviews/track-command-transcripts-slice-1.md`.
- Critical architect: approved cache isolation, normalization scope, and graph expansion behavior by read-only review.
- External `gemini_review_diff` was unavailable in the enabled tool inventory; the configured fail-open review path was used.
- The current track diff contains 9 modified tracked files (321 insertions, 65 deletions) and 6 new runner/setup/fixture/closeout files. No implementation commit exists yet.
- Track tool assessment: `.scratch/reviews/track-command-transcripts-wrapup.md`.
- Manual edit log: `.scratch/manual-edits/track-command-transcripts.md`.
- Tool friction log: `.scratch/suboptimal-tools/track-command-transcripts.md`.
- Repository `AGENTS.md` and the local wrap-up skill now require `make update-transcripts` when relevant example behavior or documented output changes.

## Remaining work

1. Rebase the reviewed track onto local `main` at `8d5c9a69`, preserving the destination's `docs/research/README.md` modification and untracked WP-VEX handover/RQ-0015 documents.
2. Resolve any content conflicts using both sides' intent and rerun `make check` on the rebased tree.
3. If the combined tree passes without further changes, commit the track and fast-forward local `main`. Then confirm the main and source worktrees are clean, clear any worktree-local Go module cache, remove the completed linked worktree, and archive the chat.

## Example maintenance in future work

When future changes affect an example fixture, its documented Maven invocation, or captured README/plugin output, run `make update-transcripts` (`go run scripts/update-transcripts.go --update`) before closing the work. Review and include the generated diff; do not edit content inside transcript marker blocks manually.
