<!-- WHY: Records the supplied session prompt, baseline, scope, and acceptance for rebasing WP-TRIM-01 onto cleaned main. -->
# WP-TRIM-01 Main Rebase Handover

## Prompt snapshot

> Main has been cleaned up. Rebase and review.

No handover file was supplied in the initial prompt for this session, so this prompt is recorded here.

## Work package

- Identifier: WP-TRIM-01 main-rebase reconciliation.
- Prior package: [WP-TRIM-01 specification](2026-10-25-intra-jar-trimming-work-package.md) and [prior closeout](2026-10-25-intra-jar-trimming-work-package-closeout.md).
- Scope: inspect the current `main` and package branch, rebase `work-package/wp-trim-01` in its retained worktree onto clean `main`, preserve both the package implementation and main changes, verify the result, and record closeout.
- Out of scope: merging into or modifying `main`, deleting worktrees, or changing the package's documented unmet performance acceptance.

## Starting state

- Main checkout: `/workspace/sources/maven-dependency-elider`, branch `main`, clean at `817956fdc69886abb859f7fc168d555fc3f3a563`.
- Package checkout: `.scratch/worktrees/wp-trim-baseline`, branch `work-package/wp-trim-01`, clean at `aa44361222205969aa51c1aeac80428ca0b53e99`.
- The package has approved functional and reporting slices, but remains incomplete against its original performance targets; see the prior closeout.

## Acceptance

- The package branch is based on the recorded clean main commit and contains both main's changes and WP-TRIM-01's approved work.
- Rebase conflicts are resolved without losing either side's intended behavior.
- Required formatting, lint, and test checks pass after the rebase.
- A sibling `2026-10-26-wp-trim-main-rebase-closeout.md` records the final branch hashes, verification, review state, and remaining limitations.
- Main remains unchanged by this session.
