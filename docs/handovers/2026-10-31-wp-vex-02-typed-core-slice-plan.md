<!-- WHY: Records the reviewable boundary for the first typed evidence implementation slice. -->
# WP-VEX-02 Typed Core Slice Plan

## Goal

Introduce a typed proof admission seam for explicit POM assertions without changing the existing omitted-code archive checks or ADR-0008 inventory proof.

## Included

1. Add immutable typed evidence for a validated POM `vulnerableClasses` assertion and for an explicit prerequisite mapping containing both `requiresDependency` and `requiresClass`.
2. Keep evidence origin explicit as POM and retain the exact affected Maven coordinate, CVE identity, and mapping values used by the proof.
3. Change `OmittedCodeProof` to accept class-mapping evidence only and `PreconditionProof` to accept prerequisite evidence only. Reject a wrong evidence kind at compile time through the method signatures.
4. Migrate the production assessment boundary to construct proof evidence only for configured POM mappings. Cache/advisory mappings without typed provenance remain ineligible at this seam.
5. Migrate direct proof tests and fixtures, and add focused checks that proof dispatch preserves the POM origin and that prerequisite-only evidence cannot enter omitted-code proof while class-only evidence cannot enter precondition proof.
6. Preserve the existing physical archive presence/absence checks, digest rechecks, precondition inventory completeness/freshness behavior, output serialization, and transactions.

## Excluded

Structured CVE source attribution, heuristic/package candidate variants and reporting, cache schema/producer gates, conventional-layout configuration, source lookup, report changes, and generated example updates remain later slices. No `HIGH` enum migration is attempted outside the proof admission boundary in this slice.

## Implementation sequence

1. Add the immutable evidence types and validation/factory methods.
2. Narrow proof method parameters and update assessment/test callers.
3. Add dispatch/origin tests while retaining the existing archive and ADR-0008 proof scenarios.
4. Run focused module tests, then `make check` with GraalVM JDK 21.0.12 and the configured `MARKDOWNLINT` binary.
5. Review the diff and commit only the plan and first-slice implementation files, preserving unrelated worktree changes.

## Acceptance

Only explicit POM-origin typed evidence reaches either proof API. A successful proof still depends on every pre-existing physical artifact, digest, class inventory, identity, and completeness check. The worktree contains no unrelated changes in the implementation commit.
