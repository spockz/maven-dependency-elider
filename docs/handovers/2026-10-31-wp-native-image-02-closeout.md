<!-- WHY: Records WP-NATIVE-02 scope, correction evidence, and the current review boundary. -->
# Work Package Closeout: WP-NATIVE-02 Native-Image Argument Ingestion

## Outcome

WP-NATIVE-02 implements the bounded GraalVM Native Image argument and descriptor inventory described in [the handover](2026-10-30-wp-native-image-02-exhaustive-flag-inference-and-permissive-acceptance.md). Sol approved final correction commit `e28c7376bc412bb0c00cda5a003151cf9f3a0afa`. After user sign-off, `track/native-image-02` was fast-forwarded into local `main` at `f2f383503ec5c9cd00b8aafc47345bd429232339` on 2026-10-31; no remote push was made.

## Correction coverage

- No-trim finish revalidates consumed external descriptor bytes and `LinkAtBuildTimePaths` aliases.
- Forwarded Java-agent options reject exact bare, empty, and malformed forms while unrelated near misses remain accepted.
- Empty and truncated predefined classdata fail with hash and configuration-path context. Tests use fresh inputs for each byte fixture, include a valid control, and prove deep truncation reaches ASM.
- CLI and descriptor bundle names share the Unicode resource-family grammar; parity tests use matching class and properties resources.
- Mixed-option coverage traces `Entry`, roots otherwise unreachable `closure.b.Unused`, and proves the selected trimmed B archive keeps `Middle` and `Unused` while removing the distinct `Discarded` control.
- File captures use an insertion-ordered keyed `SequencedMap`, avoiding quadratic sibling lookup without synchronization. Feature roots are routed per archive without a duplicate invocation-level aggregate.
- Bundle selection, archive inventory, owner routing, and sequential context construction use the reviewed hot-path and allocation refinements.
- Descriptor archive and artifact-replacement helpers are shared across service-loader, initialization, and configuration-resource trim tests. MRJAR-specific fixture construction remains separate.
- `.scratch/orchestration-status.md` was restored to the requested `b7ea8bbc` version in this track only.

No additional behavior beyond ADR-0009 and RQ-0016 was introduced. ADR-0009, RQ-0016, the Native Image FAQ, and the contributor decision row now describe the shared bundle grammar and malformed classdata behavior.

## Verification

The exact command `JAVA_HOME=/workspace/sources/maven-dependency-elider/.scratch/toolchains/graalvm-jdk-21.0.12+7.1 make fmt lint-java test-plugin test-core` passed on the corrected branch. Spotless was clean; Checkstyle reported 0 violations; PMD passed without new suppressions; SpotBugs reported 0 warnings; core tests passed 246/246; plugin tests passed 552/552; lifecycle integration tests passed 16/16. Markdown lint passed across 65 files with 0 issues. The full acceptance output is recorded at `/tmp/wp-native-image02-review-fixup5-acceptance.log`; Markdown lint output is at `/tmp/wp-native-image02-review-fixup5-markdown.log`.

## Review and compatibility

The [final Sol correction review receipt](../../.scratch/reviews/wp-native-image-02-review-fixup.md) approves `e28c7376bc412bb0c00cda5a003151cf9f3a0afa`: all five findings are resolved and no actionable findings remain. The earlier [Sol contract-slice receipt](../../.scratch/reviews/wp-native-image-02-slice-1-contract.md) covers only the contract and documentation slice. A Gemini bridge review could not run because no Gemini bridge tool is present in this environment's tool catalog.

No persisted schema version or migration policy changed. Unreleased format versions remain at version 1. The package is integrated into local `main` by fast-forward; the remote was not updated.
