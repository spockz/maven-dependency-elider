<!-- WHY: Records WP-NATIVE-02 scope, correction evidence, and the current review boundary. -->
# Work Package Closeout: WP-NATIVE-02 Native-Image Argument Ingestion

## Outcome

WP-NATIVE-02 implements the bounded GraalVM Native Image argument and descriptor inventory described in [the handover](2026-10-30-wp-native-image-02-exhaustive-flag-inference-and-permissive-acceptance.md). This correction branch, `track/native-image-02`, is based at `a63d3e5` and remains unmerged for independent read-only Sol review.

## Correction coverage

- No-trim finish revalidates consumed external descriptor bytes and `LinkAtBuildTimePaths` aliases.
- Forwarded Java-agent options reject exact bare, empty, and malformed forms while unrelated near misses remain accepted.
- Empty and truncated predefined classdata fail with hash and configuration-path context.
- CLI and descriptor bundle names share the Unicode resource-family grammar; parity tests use matching class and properties resources.
- Mixed-option coverage keeps untraced, otherwise unreachable `closure.a.Extra`, traces `Entry`, roots `Middle`, and proves `Unused` is physically removed.
- Bundle selection, archive inventory, owner routing, feature roots, and sequential context construction use the reviewed hot-path and allocation refinements.
- Descriptor archive test helpers are shared where their entry semantics match. MRJAR-specific fixture construction remains separate.
- `.scratch/orchestration-status.md` was restored to the requested `b7ea8bbc` version in this track only.

No additional behavior beyond ADR-0009 and RQ-0016 was introduced. ADR-0009, RQ-0016, the Native Image FAQ, and the contributor decision row now describe the shared bundle grammar and malformed classdata behavior.

## Verification

The exact command `JAVA_HOME=/workspace/sources/maven-dependency-elider/.scratch/toolchains/graalvm-jdk-21.0.12+7.1 make fmt lint-java test-plugin test-core` passed. Spotless was clean; Checkstyle, PMD, and SpotBugs passed; core tests passed 246/246; plugin tests passed 550/550; lifecycle integration tests passed 16/16. The final focused correction regressions passed 7/7.

## Review and compatibility

The existing [Sol contract-slice receipt](../../.scratch/reviews/wp-native-image-02-slice-1-contract.md) approves the contract and documentation slice; it does not cover this correction implementation. This branch is awaiting a new independent read-only Sol review. A Gemini bridge review could not run because no Gemini bridge tool is present in this environment's tool catalog.

No persisted schema version or migration policy changed. Unreleased format versions remain at version 1. This branch is intentionally left unmerged.
