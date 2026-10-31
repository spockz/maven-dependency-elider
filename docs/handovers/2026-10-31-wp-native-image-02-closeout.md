<!-- WHY: Records WP-NATIVE-02 implementation scope, integration review, and verification evidence. -->
# Work Package Closeout: WP-NATIVE-02 Native-Image Argument Ingestion

## Outcome

WP-NATIVE-02 is implemented on a branch synchronized with `main` at `b7ea8bbc33c2b24c2ca3f1ef146602bbbf3da6fd`. The package adds class-root inference for the audited Native Image argument and descriptor inventory, accepts unmodeled non-class compiler options without pass-through fallback, and retains explicit errors for malformed syntax and audited hidden inputs. Its handover is [2026-10-30 WP-NATIVE-02](2026-10-30-wp-native-image-02-exhaustive-flag-inference-and-permissive-acceptance.md).

## Implementation

| Slice | Commit | Result |
| :--- | :--- | :--- |
| Resource selectors and descriptor semantics | `da4f0ac`, `da0f6fc` | Matched the pinned GraalVM selector grammar, preserved empty module semantics, and resolved selected classes against archive owners. |
| Audited indirection rejection | `1a8f958` | Rejects argfiles, class/module paths, launch operands, and audited nested JVM inputs before artifact mutation. |
| Permissive argument acceptance | `80e93a2` | Removed allowlist and fallback controls; unknown non-class options no longer disable trimming. |
| Effective root routing | `6b468fb` | Routes deferred resource and ServiceLoader feature roots into owner scans so effective and multi-release trimming retain selected classes. |

The main refactor was preserved during branch synchronization. Consumed external configuration identities remain part of graph and trim cache keys, with revalidation after graph binding and immediately before direct output publication. A mutation regression proves staged output is discarded when a descriptor changes before publication.

## Verification

The full `make check` passed on the synchronized tree using GraalVM 21.0.12+7.1 and the existing `markdownlint-cli2` installation. It passed 246 core tests, 547 plugin tests, 16 lifecycle integration tests, Java static checks, Markdown lint, the fixture scheduler, SBOM comparison tests, and transcript drift checks. Configured command transcripts were up to date. Log: `/tmp/wp-native-image02-final-check.log`.

The focused direct-publication mutation regression passed (1 test), and `make lint-java` passed independently after the final publication-boundary changes. Independent review approved the synchronized implementation and its owner-root, cache-validation, and publication behavior.

## Compatibility and integration

No persisted schema version or migration policy changed. Unreleased format versions remain at version 1. The validated package branch is ready for a fast-forward to `main` after explicit user sign-off.
