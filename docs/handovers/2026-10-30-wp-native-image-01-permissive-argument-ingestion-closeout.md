# WP-NATIVE-01 Closeout: Permissive Native-Image Argument Ingestion

## Verdict

**Complete.** WP-NATIVE-01 was implemented, reviewed, fast-forwarded to `main`, and verified after integration.

## Identity and integration

- Source handover: [`2026-10-30-wp-native-image-01-permissive-argument-ingestion.md`](2026-10-30-wp-native-image-01-permissive-argument-ingestion.md).
- Base: `main` at `ee1b3d7`, including MRJAR vertical shading and the conservative optional-link fix.
- Integration: fast-forwarded `main` to `c4b509f` (`fix: integrate native-image fallback with MRJAR shading`).
- Implementation commits: `3b54433`, `0a67fc0`, `cdae1e3`, and `c4b509f`.

## Delivered behavior

- Native-image `Args` tokenization respects quoted values, removes syntactic quotes, preserves backslashes, and rejects unmatched quotes or empty tokens.
- Modeled class and resource roots are validated before name-only allowlist matching.
- Strict mode reports actionable details for unknown arguments. Permissive mode retains only the affected archive byte-identically, excludes it from both trim paths, and includes its classes in sibling link closure.
- Native-image fallback and MRJAR vertical shading remain independent: fallback does not prevent other MRJARs from shading, and unchanged MRJAR tiers continue to contribute their required sibling closure.
- Effective policy inputs participate in graph and trim-cache identity.
- User and research documentation describe the implemented policies; open RQ-0016 work is limited to a broader non-class flag taxonomy and additional dynamic resource formats.

## Review

- The dedicated reviewer approved the integrated code and strengthened Spring assertions after checking selected target-tier bytes against elevated root bytes and verifying the preserved Jackson Core Java 22 tier.
- The critical architect approved constructor/default behavior, root precedence, bounded fallback retention and closure, independent MRJAR shading, cache identity, and combined regression coverage. Its two documentation findings were corrected and the resulting Markdown lint passed.
- The Gemini review bridge was absent from the available tool catalog; the documented fail-open path was followed.
- The referenced MRJAR thread traced its Spring issue to transcript commands using default vertical shading while its legacy workflow used `pass-through` for optional Kotlin links. A cross-thread send-message tool was unavailable, so its investigation was read through the available thread reader.

## Verification

- Post-merge `make check` on `main`: 242 core tests, 398 plugin tests, 15 Maven lifecycle integration tests, and 8 SBOM comparison tests passed. Formatting, Checkstyle, PMD, SpotBugs, Markdown lint (59 files, 0 issues), SBOM comparison, and transcript drift verification passed.
- `make test-examples`: five standalone fixtures and the multi-module reactor passed. Spring nested Jackson Core and SnakeYAML assertions verified target-tier class byte identity, class-count reduction, and unchanged upper-tier bytes.
- `bash -n examples/run-elision-cycle.sh`, `git diff --check`, and `git show --check HEAD` passed.
- The repository's existing Node.js SBOM test ran under the user's explicit authorization despite the general repository Node.js restriction; no new Node.js tooling was added.

## Deviations and limits

- The handover's `[INFO]` fallback log level was resolved in favor of warning level as accepted by ADR-0009 and RQ-0016.
- Tolerated unknown native-image options do not broaden modeled roots or allowlist semantics.
- Additional reflection-resource JSON schemas remain open research and were outside this work package.
- The integration branch was fast-forwarded after explicit user approval. The merged `main` checkout passed the post-merge gate and was clean afterward.
