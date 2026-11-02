<!-- WHY: Captures the final delivery state and evidence for the completed WP-VEX-02 orchestration. -->
# WP-VEX-02 Closeout Handover

## Delivery

WP-VEX-02 is complete. The original reviewed implementation commit is `90f9c48b86f76be1bb2c8294d3df3eccff8fdd6c`. A clean check from that delivery found two PMD LawOfDemeter findings in `MavenStructuredProofCacheFixtures`; correction commit `3715439be8895e0657fe45d4443ac2418b0b2511` derives its coordinate from the prepared scenario. The exact corrected candidate with closeout updates, `74c9ca5439bed743dd9a006f1a263cdef0f21c25`, received both GO reviews and was fast-forwarded to local `main`. `git merge-base --is-ancestor` verified that it remains in the delivery target. The final receipts are `.scratch/reviews/wp-vex-02-final-completion-74c9ca5.md` and `.scratch/reviews/wp-vex-02-track-completion-74c9ca5.md`; the original `90f9` receipts remain preserved too.

The main checkout had 52 pre-existing dirty or untracked paths. They were preserved across integration and restored from stash `1e5aaf91ba6cb869796c968996ac6c7bea4369dc`. The two overlapping transcript scripts retain both feature-branch private Maven-repository wiring and main's `-f` path normalization and tests. The stash backup remains available. No remote push was requested.

## What was delivered

For supported Maven Java artifacts, the plugin can bind structured CNA file or routine claims to the exact assessed artifact, its exact Maven `sources` classifier, and the live advisory inputs. It reproduces the supported source set with the pinned compiler, checks the complete class output against the artifact, and proves the claimed class family is physically absent before issuing structured omitted-code evidence. Reports and VEX preserve provenance while keeping unresolved leads, heuristic findings, POM evidence, and structured proof separate.

The automatic path is limited to ordinary non-MRJAR Java builds under GraalVM JDK 21.0.12+7.1 and the documented fixed compiler setup. Unsupported or ambiguous inputs abstain. The conventional-layout option permits only the documented path-root translation. The pinned compiler is isolated from auto-start plugins discovered through both the original artifact and ambient application classpath; marker-provider tests prove neither executes.

## Verification

On the corrected integrated candidate, the docs-inclusive `make check` passed with core 334/334, plugin 631 total (630 passed, 1 skipped), and lifecycle 16/16. Coverage and transcript checks also passed. Log: `/tmp/wp-vex02-pmd-fix-docs-make-check.log`. The separate `make test-examples` passed five standalone fixtures and the multi-module reactor, including sequential and `-T 4` checks; log: `/tmp/wp-vex02-pmd-fix-test-examples.log`. The post-closeout `timeout 600s make lint-markdown` passed for 72 files with 0 reported issues; log: `/tmp/wp-vex02-closeout-lint-markdown.log`.

Standalone `make test-examples` passed for five standalone fixtures and the multi-module reactor, including sequential and `-T 4` checks. Log: `/tmp/wp-vex02-final-candidate-test-examples.log`.

The production publisher fixture is explicitly synthetic and test-only. It is validated against the pinned upstream CVE Record Format 5.2.0 schema before use. The bundled schema SHA-256 is `44c703322b1fcc532bc1c93f3993a0ba042c1a2831aae8cf39c4fbb707d03c8f`; source, version, and checksum are documented in `dependency-elider-maven-plugin/src/test/resources/schema/README.md`. CycloneDX 1.6 and OpenVEX 0.2.0 outputs are schema-validated and use bounded trust language.

## Limits and remaining research

No WP-VEX-02 implementation requirement remains open. The PMD correction review and integration are complete, and the separate post-closeout worktree was removed after its review receipts were copied to main. The proof is bounded to the CNA-declared claims and does not independently establish vulnerability truth or CNA declaration completeness. The configured producer-compatible typed OSV index is the selected OSV evidence source; it is not an independent authentication of upstream OSV bytes. Unsupported compiler/build configurations, including modules, MRJAR source reproduction, generated or transformed builds, and incomplete mappings, remain review-only. Broader CNA range semantics, retention/notification thresholds, and external scanner-revision research remain outside this work package. WP-VEX-03 has separate eventual-consistency and no-shared-watermark limitations documented in its handover.

## Preserved WP-REACTOR-01 Delivery Closeout

WP-REACTOR-01 delivers the existing three-module Maven reactor fixture as an end-to-end sequential and threaded verification target. Its implementation is committed as `3775d41060d8962fe2370516e870b7c228ced092` on `codex/wp-reactor-01`; it was fast-forwarded from pre-merge SHA `c15974c4b512931d1a47d66766ca3ba8e40691ee`.

The integrated `make test-examples MAKE_JOBS=4` passed the four standalone fixtures and the multi-module fixture. The reactor runner builds a baseline, then elision builds with the default sequential Maven builder and exactly `-T 4`; it fails if inherited `MAVEN_ARGS` causes the sequential build to use `MultiThreadedBuilder`. Each child module emits an independent schema-1 `dependency-elider-report.json`; a Java contract verifies unique module identity and rejects class/byte metric drift between sequential and threaded snapshots. Commons Codec is elided and Commons Compress is trimmed. The shaded app retains Tar support while omitting Zip and Codec, and the packaged app runs. Original Compress archive hashes and the configured local repository's elider-output inventory remain unchanged.

The integrated Java gate passed 195 core tests, 267 plugin tests, and 15 lifecycle tests, with compile, Spotless, Checkstyle, PMD, and SpotBugs clean. `make fmt`, shell syntax, and whitespace checks passed. The reactor topology is a strict dependency chain, so `-T 4` does not prove general cache race safety. RQ-0012 remains open for independent-module topologies, broader Maven configurations, and incremental builds. Node-based checks were not run for that historical closeout; Java and example lifecycle checks passed, and the Gemini review bridge was unavailable. Historical track records:

* Review verdict and evidence: `.scratch/reviews/track-reactor-fixture-review.md`.
* Track tool-quality assessment: `.scratch/reviews/track-reactor-fixture-wrapup.md`.
* Manual source-edit record: `.scratch/manual-edits/track-reactor-fixture.md`.
* Tool friction: `.scratch/suboptimal-tools/track-reactor-fixture.md`.
* Integrated command logs: `.scratch/verification/wp-reactor-01-integrated-focused.log`, `.scratch/verification/wp-reactor-01-integrated-java-check.log`, and `.scratch/verification/wp-reactor-01-integrated-examples.log`.

## WP-POLICY-01 closeout bundle (2026-11-02)

The source handover and package closeout are
[`2026-10-31-wp-policy-01-global-dependency-exclusions-and-retained-artifacts-flip.md`](../docs/handovers/2026-10-31-wp-policy-01-global-dependency-exclusions-and-retained-artifacts-flip.md)
and its `-closeout` sibling. The package was rebased onto current `main`
`f45cf4752c0f9940f35050163fa7d89064a43165`, with the user-authorized full dirty
snapshot in `d152ead148f98e8c20982baba37c6419a602c8f8`. Java 21 `make check`
passed on candidate `f0ef03b67ff0e359311639fbae5579c90fda35b6`; the versioned
closeout records the gate, requirement matrix, limits, and current review and
integration state.

Track evidence is bundled in `.scratch/reviews/*-wrapup.md` and
`.scratch/manual-edits/`. The Elide-ban implementer recorded focused-test,
lint, and plugin-check runtimes. Other retained track sources did not have
comparable timing data; their assessments say unknown rather than estimate.
The package remains incomplete until the fast-forward to local `main` and the
integrated-main review are recorded in the versioned closeout and orchestration
ledger.

The user then requested a rebase onto progressed `main` at
`024b092b93b05fe77de3215f92198da9e74fa80f`. The original dirty-snapshot commit
`d152ead148f98e8c20982baba37c6419a602c8f8` remains on recovery branch
`codex/wp-policy-01-pre-progressed-main-rebase`; the active branch replays only
WP-POLICY-01 commits because progressed main carries the snapshot's tracked
state. Candidate `335f1f8aef20ac2567198df0b658c09af299cd9e` / tree
`5d4a16e6d364f349f259232e45ae20aebe26347a` passes Java 21 `make check`, with
767 plugin tests (one skipped) and 27 lifecycle integration tests. A packaged
mixed Analyze/Elide test passed in both direct goal orders. Contract and
architecture reviews approved exact branch tree `33a30c70` /
`f70edffc`; receipts are `.scratch/reviews/wp-policy-01-final-33a30c7.md` and
`.scratch/reviews/wp-policy-01-architecture-33a30c7.md`. WP-POLICY-01 was
fast-forwarded to local `main` at `d3fad3a3b601ec01389ca74507b5b127d0e114a1`.
The full Java 21 `make check` passed on that integrated commit, and the
post-fast-forward review approved with no findings; receipt:
`.scratch/reviews/wp-policy-01-integrated-main-d3fad3a.md`. The main worktree's
12 tracked modifications and four unrelated untracked paths were restored from
the retained recovery stash; the older WP-POLICY handover was replaced by the
final committed version.
