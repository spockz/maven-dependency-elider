<!-- WHY: Records the reviewed implementation, verification evidence, integration, and bounded claims for WP-VEX-02. -->
# WP-VEX-02: Verified Structured Source Attribution Closeout

## Status and delivery

WP-VEX-02 is complete. The reviewed implementation is commit `90f9c48b86f76be1bb2c8294d3df3eccff8fdd6c`. Local `main` was fast-forwarded to that reviewed commit, and `git merge-base --is-ancestor` verified it is an ancestor of the current delivery target. The whole-scope review and track-completion review both returned GO for the exact SHA:

- `.scratch/reviews/wp-vex-02-final-completion-90f9c48.md`
- `.scratch/reviews/wp-vex-02-track-completion-90f9c48.md`

No WP-VEX-02 implementation requirement remains open. No remote push was requested.

### Post-closeout PMD correction

The `90f9c48b86f76be1bb2c8294d3df3eccff8fdd6c` review and local-main delivery above are the historical closeout. A later clean check from that delivered main head found two PMD LawOfDemeter violations in the test fixture `MavenStructuredProofCacheFixtures`, where it read group and artifact constants directly from another fixture class. Commit `3715439be8895e0657fe45d4443ac2418b0b2511` corrects this by deriving the coordinate from the prepared scenario. This new candidate is awaiting final review and integration; it does not change the historical review receipt for `90f9`.

On `3715439be8895e0657fe45d4443ac2418b0b2511`, focused tests, formatting, and Java lint passed. The first full-check attempt exposed stale JaCoCo data from a previous focused run; after cleaning generated targets, a fresh `make check` exited 0 with 334 core tests, 631 plugin tests (630 passed, 1 skipped), 16 lifecycle tests, coverage, and transcript checks passing. `make test-examples` also exited 0 for five standalone fixtures and the multi-module reactor. Logs: `/tmp/wp-vex02-pmd-fix-make-check.log` and `/tmp/wp-vex02-pmd-fix-test-examples.log`.

Before integration, local `main` contained 52 unrelated dirty or untracked paths. These were preserved through the fast-forward and restored from stash `1e5aaf91ba6cb869796c968996ac6c7bea4369dc`; the stash backup remains available. The only path overlap involved `scripts/update-transcripts.go` and `scripts/update-transcripts_test.go`. The integrated versions preserve the feature's isolated Maven-repository argument and regression coverage together with main's `-f` path normalization and tests.

## Delivered behavior

The plugin uses exact Maven coordinates to select current OSV and CNA evidence, then resolves the exact `sources` classifier through the configured guarded Maven Resolver path. For supported ordinary Java builds, it reproduces the complete source output with the pinned GraalVM JDK 21.0.12+7.1 compiler and fixed options. It requires byte-identical equality between the reproduced class inventory and the complete physical original artifact inventory. File claims cover sibling top-level declarations and nested, local, and anonymous class families. Routine claims require one declaring owner across the full source archive. Live scope, source, artifact, and physical omission checks run before a distinct structured proof capability is issued.

The conventional-layout setting permits only the documented source-root translation; it does not establish completeness. Invocation-scoped reuse caches successful, claim-independent reproduction metadata, while each proof rechecks current claim selection, applicability, and bytes. Compiler discovery is isolated from auto-start plugins on both the original artifact and ambient application classpath. The marker-provider tests include controls and assert that neither provider executes.

Verified proof and unresolved source findings remain separate in strict report schema version 1. Historical rendering uses saved descriptive DTOs. CycloneDX 1.6 and OpenVEX 0.2.0 carry bounded provenance and trust context in standard fields; POM proof and ADR-0008 prerequisite proof retain their existing precedence and physical safeguards.

## Test fixtures and schemas

The production publication test uses a synthetic CNA source record explicitly labeled test-only. Before publication, the test validates it against the repository-pinned upstream CVE Record Format 5.2.0 schema. The bundled schema SHA-256 is:

`44c703322b1fcc532bc1c93f3993a0ba042c1a2831aae8cf39c4fbb707d03c8f`

The schema's source, version, and checksum are recorded in `dependency-elider-maven-plugin/src/test/resources/schema/README.md`. The output fixtures validate against pinned CycloneDX 1.6 and OpenVEX 0.2.0 schemas.

## Verification evidence

Final verification was run against the exact reviewed candidate with the pinned GraalVM JDK 21.0.12+7.1 toolchain:

- `make check`: exit 0; 334 core tests passed; 631 plugin tests total (630 passed, 1 skipped); 16 lifecycle integration tests passed; coverage, Markdown/static checks, and transcript verification passed. Log: `/tmp/wp-vex02-final-candidate-make-check.log`.
- `make test-examples`: exit 0; five standalone fixtures and the multi-module reactor passed, including sequential and `-T 4` checks. Log: `/tmp/wp-vex02-final-candidate-test-examples.log`.
- After adding the closeout document, `timeout 600s make lint-markdown`: exit 0; 72 files scanned, 0 reported issues. Log: `/tmp/wp-vex02-closeout-lint-markdown.log`.

The final suite includes production resolver-to-publication coverage for installed report, CycloneDX, OpenVEX, and output manifest files. `JavacPluginServiceIsolationTest` proves auto-start providers from both the original artifact and ambient application classpath do not execute, using marker checks and positive controls. The synthetic-record schema validator checks the bundled schema digest before validating the fixture. `make check` includes formatting, Java static analysis, Markdown lint, and transcript drift validation.

## Limits

The evidence is limited to CNA-declared claims. It does not independently determine whether a vulnerability is true or whether a CNA declaration is complete. The configured producer-compatible typed OSV index is the selected OSV source; this work does not independently authenticate raw upstream OSV bytes and performs no network lookup during proof.

Automatic source reproduction supports the pinned GraalVM JDK 21.0.12+7.1 and the documented ordinary non-MRJAR Java path. Modules, MRJAR source reproduction, generated or transformed builds, unsupported compiler inputs, incomplete source mappings, and ambiguous routine ownership abstain and remain review-only. The layout assumption remains a narrow path translation, not a completeness signal.

Broader CNA range semantics, retention and notification thresholds, and external scanner-revision research remain outside WP-VEX-02. WP-VEX-03 snapshot/delta synchronization is delivered separately; its eventual-consistency and lack-of-shared-watermark limits remain documented in that handover.
