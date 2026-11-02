# Review receipt: exclusion recommendation report wiring

* **Status:** APPROVED
* **Commit:** `e67d1436248488cfd6cfed1dd703119b922960d7`
* **Tree:** `5366b14397014bd81f8cfa48afb03eb8add0783a`
* **Reviewer:** independent policy architect

Repeated-exclusion findings remain advisory and do not alter pruning policy or POMs. Available findings are validated against the frozen snapshot; stale capture is reported as unavailable and malformed capture fails before publication. Saved report replay renders persisted findings without extracting a live model. Declaration and exclusion origins remain separate, and management observations stay outside active path counts. Strict schema-v1 checks reject inconsistent counts, ordinals, origins, scalar coercion, and extra fields.

Verification on the exact slice: 41 focused tests, `make lint-java`, 289 core tests, 695 plugin unit tests (one expected fixture-property skip), 22 lifecycle tests, coverage, and `make check-transcripts` passed with an isolated offline cache. The schema remains version 1.

Limitations: recommendations require lifecycle capture, and unmatched imported-source attribution remains diagnostic. This approval does not cover ban enforcement, excluded-provider closure, or whole-operation publication guarantees.
