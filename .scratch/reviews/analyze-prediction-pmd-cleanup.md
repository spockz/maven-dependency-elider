<!-- WHY: Preserves independent review and lint evidence for the Analyze prediction PMD cleanup. -->
# Review Receipt: Analyze Prediction PMD Cleanup

* **Reviewed integration commit:** `6d62f31`
* **Reviewed tree:** `bf9d1e48615400874815da7d29e0ac492e18bf58`
* **Lint-equivalent detached commit:** `796e3a3` in `/tmp/wp-policy-01-lint-v5-src`
* **Reviewer:** dedicated policy contract reviewer (`/root/policy_contract_review`)
* **Verdict:** Approved after two focused corrections

## Scope and findings

The cleanup addressed 92 initial PMD findings and the `NonThreadSafeSingleton` PMD processing exception in the Analyze prediction production and test code. Production extraction moved invocation-base and output-path resolution into focused helpers. Test changes kept their existing inputs and assertions while removing no-op constructors, splitting fixture construction, and making diagnostics explicit. PMD rules and configuration were not changed.

The first review requested three `/* default */` access markers and a correct rationale for the `AtLeastOneConstructor` suppression. Those corrections were committed as `14028bf`. The first lint after the broader cleanup found 19 residual findings; the follow-up cleanup addressed them. The next lint found two direct session-data access findings; an unsuppressed accessor resolved both in `a36dfdb`.

The reviewer approved the helper extraction and null-presence behavior as equivalent, confirmed assertion and fixture preservation, and approved both correction commits. The final reviewed source tree is the same as the linted detached tree.

## Verification

* Offline `make fmt` passed on the cleanup and correction commits; Spotless made no further edits.
* `git diff --check` passed on every cleanup commit.
* Final offline `make lint-java` passed at tree `bf9d1e4`: Checkstyle 0 violations, PMD 0 violations, and SpotBugs 0 findings.
* `make test-plugin` passed before these style-only test refactors at the equivalent Analyze prediction behavior plus Failsafe fix: 289 core tests, 680 plugin tests (1 skipped), and 22 lifecycle tests. The full test gate remains scheduled after the in-flight strict Analyze slice is integrated.

## Review trail

* `3b1632e`: initial PMD cleanup; review requested access markers and a corrected suppression rationale.
* `14028bf`: correction approved.
* `0235c82`: remaining comment/assertion/test-structure findings addressed; review requested two remaining Law-of-Demeter findings.
* `a36dfdb`: final accessor correction approved.
