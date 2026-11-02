# Review receipt: detached Analyze ban planning

* **Reviewed commit:** `81ff99446600069b3e8edbc6c8d5f64c4e3368e0`
* **Reviewed tree:** `e38d3c9b67bb7fb9cbd693a9cca0cd88a4d2c034`
* **Reviewer verdict:** CHANGES REQUESTED

The independent review found:

1. **P1:** A banned archive's native-image resource exclusion could mask a retained archive's resource inclusion. Per-owner resource policy was computed using exclusions from all candidates, so a disappearing banned declarer could suppress an incoming retained-content obligation. Required correction: use only surviving declarers or fail conservatively, and add trim-on/off coverage.
2. **P2:** The writer added `dependencyPrediction.banContextFingerprint` and `banPlan`, but `ExampleSupport.validateDependencyPrediction` ignored those fields. Validate fingerprint syntax, canonical identities, statuses, `applied=false`, and consistency between matched coordinates and would-elide rows. Add malformed payload tests.
3. **P2:** Analyze Javadoc and plugin usage still claimed all nonempty bans fail closed, while README described detached Analyze planning. Reconcile the public contract.

The reviewer confirmed active-extension Analyze and Elide remain fail-closed. Successful Elide application and excluded-subtree restoration are outside this slice. Corrections are in progress; this commit is not approved for integration.
