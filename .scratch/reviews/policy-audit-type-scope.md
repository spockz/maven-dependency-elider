# Review receipt: original audit type and scope validation

* **Status:** APPROVED
* **Commit:** `d7eaf9caa88619de10de1559077edd4fd54e1f6f`
* **Tree:** `e59828a2fc31643a3da3539737d6d4b0cf2962b0`
* **Reviewer:** independent policy-contract reviewer

Maven artifact type is preserved separately from Resolver extension and participates in audit identity. Every original resolved G:A match is checked; unsupported and mixed supported/unsupported matches fail closed, while unmatched requests remain distinct. Missing scope or type is rejected explicitly. The real offline TEST-context fixture verifies test-only, provided-only, `test-jar`, and mixed classifier matches before checking rejection.

Verification on the exact slice: `make fmt`, 15 focused tests, `make lint-java` (Checkstyle, PMD, SpotBugs), and `git diff --check` passed using the isolated Maven cache at `/tmp/wp-policy-audit-type-m2.P3U1MZ`.

This approval covers the audit validation prerequisite. Elide application, successful ban enforcement, and excluded-subtree closure remain open.
