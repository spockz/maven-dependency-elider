<!-- WHY: Records the final architecture approval for the exact WP-POLICY-01 implementation tree. -->
# WP-POLICY-01 architecture review

- **Verdict:** APPROVED; no architectural must-fix remains.
- **Commit:** `da76d2c45a22b151be23e3312e9b009b10cb6e24`.
- **Tree:** `aa2c13cdc11fedd0d253700da6c3a4b5fe5dc3b0`.
- **Reviewer:** independent policy architect (`/root/policy_architect`).
- **Review type:** read-only source and test review; no tests or build gates run by the reviewer.

The validator checks graph schema and typed invariants before cross-section traversal. Both applied ban statuses check G:A-wide absence across reachable retained, protected, or ancestor-promoted graph nodes, trimmed rows, and configured retention policy. Forced-absent rows also require exact matched coordinates in physical dropped rows. Audit-only original entries are not treated as deployment output.

Detached Resolver inventory validates raw scope, extension, and Maven type before RepositoryUtils conversion; explicit blank Maven type cannot receive a `jar` default. Focused test sources cover these cases and a valid audit-only exclusion report.

Earlier closure, alternate-provider, lifecycle, publication/rollback, and documentation findings remain resolved. Scope remains limited to operation-specific Maven views and supported evidence; no universal future Resolver, consumer-POM, plugin/processor realm, AOT replacement, or exhaustive test-code claim is made.
