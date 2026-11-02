<!-- WHY: Preserves WP-POLICY-01 scope, verification, review, integration, and evidence limits with its source handover. -->
# WP-POLICY-01 Closeout

## Package and delivery state

- **Package:** `WP-POLICY-01`, global dependency bans and retained-artifact policy.
- **Source handover:** [WP-POLICY-01](2026-10-31-wp-policy-01-global-dependency-exclusions-and-retained-artifacts-flip.md).
- **Requested base:** local `main` at `f45cf4752c0f9940f35050163fa7d89064a43165`.
- **User amendment:** include the full dirty main snapshot. It is retained in baseline commit `d152ead148f98e8c20982baba37c6419a602c8f8`, tree `767ec799e111e6b99087bf9f427f4d43d0ed9a00`.
- **Implementation branch:** `codex/wp-policy-01`.
- **Verified candidate:** `f0ef03b67ff0e359311639fbae5579c90fda35b6`, tree `8fcb10a2c7e3c829c1b9001d46f1fac33e89eb02`.
- **Delivery target:** local `main`; remote publication was not requested. Final fast-forward and dirty-path preservation are recorded after integration.
- **Current state:** implementation and full `make check` pass. Fresh exact-tree reviews and local `main` integration are pending.

## Requirement-to-evidence matrix

| ID | Requirement | Evidence | State |
| --- | --- | --- | --- |
| R1 | Rename force retention to `retainedArtifacts`, preserve its matching rules, reject the unreleased legacy setting, and bind policy/action to operation and cache identities. | `LegacyRetentionSettingTest`, `MavenElisionPolicyIdentity`, graph/output/cache identity tests, updated goal help and user/contributor documentation. | Complete. |
| R2 | Normalize exact G:A bans; validate scope/type, unmatched requests, and conflicts with retention or trim-skip rules. | `BanishedDependencyPolicyTest`, `BanishedDependencyMojoConfigurationTest`, `MavenOriginalInputArtifactTypeTest`, `MavenOriginalInputScopeResolutionTest`. | Complete. |
| R3 | Capture original exclusions and inject first-level exclusions before resolution while preserving user state and lifecycle boundaries. | `BanishedDependencyLifecycleActivationTest`, `ElideMojoTest`, and packaged `DependencyContextLifecycleIT` cases. | Complete. |
| R4 | Enforce bans in Analyze and Elide with graph, class, resource, provider, and evidence closure; preserve trim-on/off behavior and fail before publication. | `NoExtensionAnalyzeBanPredictionTest`, `MavenBan*ClosureTest` suites, `MavenElisionServiceEffectiveOutputTransactionTest`, lifecycle integration cases. | Complete. |
| R5 | Keep original-input audit data separate from deployment inventory; distinguish pre-resolution exclusion, post-resolution absence, and unmatched requests; fail closed when audit evidence is unavailable. | `MavenOriginalInputAuditTest`, `MavenBanAuditContextTest`, `DetachedResolverCompileClasspathTest`, report validation tests. | Complete. |
| R6 | Report repeated effective-POM exclusions with provenance, separate management-only entries, and keep recommendations advisory. | `ExclusionProvenanceCaptureTest`, `ExclusionReviewReportTest`, strict report reader/writer validation. | Complete. |
| R7 | Update usage, FAQ, contributor decisions, ADRs, research, examples, and generated transcripts. | README, Maven site usage, FAQ/contributor docs, ADR-0012, RQ-0004/0005/0006/0017/0018, `make check-transcripts`. | Complete. |
| R8 | Preserve output, Maven-view, and resolver-plan rollback; verify absence and freshness before commit. | `MavenOutputTransactionTest`, `MavenElisionServiceEffectiveOutputTransactionTest`, and lifecycle failure/no-publication fixtures. | Complete. |
| R9 | Review the full source-derived scope, run the full repository gate, review integration, and preserve closeout evidence. | Independent source and architecture receipts plus a final integrated-main receipt are listed below when issued. | Pending final review and integration. |

## Verification

Java 21 `make check` passed on candidate `f0ef03b6` / tree
`8fcb10a2c7e3c829c1b9001d46f1fac33e89eb02`. It ran formatting, Checkstyle,
PMD, SpotBugs, core and plugin tests, lifecycle integration tests, coverage,
Markdown lint, scheduler and SBOM checks, and transcript drift. The transcript
tool reported that configured command transcripts are up to date. The check
also confirmed the candidate's report/snapshot copy paths compile with the newer
mainline structured-proof and source-correspondence fields. `git diff --check`
passed.

The repository-pinned Markdown tool was installed with `make tools`. The first
check exposed stale report-snapshot constructor arguments and a README blank-line
lint error; the fixes preserve mainline fields and are included in the verified
candidate. A clean-main PMD run on `f45cf475` had no findings; the merged tree's
snapshot aggregate complexity was locally suppressed because its individual
methods remain below the rule threshold, and the report decode logic was split
to keep the reader method below its threshold.

## Review receipts

The historical receipts for the pre-rebase tree remain available at
`.scratch/reviews/wp-policy-01-final-da76d2c.md` and
`.scratch/reviews/wp-policy-01-architecture-da76d2c.md`. They do not approve the
rebased tree. Fresh exact-tree source/architecture reviews and a post-fast-forward
integration review are pending and will be linked here before the package is
declared complete.

The Gemini review bridge was unavailable in this environment. No Gemini review
is claimed; the skill's documented fail-open path uses the independent policy
reviewer and architect.

## Track tool and manual-edit wrap-ups

| Track | Semantic-tool QoL and built-in comparison | Runtime | Manual edit / suboptimal-tool record |
| --- | --- | --- | --- |
| `policy-contract` | Unknown; no semantic tool was used. `rg` and `apply_patch` were used; no comparison data was retained. | Not recorded. | No manual source-edit fallback. A default-sandbox PMD inspection hit a `bwrap` capability error; that worker stopped without edits. |
| `exclusion-audit` | Unknown; R4 reviews used `rg`, targeted reads, Git diffs, and `javap`; no semantic-tool comparison is supported. | Not recorded. | No manual source-edit fallback. One read-only inspection hit `bwrap`; escalated read-only commands worked. |
| `elide-ban-enforcement` | Unknown; no semantic tools were used; built-ins were sufficient for the retained searches and edits. | Focused tests 24.1s; `make lint-java` 26.2s; `make test-plugin` 4m28s; transcript runtime not recorded. | No manual source-edit fallback. Two temporary test files were removed after consolidating their fixture. |
| `exclusion-report` | Unknown; no comparison was retained. | Not recorded. | No separate fallback or suboptimal-tool event appears in retained evidence. |
| `docs-closeout` | Unknown; `rg` and `apply_patch` were used, with no comparison data. | Not recorded. | No manual source-edit fallback or suboptimal-tool issue recorded. |

No MCP semantic tool was used for these tracks, so no MCP semantic-tool failure
is reported. Detailed work-package tool notes remain in `.scratch/orchestration-status.md`.

## Specification deviations and architectural choices

- The full 52-path dirty snapshot was included because the user explicitly chose it. The snapshot is a committed baseline on the isolated branch; it was not silently reduced to WP-only files.
- The rebased integration preserved current-main structured-proof reporting, source-correspondence results, source-classifier resolution threading, ordered JSON serialization, and deserialization error handling while adding policy fields and renderers.
- Bans use collection-time first-level exclusions when the core extension is active and strict post-resolution checks in supported goal paths. A successful operation must establish absence; ambiguous graph, closure, or audit evidence fails closed.
- The policy applies to supported current-project Maven views and generated outputs. It does not rewrite consumer POMs or claim universal future Resolver, plugin-realm, annotation-processor, Spring AOT, or exhaustive test-bytecode behavior.
- Exclusion recommendations are review-only and do not edit POMs. A policy-only run and automated migration support remain out of scope.
- Persisted report formats remain schema version 1 while unreleased. No compatibility alias or migration was added for draft formats.
- Duplicate same-name providers are not treated as equivalent without separate proof. No source-class-to-target edge diagnostic is claimed where edge attribution is unavailable.

## Cumulative change and commit record

From base `f45cf475` to the verified implementation candidate, the cumulative
change was 240 files, 24,365 insertions, and 1,916 deletions. The full commit
sequence is preserved by `git log --oneline --reverse
f45cf4752c0f9940f35050163fa7d89064a43165..f0ef03b67ff0e359311639fbae5579c90fda35b6`.
This includes the user-authorized dirty-snapshot baseline and all integrated
WP-POLICY-01 work. The final main delivery hash and post-integration diff are
added after the fast-forward.
