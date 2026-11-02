<!-- WHY: Preserves WP-POLICY-01 scope, verification, review, integration, and evidence limits with its source handover. -->
# WP-POLICY-01 Closeout

## Package and delivery state

- **Package:** `WP-POLICY-01`, global dependency bans and retained-artifact policy.
- **Source handover:** [WP-POLICY-01](2026-10-31-wp-policy-01-global-dependency-exclusions-and-retained-artifacts-flip.md).
- **Requested base:** progressed local `main` at `024b092b93b05fe77de3215f92198da9e74fa80f`.
- **User amendment:** include the full dirty main snapshot. It was captured as `d152ead148f98e8c20982baba37c6419a602c8f8` before main progressed. That snapshot commit is retained on recovery branch `codex/wp-policy-01-pre-progressed-main-rebase`; the rebased work replays only WP-POLICY-01 commits because current main already carries the snapshot's tracked state. The current main worktree has 12 modified tracked paths and 5 untracked paths; after fast-forward I will restore all current changes except the older WP-POLICY handover, which this branch supersedes.
- **Implementation branch:** `codex/wp-policy-01`.
- **Verified candidate:** `335f1f8aef20ac2567198df0b658c09af299cd9e`, tree `5d4a16e6d364f349f259232e45ae20aebe26347a`.
- **Delivery target:** local `main`; remote publication was not requested. Final fast-forward and dirty-path preservation are recorded after integration.
- **Current state:** implementation and full `make check` pass. Independent contract and architecture reviews approved exact branch tree `33a30c70`; the fast-forward to local `main` and integrated-main review are pending.

## Requirement-to-evidence matrix

| ID | Requirement | Evidence | State |
| --- | --- | --- | --- |
| R1 | Rename force retention to `retainedArtifacts`, preserve its matching rules, reject the unreleased legacy setting, and bind policy/action to operation and cache identities. | `LegacyRetentionSettingTest`, `MavenElisionPolicyIdentity`, graph/output/cache identity tests, updated goal help and user/contributor documentation. | Complete. |
| R2 | Normalize exact G:A bans; validate scope/type, unmatched requests, and conflicts with retention or trim-skip rules. | `BanishedDependencyPolicyTest`, `BanishedDependencyMojoConfigurationTest`, `MavenOriginalInputArtifactTypeTest`, `MavenOriginalInputScopeResolutionTest`. | Complete. |
| R3 | Capture original exclusions and inject first-level exclusions before resolution while preserving user state and lifecycle boundaries. | `BanishedDependencyLifecycleActivationTest`, `ElideMojoTest`, and packaged `DependencyContextLifecycleIT` cases. | Complete. |
| R4 | Enforce bans in Analyze and Elide with graph, class, resource, provider, and evidence closure; preserve trim-on/off behavior and fail before publication. | `NoExtensionAnalyzeBanPredictionTest`, `MavenBan*ClosureTest` suites, `MavenElisionServiceEffectiveOutputTransactionTest`, lifecycle integration cases. | Complete. |
| R5 | Keep original-input audit data separate from deployment inventory; distinguish pre-resolution exclusion, post-resolution absence, and unmatched requests; fail closed when audit evidence is unavailable. | `MavenOriginalInputAuditTest`, `MavenBanAuditContextTest`, `DetachedResolverCompileClasspathTest`, report validation tests. | Complete. |
| R6 | Report repeated effective-POM exclusions with provenance, separate management-only entries, and keep recommendations advisory. | `ExclusionProvenanceCaptureTest`, `ExclusionReviewReportTest`, strict report reader/writer validation. | Complete. |
| R7 | Update usage, FAQ, contributor decisions, ADRs, research, examples, and generated transcripts. | README, Maven site usage, FAQ/contributor docs, ADR-0012, RQ-0004/0005/0006/0017, `make check-transcripts`. | Complete. |
| R8 | Preserve output, Maven-view, and resolver-plan rollback; verify absence and freshness before commit. | `MavenOutputTransactionTest`, `MavenElisionServiceEffectiveOutputTransactionTest`, and lifecycle failure/no-publication fixtures. | Complete. |
| R9 | Review the full source-derived scope, run the full repository gate, review integration, and preserve closeout evidence. | Java 21 `make check` passed on `335f1f8a` / `5d4a16e6`; exact-tree contract and architecture receipts are approved at `33a30c70`; integrated-main receipt remains pending. | Gate and branch reviews complete; integration pending. |

## Verification

Java 21 `make check` passed on candidate `335f1f8a` / tree
`5d4a16e6d364f349f259232e45ae20aebe26347a`. It ran Spotless, Checkstyle, PMD,
SpotBugs, core and plugin tests, 27 lifecycle integration tests, coverage,
Markdown lint, scheduler and SBOM checks, and transcript drift. The plugin suite
reported 767 tests with one skipped; the lifecycle suite reported 27 tests with
no failures or skips. The transcript tool reported that configured command
transcripts are up to date. A targeted packaged test also passed both direct
Analyze/Elide goal orders, and `make lint-java` plus `git diff --check` passed.

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
`.scratch/reviews/wp-policy-01-architecture-da76d2c.md`; they do not approve the
rebased tree. Exact-tree reviews approved commit `33a30c70` / tree
`f70edffc`. The policy contract receipt is
`.scratch/reviews/wp-policy-01-final-33a30c7.md`; the architecture receipt is
`.scratch/reviews/wp-policy-01-architecture-33a30c7.md`. A post-fast-forward
integration receipt remains pending.

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

- The user-authorized full 52-path dirty snapshot was captured before main progressed. The rebase excludes replaying its snapshot commit because current main carries its tracked state; the current main worktree's dirty paths are backed up and restored during delivery. The older WP-POLICY handover is replaced by the final source handover.
- The rebased integration preserved current-main structured-proof reporting, source-correspondence results, source-classifier resolution threading, ordered JSON serialization, and deserialization error handling while adding policy fields and renderers.
- Bans use collection-time first-level exclusions when the core extension is active and strict post-resolution checks in supported goal paths. A successful operation must establish absence; ambiguous graph, closure, or audit evidence fails closed.
- The policy applies to supported current-project Maven views and generated outputs. It does not rewrite consumer POMs or claim universal future Resolver, plugin-realm, annotation-processor, Spring AOT, or exhaustive test-bytecode behavior.
- Exclusion recommendations are review-only and do not edit POMs. A policy-only run and automated migration support remain out of scope.
- Persisted report formats remain schema version 1 while unreleased. No compatibility alias or migration was added for draft formats.
- Duplicate same-name providers are not treated as equivalent without separate proof. No source-class-to-target edge diagnostic is claimed where edge attribution is unavailable.

## Cumulative change and commit record

From progressed base `024b092b` to code/test candidate `335f1f8a`, the cumulative
change was 207 files, 23,093 insertions, and 1,423 deletions. The implementation
sequence is preserved by `git log --oneline --reverse
024b092b93b05fe77de3215f92198da9e74fa80f..335f1f8aef20ac2567198df0b658c09af299cd9e`;
documentation-only review successors follow that candidate. The final main
delivery hash and post-integration diff will be added after the fast-forward and
integrated review.
