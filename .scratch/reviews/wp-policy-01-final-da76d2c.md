<!-- WHY: Records final independent source approval, resolved enforcement findings, and the limits of available verification for the exact WP-POLICY-01 tree. -->
# WP-POLICY-01 final independent code review

- **Code-review verdict: APPROVED.** No remaining actionable code-review finding was identified.
- Commit: `da76d2c45a22b151be23e3312e9b009b10cb6e24`.
- Tree: `aa2c13cdc11fedd0d253700da6c3a4b5fe5dc3b0`.
- Parent: `646f6691b9003565cda2ffb80812936c605f6e85`.
- Worktree: `.scratch/worktrees/track-elide-ban-enforcement`.
- Full work-package comparison: `96398e906df38e25197d16a5ed0ffa70e08a744c..da76d2c45a22b151be23e3312e9b009b10cb6e24`.
- This review includes the prior independently reviewed prerequisite/contract/report slices and direct inspection of final enforcement, lifecycle, documentation, and correction content. Findings are bound to committed files, not later working changes.
- The reviewer did not run tests/builds or edit product files. This receipt is the only write for this review.
- **Verification/package status is separate from source approval.** No final full-gate result for this exact commit/tree was supplied with this review request. R9 verification and whole-package closeout must record that evidence before claiming completion.

## Prior findings and disposition

### F1, P1: same-name provider substitution, resolved

`MavenBanClassProviderClosure.verifyReference` now rejects a reference whenever an absent provider owns the class, including when one retained/application provider has the same name. It no longer treats name uniqueness after removal as equivalence. The failure identifies the absent coordinate and explains the missing equivalence proof. The policy is shared by application source/trace/production references, retained bytecode/MRJAR scans, dynamic/service declarations, and final retained bytecode verification.

`MavenBanClassProviderClosureTest` constructs different `x.Api` bytes and verifies a retained-bytecode reference is rejected. Source inspection confirms all existing closure callers use the corrected helper. This is deliberately conservative: byte-identical or shadowed replacements are not admitted without a separate proof. The unchanged-GAVCE alternate-path case remains valid because audit reachability subtraction leaves an effective provider out of the absent set; it does not depend on the removed fallback.

### F2, P2: applied-ban/output disposition consistency, resolved

The strict report validator retains exact correspondence between every `FORCED_ABSENT_AFTER_RESOLUTION.matchedArtifacts` coordinate and a physical `droppedArtifacts` row. It also checks the complete requested G:A against configured retention policy, trimmed output rows, and reachable `RETAINED`, `PROTECTED`, or `ANCESTOR_PROMOTED` graph nodes. These family-wide absence checks cover both successful statuses, including `EXCLUDED_BEFORE_RESOLUTION`; version/classifier differences cannot evade them. Applied outcomes require an available validated mediated graph.

Graph envelope/type validation and `MediatedGraphReport` invariants run before this traversal, establishing complete node-status coverage and known dispositions. Status, applied flag, supported coordinate scope/type, canonical order, policy membership, and original/effective row consistency remain validated.

New coherent graph fixtures cover a forced v1 drop alongside retained/trimmed v2 classifier variants, excluded-before-resolution rows with retained/trimmed variants, unavailable graph data, retention-policy conflicts, missing physical drops, and a valid audit-only excluded outcome. These exercise the intended invariant rather than relying on unrelated malformed graph failures.

### F3, P2: no-extension unrelated trace drops, resolved as an explicit contract

README, site usage, FAQ, contributor guidance, and research now explain the actual boundary: ordinary no-extension requests without bans retain trace-drop candidates, while a detached explicit-ban operation can also validate and apply unrelated trace-derived drops. `UnrelatedTraceDropTest` includes both a requested ban and a distinct unused transitive artifact, executes Elide, and checks final membership, both physical drops, applied-ban status, and the separately classified raw trace drop. The standard no-ban execution lane is unchanged.

### F4, P2: detached explicit blank Maven type, resolved

Before `RepositoryUtils` conversion or `ArtifactCoordinate` defaults, detached snapshots now call the shared original-input coordinate and Maven-type readers. Explicit blank type is rejected; extension fallback applies when the property is absent. Scope and extension evidence are checked at the same boundary. Original-audit validation retains the same checks.

The new detached fixture uses an actual Aether artifact with extension `jar`, explicit `type=""`, file bytes, and classpath metadata, then verifies prediction fails with the missing-type diagnostic. Analyze and Elide share `MavenBanPreparation` and this conversion boundary; the new negative test directly exercises prediction, not a separate packaged Elide invocation.

## Review Triangle

### 1. Correctness and tests

- **R1 retention:** the rename preserves optional retention coordinate grammar and matching. Obsolete CLI/request/system/project properties and plugin/execution POM configuration are explicitly rejected by both goals. Packaged positive/negative POM controls and report sentinels address Maven descriptor filtering rather than relying only on direct Mojo injection. Recorded release-history evidence supports treating the old setting as unreleased: Maven Central search returned zero results, GitHub releases were empty, and the clone had no tags. This review did not repeat those external checks.
- **R2 policy:** exact normalized G:A values remain distinct from retention grammar, cover supported compile/runtime JAR variants and classless JARs, and reject direct, retention, trim-skip, unsupported-type/scope, and unavailable-evidence cases. Current/effective matches, original matches, and unmatched outcomes remain separate.
- **R3 activation:** selected policy is verified at goal execution; original declarations are frozen before atomic all-project injection, with idempotency and user-exclusion preservation. Default CLI and execution selection have packaged coverage. Skip/leaf behavior and ordinary no-ban preparation remain separate.
- **R4/R5 enforcement and audit:** shared immutable plans enter both goals. Active-hook operations require the original audit; detached operations require isolated resolution and exact graph/inventory correspondence. Audit sessions use fresh request-local state and bypass Elider output substitution/capture side effects. Reachable GAVCE subtraction preserves alternate paths and isolates original-only providers. Audit providers never become deployment members. Byte freshness and captured source are rechecked at the relevant preparation/publication boundaries.
- **Closure:** graph protection/ancestor promotion, application evidence, retained bytecode, retained metadata/service/provider declarations, and resource patterns are checked. Trim-off retains its closure path. MRJAR retained content and classless providers are represented. Own metadata cannot override the forced absence, while surviving owners' obligations remain checked. The corrected duplicate-provider rule is conservative.
- **R6 reports:** repeated exclusions use effective declaration paths once per exact exclusion, with raw/profile/management rows serving provenance lookup rather than additional counts. Management-only observations remain separate, wildcards are excluded, source/profile identity is structured, and unresolved/imported-BOM origins carry diagnostics. Findings remain advisory and no POM edits are generated.
- **Identity/formats:** normalized policy/actions and audit context participate in operation identity and flow into prepared/effective analysis, reports, effective output/cache identity. Prediction rows remain `applied=false`; successful Elide rows and unmatched rows have distinct outcomes. Unreleased persisted formats remain schema version 1. Summary and class-usage consumers validate their respective updated report sections.

### 2. Code quality

The helper extractions are mostly cohesive by ownership and proof phase: workspace lifetime, frozen audit subtraction, bytecode/metadata/resource evidence, live-view correspondence, and final publication checks are separate responsibilities. Pre-transformation closure and final archive verification cannot safely share one stale index/result. The freshness facade is thin, but helper count alone is not a blocker. No remaining material naming, duplication, or unnecessary abstraction finding was identified in the reviewed changes.

### 3. ADR adherence

ADR-0012's separation of policy, collection-time exclusions, original audit evidence, strict closure, prediction, and enforcement is maintained. ADR-0001/0002/0010 lifecycle and supported-consumer boundaries remain explicit. No universal Resolver interception, consumer-POM rewrite, plugin-realm mutation, annotation-processor mutation, or vulnerability mitigation follows merely from a ban. The corrected provider rule respects the handover's requirement for separate equivalence proof.

### 4. Scope, documentation, and publication

The documented matched/pre-resolution-excluded completeness prerequisite is complete source roots or complete production class output; conflicting assertions remain rejected. Unsupported type/scope and direct/retention/pass-through conflicts fail explicitly. Unmatched requests do not themselves imply removal or successful absence.

Analyze validates its plan and assesses vulnerabilities before the atomic class-usage report containing prediction and exclusion review is installed. It does not publish Maven views, resolver plans, trim generations, or output manifests. Elide stages generation, acquires rollback ownership before later callbacks/binding/publication, and uses the existing report/output transaction. Final live-view/path/digest/graph checks precede resolver-plan publication. Failure paths restore files, artifact references/file pointers, and prior plan state within the tested synchronous boundary.

README/site/FAQ/contributor/research references now describe the implemented boundaries. Generated README report transcripts include the new no-ban outcome line; a fresh transcript drift gate still belongs to final verification. No package-completion claim is made by this receipt.

## Lifecycle proof and limitations

- The new `initialize` fixture binds the real production goal to that phase, supplies complete source evidence, and checks successful audited exclusion and final views.
- The new trusted `process-classes` fixture leaves explicit completeness flags unset, runs the actual compiler before the bound Elide goal, verifies generated application bytecode references the retained library, and checks the successful excluded outcome/final view. It therefore exercises trusted post-compile selection rather than simulating it with a direct Java call.
- The retained-link failure fixture compiles an application against a retained API whose method body references the excluded runtime provider. It checks compiler-before-Elide order, the targeted retained-bytecode diagnostic, compiled application output, and six unchanged prior report/output sentinels.
- That packaged failure is an **early no-publication proof**, not a probe of transient artifact views or resolver-plan state after a staged failure. Separate injected-failure unit tests cover post-generation staging and resolver-plan publication rollback, including previous files, exact artifact references/file pointers, generation state, and prior stored plan.
- The tests do not establish crash consistency, arbitrary concurrent goal writers, every Maven/JDK version, arbitrary reactor topology, every downstream packager, or complete future Resolver/consumer behavior. Current packaged evidence is bounded to the configured Maven wrapper/JDK fixtures. Original-only metadata is not promoted to application evidence.
- Strict provider rejection intentionally does not prove safe same-name replacement. Source/production completeness assertions do not add exhaustive test-bytecode or separately modeled AOT coverage. Physical whole-artifact drop metrics concern artifacts removed from the operation's resolved inventory; pre-resolution audit-only absence is represented by its separate outcome.

## Verification and bridge

- `git diff --check 96398e9 da76d2c4` passed during this read-only review.
- No test/build/gate was run by the reviewer. A final exact-tree gate result was not provided with the request; it remains a closeout requirement, independent of this source approval.
- **[Bridge Unavailable - Failed Open]**: `gemini_review_diff` is absent from the available tool inventory. No external review result is claimed.
