<!-- WHY: Defines a dual-layer ban policy (pre-resolution first-level Exclusion injection in EliderLifecycleParticipant plus post-resolution link-closure verification), a clear retention override name, and review-only POM exclusion recommendations. -->
# Work Package Handover: `banishedDependencies` and `retainedArtifacts` (`WP-POLICY-01`)

* **Date:** 2026-10-31
* **Last Reviewed:** 2026-11-02
* **Status:** Implemented and verified; see §7 for the final evidence and supported boundary.
* **Scope:** `elider-core`, `dependency-elider-maven-plugin`, focused tests, and user documentation
* **Related Documents:**
  * [RQ-0004: Maven dependency elider implementation](../research/RQ-0004-maven-dependency-elider-implementation-handover.md)
  * [RQ-0005: Spring bean request evidence and autoconfiguration recommendations](../research/RQ-0005-spring-bean-request-evidence-and-autoconfiguration-recommendations.md)
  * [RQ-0006: Maven artifact-view consistency and early resolution hooks](../research/RQ-0006-maven-artifact-view-consistency-and-early-resolution-hooks.md)
  * [RQ-0017: Source generation lifecycle integration](../research/RQ-0017-source-generation-lifecycle-integration-and-deferred-source-root-completeness.md)

---

## 0. Motivation and Scope

`elide.excludedArtifacts` currently means force-retain. RQ-0004 explicitly describes that behavior as global retention at [line 256](../research/RQ-0004-maven-dependency-elider-implementation-handover.md#L256). This proposal does not characterize the existing contract as an accidental inversion. Rename the setting to `retainedArtifacts` because that name states its behavior plainly, and introduce `banishedDependencies` as a separate strict policy for requesting removal from the current resolved project inventory.

Repository POMs use `0.1.0-SNAPSHOT` and `git tag --list` currently yields no local release tags. Those facts do not prove that no release was published elsewhere. Before removing `elide.excludedArtifacts` without an alias, verify publication history. If it was never released, remove it and reject its obsolete CLI/POM setting explicitly so Maven cannot silently ignore a typo or stale configuration. If published, stop and document the compatibility decision before implementation.

`banishedDependencies` combines **two complementary layers** so users get the best of both worlds—true pre-mediation Maven `<exclusion>` semantics across every first-level dependency when the core extension is active, plus strict post-resolution link-closure and absence verification in `elide` / `analyze`:

1. **Pre-Resolution First-Level `Exclusion` Injection ([`EliderLifecycleParticipant.afterProjectsRead`](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/EliderLifecycleParticipant.java#L30-L33))**: Because `afterProjectsRead` runs after Maven interpolates the project model and **before** Maven Resolver collects and mediates dependencies, `EliderLifecycleParticipant` resolves `banishedDependencies` (`<banishedDependency>` / `-Delide.banishedDependencies`) for the project and attaches an `org.apache.maven.model.Exclusion(groupId, artifactId)` to every first-level `Dependency` in `project.getDependencies()` (failing fast if a first-level `<dependency>` itself matches a banished `groupId:artifactId`). Maven Resolver therefore prunes the banished transitive dependency and its subtree during dependency collection and mediates versions on the resulting graph just as if `<exclusions><exclusion>` had been written on every first-level `<dependency>` in `pom.xml`. See [Maven dependency exclusions](https://maven.apache.org/guides/introduction/introduction-to-optional-and-excludes-dependencies) and [Resolver dependency graph](https://maven.apache.org/resolver/dependency-graph.html).
2. **Post-Resolution Absence and Link-Closure Verification (`ElideMojo` / `AnalyzeMojo`)**: After resolution, `elide` and `analyze` verify that no banished coordinate remains in the resolved `compile`/`runtime` inventory (or, when running without the core extension's pre-resolution hook, enforce graph-approved post-resolution removal) and run full bytecode/resource/provider closure so any surviving reference from application code, retained dependencies, or supplied runtime traces to a banished library fails the build before publication.

A successful supported operation must either make each requested ban absent from the supported output or fail before publication with a clear reason. It must never silently retain a requested ban and report success.

For Spring, this is the explicit second step after conservative/AOT analysis: the user selects a capability to remove because static analysis cannot establish application demand. The chosen removal may intentionally change beans and condition outcomes. Regenerate and validate the selected application variant, preserving its required remaining features; do not require every baseline bean to survive or relabel baseline observations as non-use.

## 1. Configuration Contract

### 1.1 `banishedDependencies` / `<banishedDependency>`

```xml
<configuration>
  <banishedDependencies>
    <banishedDependency>org.yaml:snakeyaml</banishedDependency>
  </banishedDependencies>
</configuration>
```

The equivalent user property is `-Delide.banishedDependencies=org.yaml:snakeyaml`.

The first implementation supports exact, trimmed `groupId:artifactId` identities
against the current project's resolved `compile` and `runtime` JARs. It covers
all versions and all classifiers of that group/artifact within those scopes.
Wildcards are invalid. Any matching resolved artifact of an unsupported type or outside supported scopes,
such as a non-JAR artifact or a `provided`, `system`, or `test` dependency, makes the request unsupported and fails,
even if there are also in-scope matches. An identity matching no resolved
artifact is reported as unmatched and is not described as a successful removal.
Classless JARs remain in scope and must be removable when graph, class, resource, and provider obligations permit it. A matching starter's removal does not imply removal of its transitive libraries; each descendant remains subject to graph and evidence checks.

Conflicts are checked by the same G:A identity. A ban cannot overlap
`retainedArtifacts` or a matching `elide.trimSkipArtifacts` entry. The existing
trim setting is named `trimSkipArtifacts` in code and CLI;
`trimPassThroughArtifacts` is not an existing setting. When trimming is enabled,
`trimSkipArtifacts` protects matched artifacts from whole-artifact elision as well
as archive rewriting. It is a stronger preservation request than membership alone.

### 1.2 `retainedArtifacts` / `<retainedArtifact>`

```xml
<configuration>
  <retainedArtifacts>
    <retainedArtifact>commons-io:commons-io</retainedArtifact>
  </retainedArtifacts>
</configuration>
```

The equivalent property is `-Delide.retainedArtifacts=commons-io:commons-io`. This replaces force-retention behavior currently exposed as `excludedArtifacts`. Preserve its current optional coordinate grammar: `groupId:artifactId[:version[:type[:classifier]]]`, where omitted type means `jar`, omitted classifier means empty, and omitted version matches all versions. Preserve current matching scope behavior unless a separately reviewed change specifies otherwise.

This pins whole-artifact membership; it does not independently promise retention of every class or byte-identical JAR contents. Preserve current trimming behavior. `trimSkipArtifacts` is the separate control for unchanged archive bytes, and its current implementation also contributes retention protection; test their combination rather than treating the two controls as synonyms.

These are configuration fields on the existing record-based core API; there is no `PruneConfig.Builder` or `banishes` API. The implementation updates the actual constructors and call sites.

### 1.3 Meaning and Dual-Layer Mechanics of a Ban

* **With the core extension active (`EliderLifecycleParticipant.afterProjectsRead`)**:
  * Before dependency resolution, each configured `banishedDependency` (`groupId:artifactId`) is added as a Maven `Exclusion` on every first-level `<dependency>` of the target project (recording the pre-injection user-authored exclusions first so Track 3's repeated-exclusion report does not count Elider-injected exclusions).
  * Inject exclusions only when the selected Maven invocation includes `elide`. An Analyze-only invocation captures the original model and predicts against the unmodified resolver graph. When one invocation selects both goals, Elide's selected policy requires injection before collection, and Analyze observes that shared graph.
  * If a direct first-level `<dependency>` in `project.getDependencies()` itself matches a banished `groupId:artifactId`, fail fast with a configuration conflict explaining that a direct dependency cannot be excluded via first-level `<exclusions>` and must be removed from `<dependencies>` (or handled as a graph-approved leaf drop).
  * Because Maven Resolver sees the `Exclusion` on every first-level `<dependency>` during collection, transitive occurrences of the banished coordinate and their subtrees are pruned before version mediation, avoiding false version-conflict or ancestor-promotion blocks in [`EffectiveGraphPolicy`](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/EffectiveGraphPolicy.java).
* **Post-resolution verification and fallback (without core extension or for remaining resolved nodes)**:
  * A ban applies to the current project's dependency views and generated outputs; it does not affect Maven plugin realms, annotation processors, or a published consumer POM unless effective-POM materialization ([`RQ-0017`](../research/RQ-0017-effective-pom-materialization-and-packaging.md)) is explicitly used.
  * If a banished coordinate is still present in the resolved inventory (for example, when running without the core extension), the graph policy may protect a raw drop or promote it as an ancestor of retained nodes. If graph policy protects or ancestor-promotes a ban, fail with a diagnostic before publication rather than silently retaining it.

## 2. Evidence and Removal Rules

### 2.1 Keep Evidence Separate from Policy

Retain the complete resolved inventory and evidence provenance through analysis.
Distinguish `forced_absent` from ordinary `unused` classification in decisions,
logs, and reports, and report failed plans explicitly. A ban is not evidence that
a dependency was unused, nor a vulnerability mitigation claim by itself. It
does not automatically make advisory evidence affected/applicable or qualify an
OpenVEX assertion.

An artifact's own metadata may be excluded as a self-retention reason when the artifact is removed. However, do not erase obligations from production source/bytecode, generated AOT output, or retained artifacts' descriptors, resources, service declarations, and providers that point into the banned artifact. A reference or resource/provider obligation from retained content conflicts with the ban and must fail before any output or Maven view is published. Duplicate providers are not interchangeable without separate proof.

Current `trim=false` analysis still runs class closure: retained class-bearing libraries are analyzed as unchanged programs, and references into raw drops can promote those drops (`ElisionReachabilityEngine`, `MultiReleaseJarTrimmer`, `SingleReleaseTrimInventory`, and `SingleReleaseClosureAnalyzer`). Preserve this behavior and test it with both trim modes. Do not implement a trim-disabled shortcut that bypasses closure.

For the initial strict slice, supplied runtime evidence that observes a class
provided by a requested ban is a conflict and fails the plan. Do not rewrite or
discard trace data to relabel the artifact `unused`. A user who intends to remove
a previously observed capability must record that feature change and capture
compatible evidence again. A future baseline comparison may retain the old trace
as historical evidence without treating it as current use.

Current production bytecode and source attribution expose referenced target class names but not a general source-class-to-target edge map. The first slice may report the banned coordinate, target class, and evidence/root origin when available. It must not promise the name of the referencing application/dependency class unless edge attribution is added and tested. Production output is not test output; do not claim that test-source or test-bytecode references were exhaustively checked. The current Maven goal's TEST resolution context describes the dependency graph inventory, not complete test bytecode attribution.

Conservative Spring metadata roots declared by a retained Spring artifact remain obligations even if a ban is requested. Removing them requires separately validated replacement evidence, such as a compatible AOT output model; it is not in this work package. An unmatched ban or one blocked by a retained descriptor cannot be converted into a successful absence claim.

### 2.2 Transaction and Graph Checks

All validation must complete before the existing publisher mutates project artifact views or commits generated outputs. At every effective graph evaluation, including graph-capture fail-closed paths, check that a requested ban remains absent. Check again before the bytecode-reachability loop promotes a raw drop, before building final output/cache identity, and immediately before publication. Any inability to establish the requested absence fails the operation.

A feasible first slice rejects graph-protected and ancestor-promoted bans, accepts graph-approved safe drops, then runs class/resource/provider closure. Any closure result that reaches a banned coordinate fails instead of promoting it. Do not promise removal of interior nodes that require graph rewriting; add that capability later through a resolver integration design.

## 3. Repeated POM Exclusion Recommendations

Recommendations are read-only review findings; they are not proof that a ban is equivalent to the repeated exclusions or permission to rewrite the POM automatically.

Count distinct active effective declaration paths, with each dependency declaration contributing at most once to a G:A exclusion count. Preserve local, inherited/parent, active-profile, and dependency-management provenance separately. Do not double-count the same declaration by combining raw/original and effective Maven models. Exclude wildcard or partial-wildcard exclusions from consolidation recommendations. Report unused dependency-management entries separately; they do not represent active exclusion paths.

For counts of two or more active declaration paths, report the excluded G:A, count, declaring dependencies, and origin/profile information. Explain that a global post-resolution ban affects current project output and can remove content needed by downstream consumers, while Maven path exclusions change dependency collection/mediation and may prune subtrees. A future migration helper would need reviewable edits, dependency re-resolution, and consumer-POM checks; it is outside this work package.

## 4. Further Capabilities Worth Investigating

* **Policy-only evaluation.** A mode that retains all non-banned artifacts could evaluate a narrow ban without also requesting telemetry-driven pruning. The current pruner requires matching observed dependency classes; such a mode needs an explicit analysis contract rather than a fabricated trace or silently relaxed prerequisite. It would still require graph, source/class, resource, and provider validation.
* **Collection-time first-level exclusion injection vs. post-resolution policy.** Injecting a Maven `Exclusion(groupId, artifactId)` onto every first-level `<dependency>` in `EliderLifecycleParticipant.afterProjectsRead` gives collection-time subtree pruning and mediation when the core extension is active, while post-resolution verification and bytecode/resource/provider closure in `ElideMojo`/`AnalyzeMojo` guarantee that no dangling references or unexcluded direct dependencies slip through. Direct declarations, reactor boundaries, plugin/processor separation, and consumer-POM publication semantics (`RQ-0017`) must remain explicit.
* **Reviewable migration support.** A future tool can compare the original graph and consumer behavior with proposed centralized exclusions. Keep existing POM exclusions until re-resolution and downstream-consumer tests demonstrate the intended change. Repeated exclusion counts alone cannot supply that evidence.

## 5. Implementation Tracks

### Track 1: Rename Retention Policy and Define the Resolved Inventory Contract

* Replace the `excludedArtifacts` parameter/property with `retainedArtifacts` in the actual `ElideMojo`, `AnalyzeMojo`, `ElisionAnalysisModel`, `MavenElisionService`, policy resolver, and graph operation fingerprint.
* Preserve the current retention coordinate matching rules. Reject obsolete `elide.excludedArtifacts` explicitly if release-history review confirms it is unreleased; do not keep a compatibility alias for an unreleased draft.
* Add the independent `banishedDependencies` configuration and normalized G:A
  identity validation, supported-scope matching, unmatched reporting, and
  conflicts with retention and trim-skip policy. Do not make AOT input a hidden
  part of this configuration/inventory slice.
* Give policy values distinct, normalized field labels in operation identity. Ensure the policy/action reasons also participate in prepared-analysis, report, output, and cache identities so stale cached or generated results cannot mask a changed ban.

### Track 2: Pre-Resolution First-Level `Exclusion` Injection and Strict Post-Resolution Verification

* In [`EliderLifecycleParticipant.afterProjectsRead`](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/EliderLifecycleParticipant.java), capture user-authored POM `<exclusions>` provenance before mutation, validate configured `banishedDependencies` (`<banishedDependency>` / `-Delide.banishedDependencies`), reject direct first-level `<dependency>` matches explicitly, and append a Maven `Exclusion(groupId, artifactId)` to every first-level `Dependency` in `project.getDependencies()` so Maven Resolver prunes the banished transitive dependency and its subtree during collection and mediation.
* In `ElideMojo` and `AnalyzeMojo`, resolve the inventory and verify ban policy. Preserve all snapshots and evidence; derive a ban policy view without mutating input evidence.
* Apply ban precedence before raw-prune retention signals and suppress only
  self-origin metadata contributions of the artifact actually being removed.
  Keep incoming obligations from retained content (and verify that no retained class or resource links to a class missing because its provider was banished pre-resolution).
* Reject graph-protected, ancestor-promoted, or fail-closed graph cases involving
  a ban. At each bytecode/resource/provider closure iteration, reject any newly
  reached banned coordinate before the existing promotion behavior.
* On success, verify banned coordinates are absent from resolved/direct project
  views and final generated archive outputs. Fail before publisher commit on
  conflicts. Keep Maven view and generated-output rollback behavior intact.
* Add focused tests for trim on/off, graph protection and ancestor promotion,
  closure from application and retained dependency roots, dynamic metadata,
  resources, service/provider references, classless JARs, unmatched/out-of-scope
  identities, and publication rollback.
* Exercise both supported lifecycle boundaries (`initialize` and trusted
  `process-classes`) and verify that unsupported writers remain rejected. This
  track does not infer or consume Spring AOT output; AOT replacement evidence
  needs its own input and validation design.

### Track 3: Read-Only Exclusion Review Findings

* Analyze effective active declarations with provenance, avoiding
  raw/effective double-counting and treating dependency-management-only rows
  separately.
* Add deterministic report data for repeated exclusion candidates. Keep the
  current unreleased report schema at version 1 while updating writer, reader,
  validator, fixtures, and documentation together.
* Do not generate POM edits or state that the suggestion is behaviorally equivalent to Maven exclusions.

### Track 4: Documentation and Examples

* Update README, `dependency-elider-maven-plugin/src/site/markdown/usage.md`,
  `docs/faq.md`, and the relevant research notes.
* Refresh affected transcript fixtures using `make update-transcripts`, then verify with `make check-transcripts`.
* Use focused `make test-plugin` runs while implementing and `make check` for final verification. The latter already runs the Java checks/tests and transcript check; avoid repeating the same suites without an intervening change.

## 6. Acceptance Criteria

* `retainedArtifacts` preserves the documented existing force-retention
  matching behavior. The obsolete setting is rejected explicitly after
  release-history verification; no silent fallback or alias remains for an
  unreleased setting.
* Ban names are trimmed exact G:A identities, all versions/classifiers within resolved compile/runtime JAR scope; wildcards fail. Classless JARs are considered. Unsupported type/scope matches fail, and unmatched names are explicitly reported as unmatched rather than successful removals.
* Conflicts with `retainedArtifacts` and matching `trimSkipArtifacts` fail
  before mutation/publication.
* A ban is successful only when absent from supported project views and
  generated outputs. Protected/ancestor-promoted, fail-closed, incoming
  class/resource/provider obligations, or newly reached drops cause failure.
  Safe graph-approved leaf drops succeed.
* Closure checks run with `trimJars=true` and `false`. Existing trim-disabled closure is preserved. No referencing-class diagnostic is promised without edge evidence.
* Own metadata can no longer retain a removed artifact, but retained Spring/native-image/service/resource/provider evidence pointing to it remains a conflict. Production AOT/test coverage is not claimed without separate inputs and proof.
* Repeated exclusion findings count distinct active effective paths, retain
  provenance, separate unused management entries, and remain advisory only.
* Policy changes invalidate relevant operation/cache/report/output identity;
  writer, reader, validator, fixtures, and docs agree on schema version 1 while
  unreleased.
* Tests demonstrate rollback on a failed ban and successful absence verification before commit.
* No claim is made that this post-resolution policy changes Maven's resolver
  graph globally or rewrites consumer metadata. Such behavior requires a later
  resolver integration and consumer contract, documented in an ADR.
* The repository-defined `make check` gate passes on the rebased implementation tree, including Java/static analysis, Markdown lint, scheduler/SBOM checks, and transcript verification.

## 7. Final Implementation and Verification

The work package is rebased onto progressed `main` commit
`024b092b93b05fe77de3215f92198da9e74fa80f`. The user-selected full dirty
snapshot was captured before main progressed as commit
`d152ead148f98e8c20982baba37c6419a602c8f8` (tree
`767ec799e111e6b99087bf9f427f4d43d0ed9a00`) and remains on the
`codex/wp-policy-01-pre-progressed-main-rebase` recovery branch. The requested
rebase excludes replaying that snapshot commit because progressed main already
carries the snapshot's tracked state; the original main worktree's tracked and
untracked snapshot was restored from the retained recovery stash after fast-forward.
The old untracked WP-POLICY handover is intentionally replaced by this final
version. The verified implementation candidate is `335f1f8aef20ac2567198df0b658c09af299cd9e`
(tree `5d4a16e6d364f349f259232e45ae20aebe26347a`). Rebase corrections preserve
mainline source-correspondence results, report proof/policy/exclusion/ban fields,
and execution-configuration publication APIs. README list spacing was corrected
for Markdown lint.

The full Java 21 `make check` passed on verified candidate `335f1f8a` and again
after integration on `d3fad3a`: Spotless,
Checkstyle, PMD, SpotBugs, core/plugin tests, 27 lifecycle integration tests,
coverage, Markdown lint, scheduler and SBOM checks, and configured transcript
drift. The plugin unit suite reported 767 tests with one skipped. The transcript
tool reported “Configured command transcripts are up to date.” The packaged
mixed-goal integration test passed with both Analyze/Elide goal orders; `make
lint-java` and `git diff --check` passed. Exact-tree contract and architecture
reviews approved commit `33a30c70` / tree `f70edffc`; the integrated-main review
approved commit `d3fad3a3b601ec01389ca74507b5b127d0e114a1`. Receipts are linked
from the versioned closeout. WP-POLICY-01 is fast-forwarded to local `main`; the
main worktree's 12 tracked modifications and four unrelated untracked paths
were restored from the retained recovery stash. The final delivery state is
recorded in the versioned sibling
[`2026-10-31-wp-policy-01-global-dependency-exclusions-and-retained-artifacts-flip-closeout.md`](2026-10-31-wp-policy-01-global-dependency-exclusions-and-retained-artifacts-flip-closeout.md).

The verified boundary is the current project's supported Maven views and
generated outputs. This work does not rewrite consumer POMs or promise changes
to arbitrary future Resolver requests, plugin realms, annotation-processor
paths, Spring AOT replacement evidence, or exhaustive test-bytecode coverage.
