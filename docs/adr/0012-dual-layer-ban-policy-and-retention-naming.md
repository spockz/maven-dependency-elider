<!-- WHY: Records the strict boundary between Maven collection-time exclusions, successful ban enforcement, audit evidence, and artifact retention naming. -->
# ADR-0012: Dual-Layer Ban Policy and Retention Naming

* **Status**: Accepted
* **Date**: 2026-11-02
* **Related**:
  * [ADR-0001: Runtime Telemetry-Driven Dependency Elision](0001-runtime-telemetry-driven-dependency-elision-at-maven-initialize-phase.md)
  * [ADR-0002: In-Memory Artifact Mutation](0002-in-memory-artifact-mutation-for-downstream-packaging-transparency.md)
  * [ADR-0010: `process-classes` Lifecycle and Bytecode Completeness](0010-process-classes-lifecycle-and-bytecode-completeness.md)
  * [WP-POLICY-01 handover](../handovers/2026-10-31-wp-policy-01-global-dependency-exclusions-and-retained-artifacts-flip.md)
  * [RQ-0006: Maven artifact-view consistency and early resolution hooks](../research/RQ-0006-maven-artifact-view-consistency-and-early-resolution-hooks.md)

<!-- semedit-adr-metadata:v1 keys=summary,description,role,scope,area,languages; do not change key names or order. -->
| Key | Value |
| :--- | :--- |
| summary | Separate artifact retention from strict dependency bans; combine collection-time exclusions with post-resolution absence and closure checks. |
| description | Specify original dependency evidence as audit-only and define fail-closed Elide enforcement when a requested ban is absent from supported project views and outputs with no surviving link obligations. |
| role | policy |
| scope | build-lifecycle |
| area | plugin-core |
| languages | java |

## Context

The former `excludedArtifacts` setting means force-retain an artifact. Its name suggests Maven exclusion behavior and obscures the distinction between retaining a node and requesting its removal. A separate `banishedDependencies` policy is needed for exact groupId:artifactId removal requests.

Maven exclusions apply to dependency paths during collection and mediation. A post-resolution request also has to account for direct dependencies, graph protections, application and retained-library bytecode, resources, service declarations, and providers. Freeze the original dependency model before exclusion injection, then resolve the original-input audit from that capture. Neither the model capture nor the later audit proves that all future resolver requests or consumers use a modified graph.

## Decision

1. Name whole-artifact force-retention `retainedArtifacts`. This pins artifact membership against whole-artifact elision; it does not promise unchanged archive bytes. `trimSkipArtifacts` remains the byte-identical pass-through control and may also protect whole-artifact membership.
2. Represent requested removal separately as exact `banishedDependencies` groupId:artifactId identities.
3. For `elide` enforcement, the design injects each ban as a Maven exclusion on every first-level dependency before Resolver collection when the core extension is active. A matching direct first-level dependency is rejected explicitly. This layer gives Maven collection and mediation the exclusion request; it is not itself proof of successful removal.
4. After resolution, `elide` validates configured identities against the supported current-project inventory and output. Report an unmatched identity distinctly: it is not a successful removal claim, but does not by itself fail the operation. Unsupported identities, a remaining graph-protected or ancestor-promoted match, or any surviving bytecode, resource, or provider obligation fail enforcement.
5. An Analyze-only invocation remains a nonmutating prediction. It may report whether analysis predicts a requested identity would be removed, but does not apply the ban or claim successful enforcement. If the same Maven invocation also selects `elide`, the selected Elide policy injects exclusions before collection and Analyze observes that shared graph; the mutation belongs to Elide enforcement, not Analyze. Keep this distinct from `elide` enforcement.
6. Freeze the original dependency model before injecting exclusions. Resolve the original-input audit later from that frozen capture; preserve its results as audit evidence only. Do not treat them as a complete record of every resolver request or as evidence that project consumers, plugin realms, annotation processors, or downstream consumer POMs received the ban.
7. Complete all `elide` policy, graph, and closure validation before publication. On success, the ban must be absent from supported resolved project views and generated outputs. On enforcement failure, do not publish reports, outputs, Maven artifact-view changes, or a resolver plan.

The ban applies to the current project's supported dependency views and generated outputs. It does not rewrite POM dependency declarations or a published consumer POM, mutate Maven plugin realms or annotation-processor paths, or promise global Resolver behavior. Any future extension of those boundaries requires its own integration evidence and contract.

## Invariants

* A configured ban is policy, not evidence of non-use, vulnerability mitigation, or successful absence.
* First-level exclusions assist pre-mediation collection; post-resolution verification and closure determine whether the operation can succeed.
* Evidence from the original model or resolver remains available for audit and is not rewritten to make a ban appear unused.
* The operation either satisfies the supported absence contract or fails before publication.
* Schema and protocol versions for unreleased persisted reports remain version 1 under [ADR-0005](0005-released-format-versioning.md).

## Consequences

The design permits a strict capability-removal request while retaining original graph evidence for audit. `analyze` can predict outcomes without enforcing them; `elide` must satisfy the absence contract or fail. Unmatched identities remain distinct from successful removals and are reported without being treated as operation failures. A matched request can fail even when collection removed the coordinate, because another surviving class, resource, or provider obligation conflicts with removal. The policy intentionally makes no promise about consumer POMs or universal Resolver mutation; those require separate designs and verification. Renaming retention removes ambiguity between force-retention and Maven dependency exclusions.
