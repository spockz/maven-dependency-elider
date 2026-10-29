<!-- WHY: Defines the evidence boundary for VEX claims based on absent exploit prerequisites while keeping Maven inventory limits explicit. -->
# ADR-0008: Evidence-Bounded Precondition-Gated VEX Attestations

* **Status**: Accepted
* **Date**: 2026-10-29

<!-- semedit-adr-metadata:v1 keys=summary,description,role,scope,area,languages; do not change key names or order. -->
| Key | Value |
| :--- | :--- |
| summary | Require exact prerequisite-class absence in a complete declared Maven build inventory before emitting precondition VEX. |
| description | Permit `requires_dependency` VEX only when advisory metadata identifies both a prerequisite coordinate and exact class, and an explicit completeness opt-in allows verification across the declared Maven build inventory. The assertion does not cover providers injected outside that inventory. |
| role | architecture |
| scope | vulnerability-assessment |
| area | plugin-core |
| languages | java |

## Context

The current omitted-code proof is bound to vulnerable classes in a specific trimmed archive. It cannot establish that a retained library is unaffected because a companion dependency is missing. Vulnerability metadata already has a `requiresDependency` coordinate field, but a coordinate check alone is insufficient: another dependency can contain the same class, including a shaded copy.

The Maven build also cannot establish unconditional runtime classpath closure. Resources, stale compiled output, later packaging inputs, and externally supplied runtime providers may add classes or behavior that are not represented by declared source roots and resolved dependency JARs. A `not_affected` assertion must state what inventory was examined and fail closed when that inventory is incomplete.

CycloneDX 1.6 defines `analysis.justification = requires_dependency` for a missing required dependency. OpenVEX 0.2.0 has no equivalent justification value. Its schema permits a `not_affected` statement to provide either a justification or an `impact_statement`, so OpenVEX can describe the missing prerequisite in the impact statement without inventing a taxonomy mapping.

## Decision

Support a separate precondition proof for a retained affected component. A mapping is eligible only when it specifies both the prerequisite Maven coordinate and the exact prerequisite class whose presence is required for exploitability. Coordinate-only metadata is not sufficient.

Require explicit `elide.preconditionClassPathComplete=true` opt-in for this proof. The verifier must construct a complete, immutable inventory for the declared Maven build scope, including application classes/resources and every effective post-elision dependency archive. It must bind the proof to a deterministic inventory fingerprint and per-file digests, and search that inventory for the exact prerequisite class. If any source, resource provider, dependency archive, or inventory input is unknown or cannot be verified, suppress the precondition VEX statement.

The completeness opt-in is a user assertion about the declared Maven build inventory. It does not prove absence of classes or equivalent providers introduced later by packaging, launch-time agents, container layers, application servers, or other external runtime mechanisms. Documentation and generated impact text must preserve this boundary and must not describe the result as unconditional runtime closure.

For CycloneDX 1.6, serialize a proven precondition as `analysis.state = not_affected` and `analysis.justification = requires_dependency`, with details naming the exact missing class and coordinate and identifying the declared inventory boundary. For OpenVEX 0.2.0, serialize `status = not_affected` and an explanatory `impact_statement`; omit `justification` because the OpenVEX justification enum has no exact precondition value. The pinned [OpenVEX 0.2.0 schema](../../elider-core/src/test/resources/schema/openvex-0.2.0.schema.json) requires either field for `not_affected`, and `impact_statement` is the accurate supported representation. This has a cost: impact statements are free-form and OpenVEX discourages relying on them when a suitable justification exists, so downstream automation and interoperability are weaker. The omission is still necessary to avoid making a false taxonomy claim.

When a single CVE and affected component have both an omitted-code proof and a precondition proof, emit one statement and prefer the omitted-code proof. It establishes the mapped vulnerable code's absence directly and does not depend on the narrower runtime-inventory assertion. If omitted-code proof does not succeed, a complete precondition proof may be used. Conflicting or incomplete evidence produces no statement.

Keep POM mapping overrides ahead of cached mappings when they address the same CVE and affected artifact. A project-specific mapping is an explicit correction of source metadata; existing matching behavior already applies that precedence. This precedence does not relax any proof gate.

## Invariants

* A precondition mapping contains both a Maven coordinate and an exact fully qualified prerequisite class name.
* Presence of that class in any inventoried application provider or effective dependency archive prevents the precondition proof.
* Precondition proof is disabled unless the user explicitly sets `elide.preconditionClassPathComplete=true`.
* Inventory incompleteness, unreadable inputs, digest mismatch, or an unknown class/resource provider suppresses the VEX statement.
* The proof binds to the retained affected component's verified bytes and to the complete declared Maven inventory fingerprint.
* The inventory claim does not include providers supplied outside the declared Maven build inventory.
* CycloneDX keeps `specVersion` 1.6; OpenVEX keeps its 0.2.0 context. Their version fields are not internal schema-version counters.
* Internal unreleased persisted formats remain at schema version 1 under [ADR-0005](0005-released-format-versioning.md).
* A CVE/component pair emits at most one statement; verified omitted-code evidence takes precedence over precondition evidence.

## Consequences

This design rejects cases where only coordinates are known, and it requires callers to affirm that the declared build inventory is complete. It reduces false claims caused by equivalent classes in other artifacts and makes incomplete source or archive evidence suppress VEX. It still cannot certify provider absence in future packaging inputs or deployment-time runtime environments, which must remain visible as a limitation. OpenVEX statements explain the precondition through `impact_statement` rather than an unsupported justification category.
