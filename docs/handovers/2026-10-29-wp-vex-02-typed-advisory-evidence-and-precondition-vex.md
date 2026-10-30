<!-- WHY: Specifies typed advisory evidence and fail-closed VEX eligibility without treating heuristic class guesses as proof. -->
# Work Package Handover: WP-VEX-02 Typed Advisory Evidence and Precondition-Gated VEX

* **Status**: Revised for Review
* **Date**: 2026-10-30
* **Target Base**: `main`
* **Related Research**:
  * [RQ-0013: Precondition-Gated VEX and Multi-Artifact Exploitability](../research/RQ-0013-precondition-gated-vex-and-multi-artifact-exploitability.md)
  * [RQ-0008: OSV SBOM Comparison and VEX Evidence](../research/RQ-0008-osv-sbom-comparison-and-vex-evidence.md)
* **Related Decisions**:
  * [ADR-0008: Evidence-Bounded Precondition-Gated VEX Attestations](../adr/0008-precondition-gated-vex-attestations.md)
  * [ADR-0006: Dual-Source Vulnerability Advisory Ingestion](../adr/0006-dual-source-vulnerability-advisory-ingestion-from-cvelist-v5-and-osv-maven.md)
  * [ADR-0005: Versioning Released Persisted Formats](../adr/0005-released-format-versioning.md)
  * [ADR-0003: ProGuard Core-Driven Intra-JAR Trimming](../adr/0003-proguard-core-intra-jar-trimming-and-cyclonedx-pedigree.md)

---

## 1. Objective and Scope

Replace the single confidence flag with typed advisory evidence that preserves its source, scope, and strength. Retain bare package advisories and prose-derived candidates for reporting, while ensuring only validated evidence can reach the existing omitted-code or precondition proof engines.

The accepted precondition proof boundary in ADR-0008 remains unchanged: a precondition mapping must identify both an exact prerequisite Maven coordinate and an exact fully qualified prerequisite class; the class and coordinate must both be absent from the complete, opted-in declared Maven inventory. This work package must not weaken that rule or reimplement its inventory proof.

The work package has four outcomes:

1. Structured CVE `programFiles` or `programRoutines` evidence can support a high-confidence class mapping only when its affected product/version scope is matched and the source location/routine is unambiguously attributed to classes in the exact artifact.
2. Prose, URL, and other heuristic candidates remain distinguishable and cannot generate VEX.
3. Bare package advisories remain visible without being described as mitigated merely because an artifact was dropped or heavily trimmed.
4. Cached and explicit POM mappings preserve provenance and pass the same proof-specific gates.

This design trusts a correctly matched CNA `programFiles` entry as the CNA's assertion that the listed source file is affected. It does not independently re-derive the CVE root cause. The [CVE Record Format](https://github.com/CVEProject/cve-schema/blob/main/schema/docs/versions.md) defines `programFiles` as affected source files on an affected product entry. The format does not define a source-file-to-JVM-class mapping; that attribution is a separate requirement of this tool. If the CVE is inaccurate or its affected-file list is incomplete, this tool cannot discover that from archive trimming alone. Output and documentation must preserve that trust boundary.

## 2. Evidence and VEX Boundary

### 2.1 Evidence Levels

| Evidence kind | Meaning | Allowed outcomes |
| :--- | :--- | :--- |
| **Verified class evidence** | An explicit POM mapping or a matched structured affected-file record has been mapped to an exact class set for an exact Maven component/version, retaining source provenance. | May enter `OmittedCodeProof`; VEX is emitted only if that proof succeeds. |
| **Verified prerequisite evidence** | Explicit metadata supplies both the prerequisite coordinate and exact prerequisite class. | May enter the existing `PreconditionProof`; VEX is emitted only if ADR-0008 inventory checks succeed. |
| **Corroborated source-file candidate** | A class-file `SourceFile` attribute matches the basename of a structured `programFiles` value; where package information can be resolved from the path, the class package is consistent with it. | Stronger review evidence than a prose/URL guess. Without the conventional-layout opt-in it remains `MEDIUM` and review-only. With opt-in it can support verified attribution only if the full class set is still established. |
| **Heuristic candidate evidence** | Class or dependency candidates were mined from prose, reference URLs, commit URLs, or an ambiguous source path. | May produce a clearly labeled review lead. Never VEX or an inactive/avoided classification. |
| **Package-only evidence** | An advisory identifies a package and affected version but supplies no validated class or prerequisite mapping. | May be listed as an advisory matched to the dependency inventory. Never VEX or an avoided-CVE claim. |

`HIGH`, `MEDIUM`, and `LOW` are display labels, not proof objects. No proof API may accept a naked confidence enum, class set, or dependency string and infer that its evidence is valid. Evidence objects must carry their origin and the checks that permit a particular proof. Do not combine heuristic candidates with verified class evidence in a way that promotes the heuristic candidates to the higher tier.

### 2.2 Structured Source-Location and Routine Eligibility

The presence of `programFiles` is meaningful: it is the CNA's structured assertion about affected source files. It is not, by itself, proof that an arbitrary class name extracted from the CVE belongs to those files. A `programFiles` item may be a name, path, or location; it is not necessarily an FQCN.

The same affected-product entry can also include `programRoutines`, a structured list of affected source functions or methods. This is relevant evidence, but the schema requires only a `name` string; it does not require a declaring class, parameter types, JVM descriptor, or unique routine identifier. A routine name can be overloaded or repeated across classes. `modules` identifies affected components or features at a broader level, while `repo` identifies the source repository and can help resolve Git-based version ranges; neither field alone identifies bytecode classes. See the [CVE Record Format field definitions](https://github.com/CVEProject/cve-schema/blob/main/schema/docs/versions.md).

A CVEList v5 file or routine entry may produce verified class evidence only when all of the following hold:

1. The source is the relevant CNA record for the CVE, and the exact record bytes or digest are retained as provenance.
2. The `programFiles` and `programRoutines` values are taken from one specific `containers.cna.affected[]` product entry. Do not collect them across affected entries and then match by package-prefix resemblance.
3. That product entry maps unambiguously to the Maven group and artifact under assessment. Prefer machine-readable package identity (`collectionURL` plus `packageName`, `packageURL`, or an equivalent exact identity); otherwise use a tested explicit identity mapping. Display-name or namespace-prefix guesses are insufficient.
4. The concrete artifact version is affected by both the selected CVE product entry and the matching OSV Maven entry. An unknown, unsupported, conflicting, or unmatched range prevents high-confidence classification.
5. Every listed source path and routine used for the class mapping resolves unambiguously to all corresponding class entries in the exact artifact version. For Java, checking the named top-level class and its nested, local, or anonymous class files is not sufficient by itself: one source file can also declare other package-private top-level types whose class files have unrelated names (for example, `Helper.class` from `Outer.java`). Inspect every top-level type declaration in the reported source file, including classes, interfaces, enums, annotation interfaces, and records, and include each declaration's complete class-file family. The exact-version Java source lookup and source-to-class attribution method remains an open design point for this work package. Determine whether to use a matching source archive, repository revision, or another verifiable build mapping; do not assume artifact metadata alone is sufficient. Until the lookup can enumerate the complete class set unambiguously, retain the candidate as a review lead and do not grant high-confidence class evidence or emit VEX automatically. Explicitly ask the user to verify the proposed class mapping against the relevant source/artifact and, if confirmed, add an exact POM `vulnerableClasses` mapping. A generated POM template may help, but must be labeled unverified and must not be applied automatically. The resulting explicit POM mapping may enter the existing omitted-code proof only after validation and must still pass all physical presence/absence and digest checks. Pair routine names with a source file or otherwise prove the declaring class; resolve overloads and repeated names to the full affected class set. A slash-to-dot conversion, basename match, or routine-name match alone is not sufficient.
6. The verified mapping retains the source path and routine names, product identity, affected-version evidence, source repository/revision when available, CVE record identity/digest, and resulting class names. The VEX proof must be traceable back to these inputs.

A class-file `SourceFile` attribute can corroborate a Java candidate: when present, if its filename matches the final component of a structured `programFiles` path and, where package information can be resolved from the path, the class package is consistent with it, report it as a stronger candidate than a prose or URL match. The [JVM Specification](https://docs.oracle.com/en/java/javase/26/docs/specs/jvms/jvms-4.html#jvms-4.7.10) makes `SourceFile` optional and defines it as the source filename, not a directory or full path. A match therefore does not identify the exact source location or prove that every class emitted from that compilation unit has been found.

Add a dedicated opt-in flag for assuming the conventional Java source layout (proposed name: `elide.assumeConventionalJavaSourceLayout`; bind it using the plugin's established option conventions). It defaults to `false`. When disabled or absent, do not infer an exact source path from package layout: abstain from automatic VEX, report the corroborated candidate for user review, and suggest adding an exact POM `vulnerableClasses` mapping if the user verifies it. When enabled, treat the conventional package-to-directory mapping as an explicit user assumption and retain that assumption in the evidence and report. The flag may resolve the path attribution when `SourceFile` and package metadata agree, but it does not establish that every class emitted by the source unit has been found. Verified class evidence still requires a unique, complete class set; missing attributes, sibling top-level types that cannot be accounted for, or conflicting mappings remain review-only even with opt-in.

The current [`OsvSnapshotIndexer`](../../elider-core/src/main/java/io/github/spockz/elider/scanner/OsvSnapshotIndexer.java) does not meet this boundary: it combines prose, reference URL, and `programFiles` extractions into one class set, then assigns `HIGH` when that set is nonempty. Replace that flattening so provenance remains attached to each candidate through matching, class attribution, and proof selection.

If a file path or routine cannot be associated with the exact product/version or its binary classes, keep the structured source evidence as a review lead and classify inferred class candidates as `MEDIUM`; do not pass them to `OmittedCodeProof`. A `programRoutines` name without a unique owner/class attribution is not high-confidence class evidence. A CVE product entry with no explicit Maven package identity may still qualify through a maintained, tested exact identity mapping, but must not qualify through a fuzzy string match.

Treat the CNA's nonempty `programFiles` and/or `programRoutines` as its declared affected-source set for that product/version. This is an explicit trust assumption required for whole-component VEX; the tool does not independently prove that the CNA enumerated every vulnerable file or routine. Do not claim that Dependency Elider independently verified the vulnerability or independently established list completeness. If a consumer cannot accept that CNA assertion, or if the source record conflicts with the OSV Maven mapping or another structured affected entry, keep the mapping below VEX eligibility and report the uncertainty.

### 2.3 Other Evidence Origins

* FQCNs extracted from descriptions, summaries, references, commit URLs, or unresolved Java source attribution are heuristic candidates. Keep their provenance and use `MEDIUM`; never merge them into a structured `programFiles`/`programRoutines` high-confidence set. Give the user an actionable review suggestion and, when possible, an unverified POM `vulnerableClasses` template; only the user's confirmed POM mapping can enter omitted-code proof.
* A class-file `SourceFile` match to a `programFiles` basename with compatible package/path information is a corroborated source-file candidate, stronger than prose/URL-only evidence. With the conventional-layout flag disabled or absent, keep it `MEDIUM` and review-only. With opt-in, it may support verified attribution only after the complete source-unit output set is established. Preserve the class entry, attribute value, flag value, source record, and match rationale.
* A bare OSV Maven GAV/version advisory is `LOW`. Retain it in reports and data; do not discard it because no class mapping exists.
* An explicit POM `vulnerableClasses` mapping is a project-owner assertion. It may be high-confidence evidence for omitted-code proof when the configured component identity and class names validate, and the mapping's origin remains `POM`. The proof must still confirm original presence, trimmed absence, nested-class absence, and artifact digests.
* An explicit POM precondition mapping is eligible only when it supplies both `requiresDependency` and exact `requiresClass`. A coordinate alone is not high-confidence precondition evidence.
* Any disagreement among applicable mappings for the same CVE and exact component is fail-closed for VEX. POM precedence over cache may remain, but precedence must not turn heuristic evidence into proof evidence or bypass validation.

### 2.4 Proof Obligations

**Omitted-code VEX** requires:

* Verified class evidence scoped to the exact affected Maven coordinate and version.
* The evidence-derived vulnerable class set, including any required nested/associated classes, is present in the original artifact and absent from the trimmed artifact.
* Original and trimmed artifact identities and SHA-256 digests match the trim record; all surviving MRJAR tiers are included in the absence check.
* No unresolved path-to-class mapping or conflicting advisory evidence remains.

The proof is class-level. If a mapped class is absent, its methods and nested-class outputs attributed to that class are absent from that component. `programRoutines` may help identify the owning class, but it does not enable method-level VEX: if the class survives, this proof cannot claim that only the vulnerable routine is absent.

Only after these checks may CycloneDX emit `analysis.justification = code_not_present` or OpenVEX emit `justification = vulnerable_code_not_present`.

**Precondition VEX** continues to require the existing ADR-0008 contract:

* Exact prerequisite Maven coordinate and exact prerequisite class are both present in the mapping.
* The affected component is present and its bytes are digest-verified.
* The explicit completeness opt-in is set, the declared Maven provider inventory is complete and digest-bound, and neither prerequisite coordinate nor exact class appears in that inventory. Completeness includes inspecting raw class entries in every declared provider, including root and every `META-INF/versions/<N>/` tier of MRJARs; indexed or metadata-derived class lists alone are insufficient.
* Any incomplete inventory, provider ambiguity, changed digest, or missing exact prerequisite class suppresses the statement. A prerequisite-only evidence object cannot be dispatched to omitted-code proof, and class-only evidence cannot be dispatched to precondition proof.

Do not infer a prerequisite dependency from prose and pass it to `PreconditionProof`. Only explicit, typed prerequisite evidence can enter that proof.

## 3. Data Model and Persisted Mapping Rules

Replace a free-standing `ConfidenceLevel` as the proof gate with immutable, provenance-carrying evidence variants. The exact Java API is implementation work, but it must express at least these distinctions:

* `StructuredSourceClassEvidence`: CVE source record identity/digest, exact affected product identity, affected-version scope, `programFiles` and `programRoutines` entries, source-to-class attribution, and the resulting verified class set.
* `CorroboratedSourceClassCandidate`: CVE source record identity/digest, affected product/version scope, `programFiles` value, matching class entry and optional `SourceFile` value, package/path comparison, conventional-layout flag value, and an explicit not-yet-complete mapping status. This variant is review-only and cannot be passed to proof APIs.
* `ExplicitClassMappingEvidence`: exact affected coordinate, classes, POM origin, and the user assertion that those classes are vulnerability-relevant.
* `ExplicitPrerequisiteEvidence`: exact affected coordinate, prerequisite coordinate, exact prerequisite class, and origin.
* `HeuristicCandidateEvidence`: tentative classes/dependencies and their prose/reference/URL origin.
* `PackageAdvisoryEvidence`: package identity, affected-version scope, and advisory source without code-level claims.

Proof methods should accept the narrow evidence variant they need, not the generic advisory union. Avoid public constructors that create proof-eligible evidence from arbitrary strings or sets without provenance and validation. Compatibility accessors may be retained only as ordinary internal APIs where needed; they must not preserve or reinterpret an obsolete serialized format.

Update the mapping writer, reader, validator, fixtures, and documentation together. These persisted formats have not been released: keep schema version 1, evolve the current v1 shape directly, add no compatibility aliases or migrations, and reject malformed or unprovable payloads explicitly. Old cache entries that mark heuristic or provenance-free mappings `HIGH` must not remain VEX-eligible. In offline mode, if a cache cannot provide the new required provenance, fail closed for that evidence and surface the cache problem; do not silently retain old high-confidence semantics.

Add a producer-compatibility gate to plugin-generated caches. Record the producing Maven plugin artifact identity and version separately from each cache format's `schemaVersion`/protocol version, and accept a cache only when both its schema is supported and its producer identity matches the running plugin. Obtain the version from the installed plugin artifact/descriptor, never from the consuming project's version. Since multiple local installs can share a `-SNAPSHOT` version, also record a unique build identity (such as the plugin artifact digest or a build revision that distinguishes dirty builds) and require it to match for snapshot builds. An absent or mismatched producer identity makes the cache incompatible: online execution refreshes or rebuilds it before use; offline execution must not use its stale vulnerability mappings for proof and may use only the existing conservative seed behavior with a diagnostic. Keep this metadata local to plugin-generated caches; validate external source documents by their own protocol and wrap them in the local cache metadata rather than requiring upstream payloads to claim this plugin version. Exact producer-version rejection intentionally trades cache reuse across plugin upgrades for simpler invalidation and safer evidence.

This producer gate does not replace protocol versioning. Keep each persisted format's schema/protocol version independent and at version 1 while unreleased. After a format is released, increment that format's version for incompatible changes regardless of whether the plugin version also changed.

## 4. Classification and Reporting

| Advisory evidence | Dropped artifact | Retained and trimmed artifact | Retained artifact, no class trim |
| :--- | :--- | :--- | :--- |
| Verified class/prerequisite evidence | Report the component as removed from the output inventory. These proof engines do not emit VEX for a dropped component. | Run the appropriate physical proof; failed proof remains an unresolved finding, with no VEX. | Use `PreconditionProof` only for exact prerequisite evidence and a complete inventory. |
| Corroborated source-file candidate | Report the class/source filename match and the conventional-layout flag state. If the flag is off or mapping is incomplete, ask the user to verify and add an exact POM `vulnerableClasses` mapping if confirmed. No VEX. | If complete attribution succeeds under the explicit assumption, transition to verified class evidence and run normal proof; otherwise keep the review lead and suggest the POM mapping. | Keep as a review lead and provide the same verify-then-configure suggestion when useful; no VEX. |
| Heuristic candidate evidence | Report the component as removed and optionally show the candidate source/class for review. Do not call the CVE avoided. | If candidate classes were pruned, report a review lead, ask the user to verify the mapping against source/artifact contents, and suggest adding an exact POM `vulnerableClasses` mapping if confirmed. A template must be marked unverified and never applied automatically. No VEX until the user confirms the mapping in the POM and the normal physical proof succeeds. | Report the review lead and the same verify-then-configure suggestion when useful; no VEX. |
| Package-only evidence | Report that the package is absent from the resulting dependency inventory. Do not claim the vulnerability was avoided. | Report the package-level advisory without implying code impact or mitigation. | Keep package-level advisory data available; do not emit VEX. |

Reports must distinguish a package removed from the output from vulnerable code proven absent. Do not use labels such as “Avoided CVE” for package-only evidence or percentage-pruned heuristics. Any POM template generated from heuristic evidence must be a review aid, not a ready-to-apply assertion that promotes the candidates to verified mappings.

## 5. Implementation Tracks

### Track 1: Evidence Model and Proof APIs (`elider-core`)

1. Add immutable evidence variants with source provenance and exact scope.
2. Make omitted-code proof consume validated class evidence and preserve current identity/digest checks.
3. Keep precondition proof on ADR-0008's exact coordinate-plus-class inventory boundary.
4. Ensure conflict reconciliation keeps separate evidence origins separate and suppresses VEX on unresolved disagreement.

### Track 2: Advisory Ingestion and Cache (`elider-core`)

1. Parse CVEList v5 CNA `affected[]` entries independently. Do not flatten product entries before identity/version matching.
2. Match the CVE product entry to the OSV Maven coordinate and concrete version using exact identifiers or a tested explicit mapping.
3. Resolve `programFiles` paths and `programRoutines` names to the complete class-entry set using a deterministic attribution method. For Java, enumerate sibling package-private top-level types as well as the named type and each type's nested/local/anonymous class files; a sibling such as `Helper.class` is not covered by an `Outer$*.class` match. Use a matching class-file `SourceFile` attribute and compatible package path as corroborating candidate evidence when available, but do not treat it as complete attribution. Design and document how to locate the source matching the exact artifact version or provide an equivalent complete build mapping; this lookup strategy is not settled by this proposal. Until it is implemented, classify unresolved Java mappings as review leads, do not emit VEX automatically, and suggest that users verify the candidate and add an exact POM `vulnerableClasses` mapping if confirmed. Pair routine names with an owner/source location and resolve overloads; names without unique attribution remain `MEDIUM`. Define the supported language and compiler matrix; unsupported or ambiguous source entries remain `MEDIUM`.
4. Keep prose and URL extraction separate as heuristic evidence. Preserve bare GAV advisories as package-only evidence.
5. Update cache reader/writer/validation to reject provenance-free cached `HIGH` records and caches with missing or mismatched producer identity under the v1 unreleased-format policy. Keep schema/protocol version checks independent, and ensure online refresh and offline fail-closed behavior are explicit.

### Track 3: Configuration and Assessment (`dependency-elider-maven-plugin`)

1. Parse POM mappings as explicit owner assertions with exact component identity and typed evidence origin.
2. Add the opt-in conventional Java source layout flag (proposed name `elide.assumeConventionalJavaSourceLayout`), defaulting to `false` when absent. When enabled, treat the layout as an explicit user assumption, retain it in evidence/report provenance, and include its value in the relevant cache fingerprint so toggling it invalidates stale evidence. The flag may resolve path attribution but must not waive complete-class-set proof.
3. Apply version and component matching before selecting evidence.
4. Add a producer-compatibility gate to both plugin-owned cache paths: the vulnerability mapping/index cache and the trimmed-output cache manifest. Store the running plugin artifact identity (`groupId`, `artifactId`, and version) separately from each cache's schema/protocol version; add a build identity for `-SNAPSHOT` installs so replacing one snapshot build invalidates the previous build's cache. Reject missing or mismatched producer metadata as a cache miss. Online execution refreshes/rebuilds or reanalyzes. Offline execution may regenerate from locally available inputs, but must never use incompatible cached trim output or vulnerability evidence; if regeneration is impossible, follow the existing cache-miss behavior, preserve conservative seed handling for vulnerability data, and diagnose the mismatch. Keep each unreleased cache schema at v1 and evolve it in place; bump each format independently after release when an incompatible change is needed.
5. Keep high, medium, and low outcomes distinct through removed, retained, and trimmed artifact reporting. When the flag is disabled and attribution is unresolved, surface the review candidate and verify-then-add-POM suggestion.
6. Route only validated high evidence to proof engines. Keep the existing transactional publication and ADR-0008 inventory freshness checks.

### Track 4: Serialization and Publication

1. Preserve current CycloneDX 1.6 and OpenVEX 0.2.0 mappings for successful proof types.
2. Validate each attestation against the exact retained component or trim record and current on-disk digest.
3. Do not add unsupported schema fields to publish evidence provenance. Keep provenance in the internal evidence/report model and explain the trust boundary in `impact_statement` or `analysis.detail` where appropriate.
4. Preserve output transaction and generated-file ownership behavior, including stale OpenVEX cleanup rules already covered by ADR-0008 tests.

### Track 5: Fixtures, Unit Tests, and End-to-End Verification

Add focused fixtures covering:

* A valid CNA product entry whose Maven identity and affected version match the candidate artifact, with a source path that maps exactly to its compiled classes.
* A CVE with multiple `affected[]` products where only a different product has `programFiles`; it must not promote classes for the Maven artifact under analysis.
* A matching product but nonmatching, unknown, or conflicting version scope; no high-confidence mapping or VEX.
* Ambiguous/basename-only source paths, missing class/source metadata, and unsupported Kotlin source attribution; candidates stay heuristic and produce no VEX.
* A record containing both `programFiles` and prose FQCNs, where only the classes attributed to the structured file receive verified evidence.
* A record with `programRoutines` names that are unique, overloaded, or repeated across classes; only routines that resolve through the exact affected product/version to a complete class set may support VEX.
* A record containing only `modules` or `repo` without file/routine attribution; it must not create high-confidence class evidence.
* One Java source file declaring a public top-level type plus a package-private sibling top-level type, with nested/local/anonymous types under either; verify that the complete output families are attributed (including the sibling's unrelated binary-name prefix) using the exact source or a complete class-file mapping under the explicit layout assumption, and fail closed if neither can establish the full set unambiguously.
* A matching class-file `SourceFile` basename with a compatible package path is retained as stronger, corroborated review evidence than prose/URL extraction, while remaining ineligible for VEX until the complete source-unit class set is known; missing or mismatching attributes do not create the corroborated candidate.
* The conventional-layout flag defaults to disabled; disabled/absent behavior abstains and suggests user verification plus an exact POM mapping. With the flag enabled, a complete and unique class-file/source mapping may become verified evidence and enter normal proof; missing attributes, ambiguous matches, or unaccounted sibling types remain review-only. Record the assumption in the report and verify that toggling the flag invalidates cached mappings.
* An unresolved Java source mapping produces an actionable verify-and-add-POM-mapping suggestion but no VEX; after the user supplies a valid exact `vulnerableClasses` mapping, omitted-code VEX still requires the normal physical proof and digest checks.
* A valid mapped class omitted from all output tiers, a mapped class that survives, and a class absent from the original; only the first case may prove omitted code absent.
* An old cache payload with `HIGH` but no evidence provenance; it is rejected or made ineligible, including offline behavior.
* Vulnerability mapping/index and trimmed-output cache envelopes with the current producer identity, an older/different plugin version, a missing identity, and the same `-SNAPSHOT` plugin version but a different build identity; only the exact current producer is accepted. Test protocol/schema mismatch independently from producer mismatch. Verify offline runs regenerate from available inputs or follow the existing cache-miss behavior, never use stale trim output, and never feed stale vulnerability evidence to proof.
* Exact precondition coordinate and class absent, coordinate absent but class present in another declared provider (including a raw class entry in an MRJAR version tier), class absent but coordinate present, missing `requiresClass`, explicit completeness opt-out, incomplete inventory, and digest mutation.
* Proof dispatch rejects prerequisite-only evidence at omitted-code proof and class-only evidence at precondition proof.
* `MEDIUM` and `LOW` data never generates CycloneDX/OpenVEX `not_affected`, even when an artifact is dropped or most classes are pruned.
* Conflicting POM/cache/advisory rows, order-independent reconciliation, documented explicit POM override precedence, and explicit POM mappings passing the same physical proof gates.
* A regression where prose or a commit URL names a helper class that trimming removes while the mapped vulnerable class survives; neither CycloneDX nor OpenVEX may emit a `not_affected` claim.
* A bare package advisory whose entire component is removed; reporting may show the package is absent, but must not fabricate a class-level proof or VEX.

Every positive and negative VEX fixture validates CycloneDX 1.6 and OpenVEX 0.2.0 output against the pinned schemas. Where a real CVE fixture is unavailable, use a schema-valid synthetic record and label it as a test record; do not imply it is a real vulnerability.

## 6. Verification and Acceptance Criteria

1. `programFiles` and `programRoutines` produce verified class evidence only after exact affected product/version matching and deterministic source-to-class attribution.
2. The evidence model retains CVE record identity/digest, affected product/version context, source paths, and class attribution through proof selection.
3. Prose, reference, and URL-derived candidates remain medium-confidence and cannot be elevated by the existence of an unrelated `programFiles` entry.
4. Low and medium confidence advisories never produce VEX or “avoided CVE” claims.
5. Omitted-code VEX is emitted only when every validated mapped class is proven absent from the exact trimmed artifact, with original/output digests verified across all tiers.
6. Precondition VEX still requires exact prerequisite coordinate and class absence in the complete opted-in, digest-bound declared Maven inventory.
7. Provenance-free legacy cache entries cannot preserve high-confidence VEX eligibility; the writer, reader, validator, fixtures, and documentation agree on the current unreleased v1 format.
8. Existing safe-class fixtures still validate the Janino/Logback precondition statement against both schemas and the established inventory boundary.
9. New positive and negative `programFiles`/`programRoutines` cases cover cross-product leakage, version mismatch, path/routine ambiguity, mixed evidence origins, and complete source-to-class mapping.
10. Until exact-version Java source lookup is implemented, unresolved Java mappings produce a clearly labeled user review/configuration suggestion and no automatic VEX; a confirmed POM `vulnerableClasses` mapping is still gated by omitted-code proof. A matching class-file `SourceFile` attribute may strengthen the review candidate but never bypasses this boundary.
11. The conventional-layout flag is opt-in and false by default; disabled behavior abstains with a user decision prompt, enabled behavior records the assumption, and neither behavior bypasses complete class-set attribution. Flag changes invalidate cached mappings.
12. Both plugin-owned cache paths (vulnerability mapping/index and trimmed output) require the exact supported producer identity/version (and distinct build identity for snapshot builds), independently of their format's schema/protocol version. Missing or mismatched metadata is rejected as a cache miss; offline execution never consumes incompatible trim output or vulnerability mappings for proof.
13. Java formatting, static analysis, module tests, integration tests, and `make test-examples` pass. Run `make check` only where its Node-based targets are permitted by repository policy.

## 7. Delivery Notes

The precondition proof and publication architecture described by ADR-0008 already exist. This work package changes the evidence model and its ingestion/reporting gates; it must preserve that implementation's exact class, inventory completeness, digest, conflict, and transaction safeguards. Do not mark the proposal implemented until the evidence provenance fixtures and all negative VEX cases above pass.

This work package does not resolve the separate OSV version-range or partial-delta P1 findings. Precondition VEX proves absence only from the complete, opted-in declared Maven inventory; it does not establish that future or undeclared runtime providers are absent.
