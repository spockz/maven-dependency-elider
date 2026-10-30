<!-- WHY: Defines the work package specification, track decomposition, and committable slices for precondition-gated VEX generation (RQ-0013, ADR-0008). -->
# Work Package Handover: WP-VEX-02 Precondition-Gated VEX Generation & Multi-Artifact Exploitability

* **Status**: Implemented and Verified
* **Owning Thread / Session**: Primary Coordinating Session
* **Date**: 2026-10-29
* **Target Branch / Base**: `main`
* **Related Research Questions**:
  * [RQ-0013: Precondition-Gated VEX and Multi-Artifact Exploitability](../research/RQ-0013-precondition-gated-vex-and-multi-artifact-exploitability.md)
  * [RQ-0008: OSV SBOM Comparison and VEX Evidence](../research/RQ-0008-osv-sbom-comparison-and-vex-evidence.md)
* **Related Architecture Decisions**:
  * [ADR-0008: Precondition-Gated VEX Attestations and Dual-Standard Serialization](../adr/0008-precondition-gated-vex-attestations.md)
  * [ADR-0005: Versioning Released Persisted Formats](../adr/0005-released-format-versioning.md)
  * [ADR-0003: ProGuard Core-Driven Intra-JAR Trimming and CycloneDX Pedigree](../adr/0003-proguard-core-intra-jar-trimming-and-cyclonedx-pedigree.md)

---

## 1. Executive Summary & Non-Negotiable Invariants

### 1.1 Objective

Extend Dependency Elider's vulnerability assessment and VEX generation engine from 1:1 intra-candidate bytecode pruning proofs to cross-artifact precondition-gated VEX attestations. When a vulnerability in a retained library requires companion prerequisite dependencies that are proven absent from the post-elision classpath (such as Janino for Logback `CVE-2025-11226`), Dependency Elider will emit standards-compliant VEX statements asserting `not_affected` across both embedded CycloneDX 1.6 and standalone OpenVEX 0.2.0 documents.

### 1.2 Non-Negotiable Invariants

1. **Zero Hallucinated Precondition VEX**: The engine must **never** emit a VEX statement for an unmet precondition unless explicit machine-readable metadata defines both the prerequisite companion coordinate (`requiresDependency`) and its exact required class (`requiresClass`), and the project explicitly opts in with `elide.preconditionClassPathComplete=true`. A complete, digest-bound inventory of declared Maven dependency and application providers must confirm that neither the prerequisite coordinate nor the exact class is present. Coordinate-only absence is insufficient. For proof inventory only, the compiler-generation guard requires a known Maven Compiler Plugin version from 3.13 through 3.x, explicitly resolved `maven.compiler.proc=none` for both `compile` and `testCompile`, and Java release or source/target levels of at least 11. Missing or unresolved values, conflicts, processor paths/lists/argument channels, custom compiler modes, or interface assertions leave the inventory incomplete. A separate lifecycle guard rejects unmodeled plugin executions before and after `INITIALIZE`, configured clean/site executions with unmodeled ordering, Enforcer executions at or after inventory capture or with unknown phases, filtered resources, build extensions, custom packaging, and unmodeled resource/compiler roots. It requires a nonempty Maven request containing one default lifecycle goal from `initialize` onward, optionally preceded by one `clean`; direct plugin goals and multiple lifecycle segments suppress proof. The opt-in cannot override detected downstream generators. If either prerequisite is present, or any inventory input is unknown or incomplete, no precondition VEX statement may be generated.

   Packaging proof supports only `jar` and `pom` projects and is restricted to maven-shade-plugin 3.6.0 with one `package`/`shade` execution and one built-in manifest transformer with a resolved main class. Any modeled JAR package execution requires `clean` before package so the standard JAR plugin cannot reuse a previous archive; Shade is covered as an additional package path. Clean skip/exclusion/failure overrides and deferred clean modes suppress proof. `war` and `maven-plugin` packaging remain incomplete because their generated providers are not modeled. Only the inherited signature-resource exclusions shown in the examples are allowed; custom Shade filters, transformers, inputs, plugin dependencies, source-JAR properties, resource-plugin dependencies, and maven-jar-plugin custom configuration or executions leave proof incomplete.
   When the requested lifecycle reaches `test`, proof also requires Maven Surefire Plugin 3.5.2's standard `default-test` execution and explicit `skipTests=true` from Maven request/user/project properties. The elision fixture skips test execution but still compiles and inventories test sources; baseline runs continue to execute tests.
   The provider inventory always includes `<build.directory>/generated-sources/annotations` and `<build.directory>/generated-test-sources/test-annotations`, even before compiler lifecycle goals add those roots. Custom generated-source directories suppress proof. Only the exact diagnostic compiler argument `-Xlint:all` is accepted; compiler plugin dependencies and all other compiler arguments suppress proof. The pre-capture Enforcer exception is limited to the built-in `requireJavaVersion`, `requireMavenVersion`, `requirePluginVersions`, `banDuplicatePomDependencyVersions`, `dependencyConvergence`, and `requireUpperBoundDeps` rules, with no custom rule implementation attributes or plugin dependencies.

2. **Strict Dual-Standard Serialization Semantics**:
   * **CycloneDX 1.6**: Emits `analysis.state = "not_affected"`, `analysis.justification = "requires_dependency"` (using the official CycloneDX 1.6 enum for "Exploitability requires a dependency that is not present"), and `analysis.detail` describing the absent companion coordinate.
   * **OpenVEX 0.2.0**: Emits `status = "not_affected"`, `impact_statement` detailing the absent companion coordinate, and **explicitly omits** the `justification` field. This adheres strictly to the OpenVEX 0.2.0 JSON schema (`anyOf: [{required: ["justification"]}, {required: ["impact_statement"]}]`) because the 5-value CISA justification taxonomy does not contain an exact match for unmet companion dependencies.
3. **Post-Elision Inventory Binding & Digest Integrity**: Every VEX statement must bind to an exact retained artifact present in the post-elision inventory and must verify the SHA-256 digest of the artifact file on disk. Precondition attestations do not require intra-JAR class trimming or an `ArtifactTrimRecord`.
4. **Unreleased Format Version Policy (ADR-0005)**: The internal `dependency-elider-report.json` and generated-output-manifest formats remain at version 1. CycloneDX 1.6 and OpenVEX 0.2.0 use their standards' format identifiers unchanged. Do not introduce compatibility aliases or increment internal schema versions prematurely.
5. **Tooling & Implementation Language Policy (AGENTS.md)**: No Python or Node.js in project code or tooling. Implement all logic and test assertions in Java, shell, or Go.
6. **Verification Gates**: Every track and slice must pass Java formatting, static analysis, tests, and `make test-examples`. Run `make check` only when its Node-based targets are permitted by repository instructions.

---

## 2. Architecture & Design Specification

### 2.1 Precondition Proof vs. Omitted Code Proof

Dependency Elider supports two distinct proof mechanisms for generating `not_affected` VEX attestations:

| Dimension | Intra-JAR Trimming Proof (`OmittedCodeProof`) | Precondition Proof (`PreconditionProof`) |
| :--- | :--- | :--- |
| **Trigger** | Vulnerable classes purged from candidate archive | Prerequisite companion dependency absent from classpath |
| **Evidence Basis** | Archive class entry comparison (`originalClasses` vs `trimmedClasses`) | Explicit complete-inventory opt-in plus digest-bound inspection of retained Maven dependency and application class providers for both the prerequisite coordinate and exact class |
| **Requirement** | Candidate must have an `ArtifactTrimRecord` | Affected library must be in post-elision inventory |
| **CycloneDX 1.6 Justification** | `code_not_present` | `requires_dependency` |
| **OpenVEX 0.2.0 Justification** | `vulnerable_code_not_present` | *Omitted* (relies on `impact_statement`) |
| **Report Phrasing** | *"CVEs with vulnerable code proven absent by trimming"* | *"CVEs inactive due to unmet prerequisite dependencies"* |

### 2.2 Proof Engine & Model Abstraction

1. **`VexAttestation`**:
   * Generalize `justification` validation to accept both `"vulnerable_code_not_present"` and `"requires_dependency"`.
   * For `"vulnerable_code_not_present"`, require non-empty `evidenceSymbols`, `originalSha256`, and `trimmedSha256`.
   * For `"requires_dependency"`, require non-blank `requiredDependency`, exact `requiredClass`, non-blank `postElisionSha256`, and empty/optional `evidenceSymbols`.
2. **`PreconditionProof`**:
   * Inspects `VulnerabilitySymbolMapping` (verifying both `mapping.requiresDependency()` and exact `mapping.requiresClass()` are populated).
   * Requires explicit complete-inventory opt-in and a complete snapshot covering effective retained dependency archives, application source declarations, class outputs, resources, and relevant output targets.
   * Validates that the affected coordinate is present in the retained inventory and reads its physical file SHA-256 digest.
   * Confirms that no retained artifact matches the prerequisite coordinate and no inventoried provider defines the exact prerequisite class (for example, `org.codehaus.janino.ClassBodyEvaluator`, which Logback Core 1.5.18's conditional-script path constructs directly).
   * Produces an immutable `VexAttestation` recording the affected library coordinate, the missing prerequisite coordinate and class, the verified inventory fingerprint, and the formatted impact statement.

### 2.3 Serializer Implementations

1. **`CycloneDxSbomGenerator`**:
   * For each attestation in `vulnerabilities`:
     * If `justification.equals("requires_dependency")`:
       * Emits `analysis.justification = "requires_dependency"`.
       * Validates against post-elision component inventory using SHA-256 (bypassing `trimRecords` check).
     * If `justification.equals("vulnerable_code_not_present")`:
       * Emits `analysis.justification = "code_not_present"`.
       * Validates against `trimRecords` and purged symbol evidence.
2. **`OpenVexGenerator`**:
   * For each statement:
     * If `justification.equals("requires_dependency")`:
       * Emits `status = "not_affected"`.
       * Emits `impact_statement = attestation.impactDetail()`.
       * Does not emit the `justification` field.
     * If `justification.equals("vulnerable_code_not_present")`:
       * Emits `status = "not_affected"`.
       * Emits `justification = "vulnerable_code_not_present"`.
       * Emits `impact_statement = attestation.impactDetail()`.

---

## 3. Track Decomposition & Directed Acyclic Graph (DAG)

```text
┌────────────────────────────────────────────────────────┐
│ Track 1: Architecture Decision Record (ADR-0008)       │
└──────────────────────────┬─────────────────────────────┘
                           │
             ┌─────────────┴─────────────┐
             ▼                           ▼
┌──────────────────────────┐┌──────────────────────────┐
│ Track 2: Core Model &    ││ Track 3: Dual VEX        │
│ Precondition Proof Engine││ Serializer Upgrades      │
└────────────┬─────────────┘└────────────┬─────────────┘
             │                           │
             └─────────────┬─────────────┘
                           ▼
┌────────────────────────────────────────────────────────┐
│ Track 4: Maven Vulnerability Assessment & Output Pub   │
└──────────────────────────┬─────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│ Track 5: Fixture Assertions & End-to-End Gates         │
└────────────────────────────────────────────────────────┘
```

---

## 4. Track Specifications & Committable Slices

### Track 1: Architecture Decision Record (ADR-0008) & Design Documentation

**Goal**: Formally document the architectural decisions, standards mapping, and OpenVEX justification omission strategy for precondition-gated VEX generation.

* **Slice 1.1: Author ADR-0008**
  * Create `docs/adr/0008-precondition-gated-vex-attestations.md`.
  * Detail the context, decision drivers, schema comparison (CycloneDX 1.6 vs OpenVEX 0.2.0), and invariants.
  * Document the explicit decision to omit `justification` in OpenVEX 0.2.0 in favor of `impact_statement`.
  * Update `docs/adr/README.md` to index ADR-0008.
* **Slice 1.2: Research Documentation Status Update**
  * Update `docs/research/RQ-0013-precondition-gated-vex-and-multi-artifact-exploitability.md` status to Accepted and reference ADR-0008.

---

### Track 2: Core Model & Precondition Proof Engine (`elider-core`)

**Goal**: Support precondition-backed VEX evidence within the immutable core model.

* **Slice 2.1: Extend `VexAttestation`**
  * Refactor `VexAttestation` to support multiple justification types:
    * `"vulnerable_code_not_present"`
    * `"requires_dependency"`
  * Add accessors or constructors that accommodate unmet dependency evidence:
    * `prerequisiteCoordinate()` (optional or non-blank when justification is `"requires_dependency"`).
    * `postElisionSha256()` representing the verified archive digest.
  * Ensure immutability, thread-safety, and null-safety.
* **Slice 2.2: Implement `PreconditionProof` Engine**
  * Create `io.github.spockz.elider.model.PreconditionProof`:
    * Public static method `prove(VulnerabilitySymbolMapping mapping, PreconditionClassInventory inventory)`.
    * Validates explicit complete-inventory opt-in, both prerequisite metadata fields, and absence of both the exact coordinate and exact class from the inventory.
    * Verifies the physical SHA-256 digest of the affected artifact and binds the proof to the inventory fingerprint.
    * Returns a validated `VexAttestation` with justification `"requires_dependency"` and descriptive `impactDetail`.
  * Unit tests in `PreconditionProofTest`:
    * Successful proof when companion is absent.
    * Rejection when companion is present in `retainedArtifacts`.
    * Rejection when mapping lacks `requiresDependency`.
    * Rejection when file digest fails verification.

---

### Track 3: Dual VEX Serializers & JSON Schema Validation (`elider-core`)

**Goal**: Update CycloneDX 1.6 and OpenVEX 0.2.0 serializers to emit schema-compliant statements for both pruned code and unmet dependencies.

* **Slice 3.1: Upgrade `CycloneDxSbomGenerator`**
  * In `CycloneDxSbomGenerator.vulnerabilities(...)`:
    * Branch on `attestation.justification()`:
      * For `"vulnerable_code_not_present"`: emit `"justification": "code_not_present"`, validate against `trimRecords`.
      * For `"requires_dependency"`: emit `"justification": "requires_dependency"`, validate that the component exists in `components` and its on-disk SHA-256 matches.
  * Unit tests in `CycloneDxSbomGeneratorTest` verifying output validates against `bom-1.6.schema.json`.
* **Slice 3.2: Upgrade `OpenVexGenerator`**
  * In `OpenVexGenerator.addStatement(...)`:
    * Branch on `attestation.justification()`:
      * For `"vulnerable_code_not_present"`: emit `"justification": "vulnerable_code_not_present"`.
      * For `"requires_dependency"`: omit the `"justification"` property entirely from the statement JSON object.
    * In both cases, emit `"impact_statement": attestation.impactDetail()`.
  * Update `validateEvidenceContent` to permit `"requires_dependency"`.
  * Unit tests in `OpenVexGeneratorTest` verifying output validates against `openvex-0.2.0.schema.json`.

---

### Track 4: Maven Vulnerability Assessment & Output Publication (`dependency-elider-maven-plugin`)

**Goal**: Connect precondition proofs into the Maven plugin's assessment and output generation workflow.

* **Slice 4.1: Integrate `PreconditionProof` into `MavenVulnerabilityAssessment`**
  * In `MavenVulnerabilityAssessment.assessMappings(...)`:
    * When evaluating applicable mappings with `requiresDependency` and `requiresClass` against the opted-in complete inventory:
      * If the prerequisite coordinate and exact class are absent from every inventoried provider:
        * Add to `inactivePreconditions` finding list.
        * Locate the physical archive of the retained library (from resolved artifacts or trimmed paths).
        * Execute `PreconditionProof.prove(...)` and append the resulting attestation to `attestations`.
* **Slice 4.2: Output Publisher and Mojo Integration**
  * Ensure `MavenElisionOutputPublisher` publishes both omitted-code and precondition attestations through `MavenSbomWriter.write(...)` and `writeOpenVex(...)` inside the `MavenOutputTransaction` boundary.
  * Verify `dependency-elider.openvex.json` is generated whenever any attestations exist (even if 0 artifacts were trimmed).
  * When trim-enabled publication has no attestations, do not serialize an invalid empty OpenVEX document. Remove a prior VEX only when its exact path and digest match the previous generated-output manifest; preserve modified or unowned files. Perform cleanup in the output transaction so a later publication failure restores the prior file and manifest.
  * With `elide.trimJars=false`, SBOM/OpenVEX publication and stale OpenVEX cleanup are outside this work package and do not run.
  * Unit tests in `MavenVulnerabilityAssessmentTest` and `ElideMojoTest`.

---

### Track 5: Fixture Validation, Verification Harness & End-to-End Gates (`examples`)

**Goal**: Validate the end-to-end behavior on realistic project fixtures.

* **Slice 5.1: Update `ExampleSupport.java` CVE Verifiers**
  * In `ExampleSupport.verifyCveSboms(...)`:
    * For `example-cve-safe-class-app`:
      * Verify that `target/dependency-elider.openvex.json` exists.
      * Verify that OpenVEX contains a `not_affected` statement for `CVE-2025-11226`.
      * Verify that the statement's `impact_statement` names `org.codehaus.janino:janino` and `org.codehaus.janino.ClassBodyEvaluator`.
      * Verify that the statement does **not** contain a `justification` field.
      * Verify that `target/dependency-elider-sbom.cdx.json` contains a vulnerability for `CVE-2025-11226` with `"justification": "requires_dependency"`.
* **Slice 5.2: End-to-End Fixture Execution**
  * Run `make test-examples` to verify all fixtures (`example-basic-app`, `example-spring-boot-app`, `example-cve-unused-app`, `example-cve-safe-class-app`).
  * Run `make check` to verify zero Spotless, Checkstyle, PMD 7.28.0, SpotBugs, or Markdownlint violations.

---

## 5. Verification Matrix & Acceptance Criteria

### 5.1 Verification Commands

```bash
# 1. Core unit tests and schema validations
mvn test -pl elider-core

# 2. Plugin unit and integration tests
mvn test -pl dependency-elider-maven-plugin

# 3. Full static analysis and linting gate
make check

# 4. End-to-end fixture execution and VEX verification
make test-examples
```

### 5.2 Acceptance Criteria

1. **Schema Validation**: Emitted CycloneDX 1.6 and OpenVEX 0.2.0 documents for `example-cve-safe-class-app` validate against official schemas with 0 errors.
2. **OpenVEX Format**: Statements for `requires_dependency` omit `"justification"` and provide `"impact_statement"`.
3. **CycloneDX Format**: Statements for `requires_dependency` specify `"justification": "requires_dependency"`.
4. **Console & Report Alignment**: `dependency-elider:report` continues to list inactive CVEs under `"CVEs inactive due to unmet prerequisite dependencies"`.
5. **No Regression**: All existing CVE test cases (Cases 1 through 4) pass with identical or improved fidelity.
6. **Stale VEX Ownership**: A trim-enabled run with no attestations removes only an unchanged plugin-owned OpenVEX document; modified and unowned documents remain untouched, and failures restore prior output and manifest bytes.

## 6. Delivery Record

* Implemented in worktree `.scratch/worktrees/track-vex-precondition-gated-generation` on branch `track/vex-precondition-gated-generation`.
* The Maven goal requires explicit completeness opt-in, proves absence of both the exact prerequisite coordinate and class across the declared inventory, and publishes report/SBOM/VEX files with Maven views and resolver-plan changes inside one rollback boundary. Frozen stage digests bind the ownership manifest and installed output bytes.
* After the final generation-guard changes, `make fmt` and `make lint-java` passed, the focused ADR-0008 proof suite passed 58/58 tests, and `make test-plugin` passed 340 plugin tests plus 15 lifecycle integration tests.
* The latest `make test-examples` passed all four standalone fixtures and the multi-module reactor. The safe-class report lists `CVE-2025-11226` inactive for `ch.qos.logback:logback-core:jar:1.5.18`; the fixture verifier checks both serializers and schema validity.
* Full `make check` was not rerun after these changes because repository instructions prohibit its Node-based SBOM and Markdown checks. The README safe-class transcript now shows the expected finding and the manifest requires its exact report line. Full transcript refresh/check was interrupted after its unrelated `analyze-cve-unused-app` invocation remained CPU-bound for over eight minutes; the safe-class report command itself passed against the verified snapshot.
* Earlier `make check` passed before the final guard changes with 226 core tests, 308 plugin tests, 15 lifecycle tests, 8 SBOM-comparison tests, clean formatting/Checkstyle/PMD/SpotBugs, and Markdown lint over 49 files with 0 issues. Full log: `/tmp/wp-vex-02-make-check-final-20261030-r3.log`; SHA-256 `7ed2aa306cb2d7182083ed3448acdd2e20397c64087c7a3128d3177677026bc7`.
* Earlier `make test-examples` passed for all four fixtures. The safe-class verifier schema-validates the actual CycloneDX and OpenVEX outputs and checks unique CVE findings/statements plus exact Logback Core PURL and matching SHA-256 bindings. Full log: `/tmp/wp-vex-02-test-examples-final-20261030-r2.log`; SHA-256 `c6d15304de822652d01c142ddc0be1dd270b1045970215ce0b44bc022fe2e616`.
