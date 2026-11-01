<!-- WHY: Investigates actionable advisory gap detection, pruning thresholds, and recorded heuristics for surfacing elision candidates without becoming an SCA scanner. -->
# RQ-0015: Actionable Advisory Gap Detection and Heuristic Elision Candidates

## Status

Open

## Current boundary

Dependency Elider's vulnerability assessment engine ([`MavenVulnerabilityAssessment.java`](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenVulnerabilityAssessment.java)) operates under a strict "Fail-Closed" and "Zero Hallucinated VEX" invariant established in [ADR-0003](../adr/0003-proguard-core-intra-jar-trimming-and-cyclonedx-pedigree.md), [ADR-0006](../adr/0006-dual-source-vulnerability-advisory-ingestion-from-cvelist-v5-and-osv-maven.md), and [ADR-0007](../adr/0007-proven-serviceloader-spi-roots-and-conservative-cve-exclusions.md):

1. **Typed Owner Evidence and Physical Proof**: Omitted-code VEX can follow validated effective-POM owner assertions represented by [`ExplicitClassMappingEvidence`](../../elider-core/src/main/java/io/github/spockz/elider/model/ExplicitClassMappingEvidence.java), or the distinct live-verified structured CNA proof capability after exact product/version, source-to-bytecode and physical checks. Precondition VEX remains on [`ExplicitPrerequisiteEvidence`](../../elider-core/src/main/java/io/github/spockz/elider/model/ExplicitPrerequisiteEvidence.java) and ADR-0008's complete-inventory boundary. [`ConfidenceLevel`](../../elider-core/src/main/java/io/github/spockz/elider/model/ConfidenceLevel.java) is descriptive; `HIGH` on an advisory mapping does not grant proof eligibility, and configured POM `LOW` or `MEDIUM` remains review-only.
2. **Review-Only Advisory Gaps**: Package-only and heuristic evidence are retained in the historical `dependency-elider:report` as separate review-only rows. Each row is bound to the exact assessed Maven coordinate and preserves OSV record ownership, aliases, provenance, raw package/source claims, and an explicit applicability result. Unsupported or ambiguous ranges remain `UNRESOLVED`; a matched record alone does not establish applicability. Removed, retained-and-trimmed, and retained-unchanged values describe inventory only. None of these rows creates VEX, mitigation, or a vulnerability classification.
3. **The Downstream Scanner Problem**: Even when Dependency Elider prunes 98% of a library's bytecode, external Software Composition Analysis (SCA) scanners (Trivy, Grype, Snyk, OSV-Scanner) inspect only the package coordinate in the post-elision SBOM and continue flagging the CVE as an active vulnerability.
4. **The Anti-Pattern (Becoming an SCA Scanner)**: If Dependency Elider began reporting *all* unmitigated CVEs for retained dependencies, it would duplicate dedicated SCA scanners, create build noise, and dilute its core mission as a dead-code elider and evidence generator.

This research investigates how Dependency Elider can highlight high-probability **advisory gaps** to developers in an actionable manner—inviting them to refine the configuration—without guessing, hallucinating VEX, or acting as a generic vulnerability scanner.

### Structured Source Claim Review

The elision snapshot preserves unresolved structured source claims with the exact Maven component, CVE source-record digest, CNA affected-entry identity, file/routine claims, optional freshly recomputed `SourceFile` matches, the saved `elide.assumeConventionalJavaSourceLayout` value, and unresolved rationale. A separately typed verified-proof section preserves provenance for claims that passed live verification. The flag defaults to `false`; `true` records a user assumption and permits only the documented source-root translation. It cannot waive complete attribution or physical proof. `dependency-elider:report` renders the saved snapshot and its generation time, without applying current configuration. A basename match alone remains an incomplete review lead; users may verify it and declare an exact POM mapping if automatic attribution abstains.

Package advisory and heuristic advisory rows are also rendered from this saved report snapshot. They keep the exact matched artifact version alongside raw OSV package/range claims, source origin, aliases, candidates, applicability rationale, and inventory disposition. An exact affected-version entry can establish applicability; unsupported, multiple, or otherwise unresolved raw ranges are reported as unresolved rather than flattened into a selected scope. Heuristic source URLs or candidate names are review leads only. Users must verify the exact source and artifact before declaring an exact POM mapping; a report candidate is not a mapping template or proof input.

**S2 source/build correspondence checkpoint (2026-11-01; reviewed GO at `f9131c8`):** S2 introduced non-authoritative exact source/build correspondence. Exact source-classifier resolution is only a locator; results bind source bytes and named repository provenance to the assessed GAVCE and ordinary unclassified JAR. Resolution clears Maven's `WorkspaceReader`; workspace and unknown repository origins abstain. Reproduction is pinned to the exact Oracle GraalVM JDK 21.0.12+7.1 image and fixed compiler options; source-unit output paths and bytes must equal the complete physical class inventory, including sibling, nested, local and anonymous classes. Nonempty manifest `Class-Path`, MRJARs, modules, generated/transforming builds and unsupported compiler settings abstain. This checkpoint did not itself authorize proof or reuse.

**Current production status (2026-11-01):** the WP-VEX-02 implementation revalidates the current typed OSV index, current raw CVE record, exact CNA product/version scope and source attribution at proof time, then admits a distinct structured capability only after physical omission checks. Reports and VEX preserve provenance while unresolved candidates remain separate. Invocation-scoped reuse is claim-independent, tied to current candidate/source identity and digests, canonical paths, resolver provenance, layout assumption, compiler identity/options and reproduced inventory; every proof repeats live scope and digest validation. The production publisher path exercises configured source resolution and installs the report, CycloneDX/OpenVEX outputs and generated-output manifest. The supported compiler/language boundary is ordinary non-MRJAR Java on the exact pinned JDK image. Final whole-package review and delivery to local `main` remain pending. See the [WP-VEX-02 current requirement matrix](../../.scratch/orchestration-status.md#wp-vex-02-typed-evidence-continuation-requirement-to-evidence-matrix).

---

## The Fundamental Dilemma: Machine Proof vs. Human Domain Knowledge

A critical architectural question is:
> *If the engine can identify that a library was heavily trimmed or an optional companion was absent, why can't the engine unilaterally declare `not_affected`? Why must an engineer intervene?*

The distinction rests on legal compliance, liability, and semantic boundaries:

1. **Why the Machine CANNOT Unilaterally Claim `not_affected`**:
   * A VEX statement is a cryptographically signed or verifiable compliance attestation. Downstream security tools, compliance auditors, and CI security gates blindly trust `not_affected` statements and suppress security alerts.
   * If an automated tool emits a VEX statement based on a heuristic (*"98% of classes were stripped, so the vulnerability is probably gone"*), and the vulnerable code happens to reside in the 2% of retained classes, the tool has introduced a **critical silent false negative**.
   * Therefore, the engine may only emit VEX when it has 100% mathematical link-closure proof:
     $$\text{Vulnerable Class } C \in \text{Original JAR} \quad \land \quad C \notin \text{Trimmed JAR}$$
     Without knowing the exact identity of $C$, the machine has no proof.

2. **Why the Human Engineer CAN Intervene**:
   * Upstream vulnerability advisories are frequently published as unstructured English prose rather than machine-readable class schemas.
   * A human engineer can read the advisory description, inspect the CVE references, and check release notes or patch commits.
   * The engineer understands their project's application domain (for example, *"our application only uses Logback for standard console logging; we do not use conditional script evaluators"*).
   * The engineer supplies the missing formal specification by adding a `<vulnerabilityMapping>` with `vulnerableClasses` or `requiresDependency` in the POM.
   * Once the human supplies the specification, Dependency Elider provides the **automated bytecode proof** ensuring that the specification is physically satisfied in the build output.

---

## Primary Proposal: Configurable Retention / Pruning Threshold Heuristic

### Concept

Instead of attempting to parse natural language or guess vulnerable classes, the engine evaluates the **physical class retention ratio** of retained libraries that have matching unmapped CVEs in the local advisory index:

$$\text{Retention Ratio} = \frac{|\text{Retained Classes in Trimmed JAR}|}{|\text{Original Classes in Upstream JAR}|}$$

When a retained dependency matches an advisory in the local index that has no symbol mapping, but the dependency was heavily trimmed (its retention ratio is below a strict threshold), the plugin emits an actionable lead.

### Configuration & Default Behavior

* **Parameter**: `@Parameter(property = "elide.cveCandidateRetentionThresholdPercent", defaultValue = "5")` (or retention $\le 5\%$, representing $\ge 95\%$ pruned).
* **Execution**: During `dependency-elider:report` or in `ElisionSummary` build logs:

  ```text
  [INFO] Heavily-trimmed dependencies with unmapped CVEs:
  [INFO]   - CVE-202X-YYYY in org.apache.commons:commons-compress:1.21
  [INFO]     Notice: 96% of classes were pruned (420/438 removed, 18 retained).
  [INFO]     Action: If the vulnerable class from the advisory is among the pruned code,
  [INFO]     add a <vulnerabilityMapping> in pom.xml to prove it absent and emit a VEX statement.
  ```

### Why this proposal is sound

1. **Zero Guessing**: The plugin does not speculate on what classes caused the CVE.
2. **Zero Hallucination**: No VEX statement is generated until the user supplies the mapping and the proof engine verifies it.
3. **High Signal-to-Noise**: Libraries that are moderately used (e.g. 30% or 80% retained) are ignored because the probability of the vulnerable code surviving is high. Only extreme dead-code scenarios ($\le 5\%$ retained) are surfaced.

---

## State of Brainstorm on Alternative Heuristics & Triage Summaries

During architectural exploration, three additional heuristic approaches were analyzed. While rejected for **automated VEX generation** (due to the strict "Zero Hallucination" and mathematical proof invariant), they present strong opportunities as **informational triage summaries** presented to the developer during `dependency-elider:report` to make investigation immediate and actionable.

### Alternative A: Upstream Git Fix Commit Diff Summaries

* **Concept**: When an advisory includes commit URLs (e.g., `github.com/.../commit/abc1234`), extract the touched `.java` filenames during offline index ingestion. At build time, intersect those touched filenames against the set of classes pruned or retained by link closure.
* **Triage Summary Presentation**:

  ```text
  [INFO]   - CVE-202X-ZZZZ in com.example:lib:2.0.0
  [INFO]     Advisory diff summary: Commit abc1234 touched 'BarEvaluator.java'.
  [INFO]     Elision status: All BarEvaluator*.class entries were pruned from your artifact.
  [INFO]     Suggested action: Add <vulnerabilityMapping> for 'com.example.lib.BarEvaluator' to emit VEX.
  ```

* **Benefits & Trade-offs**:
  * Does *not* generate automated VEX, preserving compliance integrity.
  * Gives the developer immediate, high-fidelity context without requiring them to manually browse GitHub diffs.
* **Open Refinement Question**: Can the offline ingestion pipeline (ADR-0006) safely extract touched Java source names into advisory index metadata so the Maven plugin performs pure in-memory string intersection without network access?

### Alternative B: Optional Companion Dependency Summaries (`<optional>true</optional>`)

* **Concept**: Inspect the declared `<optional>true</optional>` dependencies of retained libraries. When an advisory references companion capabilities (e.g. scripting, XML, cache), correlate the advisory reference with the absence of that optional dependency from the project's dependency graph.
* **Triage Summary Presentation**:

  ```text
  [INFO]   - CVE-2025-11226 in ch.qos.logback:logback-classic:1.5.18
  [INFO]     Advisory prerequisite summary: Advisory notes Janino is required for evaluation.
  [INFO]     Classpath status: 'org.codehaus.janino:janino' is absent from your project classpath.
  [INFO]     Suggested action: Add <requiresDependency>org.codehaus.janino:janino</requiresDependency> to confirm inactive.
  ```

* **Benefits & Trade-offs**:
  * Avoids automated claims based on heuristic text matching.
  * Clearly signals to the developer that an optional integration mentioned in the advisory is not present in their deployment.
* **Open Refinement Question**: Could curated advisory indexes or upstream OSV records provide structured companion identifiers to avoid fragile natural language text parsing?

### Alternative C: Package-Level 100% Elimination Summaries

* **Concept**: When an advisory specifies a subsystem, module, or package (e.g., `org.apache.foo.xml`), and that entire Java package namespace was 100% eliminated during link closure (0 surviving classes in that package), present this fact as part of the candidate summary.
* **Triage Summary Presentation**:

  ```text
  [INFO]   - CVE-202X-AAAA in org.apache.foo:foo-all:1.5
  [INFO]     Package summary: Advisory affects package 'org.apache.foo.xml.*'.
  [INFO]     Elision status: Package 'org.apache.foo.xml' was 100% pruned (all 34 classes eliminated).
  [INFO]     Suggested action: Verify if the vulnerability is confined to that package and map its entry class.
  ```

* **Benefits & Trade-offs**:
  * Provides coarse-grained reassurance to the developer when a feature area was purged wholesale.
  * Highlights potential opportunities to refine POM mappings.

---

## Research Questions

1. **Threshold Tuning & Denominator Sensitivity**:
   * How should the threshold behave for small dependency JARs? For example, in a library with only 5 classes, retaining 1 class is a 20% retention ratio, whereas in a library with 500 classes, retaining 20 classes is a 4% retention ratio.
   * Should the threshold require both a percentage ($\le 5\%$) and a minimum absolute pruned class count (e.g., $\ge 20$ classes pruned)?
2. **Ergonomics & Reporting Section**:
   * **Current implementation:** Structured source-review claims are saved in the successful elision snapshot and rendered by the explicit `mvn dependency-elider:report` goal; they do not appear in ordinary build logs. The rendering path is [`MavenElisionReportWriter`](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenElisionReportWriter.java), invoked by [`ReportMojo`](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/ReportMojo.java), and covered by [`MavenElisionSourceReviewReportTest`](../../dependency-elider-maven-plugin/src/test/java/io/github/spockz/elider/plugin/MavenElisionSourceReviewReportTest.java) and [`ReportMojoTest`](../../dependency-elider-maven-plugin/src/test/java/io/github/spockz/elider/plugin/ReportMojoTest.java). Whether future advisory-gap notification channels should add concise build-log output remains open and requires noise/ergonomics measurement.
3. **Opt-In / Opt-Out Controls**:
   * **Current implementation:** There is no `showCveCandidates` gate. Structured source-review rows are visible in the saved report regardless of layout mode. `-Delide.assumeConventionalJavaSourceLayout` defaults to `false`; when enabled, it supplies only the documented `src/main/java/` path-root translation and never waives complete source-to-class reproduction. The setting is retained in proof provenance and historical reports. Whether future notification channels need independent controls remains open.
4. **Offline Advisory Index Enrichment**:
   * Feeds may supply typed review candidates. A separate live-verified structured capability now admits `programFiles`/`programRoutines` only after exact CNA/OSV applicability, exact-version source lookup and complete byte-equal class attribution. Commit diffs, extracted names, cached candidate lists and confidence labels cannot promote heuristics to proof inputs. The supported compiler/language boundary and CNA declaration trust assumption are documented in ADR-0006; broader advisory-gap thresholds and notification policy remain open.

---

## Evidence Gates

* **Empirical Assessment**: Measure the frequency of candidate notifications across common open-source stacks (Spring Boot, Quarkus, Micronaut) with the 5% threshold.
* **Zero False Proofs**: Confirm that no VEX statement is generated without either validated explicit POM owner evidence or the distinct live-verified structured proof capability. Cached labels, heuristics, package identity and report snapshots must not mint proof authority; all admitted claims must pass current artifact and physical omission checks.
* **Clean Formatting**: Verify that output clearly distinguishes between verified mitigations and advisory gap leads.
* **Static Analysis**: Maintain compliance with all repository linters (`make check`).
