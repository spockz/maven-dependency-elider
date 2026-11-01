<!-- WHY: Investigates actionable advisory gap detection, pruning thresholds, and recorded heuristics for surfacing elision candidates without becoming an SCA scanner. -->
# RQ-0015: Actionable Advisory Gap Detection and Heuristic Elision Candidates

## Status

Open

## Current boundary

Dependency Elider's vulnerability assessment engine ([`MavenVulnerabilityAssessment.java`](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenVulnerabilityAssessment.java)) operates under a strict "Fail-Closed" and "Zero Hallucinated VEX" invariant established in [ADR-0003](../adr/0003-proguard-core-intra-jar-trimming-and-cyclonedx-pedigree.md), [ADR-0006](../adr/0006-dual-source-vulnerability-advisory-ingestion-from-cvelist-v5-and-osv-maven.md), and [ADR-0007](../adr/0007-proven-serviceloader-spi-roots-and-conservative-cve-exclusions.md):

1. **Typed Owner Evidence and Physical Proof**: VEX attestations are generated only from validated effective-POM owner assertions represented by [`ExplicitClassMappingEvidence`](../../elider-core/src/main/java/io/github/spockz/elider/model/ExplicitClassMappingEvidence.java) or [`ExplicitPrerequisiteEvidence`](../../elider-core/src/main/java/io/github/spockz/elider/model/ExplicitPrerequisiteEvidence.java), after exact component and version-scope matching and the required physical proof. [`ConfidenceLevel`](../../elider-core/src/main/java/io/github/spockz/elider/model/ConfidenceLevel.java) is descriptive; `HIGH` on an advisory mapping does not grant proof eligibility, and configured POM `LOW` or `MEDIUM` remains review-only.
2. **Review-Only Advisory Gaps**: Package-only and heuristic evidence are retained in the historical `dependency-elider:report` as separate review-only rows. Each row is bound to the exact assessed Maven coordinate and preserves OSV record ownership, aliases, provenance, raw package/source claims, and an explicit applicability result. Unsupported or ambiguous ranges remain `UNRESOLVED`; a matched record alone does not establish applicability. Removed, retained-and-trimmed, and retained-unchanged values describe inventory only. None of these rows creates VEX, mitigation, or a vulnerability classification.
3. **The Downstream Scanner Problem**: Even when Dependency Elider prunes 98% of a library's bytecode, external Software Composition Analysis (SCA) scanners (Trivy, Grype, Snyk, OSV-Scanner) inspect only the package coordinate in the post-elision SBOM and continue flagging the CVE as an active vulnerability.
4. **The Anti-Pattern (Becoming an SCA Scanner)**: If Dependency Elider began reporting *all* unmitigated CVEs for retained dependencies, it would duplicate dedicated SCA scanners, create build noise, and dilute its core mission as a dead-code elider and evidence generator.

This research investigates how Dependency Elider can highlight high-probability **advisory gaps** to developers in an actionable manner—inviting them to refine the configuration—without guessing, hallucinating VEX, or acting as a generic vulnerability scanner.

### Structured Source Claim Review

The elision snapshot preserves matched structured source claims with the exact Maven component, CVE source-record digest, CNA affected-entry identity, file/routine claims, optional freshly recomputed `SourceFile` matches, the saved `elide.assumeConventionalJavaSourceLayout` value, and unresolved rationale. The flag defaults to `false`; `true` records a user assumption and does not change candidate selection, confidence, proof eligibility, or classification. `dependency-elider:report` renders only the saved snapshot and its generation time, without applying current configuration. A basename match is an incomplete review lead: users must verify the complete source-to-class mapping against the exact artifact before adding an exact POM `vulnerableClasses` assertion. Exact-version source lookup and complete attribution remain deferred.

Package advisory and heuristic advisory rows are also rendered from this saved report snapshot. They keep the exact matched artifact version alongside raw OSV package/range claims, source origin, aliases, candidates, applicability rationale, and inventory disposition. An exact affected-version entry can establish applicability; unsupported, multiple, or otherwise unresolved raw ranges are reported as unresolved rather than flattened into a selected scope. Heuristic source URLs or candidate names are review leads only. Users must verify the exact source and artifact before declaring an exact POM mapping; a report candidate is not a mapping template or proof input.

**Source/build correspondence status (2026-11-01; review pending):** S2 correspondence is implemented in the feature worktree, with 9 focused tests and Java lint passing. Exact source-classifier resolution remains only a locator: the result binds source bytes and provenance to the exact assessed GAVCE and ordinary unclassified JAR. Reproduction is pinned to the reviewed Oracle GraalVM JDK 21.0.12+7.1 image and fixed compiler options; one source unit is compiled per isolated task, and the disjoint output paths and bytes must equal the complete physical class inventory, including sibling, nested, local, and anonymous classes. A nonempty manifest `Class-Path`, MRJARs, modules, generated/transforming builds, and unsupported compiler settings abstain. The false-by-default conventional-layout option translates only a claimed path root and cannot establish completeness. Routine-only claims require one declaration owner across the complete exact-version source archive; overloads and repeated names abstain, and a paired file claim cannot narrow the search. S2 output remains correspondence evidence only; no result enters proof before the separate S3 live-byte gate. See the [WP-VEX-02 S2 implementation](../../.scratch/orchestration-status.md#s2-sourcebuild-correspondence-implementation-review-pending).

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
   * **Current implementation:** There is no `showCveCandidates` gate. Structured source-review rows are visible in the saved report regardless of layout mode. The separate `-Delide.assumeConventionalJavaSourceLayout` flag defaults to `false` and only records an assumption/rationale; it does not control visibility, select candidates, or change proof eligibility. Assessment parity is covered by [`MavenCorroboratedSourceAssessmentTest`](../../dependency-elider-maven-plugin/src/test/java/io/github/spockz/elider/plugin/MavenCorroboratedSourceAssessmentTest.java), and saved historical flag behavior by [`MavenElisionSourceReviewReportTest`](../../dependency-elider-maven-plugin/src/test/java/io/github/spockz/elider/plugin/MavenElisionSourceReviewReportTest.java). Whether future notification channels need independent controls remains open.
4. **Offline Advisory Index Enrichment**:
   * Feeds may supply typed review candidates, but only validated effective-POM owner assertions are proof-eligible under the current design. Could a separately reviewed future attribution design establish the complete class set for the exact affected artifact version from source evidence? Commit diffs and extracted names remain review leads; confidence labels cannot promote them to proof inputs.

---

## Evidence Gates

* **Empirical Assessment**: Measure the frequency of candidate notifications across common open-source stacks (Spring Boot, Quarkus, Micronaut) with the 5% threshold.
* **Zero False Proofs**: Confirm that no VEX statement is generated under any circumstance without explicit, validated `vulnerabilityMappings`.
* **Clean Formatting**: Verify that output clearly distinguishes between verified mitigations and advisory gap leads.
* **Static Analysis**: Maintain compliance with all repository linters (`make check`).
