/* WHY: Pins source-independent finding merge semantics before the shared model is implemented. */

package io.github.spockz.elider.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** Tests semantic version and code-group merges. */
@SuppressWarnings({"PMD.AvoidDuplicateLiterals", "PMD.LawOfDemeter", "PMD.TooManyMethods"})
class GenericFindingMergeTest {
  /** Creates a test instance. */
  /* package */
  GenericFindingMergeTest() {
    super();
  }

  @Test
  void unionsAutomaticClaimsAndAppliesManualCodeOverrideOnlyWithinItsVersionScope() {
    final ArtifactCoordinate component = ArtifactCoordinate.of("org.example", "library", null);
    final VulnerabilityFindingContribution automaticOne =
        contribution(
            "CVE-2026-12345",
            component,
            List.of("[1.0,1.3)"),
            FieldValue.supplied(
                Set.of(
                    CodeClaim.declared(CodeReference.className("org.example.First")),
                    CodeClaim.declared(
                        CodeReference.sourceFile("src/main/java/org/example/Second.java")))),
            MergePriority.AUTOMATIC,
            AssessmentIntent.AUTO_VERIFY,
            "source-a");
    final VulnerabilityFindingContribution automaticTwo =
        contribution(
            "CVE-2026-12345",
            component,
            List.of("[1.2,1.5)"),
            FieldValue.supplied(
                Set.of(
                    CodeClaim.declared(
                        CodeReference.sourceFile("./src\\main\\java\\org\\example\\Second.java")))),
            MergePriority.AUTOMATIC,
            AssessmentIntent.AUTO_VERIFY,
            "source-b");
    final VulnerabilityFindingContribution disjoint =
        contribution(
            "CVE-2026-12345",
            component,
            List.of("[1.8,2.0)"),
            FieldValue.supplied(
                Set.of(CodeClaim.declared(CodeReference.className("org.example.Disjoint")))),
            MergePriority.AUTOMATIC,
            AssessmentIntent.AUTO_VERIFY,
            "source-c");
    final VulnerabilityFindingContribution manual =
        contribution(
            "CVE-2026-12345",
            component,
            List.of("[1.4,1.6)"),
            FieldValue.supplied(
                Set.of(CodeClaim.declared(CodeReference.routine("org.example.Manual#decode()")))),
            MergePriority.MANUAL,
            AssessmentIntent.REVIEW_ONLY,
            "project-pom");

    final GenericVulnerabilityFinding finding =
        GenericVulnerabilityFinding.merge(List.of(automaticOne, automaticTwo, manual, disjoint));

    assertAll(
        "merged finding preserves distinct coverage and scoped code policy",
        () -> assertThat(finding.affects("1.1")).isTrue(),
        () -> assertThat(finding.affects("1.3.5")).isTrue(),
        () -> assertThat(finding.affects("1.5.5")).isTrue(),
        () -> assertThat(finding.affects("1.7")).isFalse(),
        () -> assertThat(finding.affects("1.9")).isTrue(),
        () -> assertThat(finding.affects("2.1")).isFalse(),
        () ->
            assertThat(finding.codeFor("1.2.5"))
                .containsExactlyInAnyOrder(
                    CodeReference.className("org.example.First"),
                    CodeReference.sourceFile("org/example/Second.java")),
        () ->
            assertThat(
                    finding.effectiveCodeClaimsFor("1.2.5").stream()
                        .filter(claim -> claim.reference().kind() == CodeReference.Kind.SOURCE_FILE)
                        .findFirst()
                        .orElseThrow()
                        .reference()
                        .originalValues())
                .containsExactlyInAnyOrder(
                    "src/main/java/org/example/Second.java",
                    "./src\\main\\java\\org\\example\\Second.java"),
        () ->
            assertThat(finding.codeFor("1.4.5"))
                .containsExactly(CodeReference.routine("org.example.Manual#decode()")),
        () -> assertThat(finding.intentFor("1.4.5")).contains(AssessmentIntent.REVIEW_ONLY),
        () ->
            assertThat(finding.provenance())
                .containsExactlyInAnyOrder("source-a", "source-b", "source-c", "project-pom"),
        () ->
            assertThatThrownBy(() -> finding.provenance().add("changed"))
                .isInstanceOf(UnsupportedOperationException.class));
  }

  @Test
  void omittedManualCodeEnrichesAndProvenanceDoesNotChangeAssessment() {
    final ArtifactCoordinate component = ArtifactCoordinate.of("org.example", "library", null);
    final VulnerabilityFindingContribution automatic =
        contribution(
            "CVE-2026-12346",
            component,
            List.of("[1.0,2.0)"),
            FieldValue.supplied(
                Set.of(CodeClaim.declared(CodeReference.className("org.example.Automatic")))),
            MergePriority.AUTOMATIC,
            AssessmentIntent.AUTO_VERIFY,
            "provider-a");
    final VulnerabilityFindingContribution manual =
        contribution(
            "CVE-2026-12346",
            component,
            List.of("[1.0,2.0)"),
            FieldValue.omitted(),
            MergePriority.MANUAL,
            AssessmentIntent.REVIEW_ONLY,
            "project-pom");
    final GenericVulnerabilityFinding first =
        GenericVulnerabilityFinding.merge(List.of(automatic, manual));
    final GenericVulnerabilityFinding swappedProvenance =
        GenericVulnerabilityFinding.merge(
            List.of(withProvenance(automatic, "provider-b"), withProvenance(manual, "pom-copy")));

    assertAll(
        "manual review intent applies when omitted code is enriched",
        () ->
            assertThat(first.codeFor("1.5"))
                .containsExactly(CodeReference.className("org.example.Automatic")),
        () -> assertThat(first.intentFor("1.5")).contains(AssessmentIntent.REVIEW_ONLY),
        () -> assertThat(swappedProvenance.codeFor("1.5")).isEqualTo(first.codeFor("1.5")),
        () -> assertThat(swappedProvenance.intentFor("1.5")).isEqualTo(first.intentFor("1.5")),
        () ->
            assertThat(swappedProvenance.applicability("1.5"))
                .isEqualTo(first.applicability("1.5")));
  }

  @Test
  void mergeIsOrderIndependentAndIdempotentAndEmptyManualCodeClearsAutomaticGroup() {
    final ArtifactCoordinate component = ArtifactCoordinate.of("org.example", "library", null);
    final VulnerabilityFindingContribution automatic =
        contribution(
            "CVE-2026-12347",
            component,
            List.of("[1.0,2.0)"),
            FieldValue.supplied(
                Set.of(
                    CodeClaim.declared(CodeReference.className("org.example.Automatic")),
                    CodeClaim.declared(
                        CodeReference.sourceFile(
                            "./src\\main\\java\\org\\example\\Original.java")))),
            MergePriority.AUTOMATIC,
            AssessmentIntent.AUTO_VERIFY,
            "source");
    final VulnerabilityFindingContribution clearingManual =
        contribution(
            "CVE-2026-12347",
            component,
            List.of("[1.4,1.6)"),
            FieldValue.supplied(Set.of()),
            MergePriority.MANUAL,
            AssessmentIntent.REVIEW_ONLY,
            "manual");
    final GenericVulnerabilityFinding forward =
        GenericVulnerabilityFinding.merge(List.of(automatic, clearingManual));
    final GenericVulnerabilityFinding reversedAndDuplicated =
        GenericVulnerabilityFinding.merge(List.of(clearingManual, automatic, automatic));

    assertAll(
        "merge order and duplicate inputs do not affect semantic results",
        () -> assertThat(forward.affects("1.5")).isEqualTo(reversedAndDuplicated.affects("1.5")),
        () -> assertThat(forward.codeFor("1.3")).isEqualTo(reversedAndDuplicated.codeFor("1.3")),
        () ->
            assertThat(forward.intentFor("1.5")).isEqualTo(reversedAndDuplicated.intentFor("1.5")),
        () -> assertThat(forward.codeFor("1.5")).isEmpty(),
        () ->
            assertThat(forward.codeGroupStatusFor("1.5"))
                .isEqualTo(ClaimGroupStatus.EXPLICITLY_EMPTY),
        () ->
            assertThat(forward.codeFor("1.3"))
                .containsExactly(
                    CodeReference.className("org.example.Automatic"),
                    CodeReference.sourceFile("org/example/Original.java")));
  }

  @Test
  void packageCoverageCanExceedTheVersionScopeOfItsCodeClaims() {
    final ArtifactCoordinate component = ArtifactCoordinate.of("org.example", "library", null);
    final GenericVulnerabilityFinding finding =
        GenericVulnerabilityFinding.merge(
            List.of(
                contribution(
                    "CVE-2026-12348",
                    component,
                    List.of("[1.0,3.0)"),
                    FieldValue.omitted(),
                    MergePriority.AUTOMATIC,
                    AssessmentIntent.AUTO_VERIFY,
                    "package-source"),
                contribution(
                    "CVE-2026-12348",
                    component,
                    List.of("[1.0,2.0)"),
                    FieldValue.supplied(
                        Set.of(CodeClaim.declared(CodeReference.className("org.example.Scoped")))),
                    MergePriority.AUTOMATIC,
                    AssessmentIntent.AUTO_VERIFY,
                    "code-source")));

    assertAll(
        "wider affected coverage does not extend narrower code attribution",
        () -> assertThat(finding.affects("2.5")).isTrue(),
        () -> assertThat(finding.codeFor("2.5")).isEmpty(),
        () ->
            assertThat(finding.codeFor("1.5"))
                .containsExactly(CodeReference.className("org.example.Scoped")));
  }

  @Test
  void unsupportedCoverageRemainsVisibleAndDoesNotBecomeUnaffectedOrAutoVerify() {
    final GenericVulnerabilityFinding unresolved =
        GenericVulnerabilityFinding.merge(
            List.of(
                contribution(
                        "CVE-2026-12349",
                        ArtifactCoordinate.of("org.example", "library", null),
                        List.of(),
                        FieldValue.omitted(),
                        MergePriority.AUTOMATIC,
                        AssessmentIntent.AUTO_VERIFY,
                        "unsupported-source")
                    .withVersionClaim(
                        VersionCoverageClaim.unresolvedAffected(
                            "maven-range:unparsed", "unsupported Maven range syntax"))));
    final GenericVulnerabilityFinding supportedAndUnresolved =
        GenericVulnerabilityFinding.merge(
            List.of(
                contribution(
                        "CVE-2026-12350",
                        ArtifactCoordinate.of("org.example", "library", null),
                        List.of("[1.0,2.0)"),
                        FieldValue.omitted(),
                        MergePriority.AUTOMATIC,
                        AssessmentIntent.AUTO_VERIFY,
                        "supported-source")
                    .withVersionClaim(
                        VersionCoverageClaim.unresolvedAffected(
                            "maven-range:other", "unsupported additional predicate"))));

    assertAll(
        "unsupported applicability remains explicit without inventing policy",
        () ->
            assertThat(unresolved.applicability("1.5")).isEqualTo(VersionApplicability.UNRESOLVED),
        () ->
            assertThat(unresolved.unresolvedVersionClaims())
                .singleElement()
                .satisfies(
                    claim ->
                        assertThat(claim.diagnostic()).isEqualTo("unsupported Maven range syntax")),
        () -> assertThat(unresolved.intentFor("1.5")).isEmpty(),
        () ->
            assertThat(supportedAndUnresolved.applicability("1.5"))
                .isEqualTo(VersionApplicability.AFFECTED),
        () -> assertThat(supportedAndUnresolved.unresolvedVersionClaims()).hasSize(1));
  }

  @Test
  void boundedUnknownCoverageDoesNotPoisonAnotherAffectedSourceOrImportItsCode() {
    final ArtifactCoordinate component = ArtifactCoordinate.of("org.example", "library", null);
    final GenericVulnerabilityFinding finding =
        GenericVulnerabilityFinding.merge(
            List.of(
                contribution(
                        "CVE-2026-12351",
                        component,
                        List.of("[1.0,3.0)"),
                        FieldValue.supplied(
                            Set.of(
                                CodeClaim.declared(CodeReference.className("org.example.Valid")))),
                        MergePriority.AUTOMATIC,
                        AssessmentIntent.AUTO_VERIFY,
                        "supported")
                    .withVersionClaim(
                        VersionCoverageClaim.unresolvedRange(
                            "[1.5,2.0)", "status overlap is ambiguous")),
                contribution(
                        "CVE-2026-12351",
                        component,
                        List.of(),
                        FieldValue.supplied(
                            Set.of(
                                CodeClaim.declared(
                                    CodeReference.className("org.example.Unknown")))),
                        MergePriority.AUTOMATIC,
                        AssessmentIntent.AUTO_VERIFY,
                        "unknown")
                    .withVersionClaim(
                        VersionCoverageClaim.unresolvedRange(
                            "[1.5,2.0)", "source coverage is ambiguous"))));

    assertAll(
        "only positively applicable sources contribute code or review intent",
        () -> assertThat(finding.applicability("1.2")).isEqualTo(VersionApplicability.AFFECTED),
        () -> assertThat(finding.applicability("1.7")).isEqualTo(VersionApplicability.AFFECTED),
        () ->
            assertThat(finding.codeFor("1.7"))
                .containsExactly(CodeReference.className("org.example.Valid")),
        () -> assertThat(finding.intentFor("1.7")).contains(AssessmentIntent.AUTO_VERIFY),
        () -> assertThat(finding.unresolvedVersionClaims()).hasSize(2));
  }

  @Test
  void unresolvedManualOmittedCodeGroupAllowsAutomaticEnrichment() {
    final GenericVulnerabilityFinding finding =
        GenericVulnerabilityFinding.merge(
            List.of(
                contribution(
                    "CVE-2026-12352",
                    ArtifactCoordinate.of("org.example", "library", null),
                    List.of("[1.0,2.0)"),
                    FieldValue.supplied(
                        Set.of(
                            CodeClaim.declared(CodeReference.className("org.example.Automatic")))),
                    MergePriority.AUTOMATIC,
                    AssessmentIntent.AUTO_VERIFY,
                    "automatic-source"),
                contribution(
                        "CVE-2026-12352",
                        ArtifactCoordinate.of("org.example", "library", null),
                        List.of(),
                        FieldValue.omitted(),
                        MergePriority.MANUAL,
                        AssessmentIntent.REVIEW_ONLY,
                        "manual-source")
                    .withVersionClaim(
                        VersionCoverageClaim.unresolvedAffected(
                            "manual-version-predicate", "manual range is unsupported"))));

    assertAll(
        "an omitted manual code group remains eligible for automatic enrichment",
        () -> assertThat(finding.applicability("1.5")).isEqualTo(VersionApplicability.AFFECTED),
        () -> assertThat(finding.codeGroupStatusFor("1.5")).isEqualTo(ClaimGroupStatus.DECLARED),
        () ->
            assertThat(finding.codeFor("1.5"))
                .containsExactly(CodeReference.className("org.example.Automatic")),
        () -> assertThat(finding.intentFor("1.5")).contains(AssessmentIntent.REVIEW_ONLY));
  }

  @Test
  void normalizedDuplicateContributionsRetainTheirDistinctOriginalLocators() {
    final ArtifactCoordinate component = ArtifactCoordinate.of("org.example", "library", null);
    final VulnerabilityFindingContribution sourceRootPath =
        contribution(
            "CVE-2026-12353",
            component,
            List.of("[1.0,2.0)"),
            FieldValue.supplied(
                Set.of(CodeClaim.declared(CodeReference.sourceFile("src/main/java/p/F.java")))),
            MergePriority.AUTOMATIC,
            AssessmentIntent.AUTO_VERIFY,
            "same-source");
    final VulnerabilityFindingContribution packageRelativePath =
        contribution(
            "CVE-2026-12353",
            component,
            List.of("[1.0,2.0)"),
            FieldValue.supplied(Set.of(CodeClaim.declared(CodeReference.sourceFile("p/F.java")))),
            MergePriority.AUTOMATIC,
            AssessmentIntent.AUTO_VERIFY,
            "same-source");
    final GenericVulnerabilityFinding finding =
        GenericVulnerabilityFinding.merge(List.of(sourceRootPath, packageRelativePath));

    assertThat(finding.effectiveCodeClaimsFor("1.5").getFirst().reference().originalValues())
        .containsExactlyInAnyOrder("src/main/java/p/F.java", "p/F.java");
  }

  @Test
  void heuristicNamesRemainReviewLeadsAndNeverJoinDeclaredCodeClaims() {
    final GenericVulnerabilityFinding finding =
        GenericVulnerabilityFinding.merge(
            List.of(
                contribution(
                    "CVE-2026-12351",
                    ArtifactCoordinate.of("org.example", "library", null),
                    List.of("[1.0,2.0)"),
                    FieldValue.supplied(
                        Set.of(
                            CodeClaim.heuristic(
                                CodeReference.className("org.example.FromDescription")))),
                    MergePriority.AUTOMATIC,
                    AssessmentIntent.AUTO_VERIFY,
                    "arbitrary-source-label")));

    assertAll(
        "declaration classification is semantic model data, independent from source labels",
        () -> assertThat(finding.effectiveCodeClaimsFor("1.5")).isEmpty(),
        () -> assertThat(finding.codeGroupStatusFor("1.5")).isEqualTo(ClaimGroupStatus.OMITTED),
        () -> assertThat(finding.codeFor("1.5")).isEmpty(),
        () ->
            assertThat(finding.heuristicLeadsFor("1.5"))
                .containsExactly(CodeReference.className("org.example.FromDescription")));
  }

  @Test
  void catalogPriorityIsBetweenManualAndAutomaticPerVersionAndField() {
    final ArtifactCoordinate component = ArtifactCoordinate.of("org.example", "library", null);
    final VulnerabilityFindingContribution automatic =
        contribution(
            "CVE-2026-12354",
            component,
            List.of("[1.0,3.0)"),
            FieldValue.supplied(
                Set.of(CodeClaim.declared(CodeReference.className("org.example.Automatic")))),
            MergePriority.AUTOMATIC,
            AssessmentIntent.AUTO_VERIFY,
            "scanner");
    final VulnerabilityFindingContribution catalog =
        new VulnerabilityFindingContribution(
            "CVE-2026-12354",
            Set.of(),
            component.groupId(),
            component.artifactId(),
            component.type(),
            component.classifier(),
            List.of(VersionCoverageClaim.affected("[1.5,2.0)")),
            FieldValue.supplied(
                Set.of(CodeClaim.declared(CodeReference.className("org.example.Catalog")))),
            FieldValue.omitted(),
            MergePriority.CATALOG,
            AssessmentIntent.AUTO_VERIFY,
            "catalog:advisory-1",
            Set.of(new AdvisoryProvenance(EvidenceOrigin.CATALOG, "advisory-1", null, null)));
    final VulnerabilityFindingContribution manual =
        contribution(
            "CVE-2026-12354",
            component,
            List.of("[1.7,1.9)"),
            FieldValue.supplied(
                Set.of(CodeClaim.declared(CodeReference.className("org.example.Manual")))),
            MergePriority.MANUAL,
            AssessmentIntent.REVIEW_ONLY,
            "effective-project-pom");
    final GenericVulnerabilityFinding finding =
        GenericVulnerabilityFinding.merge(List.of(manual, automatic, catalog));

    assertAll(
        "candidate version selects the highest supplied code-group priority",
        () ->
            assertThat(finding.codeFor("1.2"))
                .containsExactly(CodeReference.className("org.example.Automatic")),
        () ->
            assertThat(finding.codeFor("1.6"))
                .containsExactly(CodeReference.className("org.example.Catalog")),
        () ->
            assertThat(finding.codeFor("1.8"))
                .containsExactly(CodeReference.className("org.example.Manual")),
        () -> assertThat(finding.intentFor("1.8")).contains(AssessmentIntent.REVIEW_ONLY),
        () ->
            assertThat(
                    finding.contributions().stream()
                        .flatMap(value -> value.sourceProvenance().stream())
                        .toList())
                .containsExactly(
                    new AdvisoryProvenance(EvidenceOrigin.CATALOG, "advisory-1", null, null)),
        () ->
            assertThat(finding.provenance())
                .containsExactlyInAnyOrder(
                    "scanner", "catalog:advisory-1", "effective-project-pom"));
  }

  @Test
  void catalogSelectionIsFieldSpecificAndEqualPriorityUnionIsDeterministic() {
    final ArtifactCoordinate component = ArtifactCoordinate.of("org.example", "library", null);
    final PrerequisiteClaim prerequisite =
        new PrerequisiteClaim("org.example:base", "org.example.Required");
    final VulnerabilityFindingContribution automatic =
        contribution(
            "CVE-2026-12355",
            component,
            List.of("[1.0,2.0)"),
            FieldValue.supplied(
                Set.of(CodeClaim.declared(CodeReference.className("org.example.Automatic")))),
            MergePriority.AUTOMATIC,
            AssessmentIntent.AUTO_VERIFY,
            "automatic");
    final VulnerabilityFindingContribution catalogCode =
        contribution(
            "CVE-2026-12355",
            component,
            List.of("[1.0,2.0)"),
            FieldValue.supplied(
                Set.of(CodeClaim.declared(CodeReference.className("org.example.Catalog")))),
            MergePriority.CATALOG,
            AssessmentIntent.AUTO_VERIFY,
            "catalog-code");
    final VulnerabilityFindingContribution catalogPrerequisite =
        new VulnerabilityFindingContribution(
            "CVE-2026-12355",
            Set.of(),
            component.groupId(),
            component.artifactId(),
            component.type(),
            component.classifier(),
            List.of(VersionCoverageClaim.affected("[1.0,2.0)")),
            FieldValue.omitted(),
            FieldValue.supplied(Set.of(prerequisite)),
            MergePriority.CATALOG,
            AssessmentIntent.AUTO_VERIFY,
            "catalog-prerequisite",
            Set.of());
    final VulnerabilityFindingContribution catalogCodeDuplicate =
        contribution(
            "CVE-2026-12355",
            component,
            List.of("[1.0,2.0)"),
            FieldValue.supplied(
                Set.of(
                    CodeClaim.declared(CodeReference.className("org.example.Catalog")),
                    CodeClaim.declared(CodeReference.className("org.example.SecondCatalog")))),
            MergePriority.CATALOG,
            AssessmentIntent.AUTO_VERIFY,
            "catalog-code-copy");
    final List<VulnerabilityFindingContribution> rows =
        List.of(automatic, catalogCode, catalogPrerequisite, catalogCodeDuplicate);
    final GenericVulnerabilityFinding forward = GenericVulnerabilityFinding.merge(rows);
    final GenericVulnerabilityFinding reordered =
        GenericVulnerabilityFinding.merge(
            List.of(
                catalogCodeDuplicate, catalogPrerequisite, automatic, catalogCode, catalogCode));

    assertAll(
        "catalog priority applies independently to supplied fields and unions ties"
            + " deterministically",
        () ->
            assertThat(forward.codeFor("1.5"))
                .containsExactly(
                    CodeReference.className("org.example.Catalog"),
                    CodeReference.className("org.example.SecondCatalog")),
        () -> assertThat(forward.effectivePrerequisitesFor("1.5")).containsExactly(prerequisite),
        () -> assertThat(reordered.codeFor("1.5")).isEqualTo(forward.codeFor("1.5")),
        () ->
            assertThat(reordered.effectivePrerequisitesFor("1.5"))
                .isEqualTo(forward.effectivePrerequisitesFor("1.5")));
  }

  @Test
  void omittedCatalogFieldsEnrichButExplicitlyEmptyCatalogFieldClearsOnlyThatGroup() {
    final ArtifactCoordinate component = ArtifactCoordinate.of("org.example", "library", null);
    final PrerequisiteClaim automaticPrerequisite =
        new PrerequisiteClaim("org.example:base", "org.example.Required");
    final VulnerabilityFindingContribution automatic =
        new VulnerabilityFindingContribution(
            "CVE-2026-12357",
            Set.of(),
            component.groupId(),
            component.artifactId(),
            component.type(),
            component.classifier(),
            List.of(VersionCoverageClaim.affected("[1.0,2.0)")),
            FieldValue.supplied(
                Set.of(CodeClaim.declared(CodeReference.className("org.example.Automatic")))),
            FieldValue.supplied(Set.of(automaticPrerequisite)),
            MergePriority.AUTOMATIC,
            AssessmentIntent.AUTO_VERIFY,
            "automatic",
            Set.of());
    final VulnerabilityFindingContribution catalog =
        contribution(
            "CVE-2026-12357",
            component,
            List.of("[1.0,2.0)"),
            FieldValue.supplied(
                Set.of(CodeClaim.declared(CodeReference.className("org.example.Catalog")))),
            MergePriority.CATALOG,
            AssessmentIntent.AUTO_VERIFY,
            "catalog-code-only");
    final GenericVulnerabilityFinding enriched =
        GenericVulnerabilityFinding.merge(List.of(automatic, catalog));
    final VulnerabilityFindingContribution explicitEmpty =
        new VulnerabilityFindingContribution(
            "CVE-2026-12357",
            Set.of(),
            component.groupId(),
            component.artifactId(),
            component.type(),
            component.classifier(),
            List.of(VersionCoverageClaim.affected("[1.0,2.0)")),
            FieldValue.omitted(),
            FieldValue.supplied(Set.of()),
            MergePriority.CATALOG,
            AssessmentIntent.AUTO_VERIFY,
            "catalog-clear-prerequisite",
            Set.of());
    final GenericVulnerabilityFinding cleared =
        GenericVulnerabilityFinding.merge(List.of(automatic, catalog, explicitEmpty));

    assertAll(
        "field omission enriches independently while explicit empty is not an unaffected assertion",
        () ->
            assertThat(enriched.codeFor("1.5"))
                .containsExactly(CodeReference.className("org.example.Catalog")),
        () ->
            assertThat(enriched.effectivePrerequisitesFor("1.5"))
                .containsExactly(automaticPrerequisite),
        () ->
            assertThat(cleared.prerequisiteGroupStatusFor("1.5"))
                .isEqualTo(ClaimGroupStatus.EXPLICITLY_EMPTY),
        () -> assertThat(cleared.effectivePrerequisitesFor("1.5")).isEmpty(),
        () -> assertThat(cleared.applicability("1.5")).isEqualTo(VersionApplicability.AFFECTED),
        () -> assertThat(cleared.codeFor("1.5")).isEqualTo(enriched.codeFor("1.5")));
  }

  @Test
  void unresolvedCatalogPrerequisiteIsSelectedWithoutSuppressingAutomaticCode() {
    final ArtifactCoordinate component = ArtifactCoordinate.of("org.example", "library", null);
    final CodeClaim automaticCode =
        CodeClaim.declared(CodeReference.className("org.example.Automatic"));
    final PrerequisiteClaim catalogPrerequisite =
        new PrerequisiteClaim("org.example:base", "org.example.Required");
    final VulnerabilityFindingContribution automatic =
        new VulnerabilityFindingContribution(
            "CVE-2026-12358",
            Set.of(),
            component.groupId(),
            component.artifactId(),
            component.type(),
            component.classifier(),
            List.of(VersionCoverageClaim.affected("[1.0,2.0)")),
            FieldValue.supplied(Set.of(automaticCode)),
            FieldValue.omitted(),
            MergePriority.AUTOMATIC,
            AssessmentIntent.AUTO_VERIFY,
            "automatic-code",
            Set.of());
    final VulnerabilityFindingContribution catalog =
        new VulnerabilityFindingContribution(
            "CVE-2026-12358",
            Set.of(),
            component.groupId(),
            component.artifactId(),
            component.type(),
            component.classifier(),
            List.of(
                VersionCoverageClaim.unresolvedRange(
                    "[1.0,2.0)", "catalog prerequisite scope cannot be verified")),
            FieldValue.omitted(),
            FieldValue.supplied(Set.of(catalogPrerequisite)),
            MergePriority.CATALOG,
            AssessmentIntent.REVIEW_ONLY,
            "catalog-prerequisite",
            Set.of());
    final GenericVulnerabilityFinding finding =
        GenericVulnerabilityFinding.merge(List.of(automatic, catalog));

    assertAll(
        "unresolved catalog scope blocks its prerequisite group without losing omitted-field"
            + " enrichment",
        () -> assertThat(finding.applicability("1.5")).isEqualTo(VersionApplicability.AFFECTED),
        () -> assertThat(finding.codeFor("1.5")).containsExactly(automaticCode.reference()),
        () ->
            assertThat(finding.prerequisiteGroupStatusFor("1.5"))
                .isEqualTo(ClaimGroupStatus.UNRESOLVED),
        () ->
            assertThat(finding.effectivePrerequisitesFor("1.5"))
                .containsExactly(catalogPrerequisite),
        () -> assertThat(finding.intentFor("1.5")).contains(AssessmentIntent.REVIEW_ONLY));
  }

  @Test
  void catalogContributionsCannotCrossExactComponentIdentity() {
    final VulnerabilityFindingContribution jar =
        contribution(
            "CVE-2026-12356",
            ArtifactCoordinate.of("org.example", "library", null),
            List.of("[1.0,2.0)"),
            FieldValue.omitted(),
            MergePriority.CATALOG,
            AssessmentIntent.AUTO_VERIFY,
            "catalog-jar");
    final VulnerabilityFindingContribution testsClassifier =
        new VulnerabilityFindingContribution(
            jar.vulnerabilityId(),
            Set.of("GHSA-example"),
            jar.groupId(),
            jar.artifactId(),
            "test-jar",
            "tests",
            jar.versionClaims(),
            jar.codeGroup(),
            jar.prerequisiteGroup(),
            MergePriority.CATALOG,
            AssessmentIntent.AUTO_VERIFY,
            "catalog-tests",
            Set.of());

    assertAll(
        "classifier and type remain part of candidate identity while aliases stay attached to their"
            + " row",
        () ->
            assertThatThrownBy(
                    () -> GenericVulnerabilityFinding.merge(List.of(jar, testsClassifier)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("exact component identity"),
        () -> assertThat(jar.aliases()).isEmpty(),
        () -> assertThat(testsClassifier.aliases()).containsExactly("GHSA-example"));
  }

  private static VulnerabilityFindingContribution contribution(
      final String cve,
      final ArtifactCoordinate component,
      final List<String> ranges,
      final FieldValue<Set<CodeClaim>> codeGroup,
      final MergePriority priority,
      final AssessmentIntent intent,
      final String provenance) {
    return new VulnerabilityFindingContribution(
        cve,
        Set.of(),
        component.groupId(),
        component.artifactId(),
        component.type(),
        component.classifier(),
        ranges.stream().map(VersionCoverageClaim::affected).toList(),
        codeGroup,
        FieldValue.omitted(),
        priority,
        intent,
        provenance,
        Set.of());
  }

  private static VulnerabilityFindingContribution withProvenance(
      final VulnerabilityFindingContribution contribution, final String provenance) {
    return contribution.withProvenance(provenance);
  }
}
