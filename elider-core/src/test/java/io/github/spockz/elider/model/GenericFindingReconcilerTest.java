/* WHY: Prevents alias bridges and component mismatches from splicing vulnerability declarations. */

package io.github.spockz.elider.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** Tests identity grouping before common assessment. */
@SuppressWarnings({
  "PMD.AvoidDuplicateLiterals",
  "PMD.LawOfDemeter",
  "PMD.UnitTestContainsTooManyAsserts",
  "PMD.ShortVariable"
})
class GenericFindingReconcilerTest {
  /** Creates a test instance. */
  /* package */
  GenericFindingReconcilerTest() {
    super();
  }

  @Test
  void mergesUniqueCveAliasesAndPreservesCodeVersionScope() {
    final VulnerabilityFindingContribution advisory =
        contribution("GHSA-first", Set.of("CVE-2026-10001"), "jar", "", "[1,2)", "p.Code");
    final VulnerabilityFindingContribution cve =
        contribution("CVE-2026-10001", Set.of(), "jar", "", "[3,4)", null);
    final GenericFindingReconciler.Result result =
        GenericFindingReconciler.reconcile(List.of(advisory, cve));

    assertThat(result.findings()).hasSize(1);
    final GenericVulnerabilityFinding finding = result.findings().getFirst();
    assertAll(
        () -> assertThat(finding.vulnerabilityId()).isEqualTo("CVE-2026-10001"),
        () -> assertThat(finding.aliases()).contains("GHSA-first", "CVE-2026-10001"),
        () -> assertThat(finding.affects("2.5")).isFalse(),
        () -> assertThat(finding.affects("3.5")).isTrue(),
        () -> assertThat(finding.codeFor("1.5")).containsExactly(CodeReference.className("p.Code")),
        () -> assertThat(finding.codeFor("3.5")).isEmpty(),
        () -> assertThat(result.diagnostics()).isEmpty());
  }

  @Test
  void preservesAdvisoryOnlyFindingsAndExactComponentDiscriminators() {
    final VulnerabilityFindingContribution first =
        contribution("GHSA-a", Set.of("GHSA-b"), "jar", "", "[1,2)", "p.First");
    final VulnerabilityFindingContribution second =
        contribution("GHSA-b", Set.of(), "jar", "", "[1,2)", "p.Second");
    final VulnerabilityFindingContribution classified =
        contribution("GHSA-a", Set.of(), "jar", "tests", "[1,2)", "p.Classified");
    final VulnerabilityFindingContribution differentType =
        contribution("GHSA-a", Set.of(), "war", "", "[1,2)", "p.War");
    final GenericFindingReconciler.Result result =
        GenericFindingReconciler.reconcile(List.of(second, classified, first, differentType));

    assertAll(
        () -> assertThat(result.findings()).hasSize(3),
        () ->
            assertThat(result.findings())
                .allSatisfy(finding -> assertThat(finding.vulnerabilityId()).isEqualTo("GHSA-a")),
        () ->
            assertThat(result.findings().stream().map(finding -> finding.codeFor("1.5")).toList())
                .containsExactlyInAnyOrder(
                    List.of(
                        CodeReference.className("p.First"), CodeReference.className("p.Second")),
                    List.of(CodeReference.className("p.Classified")),
                    List.of(CodeReference.className("p.War"))));
  }

  @Test
  void lateAliasBridgeRevokesDerivedCanonicalizationWithoutMergingDistinctCves() {
    final VulnerabilityFindingContribution first =
        contribution("GHSA-a", Set.of("CVE-2026-10001"), "jar", "", "[1,2)", "p.First");
    final VulnerabilityFindingContribution cveOne =
        contribution("CVE-2026-10001", Set.of(), "jar", "", "[1,2)", "p.CveOne");
    final VulnerabilityFindingContribution bridge =
        contribution(
            "GHSA-bridge", Set.of("GHSA-a", "CVE-2026-10002"), "jar", "", "[1,2)", "p.Bridge");
    final VulnerabilityFindingContribution cveTwo =
        contribution("CVE-2026-10002", Set.of(), "jar", "", "[1,2)", "p.CveTwo");
    final GenericFindingReconciler.Result before =
        GenericFindingReconciler.reconcile(List.of(first, cveOne));
    final GenericFindingReconciler.Result after =
        GenericFindingReconciler.reconcile(List.of(first, cveOne, bridge, cveTwo));

    assertAll(
        () -> assertThat(before.findings()).hasSize(1),
        () -> assertThat(after.findings()).hasSize(4),
        () ->
            assertThat(finding(after, "CVE-2026-10001").codeFor("1.5"))
                .containsExactly(CodeReference.className("p.CveOne")),
        () ->
            assertThat(finding(after, "CVE-2026-10002").codeFor("1.5"))
                .containsExactly(CodeReference.className("p.CveTwo")),
        () -> assertThat(finding(after, "GHSA-a").hasAmbiguousIdentity()).isTrue(),
        () -> assertThat(after.diagnostics()).hasSize(1),
        () -> assertThat(first.vulnerabilityId()).isEqualTo("GHSA-a"));
  }

  @Test
  void ambiguousAdvisoryIdentityCannotGrantManualReplacementOrProofIntent() {
    final VulnerabilityFindingContribution first =
        contribution("GHSA-shared", Set.of("CVE-2026-10001"), "jar", "", "[1,2)", "p.First");
    final VulnerabilityFindingContribution second =
        contribution("GHSA-shared", Set.of("CVE-2026-10002"), "jar", "", "[1,2)", "p.Second");
    final VulnerabilityFindingContribution manual =
        new VulnerabilityFindingContribution(
            "GHSA-shared",
            Set.of(),
            "org.example",
            "library",
            "jar",
            "",
            List.of(VersionCoverageClaim.affected("[1,2)")),
            FieldValue.supplied(Set.of(CodeClaim.declared(CodeReference.className("p.Manual")))),
            FieldValue.omitted(),
            MergePriority.MANUAL,
            AssessmentIntent.AUTO_VERIFY,
            "manual-row",
            Set.of());
    final GenericFindingReconciler.Result result =
        GenericFindingReconciler.reconcile(List.of(first, second, manual));
    final GenericVulnerabilityFinding finding = result.findings().getFirst();
    final GenericFindingReconciler.Result reordered =
        GenericFindingReconciler.reconcile(List.of(manual, second, first, second));

    assertAll(
        () -> assertThat(result.findings()).hasSize(1),
        () -> assertThat(finding.hasAmbiguousIdentity()).isTrue(),
        () -> assertThat(finding.intentFor("1.5")).contains(AssessmentIntent.REVIEW_ONLY),
        () ->
            assertThat(finding.codeFor("1.5"))
                .containsExactly(
                    CodeReference.className("p.First"),
                    CodeReference.className("p.Manual"),
                    CodeReference.className("p.Second")),
        () ->
            assertThat(reordered.findings().getFirst().codeFor("1.5"))
                .isEqualTo(finding.codeFor("1.5")),
        () -> assertThat(reordered.diagnostics()).isEqualTo(result.diagnostics()));
  }

  private static GenericVulnerabilityFinding finding(
      final GenericFindingReconciler.Result result, final String id) {
    return result.findings().stream()
        .filter(value -> value.vulnerabilityId().equals(id))
        .findFirst()
        .orElseThrow();
  }

  private static VulnerabilityFindingContribution contribution(
      final String id,
      final Set<String> aliases,
      final String type,
      final String classifier,
      final String range,
      final String className) {
    return new VulnerabilityFindingContribution(
        id,
        aliases,
        "org.example",
        "library",
        type,
        classifier,
        List.of(VersionCoverageClaim.affected(range)),
        className == null
            ? FieldValue.omitted()
            : FieldValue.supplied(Set.of(CodeClaim.declared(CodeReference.className(className)))),
        FieldValue.omitted(),
        MergePriority.AUTOMATIC,
        AssessmentIntent.AUTO_VERIFY,
        id,
        Set.of());
  }
}
