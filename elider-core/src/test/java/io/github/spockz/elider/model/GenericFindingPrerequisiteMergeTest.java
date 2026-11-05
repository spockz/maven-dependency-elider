/* WHY: Keeps prerequisite dependency/class pairs atomic under scoped manual merge policy. */

package io.github.spockz.elider.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** Tests source-independent prerequisite merging and field presence. */
@SuppressWarnings({"PMD.AvoidDuplicateLiterals"})
class GenericFindingPrerequisiteMergeTest {
  /** Creates a test instance. */
  /* package */
  GenericFindingPrerequisiteMergeTest() {
    super();
  }

  @Test
  void unionsAtomicPairsAndAppliesManualReplacementOnlyInsideItsScope() {
    final PrerequisiteClaim first = new PrerequisiteClaim("org.example:first", "p.First");
    final PrerequisiteClaim second = new PrerequisiteClaim("org.example:second", "p.Second");
    final PrerequisiteClaim replacement =
        new PrerequisiteClaim("org.example:replacement", "p.Replacement");
    final VulnerabilityFindingContribution autoOne =
        contribution("[1,4)", FieldValue.supplied(Set.of(first)), MergePriority.AUTOMATIC, "a");
    final VulnerabilityFindingContribution autoTwo =
        contribution("[2,5)", FieldValue.supplied(Set.of(second)), MergePriority.AUTOMATIC, "b");
    final VulnerabilityFindingContribution manual =
        contribution("[2,3)", FieldValue.supplied(Set.of(replacement)), MergePriority.MANUAL, "m");
    final GenericVulnerabilityFinding finding =
        GenericVulnerabilityFinding.merge(List.of(autoOne, autoTwo, manual));
    final GenericVulnerabilityFinding reordered =
        GenericVulnerabilityFinding.merge(List.of(manual, autoTwo, autoOne, autoOne));

    assertAll(
        () -> assertThat(finding.effectivePrerequisitesFor("1.5")).containsExactly(first),
        () -> assertThat(finding.effectivePrerequisitesFor("2.5")).containsExactly(replacement),
        () -> assertThat(finding.effectivePrerequisitesFor("3.5")).containsExactly(first, second),
        () -> assertThat(finding.effectivePrerequisitesFor("4.5")).containsExactly(second),
        () ->
            assertThat(reordered.effectivePrerequisitesFor("3.5"))
                .isEqualTo(finding.effectivePrerequisitesFor("3.5")),
        () ->
            assertThat(reordered.effectivePrerequisitesFor("2.5"))
                .isEqualTo(finding.effectivePrerequisitesFor("2.5")));
  }

  @Test
  void enrichesOmittedManualGroupButExplicitEmptyClearsOnlyPrerequisites() {
    final PrerequisiteClaim prerequisite = new PrerequisiteClaim("org.example:first", "p.First");
    final VulnerabilityFindingContribution automatic =
        contribution(
            "[1,4)", FieldValue.supplied(Set.of(prerequisite)), MergePriority.AUTOMATIC, "a");
    final VulnerabilityFindingContribution omitted =
        contribution("[1,2)", FieldValue.omitted(), MergePriority.MANUAL, "m-omitted");
    final VulnerabilityFindingContribution empty =
        contribution("[2,3)", FieldValue.supplied(Set.of()), MergePriority.MANUAL, "m-empty");
    final GenericVulnerabilityFinding finding =
        GenericVulnerabilityFinding.merge(List.of(automatic, omitted, empty));

    assertAll(
        () -> assertThat(finding.effectivePrerequisitesFor("1.5")).containsExactly(prerequisite),
        () -> assertThat(finding.effectivePrerequisitesFor("2.5")).isEmpty(),
        () ->
            assertThat(finding.prerequisiteGroupStatusFor("2.5"))
                .isEqualTo(ClaimGroupStatus.EXPLICITLY_EMPTY),
        () -> assertThat(finding.codeGroupStatusFor("2.5")).isEqualTo(ClaimGroupStatus.DECLARED),
        () -> assertThat(finding.codeFor("2.5")).containsExactly(CodeReference.className("p.Code")),
        () ->
            assertThat(finding.prerequisiteGroupStatusFor("5"))
                .isEqualTo(ClaimGroupStatus.NOT_APPLICABLE));
  }

  @Test
  void unknownManualScopeCannotFallBackToAutomaticPrerequisiteProof() {
    final VulnerabilityFindingContribution automatic =
        contribution(
            "[1,4)",
            FieldValue.supplied(Set.of(new PrerequisiteClaim("org.example:first", "p.First"))),
            MergePriority.AUTOMATIC,
            "a");
    final VulnerabilityFindingContribution unknownManual =
        contribution("[1,2)", FieldValue.omitted(), MergePriority.MANUAL, "m")
            .withVersionClaim(
                VersionCoverageClaim.unresolvedAffected("git range", "unsupported version scheme"));
    final GenericVulnerabilityFinding finding =
        GenericVulnerabilityFinding.merge(List.of(automatic, unknownManual));

    assertAll(
        () ->
            assertThat(finding.prerequisiteGroupStatusFor("3"))
                .isEqualTo(ClaimGroupStatus.UNRESOLVED),
        () -> assertThat(finding.effectivePrerequisitesFor("3")).isEmpty());
  }

  @Test
  void rejectsIncompleteOrInexactPrerequisitePairs() {
    assertAll(
        () ->
            assertThatThrownBy(() -> new PrerequisiteClaim("org.example:first", null))
                .isInstanceOf(IllegalArgumentException.class),
        () ->
            assertThatThrownBy(() -> new PrerequisiteClaim(null, "p.First"))
                .isInstanceOf(IllegalArgumentException.class),
        () ->
            assertThatThrownBy(() -> new PrerequisiteClaim("org.example:*", "p.First"))
                .isInstanceOf(IllegalArgumentException.class),
        () ->
            assertThatThrownBy(() -> new PrerequisiteClaim("org.example:first", "p.First*"))
                .isInstanceOf(IllegalArgumentException.class));
  }

  private static VulnerabilityFindingContribution contribution(
      final String range,
      final FieldValue<Set<PrerequisiteClaim>> prerequisites,
      final MergePriority priority,
      final String provenance) {
    return new VulnerabilityFindingContribution(
        "CVE-2026-10000",
        Set.of(),
        "org.example",
        "library",
        "jar",
        "",
        List.of(VersionCoverageClaim.affected(range)),
        FieldValue.supplied(Set.of(CodeClaim.declared(CodeReference.className("p.Code")))),
        prerequisites,
        priority,
        AssessmentIntent.AUTO_VERIFY,
        provenance,
        Set.of());
  }
}
