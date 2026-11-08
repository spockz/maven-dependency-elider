// WHY: Pins explicit affectedness and manual priority separately from generic mapping adaptation.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.model.AdvisoryProvenance;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.AssessmentIntent;
import io.github.spockz.elider.model.CodeClaim;
import io.github.spockz.elider.model.CodeReference;
import io.github.spockz.elider.model.EvidenceOrigin;
import io.github.spockz.elider.model.FieldValue;
import io.github.spockz.elider.model.GenericVulnerabilityFinding;
import io.github.spockz.elider.model.MergePriority;
import io.github.spockz.elider.model.VersionCoverageClaim;
import io.github.spockz.elider.model.VulnerabilityFindingContribution;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** Verifies explicit affectedness and manual priority in the POM adapter. */
@SuppressWarnings("PMD.AtLeastOneConstructor")
final class ManualMappingAffectednessAndPriorityTest {
  /** Exact fallback version used by the mapping fixture. */
  private static final String COMPONENT_VERSION = "1.2";

  /** Non-singleton version range used by the mapping fixture. */
  private static final String RANGE = "[1.0,2.0)";

  @Test
  void rangeIsEvidenceScopeByDefaultAndAffectedOnlyWhenExplicitlyAsserted() {
    final VulnerabilityMappingConfig contextualRange = config();
    contextualRange.setVersion(null);
    contextualRange.setVersionRangeSpec(RANGE);
    final VulnerabilityMappingConfig assertedRange = config();
    assertedRange.setVersion(null);
    assertedRange.setVersionRangeSpec(RANGE);
    assertedRange.setAssertsAffected(true);

    final List<VulnerabilityFindingContribution> contributions =
        ConfiguredVulnerabilityMappings.fromPom(List.of(contextualRange, assertedRange))
            .contributions();

    assertAll(
        "a range scopes supplied mapping fields unless the POM explicitly asserts affectedness",
        () ->
            assertThat(contributions.getFirst().versionClaims())
                .containsExactly(VersionCoverageClaim.evidenceScope(RANGE)),
        () ->
            assertThat(contributions.get(1).versionClaims())
                .containsExactly(VersionCoverageClaim.affected(RANGE)),
        () ->
            assertThat(contributions.getFirst().versionClaims())
                .isNotEqualTo(contributions.get(1).versionClaims()));
  }

  @Test
  void exactVersionFallbackKeepsItsRangeButNeedsExplicitAffectedness() {
    final VulnerabilityMappingConfig defaultPin = config();
    final VulnerabilityMappingConfig falsePin = config();
    falsePin.setAssertsAffected(false);
    final VulnerabilityMappingConfig affectedPin = config();
    affectedPin.setAssertsAffected(true);

    final List<VulnerabilityFindingContribution> contributions =
        ConfiguredVulnerabilityMappings.fromPom(List.of(defaultPin, falsePin, affectedPin))
            .contributions();

    assertAll(
        "exact-version fallback remains a singleton range but does not imply affectedness",
        () ->
            assertThat(contributions.getFirst().versionClaims())
                .containsExactly(VersionCoverageClaim.evidenceScope("[1.2]")),
        () ->
            assertThat(contributions.get(1).versionClaims())
                .containsExactly(VersionCoverageClaim.evidenceScope("[1.2]")),
        () ->
            assertThat(contributions.get(2).versionClaims())
                .containsExactly(VersionCoverageClaim.affected("[1.2]")));
  }

  @Test
  void lowConfidenceManualMappingOverridesHighConfidenceCatalogIntentAndCode() {
    final VulnerabilityMappingConfig manualConfig = config();
    manualConfig.setVersion(null);
    manualConfig.setVersionRangeSpec(RANGE);
    manualConfig.setAssertsAffected(true);
    manualConfig.setVulnerableClasses(List.of("org.example.Manual"));
    manualConfig.setConfidenceLevel("LOW");
    final VulnerabilityFindingContribution manual =
        ConfiguredVulnerabilityMappings.fromPom(List.of(manualConfig)).contributions().getFirst();
    final ArtifactCoordinate component = ArtifactCoordinate.of("org.example", "affected", null);
    final VulnerabilityFindingContribution catalog =
        new VulnerabilityFindingContribution(
            "CVE-2025-12345",
            Set.of(),
            component.groupId(),
            component.artifactId(),
            component.type(),
            component.classifier(),
            List.of(VersionCoverageClaim.affected(RANGE)),
            FieldValue.supplied(
                Set.of(CodeClaim.declared(CodeReference.className("org.example.Catalog")))),
            FieldValue.omitted(),
            MergePriority.CATALOG,
            AssessmentIntent.AUTO_VERIFY,
            "catalog:high",
            Set.of(new AdvisoryProvenance(EvidenceOrigin.CATALOG, "catalog-high", null, null)));
    final GenericVulnerabilityFinding finding =
        GenericVulnerabilityFinding.merge(List.of(catalog, manual));

    assertAll(
        "manual LOW confidence remains review-only and its supplied code group outranks catalog"
            + " HIGH",
        () -> assertThat(manual.priority()).isEqualTo(MergePriority.MANUAL),
        () -> assertThat(finding.intentFor("1.5")).contains(AssessmentIntent.REVIEW_ONLY),
        () ->
            assertThat(finding.codeFor("1.5"))
                .containsExactly(CodeReference.className("org.example.Manual")));
  }

  private static VulnerabilityMappingConfig config() {
    final VulnerabilityMappingConfig config = new VulnerabilityMappingConfig();
    config.setCveId("CVE-2025-12345");
    config.setGroupId("org.example");
    config.setArtifactId("affected");
    config.setVersion(COMPONENT_VERSION);
    return config;
  }
}
