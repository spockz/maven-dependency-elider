/* WHY: Shares one strict contribution format between cache and saved project reports. */

package io.github.spockz.elider.advisory;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIOException;
import static org.junit.jupiter.api.Assertions.assertAll;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.spockz.elider.model.AdvisoryProvenance;
import io.github.spockz.elider.model.AssessmentIntent;
import io.github.spockz.elider.model.CodeClaim;
import io.github.spockz.elider.model.CodeReference;
import io.github.spockz.elider.model.ConfidenceLevel;
import io.github.spockz.elider.model.EvidenceOrigin;
import io.github.spockz.elider.model.FieldValue;
import io.github.spockz.elider.model.GenericVulnerabilityFinding;
import io.github.spockz.elider.model.MergePriority;
import io.github.spockz.elider.model.PrerequisiteClaim;
import io.github.spockz.elider.model.PrerequisiteGroup;
import io.github.spockz.elider.model.PrerequisiteOperator;
import io.github.spockz.elider.model.UnresolvedContributionField;
import io.github.spockz.elider.model.VersionCoverageClaim;
import io.github.spockz.elider.model.VulnerabilityFindingContribution;
import java.io.IOException;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** Checks generic project data can reuse the strict external contribution shape. */
@SuppressWarnings("PMD.LawOfDemeter")
class FindingContributionJsonCodecTest {
  /* WHY: These identifiers keep hand-authored payload rows consistent. */
  /** Group identity shared by hand-authored contribution rows. */
  private static final String GROUP_ID = "org.example";

  /** Artifact identity shared by hand-authored contribution rows. */
  private static final String ARTIFACT_ID = "library";

  /** Component type shared by hand-authored contribution rows. */
  private static final String TYPE = "jar";

  /** Affected range shared by hand-authored contribution rows. */
  private static final String RANGE = "[1,2)";

  /** Creates a test instance. */
  /* package */
  FindingContributionJsonCodecTest() {
    super();
  }

  @Test
  void manualReportRowsPreserveOmissionEmptyGroupsAndOriginalLocatorSpellings() throws IOException {
    final VulnerabilityFindingContribution mapped =
        new VulnerabilityFindingContribution(
            "CVE-2026-10000",
            Set.of("GHSA-alias"),
            GROUP_ID,
            ARTIFACT_ID,
            TYPE,
            "",
            List.of(VersionCoverageClaim.affected(RANGE)),
            FieldValue.supplied(
                Set.of(CodeClaim.declared(CodeReference.sourceFile("src/main/java/p/Foo.java")))),
            FieldValue.omitted(),
            MergePriority.MANUAL,
            AssessmentIntent.REVIEW_ONLY,
            "project-row",
            Set.of());
    final VulnerabilityFindingContribution empty =
        new VulnerabilityFindingContribution(
            "CVE-2026-10001",
            Set.of(),
            GROUP_ID,
            ARTIFACT_ID,
            TYPE,
            "",
            List.of(VersionCoverageClaim.affected(RANGE)),
            FieldValue.supplied(Set.of()),
            FieldValue.omitted(),
            MergePriority.MANUAL,
            AssessmentIntent.AUTO_VERIFY,
            "empty-project-row",
            Set.of());
    final JsonNode encoded = FindingContributionJsonCodec.encode(List.of(mapped, empty));
    final List<VulnerabilityFindingContribution> decoded =
        FindingContributionJsonCodec.decode(encoded);

    assertAll(
        () -> assertThat(decoded).containsExactly(mapped, empty),
        () ->
            assertThat(decoded.getFirst().codeGroup().value())
                .singleElement()
                .satisfies(
                    claim ->
                        assertThat(claim.reference().originalValues())
                            .containsExactly("src/main/java/p/Foo.java")),
        () -> assertThat(encoded.at("/1/codeGroup/supplied").booleanValue()).isTrue(),
        () -> assertThat(encoded.at("/1/codeGroup/value").isArray()).isTrue(),
        () -> assertThat(encoded.at("/1/codeGroup/value")).isEmpty(),
        () -> assertThat(decoded.getFirst().prerequisiteGroup()).isEqualTo(FieldValue.omitted()));
  }

  @Test
  void catalogPriorityAndTypedOriginSurviveContributionMergeAndCodec() throws IOException {
    final VulnerabilityFindingContribution catalog =
        new VulnerabilityFindingContribution(
            "CVE-2026-10002",
            Set.of("GHSA-catalog"),
            GROUP_ID,
            ARTIFACT_ID,
            TYPE,
            "",
            List.of(VersionCoverageClaim.affected(RANGE)),
            FieldValue.omitted(),
            FieldValue.omitted(),
            MergePriority.CATALOG,
            AssessmentIntent.AUTO_VERIFY,
            "catalog:record-1",
            Set.of(new AdvisoryProvenance(EvidenceOrigin.CATALOG, "record-1", null, null)));
    final GenericVulnerabilityFinding merged = GenericVulnerabilityFinding.merge(List.of(catalog));
    final JsonNode encoded = FindingContributionJsonCodec.encode(merged.contributions());
    final List<VulnerabilityFindingContribution> decoded =
        FindingContributionJsonCodec.decode(encoded);

    assertAll(
        "catalog priority and source kind remain distinct through merge and persistence",
        () -> assertThat(merged.contributions()).containsExactly(catalog),
        () -> assertThat(encoded.at("/0/priority").textValue()).isEqualTo("CATALOG"),
        () ->
            assertThat(encoded.at("/0/sourceProvenance/0/origin").textValue()).isEqualTo("CATALOG"),
        () -> assertThat(decoded).containsExactly(catalog));
  }

  @Test
  void prerequisiteOperatorsAndConfidenceSurviveTheContributionCodec() throws IOException {
    final PrerequisiteClaim first = new PrerequisiteClaim("org.example:one", "org.example.One");
    final PrerequisiteClaim second = new PrerequisiteClaim("org.example:two", "org.example.Two");
    final VulnerabilityFindingContribution catalog =
        new VulnerabilityFindingContribution(
            "CVE-2026-10003",
            Set.of(),
            GROUP_ID,
            ARTIFACT_ID,
            TYPE,
            "",
            List.of(VersionCoverageClaim.affected(RANGE)),
            FieldValue.omitted(),
            FieldValue.supplied(
                Set.of(new PrerequisiteGroup(PrerequisiteOperator.ALL_OF, Set.of(first, second)))),
            MergePriority.CATALOG,
            AssessmentIntent.AUTO_VERIFY,
            "catalog:record-3",
            Set.of(new AdvisoryProvenance(EvidenceOrigin.CATALOG, "record-3", null, null)),
            ConfidenceLevel.LOW);
    final JsonNode encoded = FindingContributionJsonCodec.encode(List.of(catalog));
    final VulnerabilityFindingContribution decoded =
        FindingContributionJsonCodec.decode(encoded).getFirst();

    assertAll(
        "group operators and descriptive confidence survive persisted contribution replay",
        () -> assertThat(decoded).isEqualTo(catalog),
        () ->
            assertThat(decoded.prerequisiteGroups().value().iterator().next().operator())
                .isEqualTo(PrerequisiteOperator.ALL_OF),
        () -> assertThat(decoded.intent()).isEqualTo(AssessmentIntent.AUTO_VERIFY),
        () -> assertThat(decoded.confidenceLevel()).isEqualTo(ConfidenceLevel.LOW),
        () -> assertThat(decoded.effectiveIntent()).isEqualTo(AssessmentIntent.REVIEW_ONLY),
        () ->
            assertThat(encoded.at("/0/prerequisiteGroups/value/0/operator").textValue())
                .isEqualTo("ALL_OF"),
        () -> assertThat(encoded.at("/0/confidenceLevel").textValue()).isEqualTo("LOW"),
        () -> assertThat(encoded.at("/0/intent").textValue()).isEqualTo("AUTO_VERIFY"));
  }

  @Test
  void flatPairsBecomeOneAnyOfGroupAndOmissionDiffersFromSuppliedEmpty() {
    final PrerequisiteClaim pair = new PrerequisiteClaim("org.example:one", "org.example.One");
    final VulnerabilityFindingContribution flat =
        new VulnerabilityFindingContribution(
            "CVE-2026-10004",
            Set.of(),
            GROUP_ID,
            ARTIFACT_ID,
            TYPE,
            "",
            List.of(VersionCoverageClaim.affected(RANGE)),
            FieldValue.omitted(),
            FieldValue.supplied(Set.of(pair)),
            MergePriority.AUTOMATIC,
            AssessmentIntent.AUTO_VERIFY,
            "automatic:flat",
            Set.of());
    final VulnerabilityFindingContribution omitted =
        new VulnerabilityFindingContribution(
            "CVE-2026-10005",
            Set.of(),
            GROUP_ID,
            ARTIFACT_ID,
            TYPE,
            "",
            List.of(VersionCoverageClaim.affected(RANGE)),
            FieldValue.omitted(),
            FieldValue.omitted(),
            MergePriority.AUTOMATIC,
            AssessmentIntent.AUTO_VERIFY,
            "automatic:omitted",
            Set.of());
    final VulnerabilityFindingContribution empty =
        new VulnerabilityFindingContribution(
            "CVE-2026-10006",
            Set.of(),
            GROUP_ID,
            ARTIFACT_ID,
            TYPE,
            "",
            List.of(VersionCoverageClaim.affected(RANGE)),
            FieldValue.omitted(),
            FieldValue.supplied(Set.of()),
            MergePriority.AUTOMATIC,
            AssessmentIntent.AUTO_VERIFY,
            "automatic:empty",
            Set.of());

    assertAll(
        () ->
            assertThat(flat.prerequisiteGroups())
                .isEqualTo(
                    FieldValue.supplied(
                        Set.of(new PrerequisiteGroup(PrerequisiteOperator.ANY_OF, Set.of(pair))))),
        () -> assertThat(omitted.prerequisiteGroups()).isEqualTo(FieldValue.omitted()),
        () -> assertThat(empty.prerequisiteGroups()).isEqualTo(FieldValue.supplied(Set.of())));
  }

  @Test
  void confidenceCapsIntentWithoutUpgradingReviewOnly() {
    final VulnerabilityFindingContribution medium =
        confidenceContribution(
            "CVE-2026-10007", ConfidenceLevel.MEDIUM, AssessmentIntent.AUTO_VERIFY);
    final VulnerabilityFindingContribution low =
        confidenceContribution("CVE-2026-10008", ConfidenceLevel.LOW, AssessmentIntent.AUTO_VERIFY);
    final VulnerabilityFindingContribution highReview =
        confidenceContribution(
            "CVE-2026-10009", ConfidenceLevel.HIGH, AssessmentIntent.REVIEW_ONLY);

    assertAll(
        () ->
            assertThat(GenericVulnerabilityFinding.merge(List.of(medium)).intentFor("1.5"))
                .contains(AssessmentIntent.REVIEW_ONLY),
        () ->
            assertThat(GenericVulnerabilityFinding.merge(List.of(low)).intentFor("1.5"))
                .contains(AssessmentIntent.REVIEW_ONLY),
        () ->
            assertThat(GenericVulnerabilityFinding.merge(List.of(highReview)).intentFor("1.5"))
                .contains(AssessmentIntent.REVIEW_ONLY),
        () -> assertThat(highReview.confidenceLevel()).isEqualTo(ConfidenceLevel.HIGH));
  }

  @Test
  void unresolvedFieldMarkersSurviveSavedContributionReplay() throws IOException {
    final VulnerabilityFindingContribution unresolved =
        new VulnerabilityFindingContribution(
            "CVE-2026-10010",
            Set.of(),
            "org.example",
            "library",
            "jar",
            "",
            List.of(VersionCoverageClaim.unresolvedAffected("catalog-row", "bad code field")),
            FieldValue.supplied(Set.of()),
            FieldValue.omitted(),
            MergePriority.CATALOG,
            AssessmentIntent.REVIEW_ONLY,
            "catalog:bad-row",
            Set.of(new AdvisoryProvenance(EvidenceOrigin.CATALOG, "bad-row", null, null)),
            null,
            Set.of(UnresolvedContributionField.CODE));
    final JsonNode encoded = FindingContributionJsonCodec.encode(List.of(unresolved));
    final VulnerabilityFindingContribution decoded =
        FindingContributionJsonCodec.decode(encoded).getFirst();

    assertAll(
        "malformed selected field state survives replay",
        () -> assertThat(decoded).isEqualTo(unresolved),
        () -> assertThat(encoded.at("/0/unresolvedFields/0").textValue()).isEqualTo("CODE"),
        () -> assertInvalidUnresolvedFieldRejected(encoded));
  }

  private static void assertInvalidUnresolvedFieldRejected(final JsonNode encoded) {
    final JsonNode malformed = encoded.deepCopy();
    final ArrayNode unresolvedFields =
        (ArrayNode) ((ObjectNode) malformed.get(0)).get("unresolvedFields");
    unresolvedFields.set(0, new ObjectMapper().getNodeFactory().textNode("UNKNOWN"));
    assertThatIOException().isThrownBy(() -> FindingContributionJsonCodec.decode(malformed));
  }

  private static VulnerabilityFindingContribution confidenceContribution(
      final String cveId, final ConfidenceLevel confidence, final AssessmentIntent intent) {
    return new VulnerabilityFindingContribution(
        cveId,
        Set.of(),
        GROUP_ID,
        ARTIFACT_ID,
        TYPE,
        "",
        List.of(VersionCoverageClaim.affected(RANGE)),
        FieldValue.omitted(),
        FieldValue.omitted(),
        MergePriority.CATALOG,
        intent,
        "catalog:" + cveId,
        Set.of(new AdvisoryProvenance(EvidenceOrigin.CATALOG, cveId, null, null)),
        confidence);
  }
}
