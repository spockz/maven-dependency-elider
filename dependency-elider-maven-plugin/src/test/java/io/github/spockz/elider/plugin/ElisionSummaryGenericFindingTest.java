/* WHY: Keeps live vulnerability summaries source-neutral and bounded by captured outcomes. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.AssessmentIntent;
import io.github.spockz.elider.model.ClaimGroupStatus;
import io.github.spockz.elider.model.VersionApplicability;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** Exercises summary output without source-specific ownership. */
class ElisionSummaryGenericFindingTest {
  /** Creates the fixture. */
  /* package */ ElisionSummaryGenericFindingTest() {
    super();
  }

  @Test
  void logsGenericOutcomesAndUnavailableSourcesWithoutInventingCvesOrProofs() {
    final MavenVulnerabilityAssessment.Result assessment =
        new MavenVulnerabilityAssessment.Result(
            List.of(),
            List.of(
                row("GHSA-only", GenericFindingAssessment.Outcome.NO_PROOF),
                row("CVE-2026-10000", GenericFindingAssessment.Outcome.DECLARED_CODE_ABSENT)),
            List.of(
                new FindingSourceObservation(
                    Optional.empty(),
                    FindingSourceObservation.Status.UNAVAILABLE,
                    null,
                    null,
                    "cache unavailable",
                    List.of(),
                    0)),
            false);
    final RecordingMavenLog published = new RecordingMavenLog();
    final RecordingMavenLog predicted = new RecordingMavenLog();
    ElisionSummaryCveReporter.report(published, assessment, false);
    ElisionSummaryCveReporter.report(predicted, assessment, true);
    final String actual = String.join("\n", published.messages());
    final String forecast = String.join("\n", predicted.messages());
    assertAll(
        () ->
            assertThat(actual)
                .contains(
                    "GHSA-only",
                    "NO_PROOF",
                    "CVE-2026-10000",
                    "DECLARED_CODE_ABSENT",
                    "cache unavailable"),
        () -> assertThat(actual).doesNotContain("Mitigated CVEs", "GHSA-only CVE"),
        () -> assertThat(forecast).contains("GHSA-only", "cache unavailable"),
        () ->
            assertThat(forecast)
                .doesNotContain("DECLARED_CODE_ABSENT", "would be pruned", "Mitigated CVEs"));
  }

  private static GenericFindingAssessment row(
      final String identifier, final GenericFindingAssessment.Outcome outcome) {
    return new GenericFindingAssessment(
        identifier,
        Set.of(),
        ArtifactCoordinate.of("org.example", "library", "1"),
        VersionApplicability.AFFECTED,
        Optional.of(AssessmentIntent.AUTO_VERIFY),
        ClaimGroupStatus.OMITTED,
        List.of(),
        List.of(),
        ClaimGroupStatus.OMITTED,
        List.of(),
        List.of(),
        Set.of(),
        Set.of(),
        outcome,
        "captured detail",
        MavenVulnerabilityAssessment.InventoryDisposition.RETAINED_UNCHANGED,
        List.of());
  }
}
