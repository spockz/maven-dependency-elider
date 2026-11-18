/* WHY: Verifies console rendering clarifies ownership and truncates long pruned-class lists. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.engine.ClassUsageReport;
import io.github.spockz.elider.model.ArtifactCoordinate;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.apache.maven.project.MavenProject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Tests console formatting of predicted pruned classes per artifact. */
@SuppressWarnings({"PMD.AtLeastOneConstructor", "PMD.CommentRequired"})
final class MavenElisionReportRendererTest {
  @TempDir private java.nio.file.Path tempDir;

  @Test
  void predictedPrunedClassesClarifyTargetJarAndTruncateLongLists() throws Exception {
    final ArtifactCoordinate manyCoord = ArtifactCoordinate.of("org.example", "many", "1.0");
    final ArtifactCoordinate fewCoord = ArtifactCoordinate.of("org.example", "few", "1.0");
    final MavenProject project = new MavenProject();
    project.setGroupId("org.example");
    project.setArtifactId("app");
    project.setVersion("1.0");
    project.setFile(tempDir.resolve("pom.xml").toFile());
    final AnalyzePrediction prediction =
        new AnalyzePrediction(
            MavenAnalysisResolutionContext.Provenance.DETACHED_CURRENT_MODEL,
            List.of(
                new ElisionAnalysisModel.ArtifactSnapshot(null, manyCoord, null),
                new ElisionAnalysisModel.ArtifactSnapshot(null, fewCoord, null)),
            List.of(manyCoord, fewCoord),
            List.of(),
            List.of(
                new AnalyzePrediction.PlannedTrim(
                    manyCoord,
                    Set.of("a.C1", "a.C2", "a.C3", "a.C4", "a.C5", "a.C6", "a.C7", "a.C8")),
                new AnalyzePrediction.PlannedTrim(fewCoord, Set.of("b.D1", "b.D2"))),
            new ElisionAnalysisModel.AnalysisEvidence(
                new ClassUsageReport(List.of()),
                Optional.empty(),
                java.util.Map.of(),
                false,
                false,
                null),
            "a".repeat(64),
            "b".repeat(64),
            "c".repeat(64));
    final MavenElisionReportSnapshot snapshot =
        MavenElisionReportSnapshot.from(
            project,
            prediction,
            new MavenVulnerabilityAssessment.Result(List.of(), List.of(), List.of(), false),
            ExclusionReview.unavailable("unavailable"));

    final List<String> lines = MavenElisionReportRenderer.render(snapshot);

    assertAll(
        () ->
            assertThat(lines)
                .contains(
                    "    Classes that would be pruned from this JAR:"
                        + " [a.C1, a.C2, a.C3, a.C4, a.C5, ... (+3 more in analysis report)]"),
        () ->
            assertThat(lines)
                .contains("    Classes that would be pruned from this JAR: [b.D1, b.D2]"),
        () -> assertThat(lines).noneMatch(line -> line.contains("Would remove classes:")));
  }
}
