// WHY: Verifies Analyze prediction fields without coupling them to trim publication records.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.spockz.elider.engine.ClassUsageReport;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.AnalysisEvidence;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.ArtifactSnapshot;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Tests the prediction fields written to Analyze reports without trim publication records. */
final class MavenClassUsageReportWriterTest {
  private static final String EXAMPLE_GROUP_ID = "org.example";

  private static final String JAR_TYPE = "jar";

  private static final String RETAINED_ARTIFACTS_FIELD = "retainedArtifacts";

  private static final String PLANNED_CLASS_REMOVALS_FIELD = "plannedClassRemovals";

  /* package */ MavenClassUsageReportWriterTest() {
    // JUnit creates each test instance through the package-visible no-argument constructor.
  }

  /** Serializes report fixtures with the same mapper used by production. */
  private static final ObjectMapper JSON = new ObjectMapper();

  /** Holds report inputs and outputs created by the test. */
  @TempDir private Path temporaryDirectory;

  @Test
  void writesPredictionProvenanceWithoutPublishedTrimState() throws Exception {
    final ArtifactCoordinate retained =
        new ArtifactCoordinate(EXAMPLE_GROUP_ID, "kept", "1.0", JAR_TYPE, "", "compile");
    final ArtifactCoordinate elided =
        new ArtifactCoordinate(EXAMPLE_GROUP_ID, "unused", "1.0", JAR_TYPE, "", "runtime");
    final ArtifactCoordinate retainedClassifier =
        new ArtifactCoordinate(EXAMPLE_GROUP_ID, "kept", "1.0", JAR_TYPE, "tests", "compile");
    final ArtifactCoordinate retainedNewerVersion =
        new ArtifactCoordinate(EXAMPLE_GROUP_ID, "kept", "2.0", JAR_TYPE, "", "compile");
    final Path input = temporaryDirectory.resolve("input.jar");
    java.nio.file.Files.writeString(input, "input-bytes");
    final org.apache.maven.artifact.Artifact mavenArtifact =
        new DefaultArtifact(
            retained.groupId(),
            retained.artifactId(),
            retained.version(),
            retained.scope(),
            retained.type(),
            retained.classifier(),
            new DefaultArtifactHandler(retained.type()));
    mavenArtifact.setFile(input.toFile());
    final AnalysisEvidence evidence =
        new AnalysisEvidence(
            new ClassUsageReport(List.of()), Optional.empty(), Map.of(), false, false, null);
    final AnalyzePrediction prediction =
        new AnalyzePrediction(
            AnalyzePrediction.Provenance.DETACHED_CURRENT_MODEL,
            List.of(new ArtifactSnapshot(mavenArtifact, retained, input)),
            List.of(retainedNewerVersion, retainedClassifier, retained),
            List.of(elided),
            List.of(
                new AnalyzePrediction.PlannedTrim(retainedNewerVersion, Set.of("kept.Newer")),
                new AnalyzePrediction.PlannedTrim(retainedClassifier, Set.of("kept.Tests")),
                new AnalyzePrediction.PlannedTrim(retained, Set.of("kept.Type"))),
            evidence,
            "c".repeat(64),
            "a".repeat(64),
            "b".repeat(64));
    final Path report = temporaryDirectory.resolve("class-usage.json");

    MavenClassUsageReportWriter.write(
        report, new ClassUsageReport(List.of()), Optional.empty(), prediction);
    final JsonNode document = JSON.readTree(report.toFile());
    final JsonNode dependencyPrediction = document.path("dependencyPrediction");
    final boolean publishesTrimmedArtifacts = dependencyPrediction.has("trimmedArtifacts");
    final boolean publishesOutputPath = dependencyPrediction.has("outputPath");
    final boolean publishesOutputSha256 = dependencyPrediction.has("outputSha256");

    assertAll(
        "Analyze report carries detached prediction identity without output artifacts",
        () -> assertThat(document.path("schemaVersion").asInt()).isEqualTo(1),
        () ->
            assertThat(dependencyPrediction.path("provenance").asText())
                .isEqualTo("DETACHED_CURRENT_MODEL"),
        () ->
            assertThat(dependencyPrediction.path(RETAINED_ARTIFACTS_FIELD).get(0).asText())
                .isEqualTo(retained.toString()),
        () ->
            assertThat(
                    List.of(
                        dependencyPrediction.path(RETAINED_ARTIFACTS_FIELD).get(0).asText(),
                        dependencyPrediction.path(RETAINED_ARTIFACTS_FIELD).get(1).asText(),
                        dependencyPrediction.path(RETAINED_ARTIFACTS_FIELD).get(2).asText()))
                .containsExactly(
                    retained.toString(),
                    retainedClassifier.toString(),
                    retainedNewerVersion.toString()),
        () ->
            assertThat(dependencyPrediction.path("wouldElideArtifacts").get(0).asText())
                .isEqualTo(elided.toString()),
        () ->
            assertThat(
                    dependencyPrediction
                        .path(PLANNED_CLASS_REMOVALS_FIELD)
                        .get(0)
                        .path("status")
                        .asText())
                .isEqualTo("PLANNED_UNVERIFIED"),
        () ->
            assertThat(
                    dependencyPrediction
                        .path(PLANNED_CLASS_REMOVALS_FIELD)
                        .get(0)
                        .path("classes")
                        .get(0)
                        .asText())
                .isEqualTo("kept.Type"),
        () ->
            assertThat(
                    List.of(
                        dependencyPrediction
                            .path(PLANNED_CLASS_REMOVALS_FIELD)
                            .get(0)
                            .path("coordinate")
                            .asText(),
                        dependencyPrediction
                            .path(PLANNED_CLASS_REMOVALS_FIELD)
                            .get(1)
                            .path("coordinate")
                            .asText(),
                        dependencyPrediction
                            .path(PLANNED_CLASS_REMOVALS_FIELD)
                            .get(2)
                            .path("coordinate")
                            .asText()))
                .containsExactly(
                    retained.toString(),
                    retainedClassifier.toString(),
                    retainedNewerVersion.toString()),
        () -> assertThat(dependencyPrediction.path("environmentFingerprint").asText()).hasSize(64),
        () -> assertThat(dependencyPrediction.path("inventoryFingerprint").asText()).hasSize(64),
        () -> assertThat(dependencyPrediction.path("operationFingerprint").asText()).hasSize(64),
        () -> assertThat(publishesTrimmedArtifacts).isFalse(),
        () -> assertThat(publishesOutputPath).isFalse(),
        () -> assertThat(publishesOutputSha256).isFalse());
  }
}
