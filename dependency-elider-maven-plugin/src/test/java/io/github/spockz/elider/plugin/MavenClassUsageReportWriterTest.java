// WHY: Verifies Analyze prediction fields independently from trim publication.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertFalse;

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

/** Tests prediction fields. JUnit uses its implicit constructor. */
@SuppressWarnings("PMD.AtLeastOneConstructor")
final class MavenClassUsageReportWriterTest {
  /** JSON mapper used to inspect serialized report fixtures. */
  private static final ObjectMapper JSON = new ObjectMapper();

  /** Temporary directory for report inputs and outputs. */
  @TempDir private Path temporaryDirectory;

  /** Maven group used by artifact report fixtures. */
  private static final String EXAMPLE_GROUP_ID = "org.example";

  /** Archive type used by artifact report fixtures. */
  private static final String JAR_TYPE = "jar";

  /** Version shared by the main report fixture artifacts. */
  private static final String VERSION_1 = "1.0";

  /** Compile scope used by the main report fixture artifacts. */
  private static final String COMPILE_SCOPE = "compile";

  /** JSON field containing retained artifact coordinates. */
  private static final String RETAINED_ARTIFACTS_FIELD = "retainedArtifacts";

  /** JSON field containing planned class removals. */
  private static final String PLANNED_CLASS_REMOVALS_FIELD = "plannedClassRemovals";

  @Test
  void writesPredictionProvenanceWithoutPublishedTrimState() throws Exception {
    final ArtifactCoordinate retained =
        new ArtifactCoordinate(EXAMPLE_GROUP_ID, "kept", VERSION_1, JAR_TYPE, "", COMPILE_SCOPE);
    final ArtifactCoordinate elided =
        new ArtifactCoordinate(EXAMPLE_GROUP_ID, "unused", VERSION_1, JAR_TYPE, "", "runtime");
    final ArtifactCoordinate retainedClassifier =
        new ArtifactCoordinate(
            EXAMPLE_GROUP_ID, "kept", VERSION_1, JAR_TYPE, "tests", COMPILE_SCOPE);
    final ArtifactCoordinate retainedNewerVersion =
        new ArtifactCoordinate(EXAMPLE_GROUP_ID, "kept", "2.0", JAR_TYPE, "", COMPILE_SCOPE);
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
            MavenAnalysisResolutionContext.Provenance.DETACHED_CURRENT_MODEL,
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
        () -> assertFalse(publishesTrimmedArtifacts, "prediction has no published trim records"),
        () -> assertFalse(publishesOutputPath, "prediction has no published output path"),
        () -> assertFalse(publishesOutputSha256, "prediction has no published output checksum"));
  }

  @Test
  void writesToleratedDuplicateClassesAsExplicitDiagnostics() throws Exception {
    final ArtifactCoordinate first =
        new ArtifactCoordinate(EXAMPLE_GROUP_ID, "first", VERSION_1, JAR_TYPE, "", COMPILE_SCOPE);
    final ArtifactCoordinate second =
        new ArtifactCoordinate(EXAMPLE_GROUP_ID, "second", VERSION_1, JAR_TYPE, "", COMPILE_SCOPE);
    final Path input = temporaryDirectory.resolve("duplicate-input.jar");
    java.nio.file.Files.writeString(input, "input-bytes");
    final org.apache.maven.artifact.Artifact mavenArtifact =
        new DefaultArtifact(
            first.groupId(),
            first.artifactId(),
            first.version(),
            first.scope(),
            first.type(),
            first.classifier(),
            new DefaultArtifactHandler(first.type()));
    mavenArtifact.setFile(input.toFile());
    final AnalysisEvidence evidence =
        new AnalysisEvidence(
            new ClassUsageReport(List.of()), Optional.empty(), Map.of(), false, false, null);
    final AnalyzePrediction prediction =
        new AnalyzePrediction(
            MavenAnalysisResolutionContext.Provenance.DETACHED_CURRENT_MODEL,
            List.of(new ArtifactSnapshot(mavenArtifact, first, input)),
            List.of(first, second),
            List.of(),
            List.of(),
            evidence,
            "c".repeat(64),
            "a".repeat(64),
            "b".repeat(64),
            MavenBanPlan.empty(),
            List.of(
                new MavenElisionReportSnapshot.ToleratedDuplicateClass(
                    "shared.Type",
                    "TRIM_OTHER_CLASSES",
                    List.of(first.toString(), second.toString()))));
    final Path report = temporaryDirectory.resolve("tolerated-duplicates.json");

    MavenClassUsageReportWriter.write(
        report, new ClassUsageReport(List.of()), Optional.empty(), prediction);

    final JsonNode duplicate = JSON.readTree(report.toFile()).path("toleratedDuplicates").get(0);
    assertAll(
        "Analyze preserves tolerated duplicate details in class usage JSON",
        () -> assertThat(duplicate.path("className").asText()).isEqualTo("shared.Type"),
        () -> assertThat(duplicate.path("action").asText()).isEqualTo("TRIM_OTHER_CLASSES"),
        () ->
            assertThat(
                    List.of(
                        duplicate.path("owners").get(0).asText(),
                        duplicate.path("owners").get(1).asText()))
                .containsExactly(first.toString(), second.toString()));
  }
}
