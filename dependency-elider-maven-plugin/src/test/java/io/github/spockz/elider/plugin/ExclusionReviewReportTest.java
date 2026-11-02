// WHY: Verifies saved advisory findings survive replay and reject malformed report payloads.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.spockz.elider.engine.ClassUsageReport;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.apache.maven.execution.DefaultMavenExecutionRequest;
import org.apache.maven.execution.DefaultMavenExecutionResult;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.model.Dependency;
import org.apache.maven.model.Exclusion;
import org.apache.maven.model.Model;
import org.apache.maven.project.MavenProject;
import org.eclipse.aether.DefaultRepositorySystemSession;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

@SuppressWarnings({
  "PMD.AtLeastOneConstructor",
  "PMD.CommentDefaultAccessModifier",
  "PMD.CommentRequired",
  "PMD.AvoidDuplicateLiterals",
  "PMD.LawOfDemeter",
  "PMD.UseExplicitTypes"
})
final class ExclusionReviewReportTest {
  @TempDir Path directory;

  @Test
  void usesFrozenCaptureRatherThanInjectedLiveExclusions() throws Exception {
    final Model model = new Model();
    model.setGroupId("g");
    model.setArtifactId("consumer");
    model.setVersion("1");
    final MavenProject project = new MavenProject(model);
    project.setFile(directory.resolve("pom.xml").toFile());
    final Dependency first = dependency("first", "old");
    final Dependency second = dependency("second", "old");
    project.setDependencies(List.of(first, second));
    final BanishedDependencyOriginalModel captured =
        BanishedDependencyOriginalModel.capture(
            project,
            List.of(
                new BanishedDependencyOriginalModel.ExecutionPolicy(
                    "run-elide",
                    "elide",
                    "1.0.0",
                    "initialize",
                    "LIFECYCLE",
                    List.of("banned:library"))),
            List.of("banned:library"));
    final DefaultRepositorySystemSession repository = new DefaultRepositorySystemSession();
    repository
        .getData()
        .set(
            BanishedDependencyLifecycleActivation.CAPTURE_STORE_KEY,
            BanishedDependencyCaptureStore.empty().withModel(captured).toPayload());
    final MavenSession session =
        new MavenSession(
            null,
            repository,
            new DefaultMavenExecutionRequest(),
            new DefaultMavenExecutionResult());
    first.addExclusion(exclusion("banned"));
    second.addExclusion(exclusion("banned"));
    final ExclusionReview review = ExclusionReview.capture(project, session);
    first.setVersion("2");
    final ExclusionReview changed = ExclusionReview.capture(project, session);
    assertAll(
        () -> assertThat(review.available()).isTrue(),
        () -> assertThat(review.candidates()).hasSize(1),
        () -> assertThat(review.candidates().getFirst().coordinate().groupId()).isEqualTo("old"),
        () -> assertThat(review.candidates().getFirst().count()).isEqualTo(2),
        () -> assertThat(changed.available()).isFalse(),
        () -> assertThat(changed.unavailableReason()).contains("changed after"),
        () -> assertThat(ExclusionReview.capture(project, null).available()).isFalse());
  }

  private static Dependency dependency(final String artifact, final String excludedGroup) {
    final Dependency result = new Dependency();
    result.setGroupId("libs");
    result.setArtifactId(artifact);
    result.setVersion("1");
    result.addExclusion(exclusion(excludedGroup));
    return result;
  }

  private static Exclusion exclusion(final String group) {
    final Exclusion result = new Exclusion();
    result.setGroupId(group);
    result.setArtifactId("library");
    return result;
  }

  @Test
  void persistsAndReplaysFrozenFindingsAndRejectsTampering() throws Exception {
    final ExclusionRecommendations.Origin origin =
        new ExclusionRecommendations.Origin("LOCAL", "g:consumer:1", "pom.xml", 5, 3, "");
    final ExclusionRecommendations.Exclusion exclusion =
        new ExclusionRecommendations.Exclusion(
            new ExclusionRecommendations.Coordinate("old", "library"), origin);
    final ExclusionRecommendations.Declaration first = declaration(0, "first", origin, exclusion);
    final ExclusionRecommendations.Declaration second = declaration(1, "second", origin, exclusion);
    final ExclusionRecommendations.Origin managementOrigin =
        new ExclusionRecommendations.Origin(
            "INHERITED_MANAGEMENT", "g:parent:1", "parent.xml", 8, 3, "");
    final ExclusionRecommendations.Declaration management =
        declaration(
            0,
            "managed",
            managementOrigin,
            new ExclusionRecommendations.Exclusion(
                new ExclusionRecommendations.Coordinate("other", "library"), managementOrigin));
    final ExclusionRecommendations.Snapshot declarations =
        new ExclusionRecommendations.Snapshot(
            List.of(first, second), List.of(management), Map.of(), List.of());
    final ExclusionReview review = ExclusionReview.from(declarations);
    final MavenElisionReportSnapshot snapshot =
        new MavenElisionReportSnapshot(
                1,
                "g",
                "consumer",
                "1",
                directory.toString(),
                "2026-10-26T16:00:00Z",
                new TrimExecutionEnvironment(21, Runtime.version().feature()),
                0,
                0,
                List.of(),
                List.of(),
                0,
                0,
                List.of(),
                MediatedGraphReportTestSupport.emptyGraph("g:consumer:1"),
                MavenElisionPolicyIdentityTestSupport.emptyPolicy())
            .withExclusionReview(review);
    final Path output = directory.resolve("report.json");
    MavenElisionReportWriter.write(output, snapshot);
    final MavenElisionReportSnapshot restored = MavenElisionReportWriter.read(output);
    final List<String> rendered = MavenElisionReportWriter.render(restored);
    final ObjectMapper json = new ObjectMapper();
    final Path analysisOutput = directory.resolve("analysis.json");
    MavenClassUsageReportWriter.write(
        analysisOutput, new ClassUsageReport(List.of()), Optional.empty(), null, review);
    final var analysisJson = json.readTree(analysisOutput.toFile());
    final ObjectNode tampered = (ObjectNode) json.readTree(output.toFile());
    ((ObjectNode) tampered.path("exclusionReview").path("candidates").get(0)).put("count", 3);
    final Path bad = directory.resolve("tampered.json");
    json.writeValue(bad.toFile(), tampered);
    final ObjectNode repeatedOrdinal = (ObjectNode) json.readTree(output.toFile());
    ((ObjectNode)
            repeatedOrdinal.path("exclusionReview").path("snapshot").path("dependencies").get(1))
        .put("ordinal", 0);
    ((ObjectNode)
            repeatedOrdinal
                .path("exclusionReview")
                .path("candidates")
                .get(0)
                .path("declarations")
                .get(1)
                .path("declaration"))
        .put("ordinal", 0);
    final Path badOrdinal = directory.resolve("repeated-ordinal.json");
    json.writeValue(badOrdinal.toFile(), repeatedOrdinal);
    assertAll(
        () -> assertThat(restored.exclusionReview()).isEqualTo(review),
        () ->
            assertThat(
                    analysisJson
                        .path("exclusionReview")
                        .path("candidates")
                        .get(0)
                        .path("count")
                        .intValue())
                .isEqualTo(2),
        () -> assertThat(restored.exclusionReview().candidates().getFirst().count()).isEqualTo(2),
        () -> assertThat(restored.exclusionReview().management()).containsExactly(management),
        () ->
            assertThat(rendered)
                .anySatisfy(
                    line -> assertThat(line).contains("managed", "other:library", "parent.xml")),
        () ->
            assertThat(rendered)
                .anySatisfy(
                    line ->
                        assertThat(line).contains("old:library", "2 effective dependency paths")),
        () ->
            assertThat(rendered)
                .anySatisfy(
                    line -> assertThat(line).contains("Review only", "collection and mediation")),
        () ->
            assertThatThrownBy(() -> MavenElisionReportWriter.read(bad))
                .isInstanceOf(java.io.IOException.class)
                .hasMessageContaining("Exclusion review"),
        () ->
            assertThatThrownBy(() -> MavenElisionReportWriter.read(badOrdinal))
                .isInstanceOf(java.io.IOException.class)
                .hasRootCauseMessage("Exclusion declaration ordinals are not canonical"));
  }

  private static ExclusionRecommendations.Declaration declaration(
      final int ordinal,
      final String artifact,
      final ExclusionRecommendations.Origin origin,
      final ExclusionRecommendations.Exclusion exclusion) {
    return new ExclusionRecommendations.Declaration(
        new ExclusionRecommendations.Reference(ordinal, "libs", artifact, "jar", "", origin),
        List.of(exclusion));
  }

  @Test
  void summarizesRepeatedDiagnosticsWithoutDiscardingSavedDetails() {
    final ExclusionRecommendations.Snapshot snapshot =
        new ExclusionRecommendations.Snapshot(
            List.of(), List.of(), Map.of(), List.of("one", "one", "two", "three", "four"));
    final ExclusionReview review = ExclusionReview.from(snapshot);
    final List<String> rendered = ExclusionReviewRenderer.render(review);
    assertAll(
        () -> assertThat(rendered).anySatisfy(line -> assertThat(line).contains("5 issue(s)")),
        () -> assertThat(rendered).contains("    one", "    two", "    three"),
        () -> assertThat(rendered).doesNotContain("    four"),
        () ->
            assertThat(ExclusionProvenancePayload.decode(review.snapshot()).diagnostics())
                .containsExactly("one", "one", "two", "three", "four"));
  }

  @Test
  void rejectsMalformedReviewPayloadsWithoutScalarCoercion() {
    final ObjectMapper json = new ObjectMapper();
    final ExclusionReview review = ExclusionReview.unavailable("capture unavailable");
    final ObjectNode extra = json.valueToTree(review);
    extra.put("unexpected", true);
    final ObjectNode wrongType = json.valueToTree(review);
    wrongType.put("available", "false");
    final ObjectNode missingReason = json.valueToTree(review);
    missingReason.put("unavailableReason", "");
    assertAll(
        () ->
            assertThatThrownBy(() -> ExclusionReviewPayloadValidator.validate(extra))
                .isInstanceOf(java.io.IOException.class),
        () ->
            assertThatThrownBy(() -> ExclusionReviewPayloadValidator.validate(wrongType))
                .isInstanceOf(java.io.IOException.class),
        () ->
            assertThatThrownBy(() -> ExclusionReviewPayloadValidator.validate(missingReason))
                .isInstanceOf(java.io.IOException.class));
  }
}
