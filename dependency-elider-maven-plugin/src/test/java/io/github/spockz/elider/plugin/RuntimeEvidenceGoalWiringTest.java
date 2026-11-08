/* WHY: Ensures Analyze and Elide expose the same opt-in evidence policy. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.MojoFailureException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/** Pins the Maven property and option path shared by both goals. */
final class RuntimeEvidenceGoalWiringTest extends MavenDependencyTrimmerInMemoryClosureSupport {
  @SuppressWarnings("PMD.UnnecessaryConstructor")
  /* default */ RuntimeEvidenceGoalWiringTest() {
    super();
  }

  @Test
  void analyzeAndElideUseTheSameClosedWorldParameterAndOption() throws Exception {
    final Fixture fixture = fixture(false);
    final Path trace = temporaryDirectory.resolve("goal-wiring.lst");
    Files.writeString(trace, "closure/a/Entry\n");
    final AnalyzeMojo analyze = new AnalyzeMojo();
    AnalyzeMojoTestFieldSupport.set(
        analyze, RuntimeEvidenceGoalFixture.PROJECT_FIELD, fixture.mavenProject());
    final MavenSession analyzeSession = RuntimeEvidenceGoalFixture.session(fixture.mavenProject());
    RuntimeEvidenceGoalFixture.seedCapturedGraph(analyzeSession, fixture);
    AnalyzeMojoTestFieldSupport.set(
        analyze, RuntimeEvidenceGoalFixture.SESSION_FIELD, analyzeSession);
    AnalyzeMojoTestFieldSupport.set(
        analyze, RuntimeEvidenceGoalFixture.TRACE_FILES_FIELD, List.of(trace.toFile()));
    AnalyzeMojoTestFieldSupport.set(analyze, RuntimeEvidenceGoalFixture.CLOSED_WORLD_FIELD, true);
    final AtomicReference<ElisionAnalysisModel.AnalysisOptions> captured = new AtomicReference<>();
    AnalyzeMojoTestFieldSupport.set(
        analyze,
        "predictionService",
        (AnalyzePredictionService)
            (project, options, resolver) -> {
              captured.set(options);
              throw new IOException("capture options only");
            });

    final Throwable analyzeFailure =
        org.assertj.core.api.Assertions.catchThrowable(analyze::execute);

    final ElideMojo elide = new ElideMojo();
    AnalyzeMojoTestFieldSupport.set(
        elide, RuntimeEvidenceGoalFixture.PROJECT_FIELD, fixture.mavenProject());
    final MavenSession elideSession = RuntimeEvidenceGoalFixture.session(fixture.mavenProject());
    RuntimeEvidenceGoalFixture.seedCapturedGraph(elideSession, fixture);
    AnalyzeMojoTestFieldSupport.set(elide, RuntimeEvidenceGoalFixture.SESSION_FIELD, elideSession);
    AnalyzeMojoTestFieldSupport.set(
        elide, RuntimeEvidenceGoalFixture.TRACE_FILES_FIELD, List.of(trace.toFile()));
    AnalyzeMojoTestFieldSupport.set(elide, RuntimeEvidenceGoalFixture.CLOSED_WORLD_FIELD, true);
    final ElisionAnalysisModel.AnalysisOptions elideOptions = elide.analysisOptions();

    final boolean analyzeClosedWorld = captured.get().closedWorld();
    final boolean elideClosedWorld = elideOptions.closedWorld();
    assertAll(
        "both goal option paths enable closed-world analysis",
        () -> assertThat(analyzeFailure).isInstanceOf(MojoFailureException.class),
        () -> Assertions.assertTrue(analyzeClosedWorld, "Analyze uses the closed-world option"),
        () -> Assertions.assertTrue(elideClosedWorld, "Elide uses the closed-world option"));
  }

  @Test
  void rejectedEvidenceLeavesAnalyzeAndElidePublicationFilesAndViewsUntouched() throws Exception {
    final Fixture fixture = fixture(false);
    final Path relevant = temporaryDirectory.resolve("goal-relevant.lst");
    final Path irrelevant = temporaryDirectory.resolve("goal-irrelevant.lst");
    Files.writeString(relevant, "closure/a/Entry\n");
    Files.writeString(irrelevant, "java.lang.String\n");
    final Path analyzeReport = temporaryDirectory.resolve("analyze-sentinel.json");
    final Path analyzeSummary = temporaryDirectory.resolve("analyze-summary-sentinel.json");
    final Path elideReport = temporaryDirectory.resolve("elide-sentinel.json");
    final Path elideSummary = temporaryDirectory.resolve("elide-summary-sentinel.json");
    Files.writeString(analyzeReport, "previous analyze report");
    Files.writeString(analyzeSummary, "previous analyze summary");
    Files.writeString(elideReport, "previous elide report");
    Files.writeString(elideSummary, "previous elide summary");
    final Set<Artifact> resolvedBefore = Set.copyOf(fixture.mavenProject().getArtifacts());
    final Set<Artifact> directBefore =
        fixture.mavenProject().getDependencyArtifacts() == null
            ? null
            : Set.copyOf(fixture.mavenProject().getDependencyArtifacts());
    final List<ArtifactFile> artifactFilesBefore =
        Stream.concat(
                resolvedBefore.stream(),
                directBefore == null ? Stream.empty() : directBefore.stream())
            .map(artifact -> new ArtifactFile(artifact, artifact.getFile()))
            .toList();

    final AnalyzeMojo analyze = new AnalyzeMojo();
    AnalyzeMojoTestFieldSupport.set(
        analyze, RuntimeEvidenceGoalFixture.PROJECT_FIELD, fixture.mavenProject());
    final MavenSession analyzeSession = RuntimeEvidenceGoalFixture.session(fixture.mavenProject());
    RuntimeEvidenceGoalFixture.seedCapturedGraph(analyzeSession, fixture);
    AnalyzeMojoTestFieldSupport.set(analyze, "session", analyzeSession);
    AnalyzeMojoTestFieldSupport.set(
        analyze,
        RuntimeEvidenceGoalFixture.TRACE_FILES_FIELD,
        List.of(relevant.toFile(), irrelevant.toFile()));
    AnalyzeMojoTestFieldSupport.set(analyze, RuntimeEvidenceGoalFixture.CLOSED_WORLD_FIELD, true);
    AnalyzeMojoTestFieldSupport.set(analyze, "reportFile", analyzeReport.toFile());
    AnalyzeMojoTestFieldSupport.set(analyze, "analysisSummaryFile", analyzeSummary.toFile());

    final ElideMojo elide = new ElideMojo();
    AnalyzeMojoTestFieldSupport.set(
        elide, RuntimeEvidenceGoalFixture.PROJECT_FIELD, fixture.mavenProject());
    final MavenSession elideSession = RuntimeEvidenceGoalFixture.session(fixture.mavenProject());
    RuntimeEvidenceGoalFixture.seedCapturedGraph(elideSession, fixture);
    AnalyzeMojoTestFieldSupport.set(elide, "session", elideSession);
    AnalyzeMojoTestFieldSupport.set(
        elide,
        RuntimeEvidenceGoalFixture.TRACE_FILES_FIELD,
        List.of(relevant.toFile(), irrelevant.toFile()));
    AnalyzeMojoTestFieldSupport.set(elide, RuntimeEvidenceGoalFixture.CLOSED_WORLD_FIELD, true);
    AnalyzeMojoTestFieldSupport.set(elide, "reportFile", elideReport.toFile());
    AnalyzeMojoTestFieldSupport.set(elide, "summaryFile", elideSummary.toFile());

    assertAll(
        "invalid runtime evidence fails before either goal publishes or mutates artifact views",
        () ->
            assertThatThrownBy(analyze::execute)
                .isInstanceOf(MojoFailureException.class)
                .hasMessageContaining("goal-irrelevant.lst"),
        () ->
            assertThatThrownBy(elide::execute)
                .isInstanceOf(MojoFailureException.class)
                .hasMessageContaining("goal-irrelevant.lst"),
        () -> assertThat(Files.readString(analyzeReport)).isEqualTo("previous analyze report"),
        () -> assertThat(Files.readString(analyzeSummary)).isEqualTo("previous analyze summary"),
        () -> assertThat(Files.readString(elideReport)).isEqualTo("previous elide report"),
        () -> assertThat(Files.readString(elideSummary)).isEqualTo("previous elide summary"),
        () ->
            assertThat(fixture.mavenProject().getArtifacts())
                .containsExactlyInAnyOrderElementsOf(resolvedBefore),
        () -> {
          if (directBefore == null) {
            assertThat(fixture.mavenProject().getDependencyArtifacts()).isNull();
          } else {
            assertThat(fixture.mavenProject().getDependencyArtifacts())
                .containsExactlyInAnyOrderElementsOf(directBefore);
          }
        },
        () -> {
          assertAll(
              "artifact file pointers remain unchanged",
              artifactFilesBefore.stream()
                  .map(
                      state ->
                          (org.junit.jupiter.api.function.Executable)
                              () -> assertThat(state.artifact().getFile()).isSameAs(state.file())));
        });
  }

  private record ArtifactFile(Artifact artifact, File file) {}
}
