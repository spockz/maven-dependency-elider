// WHY: Exercises prediction with a captured graph and MRJAR input.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.plugin.ElisionAnalysisModel.AnalysisOptions;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.CompletenessOptions;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.eclipse.aether.DefaultRepositorySystemSession;
import org.eclipse.aether.SessionData;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Tests prediction boundaries. JUnit uses its implicit constructor. */
@SuppressWarnings("PMD.AtLeastOneConstructor")
final class MavenElisionServicePredictionTest {
  /** Contains project inputs and output files for each prediction scenario. */
  @TempDir private Path temporaryDirectory;

  @Test
  void predictsCapturedEffectiveMrjarWithoutPublishingTrimState() throws Exception {
    final MavenElisionServicePredictionFixtures.Fixture fixture =
        MavenElisionServicePredictionFixtures.create(temporaryDirectory, true);
    final DefaultRepositorySystemSession repositorySession = fixture.repositorySession();
    final SessionData sessionDataBefore = sessionData(repositorySession);
    final Object captureBefore =
        sessionDataBefore.get(EliderMediatedGraphCaptureDecorator.SESSION_DATA_KEY);
    final Object planBefore = sessionDataBefore.get(ResolverArtifactPlanPublisher.SESSION_DATA_KEY);
    final Path generation = TrimPaths.generationPath(fixture.project(), "prediction-only");
    final Path output = MavenGeneratedOutputs.manifestPath(fixture.project());
    Files.createDirectories(output.getParent());
    Files.writeString(output, "existing-output-manifest");
    final Path targetArchive =
        TrimPaths.analysisLibraryDirectory(fixture.project()).resolve("sentinel.jar");
    Files.createDirectories(targetArchive.getParent());
    Files.writeString(targetArchive, "existing-analysis-archive");

    final AnalyzePrediction prediction =
        new MavenElisionService().predict(fixture.project(), fixture.options(), null);
    final SessionData sessionDataAfter = sessionData(repositorySession);

    assertAll(
        "captured-effective Analyze predicts without publishing trim state",
        () ->
            assertThat(prediction.provenance())
                .isEqualTo(AnalyzePrediction.Provenance.CAPTURED_EFFECTIVE_RESOLVER),
        () -> assertThat(fixture.project().getArtifacts()).containsExactly(fixture.artifact()),
        () ->
            assertThat(fixture.project().getDependencyArtifacts())
                .containsExactly(fixture.artifact()),
        () ->
            assertThat(prediction.plannedTrims())
                .singleElement()
                .satisfies(
                    trim ->
                        assertAll(
                            "only target-tier classes are predicted for removal",
                            () -> assertThat(trim.removedClasses()).contains("projection.NineOnly"),
                            () ->
                                assertThat(trim.removedClasses())
                                    .doesNotContain("projection.TwentyOneOnly"))),
        () -> assertThat(fixture.artifact().getFile()).isEqualTo(fixture.archive().toFile()),
        () ->
            assertThat(sessionDataAfter.get(EliderMediatedGraphCaptureDecorator.SESSION_DATA_KEY))
                .isEqualTo(captureBefore),
        () ->
            assertThat(sessionDataAfter.get(ResolverArtifactPlanPublisher.SESSION_DATA_KEY))
                .isEqualTo(planBefore),
        () -> assertThat(generation).doesNotExist(),
        () -> assertThat(output).hasContent("existing-output-manifest"),
        () -> assertThat(targetArchive).hasContent("existing-analysis-archive"));
  }

  @Test
  void refusesCapturedEffectivePredictionWhenThePairIsMissing() throws Exception {
    final MavenElisionServicePredictionFixtures.Fixture fixture =
        MavenElisionServicePredictionFixtures.create(temporaryDirectory, false);
    final Path reportSentinel = temporaryDirectory.resolve("unchanged-report.json");
    Files.writeString(reportSentinel, "report sentinel");

    assertAll(
        "missing captured graph refuses prediction without changing report output",
        () ->
            assertThatThrownBy(
                    () ->
                        new MavenElisionService()
                            .predict(fixture.project(), fixture.options(), null))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("missing for Analyze"),
        () -> assertThat(reportSentinel).hasContent("report sentinel"));
  }

  @Test
  void derivesProductionOutputFromBuildForCompleteBytecodePrediction() throws Exception {
    final MavenElisionServicePredictionFixtures.Fixture fixture =
        MavenElisionServicePredictionFixtures.create(temporaryDirectory, true);
    final Path output = Path.of(fixture.project().getBuild().getOutputDirectory());
    final Path applicationClass =
        MavenElisionServicePredictionFixtures.createProductionOutputClass(output);
    final AnalysisOptions options =
        withCompleteness(fixture.options(), new CompletenessOptions(false, true, false, true));

    final AnalyzePrediction prediction =
        new MavenElisionService().predict(fixture.project(), options, null);

    assertAll(
        "complete bytecode prediction derives and scans Maven's configured build output",
        () ->
            assertThat(prediction.evidence().bytecodeScan())
                .get()
                .extracting(scan -> scan.scope().toAbsolutePath().normalize())
                .isEqualTo(output.toAbsolutePath().normalize()),
        () ->
            assertThat(prediction.evidence().bytecodeScan().orElseThrow().classFilesScanned())
                .isEqualTo(1),
        () -> assertThat(applicationClass).exists());
  }

  @Test
  void resolvesRelativeProductionOutputAgainstProjectWhenProcessDirectoryDiffers()
      throws Exception {
    final MavenElisionServicePredictionFixtures.Fixture fixture =
        MavenElisionServicePredictionFixtures.create(temporaryDirectory, true);
    final Path projectBase = fixture.projectBase();
    final Path processDirectory =
        Path.of(System.getProperty("user.dir")).toAbsolutePath().normalize();
    fixture.project().getBuild().setOutputDirectory("target/classes");
    final Path expectedOutput = projectBase.resolve("target/classes");
    final Path applicationClass =
        MavenElisionServicePredictionFixtures.createProductionOutputClass(expectedOutput);
    final AnalysisOptions options =
        withCompleteness(fixture.options(), new CompletenessOptions(false, true, false, true));

    final AnalyzePrediction prediction =
        new MavenElisionService().predict(fixture.project(), options, null);

    assertAll(
        "relative production output is resolved from the module base, not process cwd",
        () -> assertThat(projectBase).isNotEqualTo(processDirectory),
        () ->
            assertThat(prediction.evidence().bytecodeScan().orElseThrow().scope())
                .isEqualTo(expectedOutput),
        () ->
            assertThat(prediction.evidence().bytecodeScan().orElseThrow().classFilesScanned())
                .isEqualTo(1),
        () -> assertThat(applicationClass).exists());
  }

  @Test
  void rejectsBlankProjectProductionOutputForCompleteBytecodePrediction() throws Exception {
    final MavenElisionServicePredictionFixtures.Fixture fixture =
        MavenElisionServicePredictionFixtures.create(temporaryDirectory, true);
    fixture.project().getBuild().setOutputDirectory("  ");
    final AnalysisOptions options =
        withCompleteness(fixture.options(), new CompletenessOptions(false, true, false, true));

    assertThatThrownBy(() -> new MavenElisionService().predict(fixture.project(), options, null))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("requires a nonblank production class output directory");
  }

  // WHY: The test compares Resolver session data before and after prediction.
  private static SessionData sessionData(final DefaultRepositorySystemSession session) {
    return session.getData();
  }

  private static AnalysisOptions withCompleteness(
      final AnalysisOptions options, final CompletenessOptions completeness) {
    return new AnalysisOptions(
        options.traceFiles(),
        options.retainedArtifacts(),
        options.banishedDependencies(),
        options.productionOutput(),
        options.session(),
        completeness,
        options.trim(),
        options.dynamicRoots());
  }
}
