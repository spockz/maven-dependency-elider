// WHY: Verifies the standalone report goal reads saved metrics without analysis inputs.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.project.MavenProject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Verifies the report Mojo reads saved data and validates project identity. */
@SuppressWarnings("PMD.AtLeastOneConstructor")
final class ReportMojoTest {
  /** Reused report filename for isolated snapshot scenarios. */
  private static final String REPORT_JSON = "report.json";

  /** WHY: Snapshot identity and output share one isolated directory. */
  @TempDir private Path temporaryDirectory;

  @Test
  void rejectsMismatchedGav() throws IOException, ReflectiveOperationException {
    final Path snapshotFile = temporaryDirectory.resolve(REPORT_JSON);
    MavenElisionReportWriter.write(
        snapshotFile, ReportMojoTestSupport.snapshot(temporaryDirectory, false));
    final List<String> messages = new ArrayList<>();
    final MavenProject mismatchedGav = ReportMojoTestSupport.project(temporaryDirectory);
    mismatchedGav.setArtifactId("another-project");
    final ReportMojo gavMojo = ReportMojoTestSupport.mojo(snapshotFile, mismatchedGav, messages);

    assertThatThrownBy(gavMojo::execute)
        .isInstanceOf(MojoFailureException.class)
        .hasMessageContaining("snapshot belongs to org.example:consumer:1.0");
  }

  @Test
  void rejectsAnotherCheckoutWithTheSameGav() throws IOException, ReflectiveOperationException {
    final Path snapshotFile = temporaryDirectory.resolve(REPORT_JSON);
    MavenElisionReportWriter.write(
        snapshotFile, ReportMojoTestSupport.snapshot(temporaryDirectory, false));
    final List<String> messages = new ArrayList<>();
    final Path anotherCheckout = Files.createDirectory(temporaryDirectory.resolve("checkout"));
    final MavenProject mismatchedDirectory = ReportMojoTestSupport.project(temporaryDirectory);
    mismatchedDirectory.setFile(anotherCheckout.resolve("pom.xml").toFile());
    final ReportMojo directoryMojo =
        ReportMojoTestSupport.mojo(snapshotFile, mismatchedDirectory, messages);
    assertThatThrownBy(directoryMojo::execute)
        .isInstanceOf(MojoFailureException.class)
        .hasMessageContaining("snapshot belongs to project directory");
  }

  @Test
  void rendersSavedLayoutAssumptionAndTimeWithoutCurrentGoalConfiguration()
      throws IOException, ReflectiveOperationException, MojoFailureException {
    final Path snapshotFile = temporaryDirectory.resolve(REPORT_JSON);
    final MavenElisionReportSnapshot saved =
        ReportMojoTestSupport.snapshot(temporaryDirectory, true);
    MavenElisionReportWriter.write(snapshotFile, saved);
    final List<String> messages = new ArrayList<>();
    final ReportMojo reportMojo =
        ReportMojoTestSupport.mojo(
            snapshotFile, ReportMojoTestSupport.project(temporaryDirectory), messages);

    reportMojo.execute();

    assertThat(messages)
        .contains(
            "Snapshot: last successful elide run at " + saved.generatedAt(),
            "Conventional Java source layout assumption saved for this run: true");
  }

  @Test
  void replaysTestViewOnlyForMatchingProductionReport() throws Exception {
    final Path production = temporaryDirectory.resolve(REPORT_JSON);
    final Path testView = temporaryDirectory.resolve("test-view-report.json");
    MavenElisionReportWriter.write(
        production, ReportMojoTestSupport.snapshot(temporaryDirectory, true));
    final MavenProject project = ReportMojoTestSupport.project(temporaryDirectory);
    final List<String> missingMessages = new ArrayList<>();
    ReportMojoTestSupport.mojo(production, testView, project, missingMessages).execute();

    final TestViewReportSnapshot prepared =
        new TestViewReportSnapshot(
            TestViewReportSnapshot.SCHEMA_VERSION,
            project.getGroupId(),
            project.getArtifactId(),
            project.getVersion(),
            temporaryDirectory.toRealPath().toString(),
            TestViewReportWriter.sha256(production),
            TestViewReportSnapshot.Status.PREPARED,
            null,
            temporaryDirectory.resolve("test-classes").toString(),
            List.of(
                new TestViewReportSnapshot.InputArtifact(
                    "org.example:library:jar:1.0",
                    "/original/library.jar",
                    "/trimmed/library.jar")),
            List.of(
                new TestViewReportSnapshot.Addition(
                    "org.example:library:jar:1.0", List.of("org/example/Builder"))),
            temporaryDirectory.resolve("test-additions.jar").toString(),
            false);
    TestViewReportWriter.write(testView, prepared);
    final List<String> preparedMessages = new ArrayList<>();
    ReportMojoTestSupport.mojo(production, testView, project, preparedMessages).execute();

    final TestViewReportSnapshot stale =
        new TestViewReportSnapshot(
            prepared.schemaVersion(),
            prepared.projectGroupId(),
            prepared.projectArtifactId(),
            prepared.projectVersion(),
            prepared.projectBaseDirectory(),
            "0".repeat(64),
            prepared.status(),
            prepared.reason(),
            prepared.testOutputDirectory(),
            prepared.inputArtifacts(),
            prepared.additions(),
            prepared.additionsJar(),
            prepared.conservativeFallbackUsed());
    TestViewReportWriter.write(testView, stale);
    final List<String> staleMessages = new ArrayList<>();
    ReportMojoTestSupport.mojo(production, testView, project, staleMessages).execute();

    assertAll(
        "report replays only saved test observations bound to the selected production snapshot",
        () -> assertThat(missingMessages).anyMatch(line -> line.contains("Test view: unavailable")),
        () -> assertThat(preparedMessages).contains("Test view: prepared"),
        () -> assertThat(preparedMessages).anyMatch(line -> line.contains("org/example/Builder")),
        () -> assertThat(staleMessages).anyMatch(line -> line.contains("Test view: unavailable")));

    Files.writeString(testView, "{}");
    assertThatThrownBy(
            () ->
                ReportMojoTestSupport.mojo(production, testView, project, new ArrayList<>())
                    .execute())
        .isInstanceOf(MojoFailureException.class)
        .hasMessageContaining("Could not display test-view report");
  }
}
