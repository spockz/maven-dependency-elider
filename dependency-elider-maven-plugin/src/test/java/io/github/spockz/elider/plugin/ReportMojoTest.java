// WHY: Verifies the standalone report goal reads saved metrics without analysis inputs.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

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
  /** WHY: Snapshot identity and output share one isolated directory. */
  @TempDir private Path temporaryDirectory;

  @Test
  void rejectsMismatchedGav() throws IOException, ReflectiveOperationException {
    final Path snapshotFile = temporaryDirectory.resolve("report.json");
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
    final Path snapshotFile = temporaryDirectory.resolve("report.json");
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
    final Path snapshotFile = temporaryDirectory.resolve("report.json");
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
}
