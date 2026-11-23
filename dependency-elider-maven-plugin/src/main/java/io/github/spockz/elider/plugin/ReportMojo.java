// WHY: Shows a saved analysis or elision result without re-resolving or re-analyzing dependencies.

package io.github.spockz.elider.plugin;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;

/** Displays a saved report from a successful analysis or elision run. */
@Mojo(name = "report", threadSafe = true)
public final class ReportMojo extends AbstractMojo {
  /** Maven project that owns the report snapshot. */
  @Parameter(defaultValue = "${project}", readonly = true, required = true)
  private MavenProject project;

  /** Path to a persisted summary; defaults to the {@code elide} goal's snapshot. */
  @Parameter(
      property = "elide.summaryFile",
      defaultValue = "${project.build.directory}/dependency-elider-report.json")
  private File summaryFile;

  /** Path to the separate, test-scoped observation. */
  @Parameter(
      property = "elide.testViewReportFile",
      defaultValue = "${project.build.directory}/elider/test-view-report.json")
  private File testViewReportFile;

  /** Creates the goal for Maven plugin discovery. */
  public ReportMojo() {
    super();
  }

  /** Reads and renders the selected project report snapshot. */
  @Override
  public void execute() throws MojoFailureException {
    final MavenElisionReportSnapshot snapshot = readSnapshot();
    validateProject(snapshot);
    renderSnapshot(snapshot);
    renderTestView(snapshot);
  }

  private MavenElisionReportSnapshot readSnapshot() throws MojoFailureException {
    final MavenElisionReportSnapshot snapshot;
    try {
      snapshot = MavenElisionReportWriter.read(summaryFile.toPath());
    } catch (final IOException | IllegalArgumentException exception) {
      throw new MojoFailureException(
          "Could not display dependency elision report: " + exception.getMessage(), exception);
    }
    return snapshot;
  }

  private void validateProject(final MavenElisionReportSnapshot snapshot)
      throws MojoFailureException {
    final String currentGav =
        project.getGroupId() + ":" + project.getArtifactId() + ":" + project.getVersion();
    if (!snapshot.projectGav().equals(currentGav)) {
      throw new MojoFailureException(
          "Elision report snapshot belongs to "
              + snapshot.projectGav()
              + " but the current project is "
              + currentGav);
    }
    final String currentBaseDirectory;
    try {
      currentBaseDirectory =
          MavenElisionReportSnapshot.canonicalProjectDirectory(project).toString();
    } catch (final IOException exception) {
      throw new MojoFailureException(
          "Could not identify current Maven project directory: " + exception.getMessage(),
          exception);
    }
    if (!snapshot.projectBaseDirectory().equals(currentBaseDirectory)) {
      throw new MojoFailureException(
          "Elision report snapshot belongs to project directory "
              + snapshot.projectBaseDirectory()
              + " but the current project directory is "
              + currentBaseDirectory);
    }
  }

  private void renderSnapshot(final MavenElisionReportSnapshot snapshot)
      throws MojoFailureException {
    final List<String> rendered;
    try {
      rendered = MavenElisionReportWriter.render(snapshot);
    } catch (final IllegalArgumentException exception) {
      throw new MojoFailureException(
          "Could not display dependency elision report: " + exception.getMessage(), exception);
    }
    if (getLog().isInfoEnabled()) {
      getLog()
          .info(
              "Dependency Elider report JSON snapshot: "
                  + summaryFile.toPath().toAbsolutePath().normalize());
      rendered.forEach(getLog()::info);
    }
  }

  private void renderTestView(final MavenElisionReportSnapshot production)
      throws MojoFailureException {
    if (!getLog().isInfoEnabled()) {
      return;
    }
    if (production.mode() == MavenElisionReportSnapshot.Mode.ANALYSIS) {
      getLog().info("Test view: unavailable: tests were not compiled during analyze");
      return;
    }
    if (testViewReportFile == null || !Files.isRegularFile(testViewReportFile.toPath())) {
      getLog().info("Test view: unavailable: no saved test preparation");
      return;
    }
    final Path path = testViewReportFile.toPath();
    final TestViewReportSnapshot testView;
    try {
      testView = TestViewReportWriter.read(path);
      final String base = MavenElisionReportSnapshot.canonicalProjectDirectory(project).toString();
      if (!matchesProduction(testView, production, base)) {
        getLog()
            .info(
                "Test view: unavailable: saved test preparation does not match production report");
        return;
      }
    } catch (final IOException | IllegalArgumentException failure) {
      throw new MojoFailureException(
          "Could not display test-view report: " + failure.getMessage(), failure);
    }
    getLog().info("Test-view report JSON snapshot: " + path.toAbsolutePath().normalize());
    TestViewReportRenderer.render(testView).forEach(getLog()::info);
  }

  private boolean matchesProduction(
      final TestViewReportSnapshot testView,
      final MavenElisionReportSnapshot production,
      final String base)
      throws IOException {
    return testView.projectGav().equals(production.projectGav())
        && testView.projectBaseDirectory().equals(base)
        && testView
            .productionReportSha256()
            .equals(TestViewReportWriter.sha256(summaryFile.toPath()));
  }
}
