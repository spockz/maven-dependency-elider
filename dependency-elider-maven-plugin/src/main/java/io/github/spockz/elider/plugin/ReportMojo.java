// WHY: Shows the last successful elision result without re-resolving or re-analyzing dependencies.

package io.github.spockz.elider.plugin;

import java.io.File;
import java.io.IOException;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;

/** Displays a saved report from the last successful elision run. */
@Mojo(name = "report", threadSafe = true)
public final class ReportMojo extends AbstractMojo {
  /** Maven project that owns the report snapshot. */
  @Parameter(defaultValue = "${project}", readonly = true, required = true)
  private MavenProject project;

  /** Path shared with the {@code elide} goal's persisted summary snapshot. */
  @Parameter(
      property = "elide.summaryFile",
      defaultValue = "${project.build.directory}/dependency-elider-report.json")
  private File summaryFile;

  /** Creates the goal for Maven plugin discovery. */
  public ReportMojo() {
    super();
  }

  /** Reads and renders the last successful project report snapshot. */
  @Override
  public void execute() throws MojoFailureException {
    final MavenElisionReportSnapshot snapshot;
    try {
      snapshot = MavenElisionReportWriter.read(summaryFile.toPath());
    } catch (final IOException | IllegalArgumentException exception) {
      throw new MojoFailureException(
          "Could not display dependency elision report: " + exception.getMessage(), exception);
    }
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
    MavenElisionReportWriter.render(snapshot).forEach(getLog()::info);
  }
}
