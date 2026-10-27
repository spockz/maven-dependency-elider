/* WHY: Captures views after TEST-scope lifecycle resolution. */

package io.github.spockz.elider.test;

import java.io.File;
import java.io.IOException;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.plugins.annotations.ResolutionScope;
import org.apache.maven.project.MavenProject;

/** Records project views during the later probe phase. */
@SuppressWarnings({"PMD.AtLeastOneConstructor", "PMD.CommentRequired"})
@Mojo(name = "probe", requiresDependencyResolution = ResolutionScope.TEST)
public final class ProbeArtifactViewsMojo extends AbstractMojo {
  @Parameter(defaultValue = "${project}", readonly = true, required = true)
  private MavenProject project;

  @Parameter(defaultValue = "${session}", readonly = true, required = true)
  private MavenSession session;

  @Parameter(defaultValue = "${lifecycle.reportDirectory}")
  private File reportDirectory;

  @Parameter(defaultValue = "${lifecycle.mode}", required = true)
  private String mode;

  @Override
  public void execute() throws MojoExecutionException {
    try {
      FixtureArtifactViews.write(project, reportDirectory, mode + "-later", "TEST");
      FixtureGraphSnapshots.write(session, project, reportDirectory, mode);
    } catch (IOException | IllegalStateException exception) {
      throw new MojoExecutionException("Cannot record later artifact views", exception);
    }
  }
}
