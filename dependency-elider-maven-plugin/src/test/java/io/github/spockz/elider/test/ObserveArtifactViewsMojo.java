/* WHY: Records views during a non-resolving lifecycle phase. */

package io.github.spockz.elider.test;

import java.io.File;
import java.io.IOException;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;

/** Records project views during the observer phase. */
@SuppressWarnings({"PMD.AtLeastOneConstructor", "PMD.CommentRequired"})
@Mojo(name = "observe")
public final class ObserveArtifactViewsMojo extends AbstractMojo {
  @Parameter(defaultValue = "${project}", readonly = true, required = true)
  private MavenProject project;

  @Parameter(defaultValue = "${lifecycle.reportDirectory}")
  private File reportDirectory;

  @Parameter(defaultValue = "${lifecycle.mode}", required = true)
  private String mode;

  @Override
  public void execute() throws MojoExecutionException {
    try {
      FixtureArtifactViews.write(project, reportDirectory, mode + "-intermediate", "NONE");
    } catch (IOException | IllegalStateException exception) {
      throw new MojoExecutionException("Cannot record intermediate artifact views", exception);
    }
  }
}
