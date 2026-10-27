/* WHY: Proves the real trim at TEST resolution before removing one known leaf. */

package io.github.spockz.elider.test;

import java.io.File;
import java.io.IOException;
import java.util.LinkedHashSet;
import java.util.Set;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.plugins.annotations.ResolutionScope;
import org.apache.maven.project.MavenProject;

/** Captures the post-elide view and removes one direct fixture leaf. */
@SuppressWarnings({"PMD.AtLeastOneConstructor", "PMD.CommentRequired"})
@Mojo(name = "post-elide-probe", requiresDependencyResolution = ResolutionScope.TEST)
public final class PostElideProbeMojo extends AbstractMojo {
  private static final String DROP_ARTIFACT_ID = "drop-library";

  @Parameter(defaultValue = "${project}", readonly = true, required = true)
  private MavenProject project;

  @Parameter(defaultValue = "${lifecycle.reportDirectory}")
  private File reportDirectory;

  @Override
  public void execute() throws MojoExecutionException {
    try {
      FixtureArtifactViews.write(project, reportDirectory, "post-elide", "TEST");
      final Set<Artifact> retained = new LinkedHashSet<>();
      for (final Artifact artifact : project.getDependencyArtifacts()) {
        if (!("io.github.spockz.elider.test".equals(artifact.getGroupId())
            && DROP_ARTIFACT_ID.equals(artifact.getArtifactId()))) {
          retained.add(artifact);
        }
      }
      if (retained.size() != project.getDependencyArtifacts().size() - 1) {
        throw new IllegalStateException("Expected exactly one synthetic direct drop leaf");
      }
      project.setDependencyArtifacts(retained);
    } catch (IOException exception) {
      throw new MojoExecutionException("Cannot record post-elide artifact views", exception);
    }
  }
}
