/* WHY: Probes artifact-view mutation in a resolver Mojo. */

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

/** Mutates project artifact views after Maven TEST resolution. */
@SuppressWarnings({"PMD.AtLeastOneConstructor", "PMD.CommentRequired"})
@Mojo(name = "mutate", requiresDependencyResolution = ResolutionScope.TEST)
public final class MutateArtifactViewsMojo extends AbstractMojo {
  private static final String GROUP_ID = "io.github.spockz.elider.test";

  private static final String DROP_ARTIFACT_ID = "drop-library";

  private static final String KEEP_ARTIFACT_ID = "keep-library";

  private static final String BASELINE_MODE = "baseline";

  private static final String RESOLVED_ONLY_MODE = "resolved-only";

  private static final String DIRECT_AND_RESOLVED_MODE = "direct-and-resolved";

  @Parameter(defaultValue = "${project}", readonly = true, required = true)
  private MavenProject project;

  @Parameter(defaultValue = "${lifecycle.reportDirectory}")
  private File reportDirectory;

  @Parameter(required = true)
  private String mode;

  @Parameter(required = true)
  private File replacementFile;

  @Override
  public void execute() throws MojoExecutionException {
    try {
      FixtureArtifactViews.write(project, reportDirectory, mode + "-before", "TEST");
      if (RESOLVED_ONLY_MODE.equals(mode) || DIRECT_AND_RESOLVED_MODE.equals(mode)) {
        mutateResolvedView();
      } else if (!BASELINE_MODE.equals(mode)) {
        throw new MojoExecutionException("Unknown lifecycle probe mode: " + mode);
      }
      if (DIRECT_AND_RESOLVED_MODE.equals(mode)) {
        mutateDirectView();
      }
      FixtureArtifactViews.write(project, reportDirectory, mode + "-immediate", "TEST");
    } catch (IOException | IllegalStateException exception) {
      throw new MojoExecutionException("Cannot record lifecycle artifact views", exception);
    }
  }

  private void mutateResolvedView() {
    final Set<Artifact> retained = new LinkedHashSet<>();
    for (final Artifact artifact : project.getArtifacts()) {
      if (!DROP_ARTIFACT_ID.equals(artifact.getArtifactId())) {
        if (KEEP_ARTIFACT_ID.equals(artifact.getArtifactId())) {
          artifact.setFile(replacementFile);
        }
        retained.add(artifact);
      }
    }
    for (final Artifact artifact : project.getDependencyArtifacts()) {
      if (KEEP_ARTIFACT_ID.equals(artifact.getArtifactId())) {
        artifact.setFile(replacementFile);
      }
    }
    project.setResolvedArtifacts(retained);
    project.setArtifacts(retained);
  }

  private void mutateDirectView() {
    final Set<Artifact> retained = new LinkedHashSet<>();
    for (final Artifact artifact : project.getDependencyArtifacts()) {
      if (!(GROUP_ID.equals(artifact.getGroupId())
          && DROP_ARTIFACT_ID.equals(artifact.getArtifactId()))) {
        retained.add(artifact);
      }
    }
    project.setDependencyArtifacts(retained);
  }
}
