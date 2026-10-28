/* WHY: Captures the post-goal views and explicitly resolves the unchanged TEST dependencies. */

package io.github.spockz.elider.test;

import java.io.File;
import java.io.IOException;
import javax.inject.Inject;
import javax.inject.Named;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.plugins.annotations.ResolutionScope;
import org.apache.maven.project.DefaultDependencyResolutionRequest;
import org.apache.maven.project.DependencyResolutionException;
import org.apache.maven.project.DependencyResolutionResult;
import org.apache.maven.project.MavenProject;
import org.apache.maven.project.ProjectDependenciesResolver;
import org.eclipse.aether.util.artifact.JavaScopes;
import org.eclipse.aether.util.filter.DependencyFilterUtils;

/** Captures the post-elide view and resolves unchanged project declarations again. */
@SuppressWarnings({"PMD.AtLeastOneConstructor", "PMD.CommentRequired"})
@Mojo(name = "post-elide-probe", requiresDependencyResolution = ResolutionScope.TEST)
public final class PostElideProbeMojo extends AbstractMojo {
  @Parameter(defaultValue = "${project}", readonly = true, required = true)
  private MavenProject project;

  @Parameter(defaultValue = "${session}", readonly = true, required = true)
  private MavenSession session;

  @Parameter(defaultValue = "${lifecycle.reportDirectory}")
  private File reportDirectory;

  @Inject
  @Named("default")
  private ProjectDependenciesResolver resolver;

  @Override
  public void execute() throws MojoExecutionException {
    if (resolver == null || session == null || session.getRepositorySession() == null) {
      throw new MojoExecutionException(
          "Cannot capture a fresh TEST dependency graph",
          new IllegalStateException("Maven TEST resolver context was not injected"));
    }
    try {
      FixtureArtifactViews.write(project, reportDirectory, "post-elide", "TEST");
      final DefaultDependencyResolutionRequest request =
          new DefaultDependencyResolutionRequest(project, session.getRepositorySession());
      request.setResolutionFilter(DependencyFilterUtils.classpathFilter(JavaScopes.TEST));
      final DependencyResolutionResult result = resolver.resolve(request);
      if (getLog().isInfoEnabled()) {
        getLog().info("EXPLICIT_TEST_RESOLUTION filter=TEST project=" + project.getArtifactId());
      }
      FixtureResolvedGraphSnapshot.writeGraph(reportDirectory, result.getDependencyGraph());
      FixtureResolvedGraphSnapshot.writeDependencies(
          reportDirectory, result.getResolvedDependencies());
    } catch (IOException | DependencyResolutionException exception) {
      throw new MojoExecutionException("Cannot capture a fresh TEST dependency graph", exception);
    }
  }
}
