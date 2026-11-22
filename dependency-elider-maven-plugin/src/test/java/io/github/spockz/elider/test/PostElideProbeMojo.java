/* WHY: Captures the post-goal views and explicitly resolves the unchanged TEST dependencies. */

package io.github.spockz.elider.test;

import java.io.File;
import java.io.IOException;
import java.util.Locale;
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
import org.eclipse.aether.SessionData;
import org.eclipse.aether.util.artifact.JavaScopes;
import org.eclipse.aether.util.filter.DependencyFilterUtils;

/** Captures the post-elide view and resolves unchanged project declarations again. */
@SuppressWarnings({"PMD.AtLeastOneConstructor", "PMD.CommentRequired", "PMD.LawOfDemeter"})
@Mojo(name = "post-elide-probe", requiresDependencyResolution = ResolutionScope.TEST)
public final class PostElideProbeMojo extends AbstractMojo {
  private static final String PROBE_REQUEST_KEY = "io.github.spockz.elider.test.probe-request";

  @Parameter(defaultValue = "${project}", readonly = true, required = true)
  private MavenProject project;

  @Parameter(defaultValue = "${session}", readonly = true, required = true)
  private MavenSession session;

  @Parameter(defaultValue = "${lifecycle.reportDirectory}")
  private File reportDirectory;

  @Parameter(defaultValue = "${lifecycle.resolutionScope}")
  private String resolutionScope;

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
      final String selectedScope =
          "COMPILE".equals(resolutionScope) ? JavaScopes.COMPILE : JavaScopes.TEST;
      request.setResolutionFilter(DependencyFilterUtils.classpathFilter(selectedScope));
      final SessionData data = session.getRepositorySession().getData();
      final Object previousProbeRequest = data.get(PROBE_REQUEST_KEY);
      data.set(PROBE_REQUEST_KEY, Boolean.TRUE);
      final DependencyResolutionResult result;
      try {
        result = resolver.resolve(request);
      } finally {
        data.set(PROBE_REQUEST_KEY, previousProbeRequest);
      }
      if (getLog().isInfoEnabled()) {
        getLog()
            .info(
                "EXPLICIT_TEST_RESOLUTION filter="
                    + selectedScope.toUpperCase(Locale.ROOT)
                    + " project="
                    + project.getArtifactId());
      }
      FixtureResolvedGraphSnapshot.writeGraph(reportDirectory, result.getDependencyGraph());
      FixtureResolvedGraphSnapshot.writeDependencies(
          reportDirectory, result.getResolvedDependencies());
    } catch (IOException | DependencyResolutionException exception) {
      throw new MojoExecutionException("Cannot capture a fresh TEST dependency graph", exception);
    }
  }
}
