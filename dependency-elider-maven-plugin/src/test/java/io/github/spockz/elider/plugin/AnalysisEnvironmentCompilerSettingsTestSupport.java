/* WHY: Shares the synthetic Maven session setup needed to exercise inherited user properties. */

package io.github.spockz.elider.plugin;

import java.lang.reflect.Proxy;
import java.util.Properties;
import org.apache.maven.execution.DefaultMavenExecutionRequest;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.project.MavenProject;
import org.apache.maven.toolchain.DefaultToolchainManager;
import org.codehaus.plexus.PlexusContainer;
import org.eclipse.aether.DefaultRepositorySystemSession;

/** Creates sessions that preserve inherited Maven user properties. */
final class AnalysisEnvironmentCompilerSettingsTestSupport {
  private AnalysisEnvironmentCompilerSettingsTestSupport() {
    // Static fixture creation keeps the support type from becoming a test instance.
  }

  /* package */ static MavenSession session(
      final Properties userProperties, final MavenProject currentProject) {
    final DefaultMavenExecutionRequest request =
        new DefaultMavenExecutionRequest() {
          @Override
          public Properties getUserProperties() {
            return userProperties;
          }
        };
    if (currentProject != null && currentProject.getBasedir() != null) {
      request.setBaseDirectory(currentProject.getBasedir());
    }
    final PlexusContainer container =
        (PlexusContainer)
            Proxy.newProxyInstance(
                Thread.currentThread().getContextClassLoader(),
                new Class<?>[] {PlexusContainer.class},
                (proxy, method, arguments) ->
                    "lookup".equals(method.getName()) ? new DefaultToolchainManager() : null);
    final MavenSession session =
        new MavenSession(container, new DefaultRepositorySystemSession(), request, null);
    if (currentProject != null) {
      session.setCurrentProject(currentProject);
    }
    return session;
  }
}
