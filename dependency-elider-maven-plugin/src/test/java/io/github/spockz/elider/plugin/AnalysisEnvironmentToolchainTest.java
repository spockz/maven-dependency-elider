// WHY: Proves Analyze accepts only Maven's verified absence of a selected JDK toolchain.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.lang.reflect.Proxy;
import java.nio.file.Path;
import java.util.Map;
import org.apache.maven.execution.DefaultMavenExecutionRequest;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.descriptor.PluginDescriptor;
import org.apache.maven.project.MavenProject;
import org.apache.maven.toolchain.DefaultToolchainManager;
import org.codehaus.plexus.PlexusContainer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class AnalysisEnvironmentToolchainTest {
  @TempDir private Path temporaryDirectory;

  @Test
  void capturesOnlyAbsentDefaultToolchainContextAndRejectsAnySelectedEntry() throws Exception {
    final MavenProject project = project();
    final MavenSession session = session(project);
    final AnalysisEnvironment environment = AnalysisEnvironment.capture(project, session);
    final PluginDescriptor descriptor = toolchainsDescriptor();
    final Map<String, Object> context = session.getPluginContext(descriptor, project);
    context.put(DefaultToolchainManager.getStorageKey("jdk"), new Object());

    assertAll(
        "Analyze accepts the supported Maven no-toolchain state only",
        () ->
            assertThat(environment.jdkToolchainState())
                .isEqualTo(AnalysisEnvironment.JdkToolchainState.UNSELECTED),
        () ->
            assertThatThrownBy(() -> AnalysisEnvironment.capture(project, session))
                .isInstanceOf(java.io.IOException.class)
                .hasMessageContaining("selected Maven JDK toolchain"));
  }

  private MavenProject project() {
    final MavenProject project = new MavenProject();
    project.setGroupId("org.example");
    project.setArtifactId("toolchain-check");
    project.setVersion("1");
    project.setFile(temporaryDirectory.resolve("pom.xml").toFile());
    return project;
  }

  private static MavenSession session(final MavenProject project) {
    final DefaultMavenExecutionRequest request = new DefaultMavenExecutionRequest();
    request.setBaseDirectory(project.getBasedir());
    final PlexusContainer container =
        (PlexusContainer)
            Proxy.newProxyInstance(
                PlexusContainer.class.getClassLoader(),
                new Class<?>[] {PlexusContainer.class},
                (proxy, method, arguments) ->
                    "lookup".equals(method.getName()) ? new DefaultToolchainManager() : null);
    final MavenSession session = new MavenSession(container, null, request, null);
    session.setCurrentProject(project);
    return session;
  }

  private static PluginDescriptor toolchainsDescriptor() {
    final PluginDescriptor descriptor = new PluginDescriptor();
    descriptor.setGroupId(PluginDescriptor.getDefaultPluginGroupId());
    descriptor.setArtifactId(PluginDescriptor.getDefaultPluginArtifactId("toolchains"));
    return descriptor;
  }
}
