// WHY: Locks Analyze compiler settings to Maven's frozen user-over-system-over-project precedence.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.lang.reflect.Proxy;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import org.apache.maven.execution.DefaultMavenExecutionRequest;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.model.Build;
import org.apache.maven.model.Plugin;
import org.apache.maven.project.MavenProject;
import org.apache.maven.toolchain.DefaultToolchainManager;
import org.codehaus.plexus.PlexusContainer;
import org.codehaus.plexus.util.xml.Xpp3Dom;
import org.eclipse.aether.DefaultRepositorySystemSession;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class AnalysisEnvironmentCompilerSettingsTest {
  @TempDir private Path temporaryDirectory;

  @Test
  void interpolatedCompilerSettingsPreferUserOverSystemOverProject() throws Exception {
    final MavenProject project = project();
    project.getProperties().setProperty("maven.compiler.release", "8");
    compilerPlugin(project, "${maven.compiler.release}");
    final AnalysisEnvironment environment =
        environment(Map.of("maven.compiler.release", "11"), Map.of("maven.compiler.release", "17"));
    final List<String> options =
        MavenCompilerSettings.optionsWithEnvironment(project, environment, List.of());

    assertAll(
        "Analyze uses the same user-property precedence as Maven compiler configuration",
        () -> assertThat(options).containsExactly("--release", "17"),
        () ->
            assertThat(project.getProperties().getProperty("maven.compiler.release"))
                .isEqualTo("8"));
  }

  @Test
  void userProcessorOverrideIsEvaluatedAboveSystemAndProjectValues() throws Exception {
    final MavenProject project = project();
    project.getProperties().setProperty("maven.compiler.release", "17");
    project.getProperties().setProperty("maven.compiler.proc", "full");
    compilerPlugin(project, null);
    final AnalysisEnvironment safeOverride =
        environment(Map.of("maven.compiler.proc", "full"), Map.of("maven.compiler.proc", "none"));

    final List<String> options =
        MavenCompilerSettings.optionsWithEnvironment(project, safeOverride, List.of());

    assertThat(options).containsExactly("--release", "17");
    final AnalysisEnvironment unsafeOverride =
        environment(Map.of("maven.compiler.proc", "none"), Map.of("maven.compiler.proc", "full"));
    assertThatThrownBy(
            () ->
                MavenCompilerSettings.optionsWithEnvironment(project(), unsafeOverride, List.of()))
        .isInstanceOf(java.io.IOException.class)
        .hasMessageContaining("annotation processing");
  }

  @Test
  void compilerValueResolutionIgnoresSystemPropertiesLikeTheExistingMavenPath() throws Exception {
    final MavenProject project = project();
    final AnalysisEnvironment environment =
        environment(Map.of("maven.compiler.release", "11"), Map.of());

    final List<String> options =
        MavenCompilerSettings.optionsWithEnvironment(project, environment, List.of());

    assertThat(options).containsExactly("--release", "17");
  }

  @Test
  void blankUserReleaseFallsBackToTheProjectProperty() throws Exception {
    final MavenProject project = project();
    final AnalysisEnvironment environment =
        environment(Map.of(), Map.of("maven.compiler.release", "  "));

    final List<String> options =
        MavenCompilerSettings.optionsWithEnvironment(project, environment, List.of());

    assertThat(options).containsExactly("--release", "17");
  }

  @Test
  void userFalseDoesNotHideUnsupportedProjectForkProperty() {
    final MavenProject project = project();
    project.getProperties().setProperty("maven.compiler.fork", "true");
    final AnalysisEnvironment environment =
        environment(Map.of(), Map.of("maven.compiler.fork", "false"));

    assertThatThrownBy(
            () -> MavenCompilerSettings.optionsWithEnvironment(project, environment, List.of()))
        .isInstanceOf(java.io.IOException.class)
        .hasMessageContaining("maven.compiler.fork");
  }

  @Test
  void inheritedUserReleasePropertyMatchesTheLiveMavenSessionPath() throws Exception {
    final MavenProject project = project();
    project.setFile(temporaryDirectory.resolve("release-project/pom.xml").toFile());
    final Properties defaults = new Properties();
    defaults.setProperty("maven.compiler.release", "11");
    final Properties user = new Properties(defaults);
    final MavenSession session = session(user, project);
    final AnalysisEnvironment environment = AnalysisEnvironment.capture(project, session);

    assertAll(
        "the inherited user release survives Maven request and Analyze environment capture",
        () ->
            assertThat(session.getUserProperties().getProperty("maven.compiler.release"))
                .isEqualTo("11"),
        () ->
            assertThat(MavenCompilerSettings.options(project, session, List.of()))
                .containsExactly("--release", "11"),
        () ->
            assertThat(
                    environment.userPropertiesAsProperties().getProperty("maven.compiler.release"))
                .isEqualTo("11"),
        () ->
            assertThat(
                    MavenCompilerSettings.optionsWithEnvironment(project, environment, List.of()))
                .containsExactly("--release", "11"));
  }

  @Test
  void inheritedUserGuardPropertyIsNotLostByTheLiveMavenSessionPath() throws Exception {
    final MavenProject project = project();
    project.setFile(temporaryDirectory.resolve("guard-project/pom.xml").toFile());
    final Properties defaults = new Properties();
    defaults.setProperty("maven.compiler.fork", "true");
    final Properties user = new Properties(defaults);
    final MavenSession session = session(user, project);
    final AnalysisEnvironment environment = AnalysisEnvironment.capture(project, session);

    assertAll(
        "the inherited user guard survives Maven request and Analyze environment capture",
        () ->
            assertThat(session.getUserProperties().getProperty("maven.compiler.fork"))
                .isEqualTo("true"),
        () ->
            assertThatThrownBy(() -> MavenCompilerSettings.options(project, session, List.of()))
                .isInstanceOf(java.io.IOException.class)
                .hasMessageContaining("maven.compiler.fork"),
        () ->
            assertThat(environment.userPropertiesAsProperties().getProperty("maven.compiler.fork"))
                .isEqualTo("true"),
        () ->
            assertThatThrownBy(
                    () ->
                        MavenCompilerSettings.optionsWithEnvironment(
                            project, environment, List.of()))
                .isInstanceOf(java.io.IOException.class)
                .hasMessageContaining("maven.compiler.fork"));
  }

  @Test
  void explicitUserReleaseOverridesItsInheritedDefault() throws Exception {
    final MavenProject project = project();
    project.setFile(temporaryDirectory.resolve("override-project/pom.xml").toFile());
    final Properties defaults = new Properties();
    defaults.setProperty("maven.compiler.release", "11");
    final Properties user = new Properties(defaults);
    user.setProperty("maven.compiler.release", "13");
    final MavenSession session = session(user, project);
    final AnalysisEnvironment environment = AnalysisEnvironment.capture(project, session);

    assertAll(
        "an explicit user property overrides its inherited default in both paths",
        () ->
            assertThat(MavenCompilerSettings.options(project, session, List.of()))
                .containsExactly("--release", "13"),
        () ->
            assertThat(
                    MavenCompilerSettings.optionsWithEnvironment(project, environment, List.of()))
                .containsExactly("--release", "13"));
  }

  private AnalysisEnvironment environment(
      final Map<String, String> system, final Map<String, String> user) {
    return new AnalysisEnvironment(
        system, user, temporaryDirectory, AnalysisEnvironment.JdkToolchainState.UNSELECTED, null);
  }

  private MavenProject project() {
    final MavenProject project = new MavenProject();
    project.setGroupId("org.example");
    project.setArtifactId("analysis");
    project.setVersion("1");
    project.setBuild(new Build());
    project.getProperties().setProperty("maven.compiler.release", "17");
    return project;
  }

  private static Plugin compilerPlugin(final MavenProject project, final String release) {
    final Plugin compiler = new Plugin();
    compiler.setGroupId("org.apache.maven.plugins");
    compiler.setArtifactId("maven-compiler-plugin");
    final Xpp3Dom configuration = new Xpp3Dom("configuration");
    if (release != null) {
      final Xpp3Dom node = new Xpp3Dom("release");
      node.setValue(release);
      configuration.addChild(node);
    }
    compiler.setConfiguration(configuration);
    project.getBuild().addPlugin(compiler);
    return compiler;
  }

  private static MavenSession session(final Properties userProperties) {
    return session(userProperties, null);
  }

  private static MavenSession session(
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
                PlexusContainer.class.getClassLoader(),
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
