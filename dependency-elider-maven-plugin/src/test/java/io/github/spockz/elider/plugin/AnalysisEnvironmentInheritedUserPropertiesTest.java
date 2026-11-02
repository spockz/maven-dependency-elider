/* WHY: Protects inherited Maven user defaults as they cross Analyze environment capture. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.nio.file.Path;
import java.util.List;
import java.util.Properties;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.model.Build;
import org.apache.maven.project.MavenProject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Tests inherited Maven user properties on the live session and captured Analyze paths. */
final class AnalysisEnvironmentInheritedUserPropertiesTest {
  private static final String MAVEN_COMPILER_RELEASE = "maven.compiler.release";

  private static final String MAVEN_COMPILER_FORK = "maven.compiler.fork";

  /** Holds the project files used to create Maven sessions. */
  @TempDir private Path temporaryDirectory;

  /* package */ AnalysisEnvironmentInheritedUserPropertiesTest() {
    // JUnit creates each test instance through the package-visible no-argument constructor.
  }

  @Test
  void inheritedUserReleasePropertyMatchesTheLiveMavenSessionPath() throws Exception {
    final MavenProject project = project("release-project");
    final Properties defaults = new Properties();
    defaults.setProperty(MAVEN_COMPILER_RELEASE, "11");
    final Properties user = new Properties(defaults);
    final MavenSession session =
        AnalysisEnvironmentCompilerSettingsTestSupport.session(user, project);
    final AnalysisEnvironment environment = AnalysisEnvironment.capture(project, session);

    assertAll(
        "the inherited user release survives Maven request and Analyze environment capture",
        () ->
            assertThat(session.getUserProperties().getProperty(MAVEN_COMPILER_RELEASE))
                .isEqualTo("11"),
        () ->
            assertThat(MavenCompilerSettings.options(project, session, List.of()))
                .containsExactly("--release", "11"),
        () ->
            assertThat(environment.userPropertiesAsProperties().getProperty(MAVEN_COMPILER_RELEASE))
                .isEqualTo("11"),
        () ->
            assertThat(
                    MavenCompilerSettings.optionsWithEnvironment(project, environment, List.of()))
                .containsExactly("--release", "11"));
  }

  @Test
  void inheritedUserGuardPropertyIsNotLostByTheLiveMavenSessionPath() throws Exception {
    final MavenProject project = project("guard-project");
    final Properties defaults = new Properties();
    defaults.setProperty(MAVEN_COMPILER_FORK, Boolean.TRUE.toString());
    final Properties user = new Properties(defaults);
    final MavenSession session =
        AnalysisEnvironmentCompilerSettingsTestSupport.session(user, project);
    final AnalysisEnvironment environment = AnalysisEnvironment.capture(project, session);

    assertAll(
        "the inherited user guard survives Maven request and Analyze environment capture",
        () ->
            assertThat(session.getUserProperties().getProperty(MAVEN_COMPILER_FORK))
                .isEqualTo(Boolean.TRUE.toString()),
        () ->
            assertThatThrownBy(() -> MavenCompilerSettings.options(project, session, List.of()))
                .isInstanceOf(java.io.IOException.class)
                .hasMessageContaining(MAVEN_COMPILER_FORK),
        () ->
            assertThat(environment.userPropertiesAsProperties().getProperty(MAVEN_COMPILER_FORK))
                .isEqualTo(Boolean.TRUE.toString()),
        () ->
            assertThatThrownBy(
                    () ->
                        MavenCompilerSettings.optionsWithEnvironment(
                            project, environment, List.of()))
                .isInstanceOf(java.io.IOException.class)
                .hasMessageContaining(MAVEN_COMPILER_FORK));
  }

  @Test
  void explicitUserReleaseOverridesItsInheritedDefault() throws Exception {
    final MavenProject project = project("override-project");
    final Properties defaults = new Properties();
    defaults.setProperty(MAVEN_COMPILER_RELEASE, "11");
    final Properties user = new Properties(defaults);
    user.setProperty(MAVEN_COMPILER_RELEASE, "13");
    final MavenSession session =
        AnalysisEnvironmentCompilerSettingsTestSupport.session(user, project);
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

  private MavenProject project(final String name) {
    final MavenProject project = new MavenProject();
    project.setGroupId("org.example");
    project.setArtifactId("analysis");
    project.setVersion("1");
    project.setFile(temporaryDirectory.resolve(name).resolve("pom.xml").toFile());
    project.setBuild(new Build());
    project.getProperties().setProperty(MAVEN_COMPILER_RELEASE, "17");
    return project;
  }
}
