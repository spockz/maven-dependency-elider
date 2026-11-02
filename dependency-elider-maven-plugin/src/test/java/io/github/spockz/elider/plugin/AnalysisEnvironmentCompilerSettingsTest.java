// WHY: Locks Analyze compiler settings to Maven's frozen user-over-system-over-project precedence.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.apache.maven.model.Build;
import org.apache.maven.model.Plugin;
import org.apache.maven.project.MavenProject;
import org.codehaus.plexus.util.xml.Xpp3Dom;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Tests Maven compiler property precedence and inherited user-property handling. */
final class AnalysisEnvironmentCompilerSettingsTest {
  private static final String MAVEN_COMPILER_RELEASE = "maven.compiler.release";

  private static final String MAVEN_COMPILER_PROCESSING = "maven.compiler.proc";

  private static final String MAVEN_COMPILER_FORK = "maven.compiler.fork";

  private static final String RELEASE_OPTION = "--release";

  private static final String TRUE_PROPERTY_VALUE = Boolean.TRUE.toString();

  /** Holds the project base directories used by the compiler fixtures. */
  @TempDir private Path temporaryDirectory;

  /* package */ AnalysisEnvironmentCompilerSettingsTest() {
    // JUnit creates each test instance through the package-visible no-argument constructor.
  }

  @Test
  void interpolatedCompilerSettingsPreferUserOverSystemOverProject() throws Exception {
    final MavenProject project = project();
    project.getProperties().setProperty(MAVEN_COMPILER_RELEASE, "8");
    compilerPlugin(project, "${" + MAVEN_COMPILER_RELEASE + "}");
    final AnalysisEnvironment environment =
        environment(Map.of(MAVEN_COMPILER_RELEASE, "11"), Map.of(MAVEN_COMPILER_RELEASE, "17"));
    final List<String> options =
        MavenCompilerSettings.optionsWithEnvironment(project, environment, List.of());

    assertAll(
        "Analyze uses the same user-property precedence as Maven compiler configuration",
        () -> assertThat(options).containsExactly(RELEASE_OPTION, "17"),
        () ->
            assertThat(project.getProperties().getProperty(MAVEN_COMPILER_RELEASE)).isEqualTo("8"));
  }

  @Test
  void userProcessorNoneOverrideDisablesAnnotationProcessing() throws Exception {
    final MavenProject project = project();
    project.getProperties().setProperty(MAVEN_COMPILER_RELEASE, "17");
    project.getProperties().setProperty(MAVEN_COMPILER_PROCESSING, "full");
    compilerPlugin(project, null);
    final AnalysisEnvironment safeOverride =
        environment(
            Map.of(MAVEN_COMPILER_PROCESSING, "full"), Map.of(MAVEN_COMPILER_PROCESSING, "none"));

    final List<String> options =
        MavenCompilerSettings.optionsWithEnvironment(project, safeOverride, List.of());

    assertThat(options).containsExactly(RELEASE_OPTION, "17");
  }

  @Test
  void userProcessorFullOverrideIsRejected() throws Exception {
    final MavenProject project = project();
    project.getProperties().setProperty(MAVEN_COMPILER_RELEASE, "17");
    project.getProperties().setProperty(MAVEN_COMPILER_PROCESSING, "full");
    compilerPlugin(project, null);
    final AnalysisEnvironment unsafeOverride =
        environment(
            Map.of(MAVEN_COMPILER_PROCESSING, "none"), Map.of(MAVEN_COMPILER_PROCESSING, "full"));
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
        environment(Map.of(MAVEN_COMPILER_RELEASE, "11"), Map.of());

    final List<String> options =
        MavenCompilerSettings.optionsWithEnvironment(project, environment, List.of());

    assertThat(options).containsExactly(RELEASE_OPTION, "17");
  }

  @Test
  void blankUserReleaseFallsBackToTheProjectProperty() throws Exception {
    final MavenProject project = project();
    final AnalysisEnvironment environment =
        environment(Map.of(), Map.of(MAVEN_COMPILER_RELEASE, "  "));

    final List<String> options =
        MavenCompilerSettings.optionsWithEnvironment(project, environment, List.of());

    assertThat(options).containsExactly(RELEASE_OPTION, "17");
  }

  @Test
  void userFalseDoesNotHideUnsupportedProjectForkProperty() {
    final MavenProject project = project();
    project.getProperties().setProperty(MAVEN_COMPILER_FORK, TRUE_PROPERTY_VALUE);
    final AnalysisEnvironment environment =
        environment(Map.of(), Map.of(MAVEN_COMPILER_FORK, Boolean.FALSE.toString()));

    assertThatThrownBy(
            () -> MavenCompilerSettings.optionsWithEnvironment(project, environment, List.of()))
        .isInstanceOf(java.io.IOException.class)
        .hasMessageContaining(MAVEN_COMPILER_FORK);
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
    project.getProperties().setProperty(MAVEN_COMPILER_RELEASE, "17");
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
}
