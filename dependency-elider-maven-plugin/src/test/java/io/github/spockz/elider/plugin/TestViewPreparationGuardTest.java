/* WHY: Proves automatic test analysis uses the same runtime and cannot overwrite
 * compiler output. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Properties;
import org.apache.maven.model.Build;
import org.apache.maven.model.Plugin;
import org.apache.maven.project.MavenProject;
import org.codehaus.plexus.util.xml.Xpp3Dom;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Exercises the automatic test graph's runtime and output boundaries. */
@SuppressWarnings({"PMD.AtLeastOneConstructor", "PMD.CommentRequired"})
final class TestViewPreparationGuardTest {
  private static final String JVM = "jvm";

  @TempDir private Path directory;

  @Test
  void rejectsDifferentOrMultipleRuntimeImages() {
    final MavenProject project = project();
    final Path active = Path.of(System.getProperty("java.home"));
    assertAll(
        () ->
            assertThatThrownBy(
                    () ->
                        TestViewPreparationGuard.requireActiveRuntime(
                            List.of(directory.resolve("other-jdk").toString()),
                            directory,
                            project,
                            new Properties(),
                            new Properties()))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("elide.runtimeInputs")
                .hasMessageContaining("Maven runtime"),
        () ->
            assertThatThrownBy(
                    () ->
                        TestViewPreparationGuard.requireActiveRuntime(
                            List.of(active.toString(), active.toString()),
                            directory,
                            project,
                            new Properties(),
                            new Properties()))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("exactly one"));
  }

  @Test
  void acceptsTheRunningRuntimeWhenSurefireUsesItsDefaultJvm() {
    assertDoesNotThrow(
        () ->
            TestViewPreparationGuard.requireActiveRuntime(
                List.of(System.getProperty("java.home")),
                directory,
                project(),
                new Properties(),
                new Properties()));
  }

  @Test
  void rejectsSurefireJvmAndToolchainOverrides() {
    final MavenProject configuredJvm = project();
    final Plugin surefire = surefire(configuredJvm);
    final Xpp3Dom configuration = new Xpp3Dom("configuration");
    final Xpp3Dom jvm = new Xpp3Dom(JVM);
    jvm.setValue(directory.resolve("other-jdk/bin/java").toString());
    configuration.addChild(jvm);
    surefire.setConfiguration(configuration);
    final MavenProject configuredToolchain = project();
    final Plugin toolchainSurefire = surefire(configuredToolchain);
    final Xpp3Dom toolchainConfiguration = new Xpp3Dom("configuration");
    toolchainConfiguration.addChild(new Xpp3Dom("jdkToolchain"));
    toolchainSurefire.setConfiguration(toolchainConfiguration);
    final Properties userProperties = new Properties();
    userProperties.setProperty(JVM, directory.resolve("cli-jdk/bin/java").toString());
    assertAll(
        () ->
            assertThatThrownBy(() -> require(configuredJvm, new Properties()))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("Surefire")
                .hasMessageContaining(JVM),
        () ->
            assertThatThrownBy(() -> require(configuredToolchain, new Properties()))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("Surefire")
                .hasMessageContaining("jdkToolchain"),
        () ->
            assertThatThrownBy(() -> require(project(), userProperties))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("Surefire")
                .hasMessageContaining(JVM));
  }

  @Test
  void rejectsGeneratedTargetsInsideCompilerOutputDirectories() {
    final Path main = directory.resolve("target/classes");
    final Path tests = directory.resolve("target/test-classes");
    assertAll(
        () ->
            assertThatThrownBy(
                    () ->
                        TestViewPreparationGuard.validateOutputTargets(
                            main, tests, List.of(main.resolve("report.json"))))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("production class output"),
        () ->
            assertThatThrownBy(
                    () ->
                        TestViewPreparationGuard.validateOutputTargets(
                            main, tests, List.of(tests.resolve("additions.jar"))))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("test class output"));
    try {
      TestViewPreparationGuard.validateOutputTargets(
          main, tests, List.of(directory.resolve("target/elider/report.json")));
    } catch (final IOException unexpected) {
      throw new AssertionError(unexpected);
    }
  }

  private void require(final MavenProject project, final Properties userProperties)
      throws IOException {
    TestViewPreparationGuard.requireActiveRuntime(
        List.of(System.getProperty("java.home")),
        directory,
        project,
        userProperties,
        new Properties());
  }

  private static MavenProject project() {
    final MavenProject project = new MavenProject();
    project.setBuild(new Build());
    return project;
  }

  private static Plugin surefire(final MavenProject project) {
    final Plugin plugin = new Plugin();
    plugin.setGroupId("org.apache.maven.plugins");
    plugin.setArtifactId("maven-surefire-plugin");
    project.getBuild().addPlugin(plugin);
    return plugin;
  }
}
