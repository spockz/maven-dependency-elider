/* WHY: Rejects runtime selection and output paths that invalidate the automatic test graph. */

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import org.apache.maven.model.Build;
import org.apache.maven.model.Plugin;
import org.apache.maven.model.PluginExecution;
import org.apache.maven.model.PluginManagement;
import org.apache.maven.project.MavenProject;
import org.codehaus.plexus.util.xml.Xpp3Dom;

/** Guards the platform and generated files used by test additions. */
@SuppressWarnings({"PMD.CommentDefaultAccessModifier", "PMD.TestClassWithoutTestCases"})
final class TestViewPreparationGuard {
  private TestViewPreparationGuard() {}

  @SuppressWarnings({
    "PMD.CognitiveComplexity",
    "PMD.CyclomaticComplexity",
    "PMD.AvoidLiteralsInIfCondition"
  })
  static void requireActiveRuntime(
      final List<String> runtimeInputs,
      final Path projectBase,
      final MavenProject project,
      final Properties userProperties,
      final Properties systemProperties)
      throws IOException {
    if (runtimeInputs != null && !runtimeInputs.isEmpty()) {
      if (runtimeInputs.size() != 1) {
        throw new IOException(
            "Automatic test additions require exactly one elide.runtimeInputs image matching the"
                + " Maven runtime");
      }
      final String configured = runtimeInputs.getFirst();
      if (configured == null || configured.isBlank()) {
        throw new IOException("elide.runtimeInputs contains a blank runtime path");
      }
      final Path configuredPath = Path.of(configured);
      final Path selected =
          (configuredPath.isAbsolute() ? configuredPath : projectBase.resolve(configuredPath))
              .toAbsolutePath()
              .normalize();
      final Path active = Path.of(System.getProperty("java.home")).toAbsolutePath().normalize();
      if (!Files.exists(selected) || !Files.isSameFile(selected, active)) {
        throw new IOException(
            "Automatic test additions require elide.runtimeInputs to select the active Maven"
                + " runtime: "
                + selected);
      }
    }
    rejectJvmProperty(userProperties);
    rejectJvmProperty(systemProperties);
    rejectJvmProperty(project.getProperties());
    final Build build = project.getBuild();
    if (build == null) {
      return;
    }
    final List<Plugin> plugins = new ArrayList<>(build.getPlugins());
    final PluginManagement management = build.getPluginManagement();
    if (management != null) {
      plugins.addAll(management.getPlugins());
    }
    for (final Plugin plugin : plugins) {
      if (!"maven-surefire-plugin".equals(plugin.getArtifactId())
          || !(plugin.getGroupId() == null
              || plugin.getGroupId().isBlank()
              || "org.apache.maven.plugins".equals(plugin.getGroupId()))) {
        continue;
      }
      rejectSurefireConfiguration(plugin.getConfiguration());
      for (final PluginExecution execution : plugin.getExecutions()) {
        rejectSurefireConfiguration(execution.getConfiguration());
      }
    }
  }

  private static void rejectJvmProperty(final Properties properties) throws IOException {
    if (properties != null && properties.getProperty("jvm") != null) {
      throw new IOException(
          "Automatic test additions cannot verify Surefire's jvm override; use the Maven runtime");
    }
  }

  private static void rejectSurefireConfiguration(final Object configuration) throws IOException {
    if (configuration == null) {
      return;
    }
    if (!(configuration instanceof Xpp3Dom dom)) {
      throw new IOException(
          "Cannot inspect Surefire JVM configuration for automatic test additions");
    }
    for (final String name : List.of("jvm", "jdkToolchain")) {
      if (dom.getChild(name) != null) {
        throw new IOException(
            "Automatic test additions cannot verify Surefire "
                + name
                + " selection; use the Maven runtime");
      }
    }
  }

  static void validateOutputTargets(
      final Path mainClasses, final Path testClasses, final List<Path> targets) throws IOException {
    final Path production = mainClasses.toAbsolutePath().normalize();
    final Path tests = testClasses.toAbsolutePath().normalize();
    for (final Path target : targets) {
      final Path normalized = target.toAbsolutePath().normalize();
      if (normalized.startsWith(production)) {
        throw new IOException("Test-view target overlaps production class output: " + normalized);
      }
      if (normalized.startsWith(tests)) {
        throw new IOException("Test-view target overlaps test class output: " + normalized);
      }
    }
  }
}
