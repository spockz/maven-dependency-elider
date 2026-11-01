// WHY: Checks whether Maven source attribution covers the complete production source lifecycle.

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.model.Plugin;
import org.apache.maven.model.PluginExecution;
import org.apache.maven.project.MavenProject;

/** Checks source attribution against Maven lifecycle generation. */
final class SourceRootCompleteness {
  /** Maven's standard build plugin group. */
  private static final String MAVEN_PLUGIN_GROUP = "org.apache.maven.plugins";

  private SourceRootCompleteness() {}

  /* default */ static void verifySourceRootsComplete(
      final MavenProject project, final MavenSession session, final List<Path> currentSources)
      throws IOException {
    verifySourceRootsComplete(project, session, null, currentSources);
  }

  /* default */ static void verifySourceRootsComplete(
      final MavenProject project,
      final AnalysisEnvironment environment,
      final List<Path> currentSources)
      throws IOException {
    verifySourceRootsComplete(project, null, environment, currentSources);
  }

  private static void verifySourceRootsComplete(
      final MavenProject project,
      final MavenSession session,
      final AnalysisEnvironment environment,
      final List<Path> currentSources)
      throws IOException {
    if (currentSources.isEmpty()) {
      throw new IOException(
          "elide.sourceRootsComplete=true requires current production Java sources");
    }
    for (final String root : project.getCompileSourceRoots()) {
      if (!Files.isDirectory(Path.of(root))) {
        throw new IOException("A declared production source root is not present: " + root);
      }
    }
    if (hasUnknownSourceGeneration(project, session, environment)) {
      throw new IOException(
          "elide.sourceRootsComplete=true conflicts with a source-generation lifecycle execution; "
              + "use -Delide.productionClassesComplete=true or bind dependency-elider:elide to "
              + "process-classes to analyze compiled bytecode");
    }
  }

  /* default */ static boolean hasUnknownSourceGeneration(final MavenProject project) {
    return hasUnknownSourceGeneration(project, (MavenSession) null);
  }

  /* default */ static boolean hasUnknownSourceGeneration(
      final MavenProject project, final MavenSession session) {
    return hasUnknownSourceGeneration(project, session, null);
  }

  /* default */ static boolean hasUnknownSourceGeneration(
      final MavenProject project, final AnalysisEnvironment environment) {
    return hasUnknownSourceGeneration(project, null, environment);
  }

  private static boolean hasUnknownSourceGeneration(
      final MavenProject project,
      final MavenSession session,
      final AnalysisEnvironment environment) {
    final org.apache.maven.model.Build build = project.getBuild();
    if (unsupportedBuild(project, build)) {
      return true;
    }
    final boolean annotationProcessingConfigured =
        environment == null
            ? MavenCompilerSettings.hasConfiguredAnnotationProcessing(project, session)
            : MavenCompilerSettings.hasConfiguredAnnotationProcessingWithEnvironment(
                project, environment);
    if (annotationProcessingConfigured) {
      return true;
    }
    for (final Plugin plugin : build.getPlugins()) {
      for (final PluginExecution execution : plugin.getExecutions()) {
        if (!isKnownNonGeneratingExecution(plugin, execution)
            && (execution.getPhase() == null
                || phaseCanAddProductionSources(execution.getPhase()))) {
          return true;
        }
      }
    }
    return false;
  }

  private static boolean unsupportedBuild(
      final MavenProject project, final org.apache.maven.model.Build build) {
    return build == null
        || !Set.of("jar", "pom", "war", "maven-plugin").contains(project.getPackaging())
        || !build.getExtensions().isEmpty();
  }

  private static boolean isKnownNonGeneratingExecution(
      final Plugin plugin, final PluginExecution execution) {
    if (MAVEN_PLUGIN_GROUP.equals(plugin.getGroupId())) {
      return switch (plugin.getArtifactId()) {
        case null -> false;
        case "maven-resources-plugin" ->
            execution.getGoals().stream().allMatch("resources"::equals);
        case "maven-compiler-plugin" ->
            execution.getGoals().stream().allMatch(Set.of("compile", "testCompile")::contains);
        case "maven-enforcer-plugin" -> execution.getGoals().stream().allMatch("enforce"::equals);
        default -> false;
      };
    }
    return "io.github.spockz".equals(plugin.getGroupId())
        && "dependency-elider-maven-plugin".equals(plugin.getArtifactId())
        && execution.getGoals().stream().allMatch(Set.of("elide", "analyze")::contains);
  }

  private static boolean phaseCanAddProductionSources(final String phase) {
    return Set.of(
            "validate",
            "initialize",
            "generate-sources",
            "process-sources",
            "generate-resources",
            "process-resources",
            "compile")
        .contains(phase);
  }
}
