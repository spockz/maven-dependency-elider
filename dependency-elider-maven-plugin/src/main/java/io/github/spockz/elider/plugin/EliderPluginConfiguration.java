// WHY: Reads the active elider binding from Maven's effective project model.

package io.github.spockz.elider.plugin;

import java.util.ArrayList;
import java.util.List;
import org.apache.maven.MavenExecutionException;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.model.Build;
import org.apache.maven.model.Plugin;
import org.apache.maven.model.PluginExecution;
import org.apache.maven.project.MavenProject;

@SuppressWarnings({"PMD.CommentDefaultAccessModifier", "PMD.CommentRequired"})
final class EliderPluginConfiguration {
  private static final String ELIDER_GROUP_ID = "io.github.spockz";
  private static final String ELIDER_ARTIFACT_ID = "dependency-elider-maven-plugin";
  private static final String ELIDE_GOAL = "elide";
  private static final String INITIALIZE_PHASE = "initialize";
  private static final String PROCESS_CLASSES_PHASE = "process-classes";

  private EliderPluginConfiguration() {}

  static List<ElideConfiguration> active(final MavenSession session)
      throws MavenExecutionException {
    final List<ElideConfiguration> configurations = new ArrayList<>();
    final List<MavenProject> projects = session.getProjects();
    if (projects == null) {
      return List.of();
    }
    for (final MavenProject project : projects) {
      final Plugin plugin = findPlugin(project);
      if (plugin == null) {
        continue;
      }
      final List<PluginExecution> executions = activeElideExecutions(plugin);
      if (!executions.isEmpty()) {
        configurations.add(new ElideConfiguration(project, plugin, executions));
      }
    }
    return List.copyOf(configurations);
  }

  private static Plugin findPlugin(final MavenProject project) throws MavenExecutionException {
    final Build build = project.getBuild();
    if (build == null) {
      return null;
    }
    final List<Plugin> plugins =
        build.getPlugins().stream().filter(EliderPluginConfiguration::isEliderPlugin).toList();
    if (plugins.size() > EliderGoalOrder.ONE_MATCH) {
      throw failure(project, "Multiple dependency-elider plugin declarations are ambiguous");
    }
    return plugins.isEmpty() ? null : plugins.getFirst();
  }

  private static List<PluginExecution> activeElideExecutions(final Plugin plugin) {
    final List<PluginExecution> active = new ArrayList<>();
    for (final PluginExecution execution : plugin.getExecutions()) {
      if (execution.getGoals().contains(ELIDE_GOAL)) {
        active.add(execution);
      }
    }
    return List.copyOf(active);
  }

  static void requireInitializeBinding(final PluginExecution execution, final MavenProject project)
      throws MavenExecutionException {
    effectivePhase(execution, project);
  }

  static String effectivePhase(final PluginExecution execution, final MavenProject project)
      throws MavenExecutionException {
    final String configuredPhase = execution.getPhase();
    final String phase =
        configuredPhase == null || configuredPhase.isBlank() ? INITIALIZE_PHASE : configuredPhase;
    if (!INITIALIZE_PHASE.equals(phase) && !PROCESS_CLASSES_PHASE.equals(phase)) {
      throw failure(
          project,
          "Automatic dependency:tree preparation requires dependency-elider:elide bound to "
              + INITIALIZE_PHASE
              + " or "
              + PROCESS_CLASSES_PHASE
              + " (found "
              + phase
              + ")");
    }
    return phase;
  }

  static void requireExecutionIdentity(
      final Plugin plugin, final PluginExecution execution, final MavenProject project)
      throws MavenExecutionException {
    if (plugin.getVersion() == null
        || plugin.getVersion().isBlank()
        || execution.getId() == null
        || execution.getId().isBlank()
        || execution.getId().contains("@")) {
      throw failure(
          project,
          "Automatic dependency:tree preparation requires a versioned elide plugin execution "
              + "with an execution ID");
    }
  }

  static MavenExecutionException failure(final MavenProject project, final String message) {
    return new MavenExecutionException(message, project.getFile());
  }

  private static boolean isEliderPlugin(final Plugin plugin) {
    return ELIDER_GROUP_ID.equals(plugin.getGroupId())
        && ELIDER_ARTIFACT_ID.equals(plugin.getArtifactId());
  }

  record ElideConfiguration(
      MavenProject project, Plugin plugin, List<PluginExecution> executions) {}
}
