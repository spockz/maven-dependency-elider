/* WHY: Ensures projects configuring elide run lightweight config checks in the validate phase. */

package io.github.spockz.elider.plugin;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.model.Build;
import org.apache.maven.model.Plugin;
import org.apache.maven.model.PluginExecution;
import org.apache.maven.project.MavenProject;

/** Schedules lightweight configuration checks for projects that bind {@code elide}. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class EliderValidateScheduling {
  /** Base execution ID for synthesized validate-phase executions. */
  private static final String VALIDATE_EXECUTION_ID = "dependency-elider-validate";

  private EliderValidateScheduling() {}

  static void schedule(final MavenSession session) {
    if (session == null || session.getProjects() == null) {
      return;
    }
    for (final MavenProject project : session.getProjects()) {
      scheduleProject(project);
    }
  }

  private static void scheduleProject(final MavenProject project) {
    final Build build = project == null ? null : project.getBuild();
    if (build == null) {
      return;
    }
    final Plugin plugin =
        build
            .getPluginsAsMap()
            .get(EliderPluginCoordinates.GROUP_ID + ":" + EliderPluginCoordinates.ARTIFACT_ID);
    if (plugin == null || hasValidateExecution(plugin)) {
      return;
    }
    final List<PluginExecution> elideExecutions = elideExecutions(plugin);
    if (elideExecutions.isEmpty()) {
      return;
    }
    final Set<String> usedIds = collectExecutionIds(plugin);
    for (final PluginExecution elideExecution : elideExecutions) {
      plugin.addExecution(createValidateExecution(usedIds, elideExecution));
    }
  }

  private static List<PluginExecution> elideExecutions(final Plugin plugin) {
    return plugin.getExecutions().stream()
        .filter(execution -> execution.getGoals().contains(EliderPluginCoordinates.ELIDE_GOAL))
        .toList();
  }

  private static Set<String> collectExecutionIds(final Plugin plugin) {
    final Set<String> usedIds = new HashSet<>();
    for (final PluginExecution existing : plugin.getExecutions()) {
      if (existing.getId() != null) {
        usedIds.add(existing.getId());
      }
    }
    return usedIds;
  }

  private static PluginExecution createValidateExecution(
      final Set<String> usedIds, final PluginExecution elideExecution) {
    final PluginExecution validateExecution = new PluginExecution();
    validateExecution.setId(uniqueId(usedIds, elideExecution));
    validateExecution.setPhase(EliderPluginCoordinates.VALIDATE_PHASE);
    validateExecution.setGoals(List.of(EliderPluginCoordinates.VALIDATE_GOAL));
    if (elideExecution.getConfiguration() != null) {
      validateExecution.setConfiguration(elideExecution.getConfiguration());
    }
    return validateExecution;
  }

  private static boolean hasValidateExecution(final Plugin plugin) {
    return plugin.getExecutions().stream()
        .anyMatch(
            execution -> execution.getGoals().contains(EliderPluginCoordinates.VALIDATE_GOAL));
  }

  private static String uniqueId(final Set<String> usedIds, final PluginExecution elideExecution) {
    final String elideId = elideExecution.getId();
    final String base =
        elideId == null || elideId.isBlank()
            ? VALIDATE_EXECUTION_ID
            : VALIDATE_EXECUTION_ID + "-" + elideId;
    String candidate = base;
    int suffix = 1;
    while (!usedIds.add(candidate)) {
      candidate = base + "-" + suffix;
      suffix++;
    }
    return candidate;
  }
}
