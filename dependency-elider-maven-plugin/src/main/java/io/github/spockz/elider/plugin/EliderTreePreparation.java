// WHY: Schedules configured elision before a standalone dependency-tree request.

package io.github.spockz.elider.plugin;

import java.util.List;
import org.apache.maven.MavenExecutionException;
import org.apache.maven.execution.MavenExecutionRequest;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.model.PluginExecution;
import org.apache.maven.project.MavenProject;
import org.eclipse.aether.SessionData;

@SuppressWarnings({"PMD.CommentDefaultAccessModifier", "PMD.CommentRequired"})
final class EliderTreePreparation {
  private static final int ONE_CONFIGURED_EXECUTION = 1;
  private static final int ONE_PROJECT = 1;

  private EliderTreePreparation() {}

  static void schedule(final MavenSession session) throws MavenExecutionException {
    final MavenExecutionRequest request = session.getRequest();
    final List<String> goals = request.getGoals();
    if (goals == null || !EliderGoalMatcher.containsTreeGoal(goals)) {
      return;
    }
    final List<EliderPluginConfiguration.ElideConfiguration> configurations =
        EliderPluginConfiguration.active(session);
    if (configurations.isEmpty()) {
      return;
    }
    scheduleTreePreparation(session, request, goals, configurations);
  }

  private static void scheduleTreePreparation(
      final MavenSession session,
      final MavenExecutionRequest request,
      final List<String> goals,
      final List<EliderPluginConfiguration.ElideConfiguration> configurations)
      throws MavenExecutionException {
    final MavenProject project = configurations.getFirst().project();
    final int treeIndex = EliderGoalOrder.firstTreeIndex(goals);
    final int lastCleanIndex = EliderGoalOrder.lastCleanBefore(goals, treeIndex);
    final EliderPluginConfiguration.ElideConfiguration configuration =
        requireSingleConfiguration(configurations, request);
    if (configuration.executions().size() != ONE_CONFIGURED_EXECUTION) {
      throw EliderPluginConfiguration.failure(
          project,
          "A dependency:tree request requires exactly one active "
              + "dependency-elider:elide execution");
    }
    final PluginExecution execution = configuration.executions().getFirst();
    final String requiredPhase = EliderPluginConfiguration.effectivePhase(execution, project);
    EliderPluginConfiguration.requireExecutionIdentity(configuration.plugin(), execution, project);
    EliderGoalOrder.validateCleanOrdering(goals, treeIndex, project, requiredPhase);
    if (EliderGoalOrder.hasPreparedLifecycleAfter(goals, lastCleanIndex, treeIndex, requiredPhase)
        || EliderGoalOrder.hasMatchingExecutionAfter(
            goals, configurations, lastCleanIndex, treeIndex)) {
      return;
    }
    requireSingleProjectReactor(session, request);
    EliderPluginConfiguration.requireInitializeBinding(execution, project);

    final boolean processClassesBinding = "process-classes".equals(requiredPhase);
    final List<String> preparedGoals =
        EliderGoalOrder.insertBeforeTree(
            goals,
            treeIndex,
            processClassesBinding
                ? "process-classes"
                : EliderGoalMatcher.configuredElideGoal(configuration.plugin(), execution));
    if (!processClassesBinding) {
      final SessionData data = EliderPreparationState.sessionData(session);
      if (!data.set(
          EliderPreparationState.PREPARATION_STATE_KEY,
          null,
          EliderPreparationState.pending(execution.getId(), project.getId()))) {
        throw EliderPluginConfiguration.failure(
            project, "Tree preparation state is already present in this session");
      }
    }
    request.setGoals(preparedGoals);
  }

  private static void requireSingleProjectReactor(
      final MavenSession session, final MavenExecutionRequest request)
      throws MavenExecutionException {
    if (session.getProjects() != null && session.getProjects().size() > ONE_PROJECT) {
      throw new MavenExecutionException(
          "Automatic dependency:tree preparation does not support multi-project Maven reactors",
          request.getPom());
    }
  }

  private static EliderPluginConfiguration.ElideConfiguration requireSingleConfiguration(
      final List<EliderPluginConfiguration.ElideConfiguration> configurations,
      final MavenExecutionRequest request)
      throws MavenExecutionException {
    if (configurations.size() != ONE_PROJECT) {
      throw new MavenExecutionException(
          "Automatic dependency:tree preparation requires exactly one configured Maven project",
          request.getPom());
    }
    return configurations.getFirst();
  }
}
