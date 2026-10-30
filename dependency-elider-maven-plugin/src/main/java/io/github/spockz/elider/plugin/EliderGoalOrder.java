// WHY: Validates lifecycle and clean ordering around automatic tree preparation.

package io.github.spockz.elider.plugin;

import java.util.ArrayList;
import java.util.List;
import org.apache.maven.MavenExecutionException;
import org.apache.maven.model.PluginExecution;
import org.apache.maven.project.MavenProject;

@SuppressWarnings({"PMD.CommentDefaultAccessModifier", "PMD.CommentRequired"})
final class EliderGoalOrder {
  static final int ONE_MATCH = 1;

  private static final List<String> PREPARED_PHASE_ORDER =
      List.of(
          "initialize",
          "generate-sources",
          "process-sources",
          "generate-resources",
          "process-resources",
          "compile",
          "process-classes",
          "generate-test-sources",
          "process-test-sources",
          "generate-test-resources",
          "process-test-resources",
          "test-compile",
          "process-test-classes",
          "test",
          "prepare-package",
          "package",
          "pre-integration-test",
          "integration-test",
          "post-integration-test",
          "verify",
          "install",
          "deploy");

  private EliderGoalOrder() {}

  static int firstTreeIndex(final List<String> goals) {
    for (int index = 0; index < goals.size(); index++) {
      if (EliderGoalMatcher.isTreeGoal(goals.get(index))) {
        return index;
      }
    }
    return -1;
  }

  static int lastCleanBefore(final List<String> goals, final int treeIndex) {
    int lastClean = -1;
    for (int index = 0; index < treeIndex; index++) {
      if (EliderGoalMatcher.isCleanGoal(goals.get(index))) {
        lastClean = index;
      }
    }
    return lastClean;
  }

  static void validateCleanOrdering(
      final List<String> goals, final int treeIndex, final MavenProject project)
      throws MavenExecutionException {
    validateCleanOrdering(goals, treeIndex, project, "initialize");
  }

  static void validateCleanOrdering(
      final List<String> goals,
      final int treeIndex,
      final MavenProject project,
      final String requiredPhase)
      throws MavenExecutionException {
    final int lastCleanBeforeTree = lastCleanBefore(goals, treeIndex);
    if (lastCleanBeforeTree >= 0
        && hasPreparedLifecycleAfter(goals, -1, lastCleanBeforeTree)
        && !hasPreparedLifecycleAfter(goals, lastCleanBeforeTree, treeIndex, requiredPhase)) {
      throw EliderPluginConfiguration.failure(
          project,
          "Cannot prepare dependency:tree after clean invalidated earlier lifecycle outputs");
    }
    for (int index = treeIndex + 1; index < goals.size(); index++) {
      if (EliderGoalMatcher.isCleanGoal(goals.get(index))) {
        throw EliderPluginConfiguration.failure(
            project,
            "Cannot combine automatic dependency:tree preparation with a later clean goal");
      }
    }
  }

  static boolean hasPreparedLifecycleAfter(
      final List<String> goals, final int lastCleanIndex, final int treeIndex) {
    return hasPreparedLifecycleAfter(goals, lastCleanIndex, treeIndex, "initialize");
  }

  static boolean hasPreparedLifecycleAfter(
      final List<String> goals,
      final int lastCleanIndex,
      final int treeIndex,
      final String requiredPhase) {
    final int requiredPhaseIndex = PREPARED_PHASE_ORDER.indexOf(requiredPhase);
    if (requiredPhaseIndex < 0) {
      return false;
    }
    for (int index = lastCleanIndex + 1; index < treeIndex; index++) {
      final int goalPhaseIndex = PREPARED_PHASE_ORDER.indexOf(goals.get(index));
      if (goalPhaseIndex >= requiredPhaseIndex) {
        return true;
      }
    }
    return false;
  }

  static boolean hasMatchingExecutionAfter(
      final List<String> goals,
      final List<EliderPluginConfiguration.ElideConfiguration> configurations,
      final int lastCleanIndex,
      final int treeIndex) {
    for (int index = lastCleanIndex + 1; index < treeIndex; index++) {
      final String goal = goals.get(index);
      for (final EliderPluginConfiguration.ElideConfiguration configuration : configurations) {
        for (final PluginExecution execution : configuration.executions()) {
          if (EliderGoalMatcher.isConfiguredElideGoal(goal, configuration.plugin(), execution)) {
            return true;
          }
        }
      }
    }
    return false;
  }

  static List<String> insertBeforeTree(
      final List<String> goals, final int treeIndex, final String injectedGoal) {
    final List<String> prepared = new ArrayList<>();
    for (int index = 0; index < goals.size(); index++) {
      if (index == treeIndex) {
        prepared.add(injectedGoal);
      }
      prepared.add(goals.get(index));
    }
    return List.copyOf(prepared);
  }
}
