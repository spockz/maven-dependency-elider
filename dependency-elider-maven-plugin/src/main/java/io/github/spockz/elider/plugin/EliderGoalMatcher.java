// WHY: Normalizes Maven goal spellings used to detect tree and configured elide requests.

package io.github.spockz.elider.plugin;

import java.util.List;
import java.util.Objects;
import org.apache.maven.model.Plugin;
import org.apache.maven.model.PluginExecution;

@SuppressWarnings({"PMD.CommentDefaultAccessModifier", "PMD.CommentRequired"})
final class EliderGoalMatcher {
  private static final String DEPENDENCY_PLUGIN_GROUP_ID = "org.apache.maven.plugins";
  private static final String DEPENDENCY_PLUGIN_ARTIFACT_ID = "maven-dependency-plugin";
  private static final String CLEAN_PLUGIN_ARTIFACT_ID = "maven-clean-plugin";
  private static final String DEPENDENCY_PLUGIN_PREFIX = "dependency";
  private static final String CLEAN_PLUGIN_PREFIX = "clean";
  private static final String ELIDER_PLUGIN_PREFIX = "dependency-elider";
  private static final String ELIDER_GROUP_ID = "io.github.spockz";
  private static final String ELIDER_ARTIFACT_ID = "dependency-elider-maven-plugin";
  private static final String ELIDE_GOAL = "elide";
  private static final String TREE_GOAL = "tree";
  private static final String CLEAN_GOAL = "clean";
  private static final int PREFIX_GOAL_COMPONENTS = 2;
  private static final int UNVERSIONED_COORDINATE_COMPONENTS = 3;
  private static final int VERSIONED_COORDINATE_COMPONENTS = 4;

  private EliderGoalMatcher() {}

  static boolean containsTreeGoal(final List<String> goals) {
    for (final String goal : goals) {
      if (isTreeGoal(goal)) {
        return true;
      }
    }
    return false;
  }

  static boolean isTreeGoal(final String goal) {
    return isGoal(goal, DEPENDENCY_PLUGIN_PREFIX, DEPENDENCY_PLUGIN_ARTIFACT_ID, TREE_GOAL);
  }

  static boolean isCleanGoal(final String goal) {
    return CLEAN_GOAL.equals(goal)
        || isGoal(goal, CLEAN_PLUGIN_PREFIX, CLEAN_PLUGIN_ARTIFACT_ID, CLEAN_GOAL);
  }

  static boolean isConfiguredElideGoal(
      final String goal, final Plugin plugin, final PluginExecution execution) {
    if (goal == null || execution.getId() == null) {
      return false;
    }
    final String[] selected = goal.split("@", 2);
    if (selected.length != PREFIX_GOAL_COMPONENTS || !execution.getId().equals(selected[1])) {
      return false;
    }
    final String[] parts = selected[0].split(":", -1);
    if (parts.length == PREFIX_GOAL_COMPONENTS) {
      return ELIDER_PLUGIN_PREFIX.equals(parts[0]) && ELIDE_GOAL.equals(parts[1]);
    }
    if (parts.length == UNVERSIONED_COORDINATE_COMPONENTS) {
      return ELIDE_GOAL.equals(parts[2])
          && ELIDER_GROUP_ID.equals(parts[0])
          && ELIDER_ARTIFACT_ID.equals(parts[1]);
    }
    return parts.length == VERSIONED_COORDINATE_COMPONENTS
        && ELIDE_GOAL.equals(parts[3])
        && Objects.equals(plugin.getGroupId(), parts[0])
        && Objects.equals(plugin.getArtifactId(), parts[1])
        && Objects.equals(plugin.getVersion(), parts[2]);
  }

  static String configuredElideGoal(final Plugin plugin, final PluginExecution execution) {
    return plugin.getGroupId()
        + ":"
        + plugin.getArtifactId()
        + ":"
        + plugin.getVersion()
        + ":"
        + ELIDE_GOAL
        + "@"
        + execution.getId();
  }

  private static boolean isGoal(
      final String goal, final String prefix, final String artifactId, final String goalName) {
    if (goal == null) {
      return false;
    }
    final String selected = goal.split("@", 2)[0];
    final String[] parts = selected.split(":", -1);
    if (parts.length == PREFIX_GOAL_COMPONENTS) {
      return goalName.equals(parts[1]) && prefix.equals(parts[0]);
    }
    if (parts.length == UNVERSIONED_COORDINATE_COMPONENTS) {
      return goalName.equals(parts[2])
          && (isPluginCoordinate(parts[0], parts[1], artifactId)
              || prefix.equals(parts[0]) && !parts[1].isBlank());
    }
    return parts.length == VERSIONED_COORDINATE_COMPONENTS
        && goalName.equals(parts[3])
        && !parts[2].isBlank()
        && isPluginCoordinate(parts[0], parts[1], artifactId);
  }

  private static boolean isPluginCoordinate(
      final String groupId, final String candidateArtifact, final String artifactId) {
    return DEPENDENCY_PLUGIN_GROUP_ID.equals(groupId) && artifactId.equals(candidateArtifact)
        || ELIDER_GROUP_ID.equals(groupId) && artifactId.equals(candidateArtifact);
  }
}
