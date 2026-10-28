// WHY: Carries one invocation's duplicate-suppression token across Maven extension realms.

package io.github.spockz.elider.plugin;

import java.util.Map;
import java.util.Objects;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.MojoExecution;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.SessionData;

@SuppressWarnings({"PMD.CommentDefaultAccessModifier", "PMD.CommentRequired", "PMD.LawOfDemeter"})
final class EliderPreparationState {
  static final String PREPARATION_STATE_KEY =
      EliderPreparationState.class.getName() + ".treePreparation";

  private static final String PREPARATION_PENDING = "pending";
  private static final String PREPARATION_READY = "ready";

  private EliderPreparationState() {}

  static Map<String, String> pending(final String executionId, final String projectId) {
    return Map.of("executionId", executionId, "projectId", projectId, "state", PREPARATION_PENDING);
  }

  static boolean consumePreparedLifecycleDuplicate(
      final MavenSession session,
      final String executionId,
      final String projectId,
      final MojoExecution.Source source) {
    if (source != MojoExecution.Source.LIFECYCLE || session == null) {
      return false;
    }
    final SessionData data = sessionData(session);
    while (true) {
      final Object state = data.get(PREPARATION_STATE_KEY);
      if (!matches(state, executionId, projectId, PREPARATION_READY)) {
        return false;
      }
      if (data.set(PREPARATION_STATE_KEY, state, null)) {
        return true;
      }
    }
  }

  static void completeInjectedCliPreparation(
      final MavenSession session,
      final String executionId,
      final String projectId,
      final MojoExecution.Source source) {
    if (source != MojoExecution.Source.CLI || session == null) {
      return;
    }
    final SessionData data = sessionData(session);
    while (true) {
      final Object state = data.get(PREPARATION_STATE_KEY);
      if (!matches(state, executionId, projectId, PREPARATION_PENDING)) {
        return;
      }
      if (data.set(
          PREPARATION_STATE_KEY,
          state,
          Map.of(
              "executionId", executionId,
              "projectId", projectId,
              "state", PREPARATION_READY))) {
        return;
      }
    }
  }

  @SuppressWarnings("PMD.LawOfDemeter")
  static MojoExecution.Source source(final MojoExecution execution) {
    return execution == null ? null : execution.getSource();
  }

  private static boolean matches(
      final Object state,
      final String executionId,
      final String projectId,
      final String expectedState) {
    if (!(state instanceof Map<?, ?> values)) {
      return false;
    }
    return Objects.equals(executionId, values.get("executionId"))
        && Objects.equals(projectId, values.get("projectId"))
        && expectedState.equals(values.get("state"));
  }

  static SessionData sessionData(final MavenSession session) {
    final RepositorySystemSession repositorySession = session.getRepositorySession();
    if (repositorySession == null) {
      throw new IllegalStateException("Maven session has no repository session data");
    }
    return repositorySession.getData();
  }
}
