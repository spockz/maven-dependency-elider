// WHY: Verifies automatic dependency:tree preparation, clean ordering, and reactor guards.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.util.List;
import org.apache.maven.MavenExecutionException;
import org.apache.maven.execution.DefaultMavenExecutionRequest;
import org.apache.maven.execution.MavenExecutionRequest;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.model.Build;
import org.apache.maven.model.Plugin;
import org.apache.maven.model.PluginExecution;
import org.apache.maven.project.MavenProject;
import org.apache.maven.repository.internal.MavenRepositorySystemUtils;
import org.eclipse.aether.DefaultRepositorySystemSession;
import org.junit.jupiter.api.Test;

/** Unit tests for {@link EliderTreePreparation}. */
@SuppressWarnings({"PMD.AtLeastOneConstructor", "PMD.AvoidDuplicateLiterals"})
final class EliderTreePreparationTest {
  /** Short CLI invocation of dependency:tree. */
  private static final String SHORT_TREE_GOAL = "dependency:tree";

  /** Package lifecycle phase. */
  private static final String PACKAGE_PHASE = "package";

  /** Clean lifecycle goal. */
  private static final String CLEAN_GOAL = "clean";

  /** Initialize lifecycle phase. */
  private static final String INITIALIZE_PHASE = "initialize";

  /** Process-classes lifecycle phase. */
  private static final String PROCESS_CLASSES_PHASE = "process-classes";

  @Test
  void cleanAfterEarlierPackageFailsInsteadOfReusingInvalidatedOutputs() {
    final MavenSession session =
        session(
            List.of(elideProject("consumer", PROCESS_CLASSES_PHASE)),
            List.of(PACKAGE_PHASE, CLEAN_GOAL, SHORT_TREE_GOAL));

    assertThatThrownBy(() -> EliderTreePreparation.schedule(session))
        .isInstanceOf(MavenExecutionException.class)
        .hasMessageContaining(
            "Cannot prepare dependency:tree after clean invalidated earlier lifecycle outputs");
  }

  @Test
  void cleanAfterEarlierTreeIsRejectedEvenWhenPackagePrecedesTree() {
    final MavenSession session =
        session(
            List.of(elideProject("consumer", PROCESS_CLASSES_PHASE)),
            List.of(PACKAGE_PHASE, SHORT_TREE_GOAL, CLEAN_GOAL, PACKAGE_PHASE));

    assertThatThrownBy(() -> EliderTreePreparation.schedule(session))
        .isInstanceOf(MavenExecutionException.class)
        .hasMessageContaining(
            "Cannot combine automatic dependency:tree preparation with a later clean goal");
  }

  @Test
  void cleanAfterTreeBeforePackageFailsBeforeGoalRewrite() {
    final MavenSession session =
        session(
            List.of(elideProject("consumer", PROCESS_CLASSES_PHASE)),
            List.of(SHORT_TREE_GOAL, CLEAN_GOAL, PACKAGE_PHASE));

    assertThatThrownBy(() -> EliderTreePreparation.schedule(session))
        .isInstanceOf(MavenExecutionException.class)
        .hasMessageContaining(
            "Cannot combine automatic dependency:tree preparation with a later clean goal");
  }

  @Test
  void treeAutoPreparationRejectsAnyMultiProjectReactor() {
    final MavenProject sibling = new MavenProject();
    sibling.setGroupId("fixture");
    sibling.setArtifactId("reactor");
    sibling.setVersion("1.0.0");
    sibling.setPackaging("pom");
    final MavenSession session =
        session(
            List.of(sibling, elideProject("consumer", PROCESS_CLASSES_PHASE)),
            List.of(SHORT_TREE_GOAL));

    assertThatThrownBy(() -> EliderTreePreparation.schedule(session))
        .isInstanceOf(MavenExecutionException.class)
        .hasMessageContaining(
            "Automatic dependency:tree preparation does not support multi-project Maven reactors");
  }

  @Test
  void alreadyPreparedTreeRequestDoesNotAddAnotherElideExecution() throws Exception {
    final MavenExecutionRequest initializeRequest =
        request(List.of(INITIALIZE_PHASE, SHORT_TREE_GOAL));
    final MavenSession initializeSession =
        session(initializeRequest, List.of(elideProject("consumer-init", INITIALIZE_PHASE)));
    final MavenExecutionRequest processClassesRequest =
        request(List.of(PROCESS_CLASSES_PHASE, SHORT_TREE_GOAL));
    final MavenSession processClassesSession =
        session(
            processClassesRequest,
            List.of(elideProject("consumer-process", PROCESS_CLASSES_PHASE)));

    EliderTreePreparation.schedule(initializeSession);
    EliderTreePreparation.schedule(processClassesSession);

    assertAll(
        () ->
            assertThat(initializeRequest.getGoals())
                .containsExactly(INITIALIZE_PHASE, SHORT_TREE_GOAL),
        () ->
            assertThat(processClassesRequest.getGoals())
                .containsExactly(PROCESS_CLASSES_PHASE, SHORT_TREE_GOAL));
  }

  @Test
  void ordinaryTestLifecycleDoesNotTriggerTreePreparation() throws Exception {
    final MavenExecutionRequest request = request(List.of("test"));
    final MavenSession session =
        session(request, List.of(elideProject("consumer", PROCESS_CLASSES_PHASE)));

    EliderTreePreparation.schedule(session);

    assertAll(
        () -> assertThat(request.getGoals()).containsExactly("test"),
        () ->
            assertThat(
                    EliderPreparationState.sessionData(session)
                        .get(EliderPreparationState.PREPARATION_STATE_KEY))
                .isNull());
  }

  private static MavenExecutionRequest request(final List<String> goals) {
    final MavenExecutionRequest request = new DefaultMavenExecutionRequest();
    request.setGoals(goals);
    return request;
  }

  private static MavenSession session(final List<MavenProject> projects, final List<String> goals) {
    return session(request(goals), projects);
  }

  private static MavenSession session(
      final MavenExecutionRequest request, final List<MavenProject> projects) {
    final DefaultRepositorySystemSession repoSession = MavenRepositorySystemUtils.newSession();
    final MavenSession session = new MavenSession(null, repoSession, request, null);
    session.setProjects(projects);
    return session;
  }

  private static MavenProject elideProject(final String artifactId, final String phase) {
    final MavenProject project = new MavenProject();
    project.setGroupId("fixture");
    project.setArtifactId(artifactId);
    project.setVersion("1.0.0");

    final PluginExecution execution = new PluginExecution();
    execution.setId("run-elider");
    execution.setPhase(phase);
    execution.setGoals(List.of(EliderPluginCoordinates.ELIDE_GOAL));

    final Plugin plugin = new Plugin();
    plugin.setGroupId(EliderPluginCoordinates.GROUP_ID);
    plugin.setArtifactId(EliderPluginCoordinates.ARTIFACT_ID);
    plugin.setVersion("0.1.0-SNAPSHOT");
    plugin.setExecutions(List.of(execution));

    final Build build = new Build();
    build.setPlugins(List.of(plugin));
    project.setBuild(build);
    return project;
  }
}
