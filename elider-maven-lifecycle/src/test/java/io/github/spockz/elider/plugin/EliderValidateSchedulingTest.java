/* WHY: Ensures elide-configured builds schedule lightweight config validation in validate. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.util.List;
import org.apache.maven.execution.DefaultMavenExecutionRequest;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.model.Build;
import org.apache.maven.model.Plugin;
import org.apache.maven.model.PluginExecution;
import org.apache.maven.project.MavenProject;
import org.codehaus.plexus.util.xml.Xpp3Dom;
import org.junit.jupiter.api.Test;

/** Tests automatic validate-phase scheduling for projects binding {@code elide}. */
@SuppressWarnings("PMD.AtLeastOneConstructor")
final class EliderValidateSchedulingTest {
  /** Elide goal name. */
  private static final String ELIDE_GOAL = "elide";

  /** Validate goal name. */
  private static final String VALIDATE_GOAL = "validate";

  /** Validate phase name. */
  private static final String VALIDATE_PHASE = "validate";

  @Test
  void schedulesValidateExecutionForElideProjectAndCopiesExecutionConfig() {
    final Xpp3Dom elideConfig = new Xpp3Dom("configuration");
    final Xpp3Dom workers = new Xpp3Dom("trimWorkers");
    workers.setValue("2");
    elideConfig.addChild(workers);

    final PluginExecution elideExecution = new PluginExecution();
    elideExecution.setId("run-elider");
    elideExecution.setPhase("process-classes");
    elideExecution.setGoals(List.of(ELIDE_GOAL));
    elideExecution.setConfiguration(elideConfig);

    final Plugin plugin = eliderPlugin(List.of(elideExecution));
    final MavenProject project = projectWithPlugin(plugin);
    final MavenSession session = sessionWithProjects(project);

    EliderValidateScheduling.schedule(session);

    final List<PluginExecution> validateExecutions =
        plugin.getExecutions().stream()
            .filter(execution -> execution.getGoals().contains(VALIDATE_GOAL))
            .toList();
    assertAll(
        "auto-scheduled validate execution",
        () -> assertThat(validateExecutions).hasSize(1),
        () -> {
          final PluginExecution scheduled = validateExecutions.getFirst();
          assertAll(
              () -> assertThat(scheduled.getPhase()).isEqualTo(VALIDATE_PHASE),
              () -> assertThat(scheduled.getGoals()).containsExactly(VALIDATE_GOAL),
              () -> assertThat(scheduled.getConfiguration()).isSameAs(elideConfig));
        });
  }

  @Test
  void doesNotDuplicateExistingValidateExecution() {
    final PluginExecution existingValidate = new PluginExecution();
    existingValidate.setId("custom-validate");
    existingValidate.setPhase(VALIDATE_PHASE);
    existingValidate.setGoals(List.of(VALIDATE_GOAL));

    final PluginExecution elideExecution = new PluginExecution();
    elideExecution.setId("run-elider");
    elideExecution.setGoals(List.of(ELIDE_GOAL));

    final Plugin plugin = eliderPlugin(List.of(existingValidate, elideExecution));
    final MavenSession session = sessionWithProjects(projectWithPlugin(plugin));

    EliderValidateScheduling.schedule(session);

    assertThat(plugin.getExecutions()).containsExactly(existingValidate, elideExecution);
  }

  @Test
  void skipsProjectsWithoutElideExecution() {
    final PluginExecution analyzeExecution = new PluginExecution();
    analyzeExecution.setId("analyze-only");
    analyzeExecution.setGoals(List.of("analyze"));

    final Plugin plugin = eliderPlugin(List.of(analyzeExecution));
    final MavenProject withoutPlugin = new MavenProject();
    final MavenSession session = sessionWithProjects(projectWithPlugin(plugin), withoutPlugin);

    EliderValidateScheduling.schedule(session);

    assertThat(plugin.getExecutions()).containsExactly(analyzeExecution);
  }

  @Test
  void schedulesDistinctValidateIdsForMultipleElideExecutions() {
    final PluginExecution first = new PluginExecution();
    first.setId("first-elide");
    first.setGoals(List.of(ELIDE_GOAL));

    final PluginExecution second = new PluginExecution();
    second.setId("second-elide");
    second.setGoals(List.of(ELIDE_GOAL));

    final Plugin plugin = eliderPlugin(List.of(first, second));
    final MavenSession session = sessionWithProjects(projectWithPlugin(plugin));

    EliderValidateScheduling.schedule(session);

    final List<PluginExecution> validateExecutions =
        plugin.getExecutions().stream()
            .filter(execution -> execution.getGoals().contains(VALIDATE_GOAL))
            .toList();
    assertAll(
        () -> assertThat(validateExecutions).hasSize(2),
        () ->
            assertThat(validateExecutions)
                .extracting(PluginExecution::getId)
                .doesNotHaveDuplicates());
  }

  private static Plugin eliderPlugin(final List<PluginExecution> executions) {
    final Plugin plugin = new Plugin();
    plugin.setGroupId(EliderPluginCoordinates.GROUP_ID);
    plugin.setArtifactId(EliderPluginCoordinates.ARTIFACT_ID);
    executions.forEach(plugin::addExecution);
    return plugin;
  }

  private static MavenProject projectWithPlugin(final Plugin plugin) {
    final Build build = new Build();
    build.addPlugin(plugin);
    final MavenProject project = new MavenProject();
    project.setBuild(build);
    return project;
  }

  private static MavenSession sessionWithProjects(final MavenProject... projects) {
    final MavenSession session =
        new MavenSession(null, new DefaultMavenExecutionRequest(), null, projects[0]);
    session.setProjects(List.of(projects));
    return session;
  }
}
