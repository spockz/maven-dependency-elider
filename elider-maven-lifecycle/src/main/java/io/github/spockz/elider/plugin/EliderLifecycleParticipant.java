// WHY: Connects Maven's project-read callback to the standalone tree preparation flow.

package io.github.spockz.elider.plugin;

import java.util.List;
import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;
import org.apache.maven.AbstractMavenLifecycleParticipant;
import org.apache.maven.MavenExecutionException;
import org.apache.maven.execution.ExecutionListener;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.model.Build;
import org.apache.maven.model.Plugin;
import org.apache.maven.model.PluginExecution;
import org.apache.maven.plugin.MavenPluginManager;
import org.apache.maven.plugin.prefix.PluginPrefixResolver;
import org.apache.maven.plugin.version.PluginVersionResolver;
import org.apache.maven.project.MavenProject;

/** Schedules configured elision before eligible standalone tree requests. */
@Named
@Singleton
@SuppressWarnings({
  "PMD.AvoidInstantiatingObjectsInLoops",
  "PMD.CognitiveComplexity",
  "PMD.CyclomaticComplexity"
})
public final class EliderLifecycleParticipant extends AbstractMavenLifecycleParticipant {
  /** Number of goals required to assign an independent phase priority. */
  private static final int SINGLE_GOAL_COUNT = 1;

  /** Resolves goal descriptors without configuring or executing the selected Mojo. */
  @Inject private MavenPluginManager mavenPluginManager;

  /** Resolves Maven's configured prefix spelling for direct goal requests. */
  @Inject private PluginPrefixResolver pluginPrefixResolver;

  /** Resolves the selected plugin version when the project omits one. */
  @Inject private PluginVersionResolver pluginVersionResolver;

  /** Required for Maven's component instantiation. */
  public EliderLifecycleParticipant() {
    super();
  }

  @Override
  @SuppressWarnings("PMD.LawOfDemeter")
  public void afterSessionStart(final MavenSession session) {
    final ExecutionListener prior = session.getRequest().getExecutionListener();
    session.getRequest().setExecutionListener(new EliderTestViewExecutionListener(session, prior));
  }

  @Override
  public void afterProjectsRead(final MavenSession session) throws MavenExecutionException {
    MavenOriginalInputAudit.markHookPresent(session);
    assignDefaultElidePhases(session);
    scheduleTestViewPreparation(session);
    EliderTreePreparation.schedule(session);
    new BanishedDependencyLifecycleActivation(
            mavenPluginManager, pluginPrefixResolver, pluginVersionResolver)
        .activate(session);
    EliderValidateScheduling.schedule(session);
  }

  private static void assignDefaultElidePhases(final MavenSession session)
      throws MavenExecutionException {
    if (session.getProjects() == null) {
      return;
    }
    for (final MavenProject project : session.getProjects()) {
      final Build build = project.getBuild();
      if (build == null) {
        continue;
      }
      final Plugin plugin =
          build.getPluginsAsMap().get("io.github.spockz:dependency-elider-maven-plugin");
      if (plugin == null) {
        continue;
      }
      for (final PluginExecution execution : plugin.getExecutions()) {
        applyDefaultPhase(execution, project);
      }
      if (plugin.getExecutions().stream()
          .anyMatch(
              e -> "process-classes".equals(e.getPhase()) && e.getGoals().contains("elide"))) {
        final List<Plugin> plugins = build.getPlugins();
        if (plugins.remove(plugin)) {
          plugins.add(plugin);
        }
      }
    }
  }

  private static void scheduleTestViewPreparation(final MavenSession session)
      throws MavenExecutionException {
    if (session.getProjects() == null) {
      return;
    }
    for (final MavenProject project : session.getProjects()) {
      if (!EliderTestViewPlan.requested(session, project) || project.getBuild() == null) {
        continue;
      }
      final Plugin plugin =
          project
              .getBuild()
              .getPluginsAsMap()
              .get("io.github.spockz:dependency-elider-maven-plugin");
      if (plugin == null) {
        continue;
      }
      final List<PluginExecution> elideExecutions =
          plugin.getExecutions().stream().filter(e -> e.getGoals().contains("elide")).toList();
      if (elideExecutions.isEmpty()) {
        continue;
      }
      for (final PluginExecution execution : elideExecutions) {
        if (!List.of("initialize", "process-classes").contains(execution.getPhase())) {
          throw EliderPluginConfiguration.failure(
              project,
              "Test additions require dependency-elider:elide at initialize or process-classes");
        }
      }
      if (plugin.getExecutions().stream()
          .anyMatch(
              e ->
                  "dependency-elider-test-view".equals(e.getId())
                      || e.getGoals().contains("prepare-test-view"))) {
        throw EliderPluginConfiguration.failure(
            project, "Test additions already have a prepare-test-view execution");
      }
      final PluginExecution preparation = new PluginExecution();
      preparation.setId("dependency-elider-test-view");
      preparation.setPhase("process-test-classes");
      preparation.addGoal("prepare-test-view");
      plugin.addExecution(preparation);
    }
  }

  // The default access modifier keeps lifecycle ordering internal to the plugin.
  // WHY: This callback changes only executions using the modeled default phase.
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  static void applyDefaultPhase(final PluginExecution execution, final MavenProject project)
      throws MavenExecutionException {
    if (!execution.getGoals().contains("elide")) {
      return;
    }
    final boolean omittedPhase = execution.getPhase() == null || execution.getPhase().isBlank();
    if (!omittedPhase && !"process-classes".equals(execution.getPhase())) {
      return;
    }
    final String phase = EliderPluginConfiguration.effectivePhase(execution, project);
    if (execution.getGoals().size() != SINGLE_GOAL_COUNT) {
      throw new MavenExecutionException(
          "Cannot assign the process-classes phase priority to dependency-elider execution "
              + execution.getId()
              + " because it combines elide with other goals",
          project.getFile());
    }
    if (omittedPhase) {
      execution.setPhase(phase);
    }
    execution.setPriority(Integer.MAX_VALUE);
  }
}
