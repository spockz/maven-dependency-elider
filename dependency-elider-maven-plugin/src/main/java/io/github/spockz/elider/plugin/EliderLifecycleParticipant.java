// WHY: Connects Maven's project-read callback to the standalone tree preparation flow.

package io.github.spockz.elider.plugin;

import java.util.List;
import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;
import org.apache.maven.AbstractMavenLifecycleParticipant;
import org.apache.maven.MavenExecutionException;
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
  public void afterProjectsRead(final MavenSession session) throws MavenExecutionException {
    MavenOriginalInputAudit.markHookPresent(session);
    assignDefaultElidePhases(session);
    EliderTreePreparation.schedule(session);
    new BanishedDependencyLifecycleActivation(
            mavenPluginManager, pluginPrefixResolver, pluginVersionResolver)
        .activate(session);
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
