// WHY: Connects Maven's project-read callback to the standalone tree preparation flow.

package io.github.spockz.elider.plugin;

import java.util.Properties;
import javax.inject.Named;
import javax.inject.Singleton;
import org.apache.maven.AbstractMavenLifecycleParticipant;
import org.apache.maven.MavenExecutionException;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.model.Build;
import org.apache.maven.model.Plugin;
import org.apache.maven.model.PluginExecution;
import org.apache.maven.project.MavenProject;
import org.codehaus.plexus.util.xml.Xpp3Dom;

/** Schedules configured elision before eligible standalone tree requests. */
@Named
@Singleton
public final class EliderLifecycleParticipant extends AbstractMavenLifecycleParticipant {
  /** Number of goals required to safely rebind an execution. */
  private static final int SINGLE_GOAL_COUNT = 1;

  /** Required for Maven's component instantiation. */
  public EliderLifecycleParticipant() {
    super();
  }

  @Override
  public void afterProjectsRead(final MavenSession session) throws MavenExecutionException {
    rebindProductionBytecodeExecutions(session);
    EliderTreePreparation.schedule(session);
  }

  // WHY: Rebinding must fail closed when an execution cannot move by itself.
  @SuppressWarnings({"PMD.CognitiveComplexity", "PMD.CyclomaticComplexity"})
  private static void rebindProductionBytecodeExecutions(final MavenSession session)
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
        if (!execution.getGoals().contains("elide")
            || !(execution.getPhase() == null
                || execution.getPhase().isBlank()
                || "initialize".equals(execution.getPhase()))) {
          continue;
        }
        if (!"initialize".equals(EliderPluginConfiguration.effectivePhase(execution, project))) {
          continue;
        }
        if (!productionClassesComplete(session, project, plugin, execution)
            || sourceRootsComplete(session, project, plugin, execution)) {
          continue;
        }
        if (execution.getGoals().size() != SINGLE_GOAL_COUNT) {
          throw new MavenExecutionException(
              "Cannot rebind dependency-elider execution "
                  + execution.getId()
                  + " because it combines elide with other goals",
              project.getFile());
        }
        execution.setPhase("process-classes");
      }
    }
  }

  private static boolean productionClassesComplete(
      final MavenSession session,
      final MavenProject project,
      final Plugin plugin,
      final PluginExecution execution) {
    return effectiveBoolean(
        session,
        project,
        plugin,
        execution,
        "elide.productionClassesComplete",
        "productionClassesComplete");
  }

  private static boolean sourceRootsComplete(
      final MavenSession session,
      final MavenProject project,
      final Plugin plugin,
      final PluginExecution execution) {
    return effectiveBoolean(
        session, project, plugin, execution, "elide.sourceRootsComplete", "sourceRootsComplete");
  }

  private static boolean effectiveBoolean(
      final MavenSession session,
      final MavenProject project,
      final Plugin plugin,
      final PluginExecution execution,
      final String propertyName,
      final String configurationName) {
    final Properties interpolationProperties = new Properties();
    interpolationProperties.putAll(project.getProperties());
    if (session.getSystemProperties() != null) {
      interpolationProperties.putAll(session.getSystemProperties());
    }
    if (session.getUserProperties() != null) {
      interpolationProperties.putAll(session.getUserProperties());
    }
    final String executionValue =
        configurationValue(
            execution.getConfiguration(), configurationName, interpolationProperties);
    if (executionValue != null) {
      return Boolean.parseBoolean(executionValue);
    }
    final String pluginValue =
        configurationValue(plugin.getConfiguration(), configurationName, interpolationProperties);
    if (pluginValue != null) {
      return Boolean.parseBoolean(pluginValue);
    }
    for (final Properties source :
        new Properties[] {
          session.getUserProperties(), session.getSystemProperties(), project.getProperties()
        }) {
      if (source == null) {
        continue;
      }
      final String propertyValue = source.getProperty(propertyName);
      if (propertyValue != null) {
        return Boolean.parseBoolean(propertyValue.trim());
      }
    }
    return false;
  }

  private static String configurationValue(
      final Object configuration, final String name, final Properties properties) {
    if (!(configuration instanceof Xpp3Dom root)) {
      return null;
    }
    final Xpp3Dom child = root.getChild(name);
    if (child == null || child.getValue() == null) {
      return null;
    }
    String value = child.getValue().trim();
    for (int iteration = 0; iteration < properties.size(); iteration++) {
      final int start = value.indexOf("${");
      if (start < 0) {
        break;
      }
      final int end = value.indexOf('}', start + 2);
      if (end < 0) {
        return null;
      }
      final String replacement = properties.getProperty(value.substring(start + 2, end));
      if (replacement == null) {
        return null;
      }
      value = value.substring(0, start) + replacement + value.substring(end + 1);
    }
    return value.contains("${") ? null : value;
  }
}
