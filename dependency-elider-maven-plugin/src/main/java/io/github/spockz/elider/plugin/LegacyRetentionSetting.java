// WHY: Fails clearly when users still configure the unreleased excludedArtifacts draft name.

package io.github.spockz.elider.plugin;

import java.util.Properties;
import org.apache.maven.execution.MavenExecutionRequest;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.model.Plugin;
import org.apache.maven.model.PluginExecution;
import org.apache.maven.plugin.MojoExecution;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.project.MavenProject;
import org.codehaus.plexus.util.xml.Xpp3Dom;

/** Rejects the obsolete global retention configuration name. */
final class LegacyRetentionSetting {
  /** Obsolete user-property name retained only for explicit rejection. */
  private static final String LEGACY_PROPERTY = "elide.excludedArtifacts";

  /** Obsolete mojo XML element retained only for explicit rejection. */
  private static final String LEGACY_ELEMENT = "excludedArtifacts";

  /** Identifies the plugin whose obsolete configuration must be rejected. */
  private static final String PLUGIN_GROUP_ID = "io.github.spockz";

  /** Identifies the plugin whose obsolete configuration must be rejected. */
  private static final String PLUGIN_ARTIFACT_ID = "dependency-elider-maven-plugin";

  private LegacyRetentionSetting() {}

  /* package */ static void rejectIfConfigured(
      final MavenProject project, final MavenSession session, final MojoExecution execution)
      throws MojoFailureException {
    if (hasLegacyProperty(project, session)
        || hasLegacyElement(execution)
        || hasLegacyPluginConfiguration(project, execution)) {
      throw new MojoFailureException(
          "elide.excludedArtifacts is obsolete; use elide.retainedArtifacts instead");
    }
  }

  @SuppressWarnings("PMD.LawOfDemeter")
  private static boolean hasLegacyProperty(final MavenProject project, final MavenSession session) {
    if (project != null && project.getProperties().containsKey(LEGACY_PROPERTY)) {
      return true;
    }
    if (System.getProperties().containsKey(LEGACY_PROPERTY)) {
      return true;
    }
    final MavenExecutionRequest request;
    if (session == null) {
      request = null;
    } else {
      request = session.getRequest();
    }
    return request != null
        && (contains(request.getUserProperties()) || contains(request.getSystemProperties()));
  }

  private static boolean contains(final Properties properties) {
    return properties != null && properties.containsKey(LEGACY_PROPERTY);
  }

  private static boolean hasLegacyElement(final Object configuration) {
    return configuration instanceof Xpp3Dom dom && dom.getChild(LEGACY_ELEMENT) != null;
  }

  private static boolean hasLegacyElement(final MojoExecution execution) {
    if (execution == null || execution.getConfiguration() == null) {
      return false;
    }
    return hasLegacyElement(execution.getConfiguration());
  }

  private static boolean hasLegacyPluginConfiguration(
      final MavenProject project, final MojoExecution execution) {
    if (project == null || execution == null || project.getBuildPlugins() == null) {
      return false;
    }
    final String executionId = execution.getExecutionId();
    for (final Plugin plugin : project.getBuildPlugins()) {
      if (isEliderPlugin(plugin)
          && (hasLegacyElement(plugin.getConfiguration())
              || hasLegacyExecutionConfiguration(plugin, executionId))) {
        return true;
      }
    }
    return false;
  }

  private static boolean isEliderPlugin(final Plugin plugin) {
    return PLUGIN_GROUP_ID.equals(plugin.getGroupId())
        && PLUGIN_ARTIFACT_ID.equals(plugin.getArtifactId());
  }

  private static boolean hasLegacyExecutionConfiguration(
      final Plugin plugin, final String executionId) {
    if (executionId == null) {
      return false;
    }
    for (final PluginExecution configuredExecution : plugin.getExecutions()) {
      if (executionId.equals(configuredExecution.getId())
          && hasLegacyElement(configuredExecution.getConfiguration())) {
        return true;
      }
    }
    return false;
  }
}
