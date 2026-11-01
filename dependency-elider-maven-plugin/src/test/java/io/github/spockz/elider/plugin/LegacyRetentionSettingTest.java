// WHY: Verifies every Maven input surface that could silently preserve the old draft setting.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Properties;
import org.apache.maven.execution.DefaultMavenExecutionRequest;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.model.Build;
import org.apache.maven.model.Plugin;
import org.apache.maven.model.PluginExecution;
import org.apache.maven.plugin.MojoExecution;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.project.MavenProject;
import org.codehaus.plexus.util.xml.Xpp3Dom;
import org.junit.jupiter.api.Test;

/** Verifies explicit rejection of the obsolete retention setting. */
@SuppressWarnings("PMD.TooManyMethods")
final class LegacyRetentionSettingTest {
  /** XML element name used for Maven plugin configuration DOMs. */
  private static final String CONFIGURATION_ELEMENT = "configuration";

  /** Deprecated Maven property accepted only by the rejection assertion. */
  private static final String LEGACY_PROPERTY = "elide.excludedArtifacts";

  /** XML element name retained only to prove rejection of the old draft setting. */
  private static final String LEGACY_ELEMENT = "excludedArtifacts";

  /** Goal name used while constructing representative Mojo executions. */
  private static final String ELIDE_GOAL = "elide";

  /** Default execution id used for direct-goal Mojo fixtures. */
  private static final String DEFAULT_EXECUTION_ID = "default";

  /** Current XML parameter name used by the unrelated no-legacy control. */
  private static final String RETENTION_ELEMENT = "retainedArtifacts";

  /** Shared diagnostic that identifies the only supported migration path. */
  private static final String LEGACY_REJECTION_MESSAGE =
      "elide.excludedArtifacts is obsolete; use elide.retainedArtifacts instead";

  /** Required explicit constructor for the repository's test-class PMD rule. */
  @SuppressWarnings({"PMD.CommentDefaultAccessModifier", "PMD.UncommentedEmptyConstructor"})
  LegacyRetentionSettingTest() {}

  @Test
  void rejectsLegacyPropertyFromMavenRequest() {
    final Properties userProperties = new Properties();
    userProperties.setProperty(LEGACY_PROPERTY, "org.example:legacy");
    final DefaultMavenExecutionRequest request = new DefaultMavenExecutionRequest();
    request.setUserProperties(userProperties);
    final MavenSession session = new MavenSession(null, request, null, new MavenProject());

    assertThatThrownBy(() -> LegacyRetentionSetting.rejectIfConfigured(null, session, null))
        .isInstanceOf(MojoFailureException.class)
        .hasMessageContaining(LEGACY_REJECTION_MESSAGE)
        .hasMessageContaining("elide.retainedArtifacts");
  }

  @Test
  void rejectsLegacyPropertyFromProjectProperties() {
    final MavenProject project = new MavenProject();
    project.getProperties().setProperty(LEGACY_PROPERTY, "org.example:legacy");

    assertThatThrownBy(() -> LegacyRetentionSetting.rejectIfConfigured(project, null, null))
        .isInstanceOf(MojoFailureException.class)
        .hasMessageContaining(LEGACY_REJECTION_MESSAGE);
  }

  @Test
  void rejectsLegacyPomConfigurationElement() {
    final Xpp3Dom configuration = new Xpp3Dom(CONFIGURATION_ELEMENT);
    configuration.addChild(new Xpp3Dom(LEGACY_ELEMENT));
    final MojoExecution execution = new MojoExecution(null, ELIDE_GOAL, DEFAULT_EXECUTION_ID);
    execution.setConfiguration(configuration);

    assertThatThrownBy(() -> LegacyRetentionSetting.rejectIfConfigured(null, null, execution))
        .isInstanceOf(MojoFailureException.class)
        .hasMessageContaining(LEGACY_REJECTION_MESSAGE);
  }

  @Test
  void rejectsLegacyConfigurationRetainedOnEffectiveProjectPlugin() {
    final Plugin plugin = new Plugin();
    plugin.setGroupId("io.github.spockz");
    plugin.setArtifactId("dependency-elider-maven-plugin");
    final Xpp3Dom configuration = new Xpp3Dom(CONFIGURATION_ELEMENT);
    configuration.addChild(new Xpp3Dom(LEGACY_ELEMENT));
    plugin.setConfiguration(configuration);
    final Build build = new Build();
    build.addPlugin(plugin);
    final MavenProject project = new MavenProject();
    project.setBuild(build);
    final MojoExecution execution = new MojoExecution(plugin, ELIDE_GOAL, "default-cli");
    execution.setConfiguration(new Xpp3Dom(CONFIGURATION_ELEMENT));

    assertThatThrownBy(() -> LegacyRetentionSetting.rejectIfConfigured(project, null, execution))
        .isInstanceOf(MojoFailureException.class)
        .hasMessageContaining(LEGACY_REJECTION_MESSAGE);
  }

  @Test
  void rejectsLegacyConfigurationRetainedOnActiveProjectExecution() {
    final Plugin plugin = new Plugin();
    plugin.setGroupId("io.github.spockz");
    plugin.setArtifactId("dependency-elider-maven-plugin");
    final PluginExecution configuredExecution = new PluginExecution();
    configuredExecution.setId("elider");
    final Xpp3Dom configuration = new Xpp3Dom(CONFIGURATION_ELEMENT);
    configuration.addChild(new Xpp3Dom(LEGACY_ELEMENT));
    configuredExecution.setConfiguration(configuration);
    plugin.addExecution(configuredExecution);
    final Build build = new Build();
    build.addPlugin(plugin);
    final MavenProject project = new MavenProject();
    project.setBuild(build);
    final MojoExecution execution = new MojoExecution(plugin, ELIDE_GOAL, "elider");
    execution.setConfiguration(new Xpp3Dom(CONFIGURATION_ELEMENT));

    assertThatThrownBy(() -> LegacyRetentionSetting.rejectIfConfigured(project, null, execution))
        .isInstanceOf(MojoFailureException.class)
        .hasMessageContaining(LEGACY_REJECTION_MESSAGE);
  }

  @Test
  void acceptsCurrentRetentionPropertyAndXmlElement() {
    final MavenProject project = new MavenProject();
    project.getProperties().setProperty("elide.retainedArtifacts", "org.example:current");
    final Xpp3Dom configuration = new Xpp3Dom(CONFIGURATION_ELEMENT);
    configuration.addChild(new Xpp3Dom(RETENTION_ELEMENT));
    final MojoExecution execution = new MojoExecution(null, ELIDE_GOAL, DEFAULT_EXECUTION_ID);
    execution.setConfiguration(configuration);

    assertThatCode(() -> LegacyRetentionSetting.rejectIfConfigured(project, null, execution))
        .doesNotThrowAnyException();
  }

  @Test
  void acceptsCurrentRetentionConfiguration() {
    final Properties userProperties = new Properties();
    userProperties.setProperty("elide.retainedArtifacts", "org.example:current");
    final DefaultMavenExecutionRequest request = new DefaultMavenExecutionRequest();
    request.setUserProperties(userProperties);
    final MavenSession session = new MavenSession(null, request, null, new MavenProject());
    final Xpp3Dom configuration = new Xpp3Dom(CONFIGURATION_ELEMENT);
    configuration.addChild(new Xpp3Dom(RETENTION_ELEMENT));
    final MojoExecution execution = new MojoExecution(null, ELIDE_GOAL, "default");
    execution.setConfiguration(configuration);

    assertThatCode(
            () -> LegacyRetentionSetting.rejectIfConfigured(new MavenProject(), session, execution))
        .doesNotThrowAnyException();
  }

  @Test
  void elideGoalRejectsLegacyUserProperty() throws ReflectiveOperationException {
    final ElideMojo mojo = new ElideMojo();
    final MavenProject project = new MavenProject();
    set(mojo, "project", project);
    set(mojo, "session", sessionWithLegacyUserProperty(project));

    assertThatThrownBy(mojo::execute)
        .isInstanceOf(MojoFailureException.class)
        .hasMessageContaining(LEGACY_REJECTION_MESSAGE);
  }

  @Test
  void analyzeGoalRejectsLegacyUserProperty() throws ReflectiveOperationException {
    final AnalyzeMojo mojo = new AnalyzeMojo();
    final MavenProject project = new MavenProject();
    set(mojo, "project", project);
    set(mojo, "session", sessionWithLegacyUserProperty(project));

    assertThatThrownBy(mojo::execute)
        .isInstanceOf(MojoFailureException.class)
        .hasMessageContaining(LEGACY_REJECTION_MESSAGE);
  }

  @Test
  void elideGoalRejectsLegacyXmlElement() throws ReflectiveOperationException {
    final ElideMojo mojo = new ElideMojo();
    set(mojo, "mojoExecution", executionWithLegacyXmlElement());

    assertThatThrownBy(mojo::execute)
        .isInstanceOf(MojoFailureException.class)
        .hasMessageContaining(LEGACY_REJECTION_MESSAGE);
  }

  @Test
  void analyzeGoalRejectsLegacyXmlElement() throws ReflectiveOperationException {
    final AnalyzeMojo mojo = new AnalyzeMojo();
    set(mojo, "mojoExecution", executionWithLegacyXmlElement());

    assertThatThrownBy(mojo::execute)
        .isInstanceOf(MojoFailureException.class)
        .hasMessageContaining(LEGACY_REJECTION_MESSAGE);
  }

  private static MavenSession sessionWithLegacyUserProperty(final MavenProject project) {
    final Properties userProperties = new Properties();
    userProperties.setProperty(LEGACY_PROPERTY, "org.example:legacy");
    final DefaultMavenExecutionRequest request = new DefaultMavenExecutionRequest();
    request.setUserProperties(userProperties);
    return new MavenSession(null, request, null, project);
  }

  private static MojoExecution executionWithLegacyXmlElement() {
    final Xpp3Dom configuration = new Xpp3Dom(CONFIGURATION_ELEMENT);
    configuration.addChild(new Xpp3Dom(LEGACY_ELEMENT));
    final MojoExecution execution = new MojoExecution(null, ELIDE_GOAL, "default");
    execution.setConfiguration(configuration);
    return execution;
  }

  @SuppressWarnings("PMD.AvoidAccessibilityAlteration")
  private static void set(final Object target, final String name, final Object value)
      throws ReflectiveOperationException {
    final java.lang.reflect.Field field = target.getClass().getDeclaredField(name);
    field.setAccessible(true);
    field.set(target, value);
  }
}
