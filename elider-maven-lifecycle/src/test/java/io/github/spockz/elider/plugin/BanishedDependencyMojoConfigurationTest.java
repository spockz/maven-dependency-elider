// WHY: Proves selected ban configuration follows Maven expression and Plexus list conversion.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.util.List;
import java.util.Properties;
import org.apache.maven.execution.DefaultMavenExecutionRequest;
import org.apache.maven.execution.MavenExecutionRequest;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.model.Model;
import org.apache.maven.plugin.MojoExecution;
import org.apache.maven.plugin.descriptor.MojoDescriptor;
import org.apache.maven.project.MavenProject;
import org.codehaus.plexus.configuration.DefaultPlexusConfiguration;
import org.codehaus.plexus.util.xml.Xpp3Dom;
import org.junit.jupiter.api.Test;

/** Tests Maven policy expression and list conversion. */
@SuppressWarnings({"PMD.AtLeastOneConstructor", "PMD.TooManyMethods"})
final class BanishedDependencyMojoConfigurationTest {
  /** Project property key used by the plugin descriptor. */
  private static final String BAN_PROPERTY = "elide.banishedDependencies";

  /** Descriptor expression that resolves the selected policy property. */
  private static final String BAN_PROPERTY_EXPRESSION = "${elide.banishedDependencies}";

  /** Parameter name used by the plugin descriptor. */
  private static final String BAN_PARAMETER = "banishedDependencies";

  @Test
  void descriptorPropertyTextUsesMavenCollectionCsvEvaluation() {
    final MavenSession session = session(properties(BAN_PROPERTY, "g:a,h:i"));
    final MojoExecution execution = execution(BAN_PROPERTY_EXPRESSION, null);

    final List<String> actual =
        BanishedDependencyMojoConfiguration.banishedDependencies(session, execution);

    assertThat(actual).containsExactly("g:a", "h:i");
  }

  @Test
  void configuredParentTextReplacesXmlChildrenAfterDescriptorMerge() {
    final MavenSession session = session(properties(BAN_PROPERTY, "p:q"));
    final Xpp3Dom configured = new Xpp3Dom(BAN_PARAMETER);
    final Xpp3Dom child = new Xpp3Dom("banishedDependency");
    child.setValue("child:only");
    configured.addChild(child);
    final MojoExecution execution = execution(BAN_PROPERTY_EXPRESSION, configured);

    final List<String> actual =
        BanishedDependencyMojoConfiguration.banishedDependencies(session, execution);

    assertThat(actual).containsExactly("p:q");
  }

  @Test
  void systemPropertyWinsUserPropertyAndExplicitEmptyPropertyIsEmpty() {
    final MavenExecutionRequest request = new DefaultMavenExecutionRequest();
    request.setUserProperties(properties(BAN_PROPERTY, "user:value"));
    request.setSystemProperties(properties(BAN_PROPERTY, "system:value"));
    final MavenProject project = project();
    project.getProperties().setProperty(BAN_PROPERTY, "project:value");
    final MavenSession session = new MavenSession(null, request, null, project);
    final MojoExecution execution = execution("${elide.banishedDependencies}", null);
    final MavenSession emptySession = session(properties(BAN_PROPERTY, ""));

    final List<String> actual =
        BanishedDependencyMojoConfiguration.banishedDependencies(session, execution);
    final List<String> empty =
        BanishedDependencyMojoConfiguration.banishedDependencies(
            emptySession, execution(BAN_PROPERTY_EXPRESSION, null));

    assertAll(
        "Maven properties and explicit empty configuration retain their distinct meanings",
        () -> assertThat(actual).containsExactly("system:value"),
        () -> assertThat(empty).isEmpty());
  }

  @Test
  void projectPropertyIsUsedWhenNoUserOrSystemPropertyOverridesIt() {
    final MavenProject project = project();
    project.getProperties().setProperty(BAN_PROPERTY, "project:value");
    final MavenExecutionRequest request = new DefaultMavenExecutionRequest();
    final MavenSession session = new MavenSession(null, request, null, project);
    final MojoExecution execution = execution(BAN_PROPERTY_EXPRESSION, null);

    final List<String> actual =
        BanishedDependencyMojoConfiguration.banishedDependencies(session, execution);

    assertThat(actual).containsExactly("project:value");
  }

  @Test
  void unresolvedExplicitPropertyFailsClosed() {
    final MavenSession session = session(new Properties());
    final Xpp3Dom configured = new Xpp3Dom(BAN_PARAMETER);
    configured.setValue("${missing.explicit.property}");
    final MojoExecution execution = execution(BAN_PROPERTY_EXPRESSION, configured);

    assertThatThrownBy(
            () -> BanishedDependencyMojoConfiguration.banishedDependencies(session, execution))
        .isInstanceOf(IllegalStateException.class);
  }

  @Test
  void unsetOptionalDescriptorPropertyMeansNoBanPolicy() {
    final MavenSession session = session(new Properties());
    final MojoExecution execution = execution(BAN_PROPERTY_EXPRESSION, null);

    assertThat(BanishedDependencyMojoConfiguration.banishedDependencies(session, execution))
        .isEmpty();
  }

  @Test
  void xmlChildListFallsBackWhenOptionalDescriptorPropertyIsUnset() {
    final MavenSession session = session(new Properties());
    final Xpp3Dom configured = new Xpp3Dom(BAN_PARAMETER);
    final Xpp3Dom child = new Xpp3Dom("banishedDependency");
    child.setValue("child:only");
    configured.addChild(child);

    final List<String> actual =
        BanishedDependencyMojoConfiguration.banishedDependencies(
            session, execution(BAN_PROPERTY_EXPRESSION, configured));

    assertThat(actual).containsExactly("child:only");
  }

  @Test
  @SuppressWarnings("PMD.AvoidDuplicateLiterals")
  void absentOptionalRetentionPropertiesAreEmptyButExplicitUnresolvedXmlFails() {
    final MojoDescriptor descriptor = new MojoDescriptor();
    final DefaultPlexusConfiguration defaults = new DefaultPlexusConfiguration("configuration");
    defaults.addChild("retainedArtifacts", "${elide.retainedArtifacts}");
    defaults.addChild("trimSkipArtifacts", "${elide.trimSkipArtifacts}");
    descriptor.setMojoConfiguration(defaults);
    final MojoExecution absent =
        new MojoExecution(descriptor, "default-cli", MojoExecution.Source.CLI);
    final Xpp3Dom configured = new Xpp3Dom("configuration");
    final Xpp3Dom retained = new Xpp3Dom("retainedArtifacts");
    retained.setValue("${missing.retained}");
    configured.addChild(retained);
    final Xpp3Dom trimSkip = new Xpp3Dom("trimSkipArtifacts");
    trimSkip.setValue("${missing.trimSkip}");
    configured.addChild(trimSkip);
    final MojoExecution unresolved =
        new MojoExecution(descriptor, "default-cli", MojoExecution.Source.CLI);
    unresolved.setConfiguration(configured);
    final Xpp3Dom childLists = new Xpp3Dom("configuration");
    final Xpp3Dom retainedChildren = new Xpp3Dom("retainedArtifacts");
    final Xpp3Dom retainedChild = new Xpp3Dom("artifact");
    retainedChild.setValue("org.example:retained");
    retainedChildren.addChild(retainedChild);
    childLists.addChild(retainedChildren);
    final Xpp3Dom trimSkipChildren = new Xpp3Dom("trimSkipArtifacts");
    final Xpp3Dom trimSkipChild = new Xpp3Dom("artifact");
    trimSkipChild.setValue("org.example:pass-through");
    trimSkipChildren.addChild(trimSkipChild);
    childLists.addChild(trimSkipChildren);
    final MojoExecution childOnly =
        new MojoExecution(descriptor, "default-cli", MojoExecution.Source.CLI);
    childOnly.setConfiguration(childLists);
    final Xpp3Dom emptyLists = new Xpp3Dom("configuration");
    emptyLists.addChild(new Xpp3Dom("retainedArtifacts"));
    emptyLists.addChild(new Xpp3Dom("trimSkipArtifacts"));
    final MojoExecution empty =
        new MojoExecution(descriptor, "default-cli", MojoExecution.Source.CLI);
    empty.setConfiguration(emptyLists);
    final MavenSession session = session(new Properties());
    final Properties unresolvedValues =
        properties("elide.retainedArtifacts", "${missing.retained}");
    unresolvedValues.setProperty("elide.trimSkipArtifacts", "${missing.trimSkip}");
    final MavenSession unresolvedProperties = session(unresolvedValues);

    assertAll(
        "Optional descriptor properties preserve child-list and empty-node configuration",
        () ->
            assertThat(
                    BanishedDependencyMojoConfiguration.stringListParameter(
                        session, absent, "retainedArtifacts"))
                .isEmpty(),
        () ->
            assertThat(
                    BanishedDependencyMojoConfiguration.stringListParameter(
                        session, absent, "trimSkipArtifacts"))
                .isEmpty(),
        () ->
            assertThat(
                    BanishedDependencyMojoConfiguration.stringListParameter(
                        session, childOnly, "retainedArtifacts"))
                .containsExactly("org.example:retained"),
        () ->
            assertThat(
                    BanishedDependencyMojoConfiguration.stringListParameter(
                        session, childOnly, "trimSkipArtifacts"))
                .containsExactly("org.example:pass-through"),
        () ->
            assertThat(
                    BanishedDependencyMojoConfiguration.stringListParameter(
                        session, empty, "retainedArtifacts"))
                .isEmpty(),
        () ->
            assertThat(
                    BanishedDependencyMojoConfiguration.stringListParameter(
                        session, empty, "trimSkipArtifacts"))
                .isEmpty(),
        () ->
            assertThatThrownBy(
                    () ->
                        BanishedDependencyMojoConfiguration.stringListParameter(
                            session, unresolved, "retainedArtifacts"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("retainedArtifacts"),
        () ->
            assertThatThrownBy(
                    () ->
                        BanishedDependencyMojoConfiguration.stringListParameter(
                            session, unresolved, "trimSkipArtifacts"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("trimSkipArtifacts"),
        () ->
            assertThatThrownBy(
                    () ->
                        BanishedDependencyMojoConfiguration.stringListParameter(
                            unresolvedProperties, absent, "retainedArtifacts"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("retainedArtifacts"),
        () ->
            assertThatThrownBy(
                    () ->
                        BanishedDependencyMojoConfiguration.stringListParameter(
                            unresolvedProperties, absent, "trimSkipArtifacts"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("trimSkipArtifacts"));
  }

  @Test
  @SuppressWarnings("PMD.AvoidDuplicateLiterals")
  void descriptorDefaultBooleanLiteralIsUsedWhenNoParameterWasConfigured() {
    final MojoDescriptor descriptor = new MojoDescriptor();
    final DefaultPlexusConfiguration defaults = new DefaultPlexusConfiguration("configuration");
    defaults.addChild("leafOnly", "true");
    descriptor.setMojoConfiguration(defaults);
    final MojoExecution execution =
        new MojoExecution(descriptor, "default-cli", MojoExecution.Source.CLI);

    assertThat(
            BanishedDependencyMojoConfiguration.booleanParameter(
                session(new Properties()), execution, "leafOnly", false))
        .isTrue();
  }

  @Test
  void configuredBooleanExpressionUsesMavenPropertyEvaluation() {
    final MojoDescriptor descriptor = new MojoDescriptor();
    final DefaultPlexusConfiguration defaults = new DefaultPlexusConfiguration("configuration");
    defaults.addChild("leafOnly", "${elide.leafOnly}");
    descriptor.setMojoConfiguration(defaults);
    final MojoExecution execution =
        new MojoExecution(descriptor, "default-cli", MojoExecution.Source.CLI);

    assertThat(
            BanishedDependencyMojoConfiguration.booleanParameter(
                session(properties("elide.leafOnly", "false")), execution, "leafOnly", true))
        .isFalse();
  }

  @Test
  @SuppressWarnings("PMD.AvoidDuplicateLiterals")
  void configuredBooleanExpressionFallsBackToCurrentProjectProperty() {
    final MojoDescriptor descriptor = new MojoDescriptor();
    final DefaultPlexusConfiguration defaults = new DefaultPlexusConfiguration("configuration");
    defaults.addChild("skip", "${elide.skip}");
    descriptor.setMojoConfiguration(defaults);
    final MojoExecution execution =
        new MojoExecution(descriptor, "default-cli", MojoExecution.Source.CLI);
    final MavenSession session = session(new Properties());
    session.getCurrentProject().getProperties().setProperty("elide.skip", "true");

    assertThat(
            BanishedDependencyMojoConfiguration.booleanParameter(session, execution, "skip", false))
        .isTrue();
  }

  @Test
  void emptyConfiguredBooleanUsesMavenProperty() {
    final MojoDescriptor descriptor = new MojoDescriptor();
    final MojoExecution execution =
        new MojoExecution(descriptor, "default-cli", MojoExecution.Source.CLI);
    final Xpp3Dom configured = new Xpp3Dom("configuration");
    configured.addChild(new Xpp3Dom("skip"));
    execution.setConfiguration(configured);

    assertThat(
            BanishedDependencyMojoConfiguration.booleanParameter(
                session(properties("elide.skip", "true")), execution, "skip", false))
        .isTrue();
  }

  @Test
  void unresolvedExplicitBooleanPropertyFailsClosedInsteadOfUsingFallback() {
    final MojoDescriptor descriptor = new MojoDescriptor();
    final DefaultPlexusConfiguration defaults = new DefaultPlexusConfiguration("configuration");
    defaults.addChild("skip", "${elide.skip}");
    descriptor.setMojoConfiguration(defaults);
    final MojoExecution execution =
        new MojoExecution(descriptor, "default-cli", MojoExecution.Source.CLI);

    assertThatThrownBy(
            () ->
                BanishedDependencyMojoConfiguration.booleanParameter(
                    session(properties("elide.skip", "${missing.skip}")), execution, "skip", false))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("contains an unresolved value");
  }

  @Test
  void invalidExplicitBooleanValueFailsClosedInsteadOfUsingFallback() {
    final MojoDescriptor descriptor = new MojoDescriptor();
    final DefaultPlexusConfiguration defaults = new DefaultPlexusConfiguration("configuration");
    defaults.addChild("skip", "false");
    descriptor.setMojoConfiguration(defaults);
    final MojoExecution execution =
        new MojoExecution(descriptor, "default-cli", MojoExecution.Source.CLI);
    final Xpp3Dom configured = new Xpp3Dom("configuration");
    final Xpp3Dom skip = new Xpp3Dom("skip");
    skip.setValue("sometimes");
    configured.addChild(skip);
    execution.setConfiguration(configured);

    assertThatThrownBy(
            () ->
                BanishedDependencyMojoConfiguration.booleanParameter(
                    session(new Properties()), execution, "skip", false))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("not a resolved boolean");
  }

  @Test
  void booleanParameterRejectsChildElements() {
    final MojoDescriptor descriptor = new MojoDescriptor();
    final DefaultPlexusConfiguration defaults = new DefaultPlexusConfiguration("configuration");
    defaults.addChild("skip", "false");
    descriptor.setMojoConfiguration(defaults);
    final MojoExecution execution =
        new MojoExecution(descriptor, "default-cli", MojoExecution.Source.CLI);
    final Xpp3Dom configured = new Xpp3Dom("configuration");
    final Xpp3Dom skip = new Xpp3Dom("skip");
    skip.addChild(new Xpp3Dom("unexpected"));
    configured.addChild(skip);
    execution.setConfiguration(configured);

    assertThatThrownBy(
            () ->
                BanishedDependencyMojoConfiguration.booleanParameter(
                    session(new Properties()), execution, "skip", false))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("must not contain child elements");
  }

  private static MavenSession session(final Properties userProperties) {
    final MavenExecutionRequest request = new DefaultMavenExecutionRequest();
    request.setUserProperties(userProperties);
    return new MavenSession(null, request, null, project());
  }

  private static MavenProject project() {
    final Model model = new Model();
    model.setGroupId("org.example");
    model.setArtifactId("consumer");
    model.setVersion("1.0");
    return new MavenProject(model);
  }

  private static MojoExecution execution(final String defaultValue, final Xpp3Dom configured) {
    final MojoDescriptor descriptor = new MojoDescriptor();
    final DefaultPlexusConfiguration defaults = new DefaultPlexusConfiguration("configuration");
    defaults.addChild(BAN_PARAMETER, defaultValue);
    descriptor.setMojoConfiguration(defaults);
    final MojoExecution execution =
        new MojoExecution(descriptor, "default-cli", MojoExecution.Source.CLI);
    if (configured != null) {
      final Xpp3Dom root = new Xpp3Dom("configuration");
      root.addChild(configured);
      execution.setConfiguration(root);
    }
    return execution;
  }

  private static Properties properties(final String name, final String value) {
    final Properties properties = new Properties();
    properties.setProperty(name, value);
    return properties;
  }
}
