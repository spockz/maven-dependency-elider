// WHY: Converts selected Mojo policy parameters using Maven's own expression and collection rules.

package io.github.spockz.elider.plugin;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.MojoExecution;
import org.apache.maven.plugin.PluginParameterExpressionEvaluator;
import org.apache.maven.plugin.descriptor.MojoDescriptor;
import org.apache.maven.project.MavenProject;
import org.codehaus.plexus.component.configurator.ComponentConfigurationException;
import org.codehaus.plexus.component.configurator.converters.basic.BooleanConverter;
import org.codehaus.plexus.component.configurator.converters.composite.CollectionConverter;
import org.codehaus.plexus.component.configurator.converters.lookup.DefaultConverterLookup;
import org.codehaus.plexus.component.configurator.expression.ExpressionEvaluationException;
import org.codehaus.plexus.configuration.PlexusConfiguration;
import org.codehaus.plexus.configuration.xml.XmlPlexusConfiguration;
import org.codehaus.plexus.util.xml.Xpp3Dom;

@SuppressWarnings({
  "PMD.CommentDefaultAccessModifier",
  "PMD.CommentRequired",
  "PMD.LawOfDemeter",
  "PMD.GodClass",
  "PMD.CyclomaticComplexity",
  "PMD.TooManyMethods"
})
final class BanishedDependencyMojoConfiguration {
  private static final String BANISHED_DEPENDENCIES = "banishedDependencies";

  private BanishedDependencyMojoConfiguration() {}

  // WHY: Maven's list conversion has multiple independent malformed-shape checks.
  static List<String> banishedDependencies(
      final MavenSession session, final MojoExecution execution) {
    final Optional<List<String>> optional =
        optionalPropertyList(session, execution, BANISHED_DEPENDENCIES);
    if (optional.isPresent()) {
      return optional.orElseThrow();
    }
    final Xpp3Dom parameter = parameter(execution, BANISHED_DEPENDENCIES);
    if (parameter == null) {
      return List.of();
    }
    return convertConfiguredCollection(session, execution, parameter, BANISHED_DEPENDENCIES);
  }

  static List<String> stringListParameter(
      final MavenSession session, final MojoExecution execution, final String parameterName) {
    final Optional<List<String>> optional = optionalPropertyList(session, execution, parameterName);
    if (optional.isPresent()) {
      return optional.orElseThrow();
    }
    final Xpp3Dom parameter = parameter(execution, parameterName);
    return parameter == null
        ? List.of()
        : convertConfiguredCollection(session, execution, parameter, parameterName);
  }

  @SuppressWarnings("PMD.CyclomaticComplexity")
  private static List<String> convertConfiguredCollection(
      final MavenSession session,
      final MojoExecution execution,
      final Xpp3Dom parameter,
      final String parameterName) {
    try {
      final PluginParameterExpressionEvaluator evaluator =
          new PluginParameterExpressionEvaluator(session, execution);
      final String configuredText = parameter.getValue();
      if (configuredText != null && configuredText.contains("${")) {
        final Object resolved = evaluator.evaluate(configuredText);
        if (resolved == null || resolved.toString().contains("${")) {
          throw invalid(parameterName + " contains an unresolved expression");
        }
      }
      final Object converted = convertCollection(parameter, evaluator);
      if (!(converted instanceof List<?> values)) {
        throw invalid(parameterName + " did not convert to a list");
      }
      final List<String> result = new ArrayList<>();
      for (final Object value : values) {
        if (!(value instanceof String string) || string.contains("${")) {
          throw invalid(parameterName + " contains an unresolved or non-string value");
        }
        result.add(string);
      }
      return List.copyOf(result);
    } catch (final ComponentConfigurationException | ExpressionEvaluationException exception) {
      throw new IllegalStateException("Cannot resolve Maven parameter " + parameterName, exception);
    }
  }

  private static Optional<List<String>> optionalPropertyList(
      final MavenSession session, final MojoExecution execution, final String parameterName) {
    if (hasParameterProperty(session, parameterName)
        || !isOptionalStringListPropertyDefault(execution, parameterName)) {
      return Optional.empty();
    }
    final Xpp3Dom configured = configuredParameter(execution, parameterName);
    if (configured == null || configured.getValue() == null) {
      if (configured == null || configured.getChildCount() == 0) {
        return Optional.of(List.of());
      }
      return Optional.of(
          convertConfiguredCollection(session, execution, new Xpp3Dom(configured), parameterName));
    }
    return Optional.empty();
  }

  private static boolean isOptionalStringListPropertyDefault(
      final MojoExecution execution, final String parameterName) {
    final MojoDescriptor descriptor = execution.getMojoDescriptor();
    final PlexusConfiguration mojoDefaults =
        descriptor == null ? null : descriptor.getMojoConfiguration();
    final PlexusConfiguration defaultConfiguration =
        mojoDefaults == null ? null : mojoDefaults.getChild(parameterName);
    return defaultConfiguration != null
        && ("${elide." + parameterName + "}").equals(defaultConfiguration.getValue());
  }

  private static boolean hasParameterProperty(
      final MavenSession session, final String parameterName) {
    final String propertyName = "elide." + parameterName;
    return propertyPresent(session.getUserProperties(), propertyName)
        || propertyPresent(session.getSystemProperties(), propertyName)
        || (session.getCurrentProject() != null
            && propertyPresent(session.getCurrentProject().getProperties(), propertyName));
  }

  private static boolean propertyPresent(final java.util.Properties properties, final String name) {
    return properties != null && properties.getProperty(name) != null;
  }

  private static Object convertCollection(
      final Xpp3Dom parameter, final PluginParameterExpressionEvaluator evaluator)
      throws ComponentConfigurationException, ExpressionEvaluationException {
    return new CollectionConverter()
        .fromConfiguration(
            new DefaultConverterLookup(),
            new XmlPlexusConfiguration(parameter),
            List.class,
            String.class,
            Thread.currentThread().getContextClassLoader(),
            evaluator,
            null);
  }

  // WHY: Plexus conversion applies defaults and Maven expression semantics.
  @SuppressWarnings({
    "PMD.CyclomaticComplexity",
    "PMD.CognitiveComplexity",
    "PMD.NPathComplexity",
    "PMD.AvoidDuplicateLiterals"
  })
  static boolean booleanParameter(
      final MavenSession session,
      final MojoExecution execution,
      final String parameterName,
      final boolean fallback) {
    try {
      final Xpp3Dom configured = configuredParameter(execution, parameterName);
      final PluginParameterExpressionEvaluator evaluator =
          new PluginParameterExpressionEvaluator(session, execution);
      final String propertyName = "elide." + parameterName;
      final String explicitProperty = explicitPropertyValue(session, propertyName);
      if (configured != null && configured.getChildCount() > 0) {
        throw invalid("Maven parameter " + parameterName + " must not contain child elements");
      }
      Xpp3Dom parameter = parameter(execution, parameterName);
      if (parameter == null && explicitProperty == null) {
        return fallback;
      }
      if (parameter == null) {
        parameter = new Xpp3Dom(parameterName);
        parameter.setValue("${" + propertyName + "}");
      }
      if (parameter.getValue() == null
          && explicitProperty != null
          && !explicitProperty.contains("${")) {
        parameter.setValue(explicitProperty);
      }
      final String configuredText = parameter.getValue();
      Object resolved =
          configuredText == null
              ? null
              : configuredText.contains("${") ? evaluator.evaluate(configuredText) : configuredText;
      if ((resolved == null || resolved.toString().contains("${"))
          && ("${" + propertyName + "}").equals(configuredText)
          && explicitProperty != null
          && !explicitProperty.contains("${")) {
        resolved = explicitProperty;
      }
      if (resolved == null || resolved.toString().contains("${")) {
        if (explicitProperty != null || configured != null && configured.getValue() != null) {
          throw invalid(
              "Maven parameter "
                  + parameterName
                  + " contains an unresolved value: "
                  + configuredText
                  + " (matching property present: "
                  + (explicitProperty != null)
                  + ")");
        }
        return fallback;
      }
      final String booleanText = resolved.toString().trim();
      if (!"true".equalsIgnoreCase(booleanText) && !"false".equalsIgnoreCase(booleanText)) {
        throw invalid("Maven parameter " + parameterName + " is not a resolved boolean");
      }
      parameter.setValue(booleanText);
      final Object value =
          new BooleanConverter()
              .fromConfiguration(
                  new DefaultConverterLookup(),
                  new XmlPlexusConfiguration(parameter),
                  Boolean.class,
                  null,
                  Thread.currentThread().getContextClassLoader(),
                  evaluator,
                  null);
      if (value instanceof Boolean booleanValue) {
        return booleanValue;
      }
      if (value == null) {
        throw invalid("Maven parameter " + parameterName + " did not convert to a boolean");
      }
      throw invalid("Maven parameter " + parameterName + " is not a resolved boolean");
    } catch (final ComponentConfigurationException | ExpressionEvaluationException exception) {
      throw new IllegalStateException("Cannot resolve Maven parameter " + parameterName, exception);
    }
  }

  private static String explicitPropertyValue(
      final MavenSession session, final String propertyName) {
    final String systemValue = session.getSystemProperties().getProperty(propertyName);
    if (systemValue != null) {
      return systemValue;
    }
    final String userValue = session.getUserProperties().getProperty(propertyName);
    if (userValue != null) {
      return userValue;
    }
    final MavenProject project = session.getCurrentProject();
    return project == null ? null : project.getProperties().getProperty(propertyName);
  }

  private static Xpp3Dom parameter(final MojoExecution execution, final String name) {
    final Xpp3Dom configured = configuredParameter(execution, name);
    final MojoDescriptor descriptor = execution.getMojoDescriptor();
    final PlexusConfiguration mojoDefaults =
        descriptor == null ? null : descriptor.getMojoConfiguration();
    final PlexusConfiguration defaultConfiguration =
        mojoDefaults == null ? null : mojoDefaults.getChild(name);
    final Xpp3Dom defaultNode = defaultConfiguration == null ? null : toDom(defaultConfiguration);
    return configured == null
        ? defaultNode
        : Xpp3Dom.mergeXpp3Dom(new Xpp3Dom(configured), defaultNode, Boolean.TRUE);
  }

  private static Xpp3Dom configuredParameter(final MojoExecution execution, final String name) {
    Objects.requireNonNull(execution, "execution");
    final Xpp3Dom mojoConfig = execution.getConfiguration();
    return mojoConfig == null ? null : mojoConfig.getChild(name);
  }

  private static Xpp3Dom toDom(final PlexusConfiguration configuration) {
    final Xpp3Dom dom = new Xpp3Dom(configuration.getName());
    dom.setValue(configuration.getValue());
    for (final String name : configuration.getAttributeNames()) {
      dom.setAttribute(name, configuration.getAttribute(name));
    }
    for (final PlexusConfiguration child : configuration.getChildren()) {
      dom.addChild(toDom(child));
    }
    return dom;
  }

  private static IllegalStateException invalid(final String message) {
    return new IllegalStateException("Invalid selected Maven policy configuration: " + message);
  }
}
