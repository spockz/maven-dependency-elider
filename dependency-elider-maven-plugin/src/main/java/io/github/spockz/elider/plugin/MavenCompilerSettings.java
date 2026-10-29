// WHY: Reproduce only compiler settings source attribution can model exactly; reject setups whose
// compiler, toolchain, processing, or module behavior could make its symbols incomplete.

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.model.Build;
import org.apache.maven.model.Plugin;
import org.apache.maven.model.PluginExecution;
import org.apache.maven.model.PluginManagement;
import org.apache.maven.project.MavenProject;
import org.apache.maven.toolchain.Toolchain;
import org.apache.maven.toolchain.ToolchainManager;
import org.codehaus.plexus.util.xml.Xpp3Dom;

/** Resolves supported javac options for source attribution. */
@SuppressWarnings({
  "PMD.CommentDefaultAccessModifier",
  "PMD.CyclomaticComplexity",
  "PMD.GodClass",
  "PMD.TooManyMethods"
})
final class MavenCompilerSettings {
  /** Maven compiler plugin key used to resolve compile settings. */
  private static final String COMPILER_PLUGIN = "org.apache.maven.plugins:maven-compiler-plugin";

  /** Maven compiler property used to disable annotation processing. */
  private static final String PROCESSING_DISABLED = "none";

  /** Safe Boolean compiler value. */
  private static final String SAFE_FALSE = "false";

  /** Lint-only option that does not change source attribution symbols. */
  private static final String SAFE_LINT_ARGUMENT = "-Xlint:all";

  /** Number of settings that is not a conflict. */
  private static final int SINGLE_VALUE_COUNT = 1;

  private MavenCompilerSettings() {}

  /** Resolves supported javac options or rejects unmodeled settings. */
  static List<String> options(
      final MavenProject project, final MavenSession session, final List<String> compileClasspath)
      throws IOException {
    rejectSelectedToolchain(session);
    final List<Xpp3Dom> configurations = compilerConfigurations(project);
    final Properties userProperties =
        session == null ? new Properties() : session.getUserProperties();
    rejectUnsupportedSettings(configurations, project.getProperties(), userProperties);
    final String release =
        value("release", "maven.compiler.release", project, session, configurations);
    final String source =
        value("source", "maven.compiler.source", project, session, configurations);
    final String target =
        value("target", "maven.compiler.target", project, session, configurations);
    if (release != null && (source != null || target != null)) {
      throw new IOException("Cannot attribute source with both compiler release and source/target");
    }
    final List<String> options = new ArrayList<>();
    if (release != null) {
      options.addAll(List.of("--release", release));
    } else if (source != null && target != null) {
      options.addAll(List.of("-source", source, "-target", target));
    } else {
      throw new IOException(
          "Source attribution requires effective compiler release or source/target settings");
    }
    final String encoding =
        value("encoding", "maven.compiler.encoding", project, session, configurations);
    final String projectEncoding =
        project.getProperties().getProperty("project.build.sourceEncoding");
    final String effectiveEncoding = encoding == null ? projectEncoding : encoding;
    if (effectiveEncoding != null && !effectiveEncoding.isBlank()) {
      options.addAll(List.of("-encoding", effectiveEncoding));
    }
    rejectAnnotationProcessors(project, session, configurations, compileClasspath);
    return List.copyOf(options);
  }

  static List<String> releaseIdentity(final MavenProject project, final MavenSession session)
      throws IOException {
    final List<Xpp3Dom> configurations = compilerConfigurations(project);
    final String release =
        value("release", "maven.compiler.release", project, session, configurations);
    final String source =
        value("source", "maven.compiler.source", project, session, configurations);
    final String target =
        value("target", "maven.compiler.target", project, session, configurations);
    if (release != null && (source != null || target != null)) {
      throw new IOException("Cannot identify compiler release with both release and source/target");
    }
    if (release != null) {
      return List.of("--release", release);
    }
    if (source != null && target != null) {
      return List.of("-source", source, "-target", target);
    }
    return List.of("unspecified-compiler-release");
  }

  private static void rejectSelectedToolchain(final MavenSession session) throws IOException {
    if (session == null) {
      return;
    }
    try {
      final ToolchainManager manager =
          (ToolchainManager) session.lookup(ToolchainManager.class.getName());
      if (manager == null) {
        throw new IOException("Cannot verify the selected Maven JDK toolchain");
      }
      final Toolchain toolchain = manager.getToolchainFromBuildContext("jdk", session);
      if (toolchain != null) {
        throw new IOException("Source attribution does not support a selected Maven JDK toolchain");
      }
    } catch (
        final org.codehaus.plexus.component.repository.exception.ComponentLookupException
            exception) {
      throw new IOException("Cannot verify the selected Maven JDK toolchain", exception);
    }
  }

  private static List<Xpp3Dom> compilerConfigurations(final MavenProject project) {
    final Build build = project.getBuild();
    if (build == null) {
      return List.of();
    }
    final List<Plugin> compilers = new ArrayList<>();
    final Plugin configuredCompiler = build.getPluginsAsMap().get(COMPILER_PLUGIN);
    if (configuredCompiler != null) {
      compilers.add(configuredCompiler);
    }
    final PluginManagement management = build.getPluginManagement();
    if (management != null) {
      final Plugin managedCompiler = management.getPluginsAsMap().get(COMPILER_PLUGIN);
      if (managedCompiler != null) {
        compilers.add(managedCompiler);
      }
    }
    final List<Xpp3Dom> configurations = new ArrayList<>();
    for (final Plugin compiler : compilers) {
      if (compiler.getConfiguration() instanceof Xpp3Dom root) {
        configurations.add(root);
      }
      for (final PluginExecution execution : compiler.getExecutions()) {
        if (execution.getGoals().contains("compile")
            && execution.getConfiguration() instanceof Xpp3Dom configuration) {
          configurations.add(configuration);
        }
      }
    }
    return List.copyOf(configurations);
  }

  static void rejectUnsupportedSettings(
      final List<Xpp3Dom> configurations,
      final Properties projectProperties,
      final Properties userProperties)
      throws IOException {
    final Set<String> unsupported =
        Set.of(
            "compilerArgument",
            "compilerArguments",
            "executable",
            "jdkToolchain",
            "moduleVersion",
            "modulePath",
            "sourcepath",
            "includes",
            "excludes",
            "compileSourceRoots",
            "generatedSourcesDirectory",
            "annotationProcessorPaths",
            "annotationProcessors",
            "annotationProcessorPath",
            "processorpath",
            "modulepath");
    for (final Xpp3Dom configuration : configurations) {
      if (!safeCompilerArgs(configuration.getChild("compilerArgs"))) {
        throw new IOException("Source attribution does not support compiler setting compilerArgs");
      }
      for (final String name : unsupported) {
        if (hasValue(configuration.getChild(name))) {
          throw new IOException("Source attribution does not support compiler setting " + name);
        }
      }
      if (unsupportedBoolean(configuration, "enablePreview")
          || unsupportedBoolean(configuration, "useModulePath")
          || unsupportedBoolean(configuration, "fork")
          || hasNonJavacCompiler(configuration)) {
        throw new IOException("Source attribution does not support the configured compiler mode");
      }
    }
    rejectUnsupportedProperties(projectProperties);
    rejectUnsupportedProperties(userProperties);
  }

  private static void rejectUnsupportedProperties(final Properties properties) throws IOException {
    rejectProperty(properties, "maven.compiler.compilerArgs", SAFE_LINT_ARGUMENT);
    rejectProperty(properties, "maven.compiler.compilerArgument");
    rejectProperty(properties, "maven.compiler.compilerArguments");
    rejectProperty(properties, "maven.compiler.executable");
    rejectProperty(properties, "maven.compiler.jdkToolchain");
    rejectProperty(properties, "maven.compiler.annotationProcessorPaths");
    rejectProperty(properties, "maven.compiler.annotationProcessors");
    rejectProperty(properties, "maven.compiler.modulePath");
    rejectProperty(properties, "maven.compiler.sourcepath");
    rejectProperty(properties, "maven.compiler.includes");
    rejectProperty(properties, "maven.compiler.excludes");
    rejectProperty(properties, "maven.compiler.fork", SAFE_FALSE);
    rejectProperty(properties, "maven.compiler.enablePreview", SAFE_FALSE);
    rejectProperty(properties, "maven.compiler.useModulePath", SAFE_FALSE);
    rejectProperty(properties, "maven.compiler.compilerId", "javac");
  }

  private static boolean safeCompilerArgs(final Xpp3Dom compilerArgs) {
    if (!hasValue(compilerArgs)) {
      return true;
    }
    final Xpp3Dom[] arguments = compilerArgs.getChildren("arg");
    return arguments.length == SINGLE_VALUE_COUNT
        && SAFE_LINT_ARGUMENT.equals(arguments[0].getValue());
  }

  private static void rejectProperty(final Properties properties, final String name)
      throws IOException {
    rejectProperty(properties, name, null);
  }

  private static void rejectProperty(
      final Properties properties, final String name, final String acceptedValue)
      throws IOException {
    final String configuredValue = properties.getProperty(name);
    if (configuredValue != null
        && !configuredValue.isBlank()
        && (acceptedValue == null || !acceptedValue.equalsIgnoreCase(configuredValue.trim()))) {
      throw new IOException("Source attribution does not support compiler property " + name);
    }
  }

  private static void rejectAnnotationProcessors(
      final MavenProject project,
      final MavenSession session,
      final List<Xpp3Dom> configurations,
      final List<String> classpath)
      throws IOException {
    final String proc = value("proc", "maven.compiler.proc", project, session, configurations);
    if (PROCESSING_DISABLED.equalsIgnoreCase(proc)) {
      return;
    }
    if (proc != null) {
      throw new IOException("Source attribution requires annotation processing to be disabled");
    }
    for (final String entry : classpath) {
      if (hasProcessorService(java.nio.file.Path.of(entry))) {
        throw new IOException("Source attribution cannot run with a compiler-visible processor");
      }
    }
  }

  private static boolean hasProcessorService(final java.nio.file.Path path) throws IOException {
    final String service = "META-INF/services/javax.annotation.processing.Processor";
    if (java.nio.file.Files.isDirectory(path)) {
      return java.nio.file.Files.exists(path.resolve(service));
    }
    if (!java.nio.file.Files.isRegularFile(path)) {
      return false;
    }
    try (java.util.jar.JarFile archive = new java.util.jar.JarFile(path.toFile())) {
      return archive.getEntry(service) != null;
    }
  }

  private static String value(
      final String name,
      final String property,
      final MavenProject project,
      final MavenSession session,
      final List<Xpp3Dom> configurations)
      throws IOException {
    final Set<String> configuredValues = new LinkedHashSet<>();
    for (final Xpp3Dom configuration : configurations) {
      final Xpp3Dom configured = configuration.getChild(name);
      if (hasValue(configured)) {
        configuredValues.add(resolve(configured.getValue().trim(), project, session));
      }
    }
    if (hasConflictingValues(configuredValues)) {
      throw new IOException("Conflicting effective compiler settings for " + name);
    }
    if (!configuredValues.isEmpty()) {
      return configuredValues.iterator().next();
    }
    final String configuredProperty =
        session == null ? null : session.getUserProperties().getProperty(property);
    if (configuredProperty != null && !configuredProperty.isBlank()) {
      return configuredProperty.trim();
    }
    final String projectProperty = project.getProperties().getProperty(property);
    final String modelEncoding =
        "maven.compiler.encoding".equals(property)
            ? project.getProperties().getProperty("project.build.sourceEncoding")
            : null;
    final String effectiveProperty = projectProperty == null ? modelEncoding : projectProperty;
    return effectiveProperty == null || effectiveProperty.isBlank()
        ? null
        : effectiveProperty.trim();
  }

  private static boolean hasConflictingValues(final Set<String> values) {
    return values.size() > SINGLE_VALUE_COUNT;
  }

  private static String resolve(
      final String value, final MavenProject project, final MavenSession session)
      throws IOException {
    if (!value.startsWith("${") || !value.endsWith("}")) {
      return value;
    }
    final String property = value.substring(2, value.length() - 1);
    final String userValue =
        session == null ? null : session.getUserProperties().getProperty(property);
    final String resolved =
        userValue == null ? project.getProperties().getProperty(property) : userValue;
    if (resolved == null || resolved.isBlank()) {
      throw new IOException("Cannot resolve effective compiler property " + property);
    }
    return resolved.trim();
  }

  private static boolean hasValue(final Xpp3Dom value) {
    return value != null
        && ((value.getValue() != null && !value.getValue().isBlank()) || value.getChildCount() > 0);
  }

  private static boolean unsupportedBoolean(final Xpp3Dom configuration, final String name) {
    final Xpp3Dom value = configuration.getChild(name);
    if (!hasValue(value)) {
      return false;
    }
    return value.getValue() == null || !SAFE_FALSE.equalsIgnoreCase(value.getValue().trim());
  }

  private static boolean hasNonJavacCompiler(final Xpp3Dom configuration) {
    final Xpp3Dom compilerId = configuration.getChild("compilerId");
    return hasValue(compilerId)
        && (compilerId.getValue() == null
            || !"javac".equalsIgnoreCase(compilerId.getValue().trim()));
  }
}
