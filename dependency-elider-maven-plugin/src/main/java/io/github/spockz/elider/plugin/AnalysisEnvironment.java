// WHY: Freezes Maven build configuration needed by prediction without retaining mutable sessions.

package io.github.spockz.elider.plugin;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;
import org.apache.maven.execution.MavenExecutionRequest;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.project.MavenProject;
import org.apache.maven.toolchain.DefaultToolchainManager;
import org.apache.maven.toolchain.ToolchainManager;

/** Immutable Maven settings consumed by source attribution and in-memory closure. */
record AnalysisEnvironment(
    Map<String, String> systemProperties,
    Map<String, String> userProperties,
    Path invocationBase,
    JdkToolchainState jdkToolchainState,
    Path projectionDirectory) {
  AnalysisEnvironment {
    systemProperties = immutableProperties(systemProperties);
    userProperties = immutableProperties(userProperties);
    Objects.requireNonNull(jdkToolchainState, "jdkToolchainState");
  }

  /* default */
  @SuppressWarnings(
      "PMD.LawOfDemeter") // MavenSession owns the request and current-project accessors.
  static AnalysisEnvironment capture(final MavenProject project, final MavenSession session)
      throws IOException {
    if (session == null) {
      throw new IOException("Analyze requires a Maven session to capture build configuration");
    }
    verifyCurrentProject(project, session.getCurrentProject());
    verifyNoSelectedJdkToolchain(session);
    final MavenExecutionRequest request = session.getRequest();
    final String baseDirectory = request == null ? null : request.getBaseDirectory();
    final Path invocationBase =
        baseDirectory == null || baseDirectory.isBlank()
            ? null
            : Path.of(baseDirectory).toAbsolutePath().normalize();
    return new AnalysisEnvironment(
        properties(session.getSystemProperties()),
        properties(session.getUserProperties()),
        invocationBase,
        JdkToolchainState.UNSELECTED,
        null);
  }

  /* default */ Properties systemPropertiesAsProperties() {
    return toProperties(systemProperties);
  }

  /* default */ Properties userPropertiesAsProperties() {
    return toProperties(userProperties);
  }

  /* default */ String fingerprint() {
    final java.util.List<String> fields = new ArrayList<>();
    fields.add("analysis-environment-v1");
    fields.add("toolchain-state=" + jdkToolchainState.name());
    fields.add(invocationBase == null ? "invocation-base=absent" : "invocation-base=present");
    if (invocationBase != null) {
      fields.add(invocationBase.toString());
    }
    appendProperties(fields, "system", systemProperties);
    appendProperties(fields, "user", userProperties);
    return MavenElisionGraphBinding.sha256(fields);
  }

  /* default */ AnalysisEnvironment withProjectionDirectory(final Path value) {
    return new AnalysisEnvironment(
        systemProperties, userProperties, invocationBase, jdkToolchainState, value);
  }

  private static void verifyCurrentProject(
      final MavenProject requestedProject, final MavenProject sessionProject) throws IOException {
    if (requestedProject == null
        || sessionProject == null
        || !sameProject(requestedProject, sessionProject)) {
      throw new IOException("Maven session current project does not match the Analyze project");
    }
  }

  private static boolean sameProject(
      final MavenProject requestedProject, final MavenProject sessionProject) {
    if (!Objects.equals(requestedProject.getGroupId(), sessionProject.getGroupId())
        || !Objects.equals(requestedProject.getArtifactId(), sessionProject.getArtifactId())
        || !Objects.equals(requestedProject.getVersion(), sessionProject.getVersion())) {
      return false;
    }
    final Path requestedBase = baseDirectory(requestedProject);
    final Path sessionBase = baseDirectory(sessionProject);
    return requestedBase != null && requestedBase.equals(sessionBase);
  }

  @SuppressWarnings(
      "PMD.LawOfDemeter") // MavenProject exposes its base directory through this accessor.
  private static Path baseDirectory(final MavenProject project) {
    final File baseDirectory = project.getBasedir();
    if (baseDirectory == null) {
      return null;
    }
    final Path basePath = baseDirectory.toPath();
    return basePath.toAbsolutePath().normalize();
  }

  private static void verifyNoSelectedJdkToolchain(final MavenSession session) throws IOException {
    final Object manager = toolchainManager(session);
    if (manager == null || manager.getClass() != DefaultToolchainManager.class) {
      throw new IOException(
          "Analyze cannot verify JDK toolchain selection with this Maven ToolchainManager");
    }
    final Map<String, Object> pluginContext = jdkToolchainPluginContext(session);
    if (pluginContext == null) {
      throw new IOException("Maven did not expose its JDK toolchain plugin context");
    }
    final String storageKey = DefaultToolchainManager.getStorageKey("jdk");
    if (pluginContext.containsKey(storageKey)) {
      throw new IOException("Source attribution does not support a selected Maven JDK toolchain");
    }
  }

  private static Object toolchainManager(final MavenSession session) throws IOException {
    try {
      return session.lookup(ToolchainManager.class.getName());
    } catch (
        final org.codehaus.plexus.component.repository.exception.ComponentLookupException
            exception) {
      throw new IOException("Cannot verify the selected Maven JDK toolchain", exception);
    }
  }

  @SuppressWarnings("PMD.AvoidCatchingGenericException")
  // Runtime failures while reading Maven's plugin context must abort Analyze.
  private static Map<String, Object> jdkToolchainPluginContext(final MavenSession session)
      throws IOException {
    try {
      final org.apache.maven.plugin.descriptor.PluginDescriptor descriptor =
          new org.apache.maven.plugin.descriptor.PluginDescriptor();
      descriptor.setGroupId(
          org.apache.maven.plugin.descriptor.PluginDescriptor.getDefaultPluginGroupId());
      descriptor.setArtifactId(
          org.apache.maven.plugin.descriptor.PluginDescriptor.getDefaultPluginArtifactId(
              "toolchains"));
      return session.getPluginContext(descriptor, session.getCurrentProject());
    } catch (final RuntimeException exception) {
      throw new IOException("Cannot inspect Maven's selected JDK toolchain context", exception);
    }
  }

  private static Map<String, String> properties(final Properties properties) {
    if (properties == null) {
      return Map.of();
    }
    final Map<String, String> values = new ConcurrentHashMap<>();
    properties.stringPropertyNames().stream()
        .sorted()
        .forEach(key -> values.put(key, properties.getProperty(key)));
    return Collections.unmodifiableMap(values);
  }

  private static Map<String, String> immutableProperties(final Map<String, String> values) {
    final Map<String, String> copy = new ConcurrentHashMap<>();
    values.forEach(
        (key, value) -> {
          Objects.requireNonNull(key, "property key");
          Objects.requireNonNull(value, "property value");
          copy.put(key, value);
        });
    return Collections.unmodifiableMap(copy);
  }

  private static void appendProperties(
      final java.util.List<String> fields,
      final String source,
      final Map<String, String> properties) {
    fields.add(source + "-properties");
    fields.add(Integer.toString(properties.size()));
    properties.entrySet().stream()
        .sorted(Map.Entry.comparingByKey())
        .forEach(
            entry -> {
              fields.add(entry.getKey());
              fields.add(entry.getValue());
            });
  }

  private static Properties toProperties(final Map<String, String> values) {
    final Properties properties = new Properties();
    properties.putAll(values);
    return properties;
  }

  /** Toolchain state accepted by Analyze source attribution. */
  /* default */ enum JdkToolchainState {
    UNSELECTED
  }
}
