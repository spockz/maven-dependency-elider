// WHY: Prevents exact-class proofs when downstream Maven compiler settings can generate providers.

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.regex.Pattern;
import org.apache.maven.artifact.versioning.ComparableVersion;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.model.Build;
import org.apache.maven.model.Plugin;
import org.apache.maven.model.PluginExecution;
import org.apache.maven.model.PluginManagement;
import org.apache.maven.project.MavenProject;
import org.codehaus.plexus.util.xml.Xpp3Dom;

/** Requires explicit compiler settings for opted-in inventories. */
// PMD: One compiler-safety boundary owns the parsed Maven model state.
@SuppressWarnings({
  "PMD.CommentDefaultAccessModifier",
  "PMD.CouplingBetweenObjects",
  "PMD.CyclomaticComplexity",
  "PMD.GodClass",
  "PMD.TooManyMethods"
})
final class MavenCompilerGenerationGuard {
  /** WHY: Only the Maven compiler plugin can be resolved by this guard. */
  private static final String COMPILER_GROUP = "org.apache.maven.plugins";

  /** WHY: The supported compiler configuration is tied to this Maven plugin. */
  private static final String COMPILER_ARTIFACT = "maven-compiler-plugin";

  /** WHY: This property must explicitly disable processor discovery. */
  private static final String PROC_PROPERTY = "maven.compiler.proc";

  /** WHY: Earlier plugin releases do not provide the verified property binding. */
  private static final String MINIMUM_COMPILER_VERSION = "3.13";

  /** WHY: Future plugin behavior is outside the verified boundary. */
  private static final String MAXIMUM_COMPILER_VERSION = "4.0";

  /** WHY: Version resolution rejects ranges, qualifiers and interpolation leftovers. */
  private static final Pattern NUMERIC_PLUGIN_VERSION = Pattern.compile("[0-9]+(?:\\.[0-9]+)*");

  /** WHY: Older bytecode targets can create undeclared synthetic providers. */
  private static final int MINIMUM_CLASS_TARGET = 11;

  /** WHY: Processor discovery is safe only when explicitly disabled. */
  private static final String NONE = "none";

  /** WHY: Alternative compiler implementations are not audited here. */
  private static final String JAVAC = "javac";

  /** WHY: Empty configuration nodes provide no compiler options. */
  private static final int NO_CHILDREN = 0;

  /** WHY: The model rejects duplicate compiler settings. */
  private static final int ONE_CHILD = 1;

  /** WHY: Maven configuration arrays are read from their only accepted entry. */
  private static final int FIRST_INDEX = 0;

  /** WHY: ComparableVersion returns zero when versions match. */
  private static final int UNRESOLVED_COMPARISON = 0;

  /** WHY: Compiler goals are matched by their exact Maven goal names. */
  private static final String COMPILE_GOAL = "compile";

  /** WHY: Compiler goals are matched by their exact Maven goal names. */
  private static final String TEST_COMPILE_GOAL = "testCompile";

  /** WHY: Maven lifecycle execution IDs can carry implicit compile goals. */
  private static final String DEFAULT_COMPILE_ID = "default-compile";

  /** WHY: Maven lifecycle execution IDs can carry implicit testCompile goals. */
  private static final String DEFAULT_TEST_COMPILE_ID = "default-testCompile";

  /** WHY: These property channels can add or redirect compiler-generated providers. */
  private static final List<String> UNSUPPORTED_COMPILER_PROPERTIES =
      List.of(
          "maven.compiler.annotationProcessorPaths",
          "maven.compiler.annotationProcessors",
          "maven.compiler.annotationProcessorPath",
          "maven.compiler.processorpath",
          "maven.compiler.processorPath",
          "maven.compiler.processorPaths",
          "maven.compiler.compilerArgument",
          "maven.compiler.compilerArguments",
          "maven.compiler.testCompilerArgument",
          "maven.compiler.testCompilerArguments",
          "maven.compiler.compileSourceRoots",
          "maven.compiler.testCompileSourceRoots",
          "maven.compiler.generatedSourcesDirectory",
          "maven.compiler.generatedTestSourcesDirectory",
          "maven.compiler.outputDirectory",
          "maven.compiler.testOutputDirectory",
          "maven.compiler.executable",
          "maven.compiler.jdkToolchain",
          "maven.compiler.compilerVersion");

  /** WHY: This property exposes only the allowlisted diagnostic argument. */
  private static final String DIAGNOSTIC_ARGUMENT_PROPERTY = "maven.compiler.compilerArgs";

  /** WHY: This argument changes diagnostics without generating providers. */
  private static final String DIAGNOSTIC_ARGUMENT = "-Xlint:all";

  private MavenCompilerGenerationGuard() {}

  static void requireSafeCompilerConfiguration(
      final MavenProject project, final MavenSession session) throws IOException {
    requireSafeCompilerConfiguration(project, session, false);
  }

  static void requireSafeCompilerConfiguration(
      final MavenProject project, final MavenSession session, final boolean trustedProcessClasses)
      throws IOException {
    if (project == null || project.getBuild() == null) {
      throw unsupported("Maven build configuration is unavailable");
    }
    final List<Properties> propertySources = propertySources(project, session);
    rejectUnsupportedProperties(propertySources);
    requireSupportedCompilerPluginVersion(project.getBuild(), propertySources);
    final CompilerConfigurations configurations = configurations(project.getBuild());
    requireSupportedTargetLevels(configurations, propertySources);
    if (trustedProcessClasses) {
      requireSafeTrustedTestCompile(configurations, propertySources);
      return;
    }
    final List<String> fallbackProcValues = rootProcValues(configurations, propertySources);
    if (!fallbackProcValues.isEmpty()) {
      requireOnlyNone(fallbackProcValues, "root compiler configuration", propertySources);
    }
    requireSafeExecutionProcessing(configurations, propertySources, !fallbackProcValues.isEmpty());
  }

  private static void requireSafeTrustedTestCompile(
      final CompilerConfigurations configurations, final List<Properties> propertySources)
      throws IOException {
    final List<String> fallbackProcValues = rootProcValues(configurations, propertySources);
    if (!fallbackProcValues.isEmpty()) {
      requireOnlyNone(fallbackProcValues, "root compiler configuration", propertySources);
    }
    final boolean globalFallback = !fallbackProcValues.isEmpty();
    for (final Xpp3Dom root : configurations.root()) {
      rejectUnsupportedConfiguration(root);
    }
    rejectUnsupportedProperties(propertySources);
    requireSafeGoalProcessing(
        CompileGoal.TEST_COMPILE,
        configurations.executions().get(CompileGoal.TEST_COMPILE),
        propertySources,
        globalFallback);
  }

  private static List<String> rootProcValues(
      final CompilerConfigurations configurations, final List<Properties> propertySources)
      throws IOException {
    final List<String> values = propertyValues(PROC_PROPERTY, propertySources);
    for (final Xpp3Dom root : configurations.root()) {
      rejectUnsupportedConfiguration(root);
      final String value = configuredProc(root, "root compiler configuration");
      if (value != null) {
        values.add(value);
      }
    }
    return values;
  }

  private static void requireSafeExecutionProcessing(
      final CompilerConfigurations configurations,
      final List<Properties> propertySources,
      final boolean globalFallback)
      throws IOException {
    for (final CompileGoal goal : CompileGoal.values()) {
      requireSafeGoalProcessing(
          goal, configurations.executions().get(goal), propertySources, globalFallback);
    }
  }

  private static void requireSafeGoalProcessing(
      final CompileGoal goal,
      final List<ExecutionConfiguration> executions,
      final List<Properties> propertySources,
      final boolean globalFallback)
      throws IOException {
    boolean defaultExecutionSafe = false;
    for (final ExecutionConfiguration execution : executions) {
      final String value = executionProc(execution, goal);
      if (value == null && !globalFallback) {
        throw unsupported(
            "explicit proc=none is required for compiler execution " + execution.executionId());
      }
      if (value != null) {
        requireOnlyNone(List.of(value), "execution " + execution.executionId(), propertySources);
      }
      defaultExecutionSafe |= value != null && execution.defaultLifecycleExecution();
    }
    if (!globalFallback && !defaultExecutionSafe) {
      throw unsupported(
          "explicit proc=none is required for default " + goal.label() + " execution");
    }
  }

  private static String executionProc(
      final ExecutionConfiguration execution, final CompileGoal goal) throws IOException {
    final Xpp3Dom configuration = execution.configuration();
    if (configuration == null) {
      return null;
    }
    rejectUnsupportedConfiguration(configuration);
    return configuredProc(
        configuration, "execution " + execution.executionId() + " for " + goal.label());
  }

  private static String configuredProc(final Xpp3Dom configuration, final String location)
      throws IOException {
    final Xpp3Dom proc = configuration.getChild("proc");
    if (proc == null) {
      return null;
    }
    final String value = proc.getValue();
    if (value == null || value.isBlank()) {
      throw unsupported("blank proc configuration in " + location);
    }
    return value;
  }

  private static void requireOnlyNone(
      final List<String> values, final String location, final List<Properties> sources)
      throws IOException {
    final Set<String> resolvedValues = new HashSet<>();
    for (final String value : values) {
      resolvedValues.add(resolve(value, sources, new HashSet<>()));
    }
    if (!Set.of(NONE).equals(resolvedValues)) {
      throw unsupported(
          "conflicting or unsupported proc value in " + location + ": " + resolvedValues);
    }
  }

  private static List<Properties> propertySources(
      final MavenProject project, final MavenSession session) {
    final List<Properties> sources = new ArrayList<>();
    sources.add(project.getProperties());
    if (session != null) {
      sources.add(session.getUserProperties());
      sources.add(session.getSystemProperties());
    }
    return List.copyOf(sources);
  }

  // PMD: EnumMap is correct because this method confines all access to one thread.
  @SuppressWarnings("PMD.UseConcurrentHashMap")
  private static CompilerConfigurations configurations(final Build build) throws IOException {
    final List<Xpp3Dom> roots = new ArrayList<>();
    final Map<CompileGoal, List<ExecutionConfiguration>> executions =
        new EnumMap<>(CompileGoal.class);
    executions.put(CompileGoal.COMPILE, new ArrayList<>());
    executions.put(CompileGoal.TEST_COMPILE, new ArrayList<>());
    if (build == null) {
      throw unsupported("Maven build configuration is unavailable");
    }
    final List<Plugin> compilerPlugins = compilerPlugins(build);
    for (final Plugin compiler : compilerPlugins) {
      addRootConfiguration(compiler, roots);
      addExecutionConfigurations(compiler, executions);
    }
    return new CompilerConfigurations(List.copyOf(roots), Map.copyOf(executions));
  }

  private static void addRootConfiguration(final Plugin compiler, final List<Xpp3Dom> roots)
      throws IOException {
    final Xpp3Dom root = configuration(compiler.getConfiguration(), "plugin");
    if (root != null) {
      roots.add(root);
    }
  }

  private static void addExecutionConfigurations(
      final Plugin compiler, final Map<CompileGoal, List<ExecutionConfiguration>> executions)
      throws IOException {
    for (final PluginExecution execution : compiler.getExecutions()) {
      addExecutionConfiguration(execution, executions);
    }
  }

  private static void addExecutionConfiguration(
      final PluginExecution execution,
      final Map<CompileGoal, List<ExecutionConfiguration>> executions)
      throws IOException {
    final Xpp3Dom executionConfig =
        configuration(execution.getConfiguration(), "execution " + execution.getId());
    final Set<CompileGoal> goals = executionGoals(execution);
    if (goals.isEmpty()) {
      if (executionConfig != null) {
        throw unsupported("cannot classify configured compiler execution " + execution.getId());
      }
      return;
    }
    for (final CompileGoal goal : goals) {
      executions
          .get(goal)
          .add(
              new ExecutionConfiguration(
                  execution.getId(),
                  executionConfig,
                  goal.defaultExecutionId().equals(execution.getId())));
    }
  }

  private static List<Plugin> compilerPlugins(final Build build) throws IOException {
    if (build == null) {
      throw unsupported("Maven build configuration is unavailable");
    }
    final List<Plugin> plugins = new ArrayList<>();
    build.getPlugins().stream()
        .filter(MavenCompilerGenerationGuard::isCompiler)
        .forEach(plugins::add);
    final PluginManagement management = build.getPluginManagement();
    if (management != null) {
      management.getPlugins().stream()
          .filter(MavenCompilerGenerationGuard::isCompiler)
          .forEach(plugins::add);
    }
    return List.copyOf(plugins);
  }

  private static void requireSupportedCompilerPluginVersion(
      final Build build, final List<Properties> propertySources) throws IOException {
    rejectCompilerPluginDependencies(build);
    final List<String> versions = configuredCompilerVersions(build);
    if (versions.isEmpty()) {
      throw unsupported("Maven Compiler Plugin version is unknown");
    }
    final Set<String> resolvedVersions = resolveCompilerVersions(versions, propertySources);
    if (resolvedVersions.size() != ONE_CHILD) {
      throw unsupported("conflicting Maven Compiler Plugin versions");
    }
  }

  private static List<String> configuredCompilerVersions(final Build build) throws IOException {
    final List<String> managedVersions = new ArrayList<>();
    final List<Plugin> managedPlugins = managedCompilerPlugins(build);
    requireUniqueManagedCompilerPlugins(managedPlugins);
    for (final Plugin plugin : managedPlugins) {
      managedVersions.add(plugin.getVersion());
    }
    final List<String> activeVersions = new ArrayList<>();
    for (final Plugin plugin : build.getPlugins()) {
      if (isCompiler(plugin)) {
        activeVersions.add(activeVersion(plugin, managedPlugins));
      }
    }
    return activeVersions.isEmpty() ? managedVersions : activeVersions;
  }

  private static List<Plugin> managedCompilerPlugins(final Build build) throws IOException {
    final PluginManagement management = build.getPluginManagement();
    if (management == null) {
      return List.of();
    }
    return management.getPlugins().stream()
        .filter(MavenCompilerGenerationGuard::isCompiler)
        .toList();
  }

  private static void requireUniqueManagedCompilerPlugins(final List<Plugin> managedPlugins)
      throws IOException {
    final Set<String> keys = new HashSet<>();
    for (final Plugin plugin : managedPlugins) {
      if (!keys.add(plugin.getKey())) {
        throw unsupported("duplicate Maven Compiler Plugin management version declarations");
      }
    }
  }

  private static String activeVersion(final Plugin plugin, final List<Plugin> managedPlugins)
      throws IOException {
    final String version = plugin.getVersion();
    if (version != null && !version.isBlank()) {
      return version;
    }
    String managedVersion = null;
    boolean foundManagedPlugin = false;
    for (final Plugin managed : managedPlugins) {
      if (plugin.getKey().equals(managed.getKey())) {
        if (foundManagedPlugin) {
          throw unsupported("duplicate Maven Compiler Plugin management version declarations");
        }
        foundManagedPlugin = true;
        managedVersion = managed.getVersion();
      }
    }
    return managedVersion;
  }

  private static void rejectCompilerPluginDependencies(final Build build) throws IOException {
    for (final Plugin plugin : compilerPlugins(build)) {
      if (!plugin.getDependencies().isEmpty()) {
        throw unsupported("Maven Compiler Plugin dependencies can replace compiler providers");
      }
    }
  }

  private static Set<String> resolveCompilerVersions(
      final List<String> versions, final List<Properties> propertySources) throws IOException {
    final Set<String> resolvedVersions = new HashSet<>();
    for (final String configuredVersion : versions) {
      if (configuredVersion == null || configuredVersion.isBlank()) {
        throw unsupported("active Maven Compiler Plugin version is unknown");
      }
      resolvedVersions.add(resolve(configuredVersion, propertySources, new HashSet<>()));
      requireSupportedVersion(configuredVersion, propertySources);
    }
    return resolvedVersions;
  }

  private static void requireSupportedVersion(
      final String configuredVersion, final List<Properties> propertySources) throws IOException {
    if (configuredVersion == null || configuredVersion.isBlank()) {
      throw unsupported("Maven Compiler Plugin version is unknown");
    }
    final String version = resolve(configuredVersion, propertySources, new HashSet<>());
    if (!NUMERIC_PLUGIN_VERSION.matcher(version).matches()) {
      throw unsupported("Maven Compiler Plugin version is unresolved or unknown: " + version);
    }
    final ComparableVersion candidate = new ComparableVersion(version);
    if (candidate.compareTo(new ComparableVersion(MINIMUM_COMPILER_VERSION)) < UNRESOLVED_COMPARISON
        || candidate.compareTo(new ComparableVersion(MAXIMUM_COMPILER_VERSION))
            >= UNRESOLVED_COMPARISON) {
      throw unsupported("Maven Compiler Plugin version must be at least 3.13 and below 4.0");
    }
  }

  private static void requireSupportedTargetLevels(
      final CompilerConfigurations configurations, final List<Properties> propertySources)
      throws IOException {
    final TargetSettings fallback = rootSettings(configurations.root(), propertySources);
    for (final CompileGoal goal : CompileGoal.values()) {
      requireGoalTargetLevels(
          goal, configurations.executions().get(goal), fallback, propertySources);
    }
  }

  private static void requireGoalTargetLevels(
      final CompileGoal goal,
      final List<ExecutionConfiguration> executions,
      final TargetSettings fallback,
      final List<Properties> propertySources)
      throws IOException {
    final CompilerLevels globalLevels = effectiveLevels(goal, fallback, TargetSettings.empty());
    final boolean globalTarget = hasTargetSettings(globalLevels);
    if (globalTarget) {
      requireTargetAtLeastEleven(globalLevels, "root compiler settings for " + goal.label());
    }
    boolean defaultTarget = false;
    for (final ExecutionConfiguration execution : executions) {
      defaultTarget |=
          requireExecutionTarget(goal, execution, fallback, propertySources, globalTarget);
    }
    if (!globalTarget && !defaultTarget) {
      throw unsupported(
          "explicit Java target of at least 11 is required for default "
              + goal.label()
              + " execution");
    }
  }

  private static boolean requireExecutionTarget(
      final CompileGoal goal,
      final ExecutionConfiguration execution,
      final TargetSettings fallback,
      final List<Properties> propertySources,
      final boolean globalTarget)
      throws IOException {
    final TargetSettings local = executionSettings(execution.configuration(), propertySources);
    final CompilerLevels levels = effectiveLevels(goal, fallback, local);
    if (!hasTargetSettings(levels)) {
      if (!globalTarget) {
        throw unsupported(
            "explicit Java target of at least 11 is required for compiler execution "
                + execution.executionId());
      }
      return false;
    }
    requireTargetAtLeastEleven(
        levels, "compiler execution " + execution.executionId() + " for " + goal.label());
    return execution.defaultLifecycleExecution();
  }

  private static TargetSettings rootSettings(
      final List<Xpp3Dom> roots, final List<Properties> propertySources) throws IOException {
    return new TargetSettings(
        rootSetting("release", "maven.compiler.release", roots, propertySources),
        rootSetting("source", "maven.compiler.source", roots, propertySources),
        rootSetting("target", "maven.compiler.target", roots, propertySources),
        rootSetting("testRelease", "maven.compiler.testRelease", roots, propertySources),
        rootSetting("testSource", "maven.compiler.testSource", roots, propertySources),
        rootSetting("testTarget", "maven.compiler.testTarget", roots, propertySources));
  }

  private static String rootSetting(
      final String name,
      final String property,
      final List<Xpp3Dom> roots,
      final List<Properties> propertySources)
      throws IOException {
    final List<String> values = propertyValues(property, propertySources);
    for (final Xpp3Dom root : roots) {
      addConfigurationValue(values, root, name, propertySources);
    }
    return consistentValue(values, "compiler setting " + name, propertySources);
  }

  private static TargetSettings executionSettings(
      final Xpp3Dom configuration, final List<Properties> propertySources) throws IOException {
    if (configuration == null) {
      return TargetSettings.empty();
    }
    return new TargetSettings(
        configurationValue(configuration, "release", propertySources),
        configurationValue(configuration, "source", propertySources),
        configurationValue(configuration, "target", propertySources),
        configurationValue(configuration, "testRelease", propertySources),
        configurationValue(configuration, "testSource", propertySources),
        configurationValue(configuration, "testTarget", propertySources));
  }

  private static void addConfigurationValue(
      final List<String> values,
      final Xpp3Dom configuration,
      final String name,
      final List<Properties> propertySources)
      throws IOException {
    final String value = configurationValue(configuration, name, propertySources);
    if (value != null) {
      values.add(value);
    }
  }

  private static String configurationValue(
      final Xpp3Dom configuration, final String name, final List<Properties> propertySources)
      throws IOException {
    final Xpp3Dom[] children = configuration.getChildren(name);
    if (children.length > ONE_CHILD) {
      throw unsupported("duplicate compiler setting " + name);
    }
    if (children.length == NO_CHILDREN) {
      return null;
    }
    final String value = children[FIRST_INDEX].getValue();
    if (value == null || value.isBlank()) {
      throw unsupported("blank compiler setting " + name);
    }
    return resolve(value, propertySources, new HashSet<>());
  }

  private static String consistentValue(
      final List<String> values, final String name, final List<Properties> propertySources)
      throws IOException {
    if (values.isEmpty()) {
      return null;
    }
    final Set<String> resolved = new HashSet<>();
    for (final String value : values) {
      resolved.add(resolve(value, propertySources, new HashSet<>()));
    }
    if (resolved.size() != ONE_CHILD) {
      throw unsupported("conflicting definitions for " + name);
    }
    return resolved.iterator().next();
  }

  private static CompilerLevels effectiveLevels(
      final CompileGoal goal, final TargetSettings fallback, final TargetSettings local) {
    if (goal == CompileGoal.COMPILE) {
      return new CompilerLevels(
          first(local.release(), fallback.release()),
          first(local.source(), fallback.source()),
          first(local.target(), fallback.target()));
    }
    return new CompilerLevels(
        first(local.testRelease(), local.release(), fallback.testRelease(), fallback.release()),
        first(local.testSource(), local.source(), fallback.testSource(), fallback.source()),
        first(local.testTarget(), local.target(), fallback.testTarget(), fallback.target()));
  }

  private static String first(final String... values) {
    for (final String value : values) {
      if (value != null) {
        return value;
      }
    }
    return null;
  }

  private static boolean hasTargetSettings(final CompilerLevels levels) {
    return levels.release() != null || levels.source() != null || levels.target() != null;
  }

  private static void requireTargetAtLeastEleven(final CompilerLevels levels, final String location)
      throws IOException {
    if (levels.release() != null) {
      if (levels.source() != null || levels.target() != null) {
        throw unsupported("conflicting release/source/target settings in " + location);
      }
      requireLevel(levels.release(), location);
      return;
    }
    if (levels.source() == null || levels.target() == null) {
      throw unsupported("explicit source and target are required in " + location);
    }
    final int source = requireLevel(levels.source(), location);
    final int target = requireLevel(levels.target(), location);
    if (source > target) {
      throw unsupported("source exceeds target in " + location);
    }
  }

  private static int requireLevel(final String configuredLevel, final String location)
      throws IOException {
    try {
      final int level = Integer.parseInt(configuredLevel.trim());
      if (level < MINIMUM_CLASS_TARGET) {
        throw unsupported("Java compiler target must be at least 11 in " + location);
      }
      return level;
    } catch (final NumberFormatException failure) {
      throw unsupported("unresolved or unknown Java compiler target in " + location, failure);
    }
  }

  private static Set<CompileGoal> executionGoals(final PluginExecution execution)
      throws IOException {
    final Set<CompileGoal> goals = EnumSet.noneOf(CompileGoal.class);
    for (final String goal : execution.getGoals()) {
      if (COMPILE_GOAL.equals(goal)) {
        goals.add(CompileGoal.COMPILE);
      } else if (TEST_COMPILE_GOAL.equals(goal)) {
        goals.add(CompileGoal.TEST_COMPILE);
      } else {
        throw unsupported("unsupported compiler execution goal " + goal);
      }
    }
    if (DEFAULT_COMPILE_ID.equals(execution.getId())) {
      goals.add(CompileGoal.COMPILE);
    } else if (DEFAULT_TEST_COMPILE_ID.equals(execution.getId())) {
      goals.add(CompileGoal.TEST_COMPILE);
    }
    return goals;
  }

  private static Xpp3Dom configuration(final Object configuration, final String location)
      throws IOException {
    if (configuration == null) {
      return null;
    }
    if (configuration instanceof Xpp3Dom dom) {
      return dom;
    }
    throw unsupported("unrecognized compiler configuration in " + location);
  }

  private static boolean isCompiler(final Plugin plugin) {
    final String group = plugin.getGroupId() == null ? COMPILER_GROUP : plugin.getGroupId();
    return COMPILER_GROUP.equals(group) && COMPILER_ARTIFACT.equals(plugin.getArtifactId());
  }

  private static void rejectUnsupportedConfiguration(final Xpp3Dom configuration)
      throws IOException {
    if (configuration.getAttribute("combine.self") != null
        || configuration.getAttribute("combine.children") != null) {
      throw unsupported("compiler configuration merge override");
    }
    for (final String name :
        List.of(
            "annotationProcessorPaths",
            "annotationProcessors",
            "annotationProcessorPath",
            "processorpath",
            "processorPath",
            "processorPaths",
            "compilerArgument",
            "compilerArguments",
            "testCompilerArgument",
            "testCompilerArguments",
            "compileSourceRoots",
            "testCompileSourceRoots",
            "generatedSourcesDirectory",
            "generatedTestSourcesDirectory",
            "outputDirectory",
            "testOutputDirectory",
            "executable",
            "jdkToolchain",
            "compilerVersion")) {
      if (configuration.getChild(name) != null) {
        throw unsupported("processor or custom compiler setting " + name);
      }
    }
    final Xpp3Dom compilerArgs = configuration.getChild("compilerArgs");
    if (compilerArgs != null && !isDiagnosticOnlyCompilerArgument(compilerArgs)) {
      throw unsupported("unsupported compilerArgs");
    }
    final Xpp3Dom compilerId = configuration.getChild("compilerId");
    if (compilerId != null) {
      final String value = compilerId.getValue();
      if (value == null || !JAVAC.equals(value.trim())) {
        throw unsupported("custom compilerId");
      }
    }
    final Xpp3Dom fork = configuration.getChild("fork");
    if (fork != null && !Boolean.FALSE.toString().equalsIgnoreCase(fork.getValue())) {
      throw unsupported("forked compiler mode");
    }
  }

  private static void rejectUnsupportedProperties(final List<Properties> sources)
      throws IOException {
    for (final Properties properties : sources) {
      rejectUnsupportedProperties(properties, sources);
    }
  }

  private static void rejectUnsupportedProperties(
      final Properties properties, final List<Properties> sources) throws IOException {
    for (final String name : UNSUPPORTED_COMPILER_PROPERTIES) {
      if (properties.getProperty(name) != null) {
        throw unsupported("processor or custom compiler property " + name);
      }
    }
    rejectCompilerArguments(properties);
    rejectCompilerId(properties, sources);
    rejectForkedCompiler(properties);
  }

  private static void rejectCompilerArguments(final Properties properties) throws IOException {
    final String compilerArgs = properties.getProperty(DIAGNOSTIC_ARGUMENT_PROPERTY);
    if (compilerArgs != null && !DIAGNOSTIC_ARGUMENT.equals(compilerArgs.trim())) {
      throw unsupported("unsupported maven.compiler.compilerArgs property");
    }
  }

  private static void rejectCompilerId(final Properties properties, final List<Properties> sources)
      throws IOException {
    final String compilerId = properties.getProperty("maven.compiler.compilerId");
    if (compilerId != null && !JAVAC.equals(resolve(compilerId, sources, new HashSet<>()))) {
      throw unsupported("custom maven.compiler.compilerId");
    }
  }

  private static void rejectForkedCompiler(final Properties properties) throws IOException {
    final String fork = properties.getProperty("maven.compiler.fork");
    if (fork != null && !Boolean.FALSE.toString().equalsIgnoreCase(fork.trim())) {
      throw unsupported("forked compiler property");
    }
  }

  private static boolean isDiagnosticOnlyCompilerArgument(final Xpp3Dom compilerArgs) {
    if (compilerArgs.getAttribute("combine.self") != null
        || compilerArgs.getAttribute("combine.children") != null) {
      return false;
    }
    final Xpp3Dom[] arguments = compilerArgs.getChildren();
    if (arguments.length != ONE_CHILD
        || !"arg".equals(arguments[FIRST_INDEX].getName())
        || arguments[FIRST_INDEX].getChildCount() != NO_CHILDREN) {
      return false;
    }
    final String argument = arguments[FIRST_INDEX].getValue();
    return argument != null && "-Xlint:all".equals(argument.trim());
  }

  private static List<String> propertyValues(
      final String propertyName, final List<Properties> sources) {
    final List<String> values = new ArrayList<>();
    for (final Properties properties : sources) {
      final String value = properties.getProperty(propertyName);
      if (value != null) {
        values.add(value);
      }
    }
    return values;
  }

  private static String resolve(
      final String value, final List<Properties> sources, final Set<String> resolving)
      throws IOException {
    final String candidate = value.trim();
    if (!candidate.startsWith("${") && !candidate.contains("${") && !candidate.contains("}")) {
      return candidate;
    }
    if (!candidate.startsWith("${")
        || !candidate.endsWith("}")
        || candidate.indexOf('}') != candidate.length() - ONE_CHILD) {
      throw unsupported("unresolved compiler property " + candidate);
    }
    final String propertyName = candidate.substring(2, candidate.length() - 1).trim();
    if (propertyName.isEmpty() || !resolving.add(propertyName)) {
      throw unsupported("cyclic or empty compiler property " + candidate);
    }
    try {
      final List<String> definitions = propertyValues(propertyName, sources);
      if (definitions.isEmpty()) {
        throw unsupported("unresolved compiler property " + propertyName);
      }
      final Set<String> resolved = new HashSet<>();
      for (final String definition : definitions) {
        resolved.add(resolve(definition, sources, resolving));
      }
      if (resolved.size() != ONE_CHILD) {
        throw unsupported("conflicting definitions for compiler property " + propertyName);
      }
      return resolved.iterator().next();
    } finally {
      resolving.remove(propertyName);
    }
  }

  private static IOException unsupported(final String detail) {
    return new IOException(
        "Precondition inventory cannot prove compiler-generated classes: " + detail);
  }

  private static IOException unsupported(final String detail, final Exception cause) {
    return new IOException(
        "Precondition inventory cannot prove compiler-generated classes: " + detail, cause);
  }

  /** WHY: The two Maven compiler lifecycle goals have independent effective settings. */
  private enum CompileGoal {
    COMPILE(COMPILE_GOAL, DEFAULT_COMPILE_ID),
    TEST_COMPILE(TEST_COMPILE_GOAL, DEFAULT_TEST_COMPILE_ID);

    /** WHY: User-facing goal label for fail-closed diagnostics. */
    private final String displayLabel;

    /** WHY: Identifies Maven's lifecycle-bound execution for this goal. */
    private final String defaultExecutionIdentifier;

    CompileGoal(final String displayLabel, final String defaultExecutionIdentifier) {
      this.displayLabel = displayLabel;
      this.defaultExecutionIdentifier = defaultExecutionIdentifier;
    }

    String label() {
      return displayLabel;
    }

    String defaultExecutionId() {
      return defaultExecutionIdentifier;
    }
  }

  private record CompilerConfigurations(
      List<Xpp3Dom> root, Map<CompileGoal, List<ExecutionConfiguration>> executions) {}

  private record ExecutionConfiguration(
      String executionId, Xpp3Dom configuration, boolean defaultLifecycleExecution) {}

  private record TargetSettings(
      String release,
      String source,
      String target,
      String testRelease,
      String testSource,
      String testTarget) {
    static TargetSettings empty() {
      return new TargetSettings(null, null, null, null, null, null);
    }
  }

  private record CompilerLevels(String release, String source, String target) {}
}
