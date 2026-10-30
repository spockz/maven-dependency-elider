// WHY: Prevents later Maven lifecycle executions from adding unseen class providers after capture.

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.regex.Pattern;
import org.apache.maven.execution.MavenExecutionRequest;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.model.Build;
import org.apache.maven.model.Dependency;
import org.apache.maven.model.Plugin;
import org.apache.maven.model.PluginExecution;
import org.apache.maven.model.PluginManagement;
import org.apache.maven.model.Resource;
import org.apache.maven.project.MavenProject;
import org.codehaus.plexus.util.xml.Xpp3Dom;

/** Rejects unmodeled lifecycle executions that can add providers. */
// PMD: Keep the complete lifecycle whitelist in one fail-closed proof boundary.
@SuppressWarnings({
  "PMD.CommentDefaultAccessModifier",
  "PMD.CyclomaticComplexity",
  "PMD.GodClass",
  "PMD.TooManyMethods"
})
final class MavenPreconditionGenerationGuard {
  /** WHY: Maven lifecycle plugins are matched by canonical group. */
  private static final String MAVEN_GROUP = "org.apache.maven.plugins";

  /** WHY: Compiler executions can discover processors and synthetic classes. */
  private static final String COMPILER = "maven-compiler-plugin";

  /** WHY: Resource executions can create or transform file providers. */
  private static final String RESOURCES = "maven-resources-plugin";

  /** WHY: Only verified pre-capture Enforcer rules are modeled. */
  private static final String ENFORCER = "maven-enforcer-plugin";

  /** WHY: Clean is required before any package operation can reuse stale JARs. */
  private static final String CLEAN = "maven-clean-plugin";

  /** WHY: Tests are permitted only when Maven skips arbitrary test execution. */
  private static final String SUREFIRE = "maven-surefire-plugin";

  /** WHY: This is the only verified Surefire configuration boundary. */
  private static final String SUREFIRE_VERSION = "3.5.2";

  /** WHY: Shading is allowed only with a narrow built-in transformer model. */
  private static final String SHADE = "maven-shade-plugin";

  /** WHY: This is the only audited Maven Shade implementation. */
  private static final String SHADE_VERSION = "3.6.0";

  /** WHY: Custom JAR executions can alter the artifact provider boundary. */
  private static final String JAR = "maven-jar-plugin";

  /** WHY: The lifecycle phase table contains canonical phase names. */
  private static final String PHASE_PRE_CLEAN = "pre-clean";

  /** WHY: Clean removes stale package input artifacts. */
  private static final String PHASE_CLEAN = "clean";

  /** WHY: The lifecycle phase table contains canonical phase names. */
  private static final String PHASE_POST_CLEAN = "post-clean";

  /** WHY: Enforcer's modeled built-ins run before proof capture. */
  private static final String PHASE_VALIDATE = "validate";

  /** WHY: The elider captures proof inputs at initialize. */
  private static final String PHASE_INITIALIZE = "initialize";

  /** WHY: Compiler output roots are captured before compile. */
  private static final String PHASE_COMPILE = "compile";

  /** WHY: Surefire's default execution runs after inventory capture. */
  private static final String PHASE_TEST = "test";

  /** WHY: JAR creation can reuse stale artifacts without a clean prelude. */
  private static final String PHASE_PACKAGE = "package";

  /** WHY: Site lifecycle work is outside the provider model. */
  private static final String PHASE_PRE_SITE = "pre-site";

  /** WHY: Site lifecycle work is outside the provider model. */
  private static final String PHASE_SITE = "site";

  /** WHY: Site lifecycle work is outside the provider model. */
  private static final String PHASE_POST_SITE = "post-site";

  /** WHY: Site lifecycle work is outside the provider model. */
  private static final String PHASE_SITE_DEPLOY = "site-deploy";

  /** WHY: Enforcer's modeled goal is named explicitly. */
  private static final String GOAL_ENFORCE = "enforce";

  /** WHY: Shade is modeled only through its built-in goal. */
  private static final String GOAL_SHADE = "shade";

  /** WHY: The default JAR goal is the package provider being guarded. */
  private static final String GOAL_JAR = "jar";

  /** WHY: The standard production resource goal is allowed. */
  private static final String GOAL_RESOURCES = "resources";

  /** WHY: The standard test resource goal is allowed. */
  private static final String GOAL_TEST_RESOURCES = "testResources";

  /** WHY: The standard test compiler goal is inspected. */
  private static final String GOAL_TEST_COMPILE = "testCompile";

  /** WHY: Maven lifecycle execution IDs identify built-in goals. */
  private static final String EXEC_DEFAULT_COMPILE = "default-compile";

  /** WHY: Maven lifecycle execution IDs identify built-in goals. */
  private static final String EXEC_DEFAULT_TEST_COMPILE = "default-testCompile";

  /** WHY: Maven lifecycle execution IDs identify built-in goals. */
  private static final String EXEC_DEFAULT_RESOURCES = "default-resources";

  /** WHY: Maven lifecycle execution IDs identify built-in goals. */
  private static final String EXEC_DEFAULT_TEST_RESOURCES = "default-testResources";

  /** WHY: Maven lifecycle execution IDs identify built-in goals. */
  private static final String EXEC_DEFAULT_CLEAN = "default-clean";

  /** WHY: Maven lifecycle execution IDs identify built-in goals. */
  private static final String EXEC_DEFAULT_JAR = "default-jar";

  /** WHY: Plugin-level configuration is distinguished from management. */
  private static final String LOCATION_PLUGIN = "plugin";

  /** WHY: Plugin-level configuration is distinguished from management. */
  private static final String LOCATION_PLUGIN_MANAGEMENT = "pluginManagement";

  /** WHY: The effective Shade transformer node is checked for uniqueness. */
  private static final String SHADE_TRANSFORMERS = "transformers";

  /** WHY: Other filters could change class-provider membership. */
  private static final String SHADE_SIGNATURE_FILTER_ERROR =
      "Maven Shade Plugin filter must only exclude signature resources";

  /** WHY: No lifecycle phase was resolved. */
  private static final int NO_PHASE = -1;

  /** WHY: Empty Maven nodes carry no configuration content. */
  private static final int NO_ITEMS = 0;

  /** WHY: Maven collection checks use named cardinality bounds. */
  private static final int FIRST_INDEX = 0;

  /** WHY: The clean prelude is followed by one requested lifecycle goal. */
  private static final int SECOND_INDEX = 1;

  /** WHY: Maven collection checks use named cardinality bounds. */
  private static final int ONE_ITEM = 1;

  /** WHY: The request allows only clean followed by one lifecycle goal. */
  private static final int TWO_ITEMS = 2;

  /** WHY: Repeated diagnostics identify the same audited Maven plugin. */
  private static final String SHADE_LABEL = "Maven Shade Plugin";

  /** WHY: Repeated diagnostics identify the same audited Maven plugin. */
  private static final String SUREFIRE_LABEL = "Maven Surefire Plugin";

  /** WHY: The managed Shade filter node has one supported shape. */
  private static final String SHADE_FILTERS = "filters";

  /** WHY: Only the signature-only Shade filter is accepted. */
  private static final String SHADE_REDUCED_POM_OPTION = "createDependencyReducedPom";

  /** WHY: Configuration flags are compared without accepting unresolved values. */
  private static final String BOOLEAN_FALSE = "false";

  /** WHY: Configuration flags are compared without accepting unresolved values. */
  private static final String BOOLEAN_TRUE = "true";

  /** WHY: The default test goal runs after inventory capture. */
  private static final String EXEC_DEFAULT_TEST = "default-test";

  /** WHY: Custom transformer code can add classes during shading. */
  private static final String MANIFEST_TRANSFORMER =
      "org.apache.maven.plugins.shade.resource.ManifestResourceTransformer";

  /** WHY: Manifest transformer main classes require fully qualified Java names. */
  private static final Pattern FULLY_QUALIFIED_CLASS =
      Pattern.compile("[A-Za-z_$][A-Za-z0-9_$]*(\\.[A-Za-z_$][A-Za-z0-9_$]*)+");

  /** WHY: The inherited fixture Shade filter removes signature metadata only. */
  private static final List<String> SHADE_SIGNATURE_EXCLUDES =
      List.of(
          "META-INF/*.SF", "META-INF/*.DSA", "META-INF/*.RSA", "META-INF/*.EC", "META-INF/SIG-*");

  /** WHY: The plugin's own initialize execution is safe and modeled. */
  private static final String ELIDER_GROUP = "io.github.spockz";

  /** WHY: The plugin's own initialize execution is safe and modeled. */
  private static final String ELIDER = "dependency-elider-maven-plugin";

  /** WHY: The fixture runner needs these explicitly allowed Surefire properties. */
  private static final Set<String> SUREFIRE_SYSTEM_PROPERTIES =
      Set.of("elider.verifyElision", "elider.examples.dir");

  /** WHY: These clean properties can preserve stale output files. */
  private static final Set<String> CLEAN_FALSE_PROPERTIES =
      Set.of(
          "maven.clean.skip",
          "clean.skip",
          "maven.clean.excludeDefaultDirectories",
          "clean.excludeDefaultDirectories");

  /** WHY: A false failOnError value can leave stale package inputs behind. */
  private static final Set<String> CLEAN_TRUE_PROPERTIES =
      Set.of("maven.clean.failOnError", "clean.failOnError");

  /** WHY: Deferred deletion does not prove stale package inputs were removed. */
  private static final Set<String> CLEAN_UNMODELED_PROPERTIES =
      Set.of("maven.clean.fastMode", "clean.fastMode");

  /** WHY: Other packaging lifecycles can generate providers outside scanned roots. */
  private static final Set<String> SUPPORTED_PACKAGING = Set.of(GOAL_JAR, "pom");

  /** WHY: These lifecycle phases can run destructive or report-generation goals. */
  private static final Set<String> UNMODELED_CLEAN_SITE_PHASES =
      Set.of(
          PHASE_PRE_CLEAN,
          PHASE_CLEAN,
          PHASE_POST_CLEAN,
          PHASE_PRE_SITE,
          PHASE_SITE,
          PHASE_POST_SITE,
          PHASE_SITE_DEPLOY);

  /** WHY: Only these Maven built-in rules were checked for provider generation. */
  private static final Set<String> SUPPORTED_ENFORCER_RULES =
      Set.of(
          "requireJavaVersion",
          "requireMavenVersion",
          "requirePluginVersions",
          "banDuplicatePomDependencyVersions",
          "dependencyConvergence",
          "requireUpperBoundDeps");

  /** WHY: Custom Enforcer rule implementations can mutate provider roots. */
  private static final Set<String> RULE_IMPLEMENTATION_NAMES =
      Set.of("implementation", "class", "className", "ruleClass", "implementationClass");

  /** WHY: The phase table bounds the single lifecycle invocation accepted here. */
  private static final List<String> LIFECYCLE_PHASES =
      List.of(
          PHASE_PRE_CLEAN,
          PHASE_CLEAN,
          PHASE_POST_CLEAN,
          PHASE_VALIDATE,
          PHASE_INITIALIZE,
          "generate-sources",
          "process-sources",
          "generate-resources",
          "process-resources",
          PHASE_COMPILE,
          "process-classes",
          "generate-test-sources",
          "process-test-sources",
          "generate-test-resources",
          "process-test-resources",
          "test-compile",
          "process-test-classes",
          PHASE_TEST,
          "prepare-package",
          PHASE_PACKAGE,
          "pre-integration-test",
          "integration-test",
          "post-integration-test",
          "verify",
          "install",
          "deploy",
          PHASE_PRE_SITE,
          PHASE_SITE,
          PHASE_POST_SITE,
          PHASE_SITE_DEPLOY);

  private MavenPreconditionGenerationGuard() {}

  static void requireKnownProviderGeneration(final MavenProject project, final MavenSession session)
      throws IOException {
    final Build build = project.getBuild();
    if (build == null
        || project.getPackaging() == null
        || !SUPPORTED_PACKAGING.contains(project.getPackaging())) {
      throw unsupported("custom or unavailable Maven packaging");
    }
    requireSafeGoalOrder(session);
    final int requestedPhaseIndex = LIFECYCLE_PHASES.indexOf(requestedDefaultPhase(session));
    requireSafeSurefireIfTestsRun(project, session, build);
    requireDeclaredRootsAndResourcesAreModeled(build);
    final boolean shadePackageWillRun =
        inspectConfiguredPlugins(project, session, build, requestedPhaseIndex);
    requireCleanBeforePackage(project, build, session, requestedPhaseIndex, shadePackageWillRun);
  }

  private static void requireDeclaredRootsAndResourcesAreModeled(final Build build)
      throws IOException {
    if (!build.getExtensions().isEmpty()) {
      throw unsupported("build extensions can add unmodeled providers");
    }
    rejectFilteredResources(build.getResources(), "production");
    rejectFilteredResources(build.getTestResources(), PHASE_TEST);
  }

  private static boolean inspectConfiguredPlugins(
      final MavenProject project,
      final MavenSession session,
      final Build build,
      final int requestedPhaseIndex)
      throws IOException {
    rejectShadeSourcesProperty(project, session);
    final boolean shadePackageWillRun = inspectActiveShadePlugin(build, requestedPhaseIndex);
    for (final Plugin plugin : build.getPlugins()) {
      if (!isShadePlugin(plugin)) {
        inspectPlugin(plugin, build, requestedPhaseIndex);
      }
    }
    final PluginManagement management = build.getPluginManagement();
    if (management != null) {
      for (final Plugin plugin : management.getPlugins()) {
        if (!isShadePlugin(plugin)
            && !hasActiveDeclaration(build, plugin)
            && isDefaultLifecyclePlugin(plugin)) {
          inspectPlugin(plugin, build, requestedPhaseIndex);
        }
      }
    }
    return shadePackageWillRun;
  }

  private static void requireCleanBeforePackage(
      final MavenProject project,
      final Build build,
      final MavenSession session,
      final int requestedPhaseIndex,
      final boolean shadePackageWillRun)
      throws IOException {
    if (requiresCleanBeforePackage(project, build, requestedPhaseIndex, shadePackageWillRun)) {
      if (!hasCleanPrelude(session)) {
        throw unsupported("Package execution requires a clean goal before packaging");
      }
      requireSafeCleanProperties(project, session);
    }
  }

  private static boolean inspectActiveShadePlugin(final Build build, final int requestedPhaseIndex)
      throws IOException {
    final List<Plugin> activeShadePlugins =
        build.getPlugins().stream()
            .filter(MavenPreconditionGenerationGuard::isShadePlugin)
            .toList();
    if (activeShadePlugins.size() > ONE_ITEM) {
      throw unsupported("multiple active Maven Shade Plugin declarations");
    }
    if (activeShadePlugins.isEmpty()) {
      return false;
    }
    final Plugin active = activeShadePlugins.get(FIRST_INDEX);
    validateShadeDeclaration(active, LOCATION_PLUGIN);
    final List<Plugin> managed = managedShadePlugins(build);
    if (managed.size() > ONE_ITEM) {
      throw unsupported("multiple Maven Shade Plugin management declarations");
    }
    for (final Plugin candidate : managed) {
      validateShadeDeclaration(candidate, LOCATION_PLUGIN_MANAGEMENT);
    }
    final boolean activeExecutionWillRun =
        hasShadeExecutionAtOrBefore(active.getExecutions(), requestedPhaseIndex, "active");
    boolean managedExecutionWillRun = false;
    for (final Plugin candidate : managed) {
      managedExecutionWillRun |=
          hasShadeExecutionAtOrBefore(candidate.getExecutions(), requestedPhaseIndex, "managed");
    }
    if (managedExecutionWillRun && !activeExecutionWillRun) {
      throw unsupported("active Shade plugin does not include its managed execution");
    }
    if (activeExecutionWillRun) {
      inspectShadePlugin(active, build);
      return requestedPhaseIndex >= LIFECYCLE_PHASES.indexOf(PHASE_PACKAGE);
    }
    return false;
  }

  private static boolean requiresCleanBeforePackage(
      final MavenProject project,
      final Build build,
      final int requestedPhaseIndex,
      final boolean shadePackageWillRun)
      throws IOException {
    if (requestedPhaseIndex < LIFECYCLE_PHASES.indexOf(PHASE_PACKAGE)) {
      return false;
    }
    return GOAL_JAR.equals(project.getPackaging())
        || shadePackageWillRun
        || hasDefaultJarExecution(build, requestedPhaseIndex);
  }

  private static boolean hasDefaultJarExecution(final Build build, final int requestedPhaseIndex)
      throws IOException {
    for (final Plugin plugin : build.getPlugins()) {
      if (!isPlugin(plugin, JAR)) {
        continue;
      }
      for (final PluginExecution execution : plugin.getExecutions()) {
        if (isSafeDefaultJarExecution(execution)
            && LIFECYCLE_PHASES.indexOf(executionPhase(MAVEN_GROUP, JAR, execution))
                <= requestedPhaseIndex) {
          return true;
        }
      }
    }
    return false;
  }

  private static boolean hasCleanPrelude(final MavenSession session) throws IOException {
    final List<String> goals = requestGoals(session);
    return goals.size() == TWO_ITEMS && PHASE_CLEAN.equals(goals.getFirst());
  }

  private static void requireSafeCleanProperties(
      final MavenProject project, final MavenSession session) throws IOException {
    final List<Properties> sources = new ArrayList<>();
    if (project.getProperties() != null) {
      sources.add(project.getProperties());
    }
    addPropertySource(sources, session.getUserProperties());
    addPropertySource(sources, session.getSystemProperties());
    addPropertySource(sources, requestUserProperties(session));
    addPropertySource(sources, requestSystemProperties(session));
    for (final Properties properties : sources) {
      for (final String key : CLEAN_FALSE_PROPERTIES) {
        requirePropertyValue(properties, key, BOOLEAN_FALSE);
      }
      for (final String key : CLEAN_TRUE_PROPERTIES) {
        requirePropertyValue(properties, key, BOOLEAN_TRUE);
      }
      for (final String key : CLEAN_UNMODELED_PROPERTIES) {
        if (properties.containsKey(key)) {
          throw unsupported("Maven Clean Plugin property " + key + " is not modeled");
        }
      }
    }
  }

  // PMD: Isolate Maven's nested request API here.
  @SuppressWarnings("PMD.LawOfDemeter")
  private static List<String> requestGoals(final MavenSession session) {
    final MavenExecutionRequest request = session.getRequest();
    return request == null ? List.of() : request.getGoals();
  }

  // PMD: Isolate Maven's nested request API here.
  @SuppressWarnings("PMD.LawOfDemeter")
  private static Properties requestUserProperties(final MavenSession session) {
    final MavenExecutionRequest request = session.getRequest();
    return request == null ? new Properties() : request.getUserProperties();
  }

  // PMD: Isolate Maven's nested request API here.
  @SuppressWarnings("PMD.LawOfDemeter")
  private static Properties requestSystemProperties(final MavenSession session) {
    final MavenExecutionRequest request = session.getRequest();
    return request == null ? new Properties() : request.getSystemProperties();
  }

  private static void requirePropertyValue(
      final Properties properties, final String key, final String expected) throws IOException {
    final String value = properties.getProperty(key);
    if (value != null && !expected.equalsIgnoreCase(value.trim())) {
      throw unsupported("Maven Clean Plugin property " + key + " must resolve to " + expected);
    }
  }

  private static boolean hasShadeExecutionAtOrBefore(
      final List<PluginExecution> executions, final int requestedPhaseIndex, final String location)
      throws IOException {
    boolean executionWillRun = false;
    for (final PluginExecution execution : executions) {
      final String phase = execution.getPhase();
      final int phaseIndex = phase == null ? -1 : LIFECYCLE_PHASES.indexOf(phase);
      if (phaseIndex <= NO_PHASE) {
        throw unsupported(SHADE_LABEL + " " + location + " execution has an unknown phase");
      }
      executionWillRun |= phaseIndex <= requestedPhaseIndex;
    }
    return executionWillRun;
  }

  private static void validateShadeDeclaration(final Plugin plugin, final String location)
      throws IOException {
    final String scope = LOCATION_PLUGIN_MANAGEMENT.equals(location) ? " management" : "";
    if (plugin.isExtensions()) {
      throw unsupported("Maven Shade Plugin" + scope + " extension changes provider generation");
    }
    rejectPluginDependencies(plugin.getDependencies(), "Maven Shade Plugin" + scope);
  }

  private static boolean isShadePlugin(final Plugin plugin) {
    return isPlugin(plugin, SHADE);
  }

  private static void requireSafeGoalOrder(final MavenSession session) throws IOException {
    final String defaultPhase = requestedDefaultPhase(session);
    final int phaseIndex = LIFECYCLE_PHASES.indexOf(defaultPhase);
    if (phaseIndex < LIFECYCLE_PHASES.indexOf(PHASE_INITIALIZE)
        || UNMODELED_CLEAN_SITE_PHASES.contains(defaultPhase)) {
      throw unsupported("Maven goal sequence is not a safe default lifecycle invocation");
    }
  }

  private static String requestedDefaultPhase(final MavenSession session) throws IOException {
    if (session == null || requestGoals(session).isEmpty()) {
      throw unsupported("Maven session goal order is unavailable");
    }
    final List<String> requestedGoals = requestGoals(session);
    if (requestedGoals.size() > TWO_ITEMS) {
      throw unsupported("Maven goal sequence is not a single default lifecycle invocation");
    }
    final String defaultPhase =
        requestedGoals.size() == TWO_ITEMS && PHASE_CLEAN.equals(requestedGoals.get(FIRST_INDEX))
            ? requestedGoals.get(SECOND_INDEX)
            : requestedGoals.size() == ONE_ITEM ? requestedGoals.get(FIRST_INDEX) : null;
    if (defaultPhase == null) {
      throw unsupported("Maven goal sequence is not a safe default lifecycle invocation");
    }
    return defaultPhase;
  }

  private static void requireSafeSurefireIfTestsRun(
      final MavenProject project, final MavenSession session, final Build build)
      throws IOException {
    final String requestedPhase = requestedDefaultPhase(session);
    if (LIFECYCLE_PHASES.indexOf(requestedPhase) < LIFECYCLE_PHASES.indexOf(PHASE_TEST)) {
      return;
    }
    requireSurefireTestsSkipped(project, session);
    final List<Plugin> active =
        build.getPlugins().stream().filter(MavenPreconditionGenerationGuard::isSurefire).toList();
    final List<Plugin> managed = managedSurefirePlugins(build);
    if (active.size() != ONE_ITEM || managed.size() > ONE_ITEM) {
      throw unsupported(
          "effective Maven Surefire Plugin configuration is unavailable or ambiguous");
    }
    final Plugin activePlugin = active.get(FIRST_INDEX);
    validateSurefirePlugin(activePlugin, "active plugin");
    if (activePlugin.getExecutions().size() != ONE_ITEM) {
      throw unsupported("Maven Surefire Plugin must have one effective default-test execution");
    }
    for (final PluginExecution execution : activePlugin.getExecutions()) {
      validateSurefireExecution(execution, "active plugin");
    }
    if (!managed.isEmpty()) {
      final Plugin managedPlugin = managed.get(FIRST_INDEX);
      validateSurefirePlugin(managedPlugin, LOCATION_PLUGIN_MANAGEMENT);
      if (managedPlugin.getExecutions().size() > ONE_ITEM) {
        throw unsupported("Maven Surefire Plugin management has unmodeled executions");
      }
      for (final PluginExecution execution : managedPlugin.getExecutions()) {
        validateSurefireExecution(execution, LOCATION_PLUGIN_MANAGEMENT);
      }
      requireManagedSurefireConfiguration(activePlugin, managedPlugin);
      requireManagedSurefireExecutions(activePlugin, managedPlugin);
    }
    requireSurefireVersion(activePlugin, managed);
  }

  private static boolean isSurefire(final Plugin plugin) {
    return isPlugin(plugin, SUREFIRE);
  }

  private static List<Plugin> managedSurefirePlugins(final Build build) {
    final PluginManagement management = build.getPluginManagement();
    if (management == null) {
      return List.of();
    }
    return management.getPlugins().stream()
        .filter(MavenPreconditionGenerationGuard::isSurefire)
        .toList();
  }

  private static void requireSurefireTestsSkipped(
      final MavenProject project, final MavenSession session) throws IOException {
    final List<Properties> propertySources = new ArrayList<>();
    propertySources.add(project.getProperties());
    addPropertySource(propertySources, session.getUserProperties());
    addPropertySource(propertySources, session.getSystemProperties());
    addPropertySource(propertySources, requestUserProperties(session));
    addPropertySource(propertySources, requestSystemProperties(session));
    final Set<String> values = new HashSet<>();
    for (final Properties properties : propertySources) {
      final String value = properties.getProperty("skipTests");
      if (value != null) {
        values.add(value);
      }
    }
    if (!Set.of(BOOLEAN_TRUE).equals(values)) {
      throw unsupported("Maven tests must be explicitly skipped with effective skipTests=true");
    }
  }

  private static void addPropertySource(final List<Properties> sources, final Properties value) {
    if (value != null) {
      sources.add(value);
    }
  }

  private static void validateSurefirePlugin(final Plugin plugin, final String location)
      throws IOException {
    if (plugin.isExtensions()) {
      throw unsupported("Maven Surefire Plugin extensions are unsupported");
    }
    rejectPluginDependencies(plugin.getDependencies(), SUREFIRE_LABEL + " " + location);
    validateSurefireConfiguration(plugin.getConfiguration(), location);
  }

  private static void validateSurefireExecution(
      final PluginExecution execution, final String location) throws IOException {
    if (!EXEC_DEFAULT_TEST.equals(execution.getId())
        || !PHASE_TEST.equals(execution.getPhase())
        || !List.of(PHASE_TEST).equals(execution.getGoals())) {
      throw unsupported("Maven Surefire Plugin execution is not the standard test goal");
    }
    validateSurefireConfiguration(execution.getConfiguration(), location + " execution");
  }

  private static void validateSurefireConfiguration(
      final Object rawConfiguration, final String location) throws IOException {
    if (rawConfiguration == null) {
      return;
    }
    if (!(rawConfiguration instanceof Xpp3Dom configuration)) {
      throw unsupported("unrecognized Maven Surefire Plugin configuration in " + location);
    }
    requireAttributes(configuration, Set.of(), SUREFIRE_LABEL + " " + location);
    rejectMergeOverrides(configuration, SUREFIRE_LABEL + " " + location);
    requireBlankValue(configuration, SUREFIRE_LABEL + " " + location);
    final Set<String> seen = new HashSet<>();
    for (final Xpp3Dom child : configuration.getChildren()) {
      if (!"systemPropertyVariables".equals(child.getName()) || !seen.add(child.getName())) {
        throw unsupported("Maven Surefire Plugin has configuration that can change test execution");
      }
      requireAttributes(child, Set.of(), "Maven Surefire Plugin system properties");
      rejectMergeOverrides(child, "Maven Surefire Plugin system properties");
      requireBlankValue(child, "Maven Surefire Plugin system properties");
      validateSurefireProperties(child);
    }
  }

  private static void validateSurefireProperties(final Xpp3Dom systemProperties)
      throws IOException {
    final Set<String> seenProperties = new HashSet<>();
    for (final Xpp3Dom property : systemProperties.getChildren()) {
      if (!SUREFIRE_SYSTEM_PROPERTIES.contains(property.getName())
          || !seenProperties.add(property.getName())
          || property.getChildCount() != NO_ITEMS
          || property.getValue() == null
          || property.getValue().isBlank()
          || property.getValue().contains("${")) {
        throw unsupported("Maven Surefire Plugin has unmodeled test system properties");
      }
      requireAttributes(property, Set.of(), "Maven Surefire Plugin system property");
    }
  }

  private static void requireManagedSurefireConfiguration(final Plugin active, final Plugin managed)
      throws IOException {
    requireManagedSurefireProperties(
        managed.getConfiguration(), active.getConfiguration(), "plugin configuration");
  }

  private static void requireManagedSurefireExecutions(final Plugin active, final Plugin managed)
      throws IOException {
    if (managed.getExecutions().isEmpty()) {
      return;
    }
    if (managed.getExecutions().size() != ONE_ITEM || active.getExecutions().size() != ONE_ITEM) {
      throw unsupported("active Surefire plugin does not include its managed test execution");
    }
    final PluginExecution managedExecution = managed.getExecutions().get(FIRST_INDEX);
    final PluginExecution activeExecution = active.getExecutions().get(FIRST_INDEX);
    if (!java.util.Objects.equals(managedExecution.getId(), activeExecution.getId())
        || !java.util.Objects.equals(managedExecution.getPhase(), activeExecution.getPhase())
        || !java.util.Objects.equals(managedExecution.getGoals(), activeExecution.getGoals())) {
      throw unsupported("active Surefire execution does not preserve managed execution identity");
    }
    requireManagedSurefireProperties(
        managedExecution.getConfiguration(),
        activeExecution.getConfiguration(),
        "execution configuration");
  }

  private static void requireManagedSurefireProperties(
      final Object rawManaged, final Object rawEffective, final String location)
      throws IOException {
    if (rawManaged == null) {
      return;
    }
    if (!(rawManaged instanceof Xpp3Dom managed) || !(rawEffective instanceof Xpp3Dom effective)) {
      throw unsupported("active Surefire " + location + " does not include managed properties");
    }
    final Xpp3Dom managedProperties = managed.getChild("systemPropertyVariables");
    final Xpp3Dom effectiveProperties = effective.getChild("systemPropertyVariables");
    if (managedProperties == null) {
      return;
    }
    if (effectiveProperties == null) {
      throw unsupported("active Surefire " + location + " does not include managed properties");
    }
    for (final Xpp3Dom property : managedProperties.getChildren()) {
      if (effectiveProperties.getChildren(property.getName()).length != ONE_ITEM) {
        throw unsupported("active Surefire " + location + " omits a managed system property");
      }
    }
  }

  private static void requireSurefireVersion(final Plugin active, final List<Plugin> managed)
      throws IOException {
    final List<String> versions = new ArrayList<>();
    if (active.getVersion() != null && !active.getVersion().isBlank()) {
      versions.add(active.getVersion());
    }
    for (final Plugin plugin : managed) {
      if (plugin.getVersion() != null && !plugin.getVersion().isBlank()) {
        versions.add(plugin.getVersion());
      }
    }
    if (versions.isEmpty()
        || versions.stream().anyMatch(version -> !SUREFIRE_VERSION.equals(version))) {
      throw unsupported("Maven Surefire Plugin version must be exactly " + SUREFIRE_VERSION);
    }
  }

  private static List<Plugin> configuredPlugins(final Build build) {
    final List<Plugin> plugins = new ArrayList<>(build.getPlugins());
    final PluginManagement management = build.getPluginManagement();
    if (management != null) {
      plugins.addAll(management.getPlugins());
    }
    return List.copyOf(plugins);
  }

  private static boolean hasActiveDeclaration(final Build build, final Plugin candidate) {
    final String group = candidate.getGroupId() == null ? MAVEN_GROUP : candidate.getGroupId();
    return build.getPlugins().stream()
        .anyMatch(
            active -> {
              final String activeGroup =
                  active.getGroupId() == null ? MAVEN_GROUP : active.getGroupId();
              return group.equals(activeGroup)
                  && candidate.getArtifactId().equals(active.getArtifactId());
            });
  }

  private static boolean isDefaultLifecyclePlugin(final Plugin plugin) {
    return isPlugin(plugin, COMPILER)
        || isPlugin(plugin, RESOURCES)
        || isPlugin(plugin, JAR)
        || isPlugin(plugin, CLEAN);
  }

  private static void rejectShadeSourcesProperty(
      final MavenProject project, final MavenSession session) throws IOException {
    final List<Properties> propertySources = new ArrayList<>();
    propertySources.add(project.getProperties());
    if (session != null) {
      propertySources.add(session.getUserProperties());
      propertySources.add(session.getSystemProperties());
    }
    for (final Properties properties : propertySources) {
      if (properties.containsKey("shadeSourcesContent")
          || properties.containsKey("maven.shade.shadeSourcesContent")) {
        throw unsupported("shadeSourcesContent property can enable an unmodeled source JAR");
      }
    }
  }

  private static void inspectShadePlugin(final Plugin plugin, final Build build)
      throws IOException {
    validateShadeDeclaration(plugin, LOCATION_PLUGIN);
    final List<Plugin> managedShadePlugins = managedShadePlugins(build);
    if (managedShadePlugins.size() > ONE_ITEM) {
      throw unsupported("multiple Maven Shade Plugin management declarations");
    }
    for (final Plugin managed : managedShadePlugins) {
      validateShadeDeclaration(managed, LOCATION_PLUGIN_MANAGEMENT);
      validateShadeRootConfiguration(managed.getConfiguration(), LOCATION_PLUGIN_MANAGEMENT);
    }
    if (plugin.getExecutions().isEmpty()) {
      if (managedShadePlugins.stream().anyMatch(managed -> !managed.getExecutions().isEmpty())) {
        throw unsupported("active Shade plugin does not include its managed execution");
      }
      return;
    }
    requireSupportedShadeVersion(plugin, build);
    validateShadeRootConfiguration(plugin.getConfiguration(), LOCATION_PLUGIN);
    for (final Plugin managed : managedShadePlugins) {
      requireManagedShadeOptionsInEffectiveConfiguration(
          managed.getConfiguration(), plugin.getConfiguration());
      requireManagedShadeExecutionsInEffectivePlugin(managed, plugin);
    }
    if (plugin.getExecutions().size() > ONE_ITEM) {
      throw unsupported("Maven Shade Plugin has multiple executions");
    }
    for (final PluginExecution execution : plugin.getExecutions()) {
      if (!PHASE_PACKAGE.equals(execution.getPhase())
          || !List.of(GOAL_SHADE).equals(execution.getGoals())) {
        throw unsupported("Maven Shade Plugin must have one package-phase shade execution");
      }
      validateShadeExecutionConfiguration(execution.getConfiguration());
    }
  }

  private static List<Plugin> managedShadePlugins(final Build build) {
    final PluginManagement management = build.getPluginManagement();
    if (management == null) {
      return List.of();
    }
    return management.getPlugins().stream()
        .filter(MavenPreconditionGenerationGuard::isShadePlugin)
        .toList();
  }

  private static void requireManagedShadeOptionsInEffectiveConfiguration(
      final Object rawManaged, final Object rawEffective) throws IOException {
    if (rawManaged == null) {
      return;
    }
    if (!(rawManaged instanceof Xpp3Dom managed) || !(rawEffective instanceof Xpp3Dom effective)) {
      throw unsupported("active Shade plugin configuration does not include managed options");
    }
    for (final Xpp3Dom managedOption : managed.getChildren()) {
      if (effective.getChildren(managedOption.getName()).length != ONE_ITEM) {
        throw unsupported(
            "active Shade plugin configuration does not include managed "
                + managedOption.getName());
      }
    }
  }

  private static void requireManagedShadeExecutionsInEffectivePlugin(
      final Plugin managed, final Plugin effective) throws IOException {
    if (managed.getExecutions().isEmpty()) {
      return;
    }
    if (managed.getExecutions().size() != ONE_ITEM
        || effective.getExecutions().size() != ONE_ITEM) {
      throw unsupported("managed Shade executions are not present as one effective execution");
    }
    final PluginExecution managedExecution = managed.getExecutions().get(FIRST_INDEX);
    final PluginExecution effectiveExecution = effective.getExecutions().get(FIRST_INDEX);
    if (!java.util.Objects.equals(managedExecution.getId(), effectiveExecution.getId())
        || !java.util.Objects.equals(managedExecution.getGoals(), effectiveExecution.getGoals())
        || !java.util.Objects.equals(managedExecution.getPhase(), effectiveExecution.getPhase())) {
      throw unsupported("active Shade execution does not preserve managed execution identity");
    }
    validateShadeExecutionConfiguration(effectiveExecution.getConfiguration());
    if (managedExecution.getConfiguration() != null) {
      validateShadeExecutionConfiguration(managedExecution.getConfiguration());
      if (!(managedExecution.getConfiguration() instanceof Xpp3Dom managedConfiguration)
          || !(effectiveExecution.getConfiguration() instanceof Xpp3Dom effectiveConfiguration)
          || effectiveConfiguration.getChild(SHADE_TRANSFORMERS) == null
          || managedConfiguration.getChild(SHADE_TRANSFORMERS) == null) {
        throw unsupported("active Shade execution does not include managed transformer options");
      }
      final String managedMainClass =
          managedConfiguration
              .getChild(SHADE_TRANSFORMERS)
              .getChild(0)
              .getChild("mainClass")
              .getValue();
      final String effectiveMainClass =
          effectiveConfiguration
              .getChild(SHADE_TRANSFORMERS)
              .getChild(0)
              .getChild("mainClass")
              .getValue();
      if (!java.util.Objects.equals(managedMainClass, effectiveMainClass)) {
        throw unsupported("active Shade execution overrides the managed manifest mainClass");
      }
    }
  }

  private static void requireSupportedShadeVersion(final Plugin shade, final Build build)
      throws IOException {
    final List<String> versions = new ArrayList<>();
    for (final Plugin candidate : configuredPlugins(build)) {
      if (isPlugin(candidate, SHADE)) {
        final String version = candidate.getVersion();
        if (version != null && !version.isBlank()) {
          versions.add(version);
        }
      }
    }
    final String declaredVersion = shade.getVersion();
    if (declaredVersion != null && !declaredVersion.isBlank()) {
      versions.add(declaredVersion);
    }
    if (versions.isEmpty()
        || versions.stream().anyMatch(version -> !SHADE_VERSION.equals(version))) {
      throw unsupported("Maven Shade Plugin version must be exactly " + SHADE_VERSION);
    }
  }

  private static boolean isPlugin(final Plugin plugin, final String artifact) {
    final String group = plugin.getGroupId() == null ? MAVEN_GROUP : plugin.getGroupId();
    return isPlugin(group, plugin.getArtifactId(), artifact);
  }

  private static boolean isPlugin(
      final String group, final String artifact, final String expectedArtifact) {
    return MAVEN_GROUP.equals(group) && expectedArtifact.equals(artifact);
  }

  private static void validateShadeRootConfiguration(
      final Object rawConfiguration, final String location) throws IOException {
    if (rawConfiguration == null) {
      return;
    }
    if (!(rawConfiguration instanceof Xpp3Dom configuration)) {
      throw unsupported("unrecognized Maven Shade Plugin configuration in " + location);
    }
    requireAttributes(configuration, Set.of(), SHADE_LABEL + " " + location);
    requireBlankValue(configuration, SHADE_LABEL + " " + location);
    rejectMergeOverrides(configuration, SHADE_LABEL + " " + location);
    final Set<String> seen = new HashSet<>();
    for (final Xpp3Dom child : configuration.getChildren()) {
      if (!seen.add(child.getName())) {
        throw unsupported("duplicate Maven Shade Plugin option " + child.getName());
      }
      validateShadeRootOption(child);
    }
  }

  private static void validateShadeRootOption(final Xpp3Dom option) throws IOException {
    if (SHADE_REDUCED_POM_OPTION.equals(option.getName())) {
      requireAttributes(option, Set.of(), "Maven Shade Plugin dependency-reduced POM option");
      if (!BOOLEAN_FALSE.equals(option.getValue()) || option.getChildCount() != NO_ITEMS) {
        throw unsupported("Maven Shade Plugin dependency-reduced POM generation is unsupported");
      }
    } else if (SHADE_FILTERS.equals(option.getName())) {
      validateShadeSignatureFilters(option);
    } else {
      throw unsupported("unmodeled Maven Shade Plugin root option " + option.getName());
    }
  }

  private static void validateShadeSignatureFilters(final Xpp3Dom filters) throws IOException {
    requireAttributes(filters, Set.of(), "Maven Shade Plugin filters");
    requireBlankValue(filters, "Maven Shade Plugin filters");
    rejectMergeOverrides(filters, "Maven Shade Plugin filters");
    if (filters.getChildren().length != ONE_ITEM) {
      throw unsupported("Maven Shade Plugin filters must contain one signature-only filter");
    }
    final Xpp3Dom filter = filters.getChildren()[0];
    requireAttributes(filter, Set.of(), "Maven Shade Plugin filter");
    requireBlankValue(filter, "Maven Shade Plugin filter");
    rejectMergeOverrides(filter, "Maven Shade Plugin filter");
    if (filter.getChildren().length != 2
        || !"*:*".equals(valueOf(filter, "artifact"))
        || filter.getChild("includes") != null) {
      throw unsupported(SHADE_SIGNATURE_FILTER_ERROR);
    }
    final Xpp3Dom excludes = filter.getChild("excludes");
    if (excludes == null || excludes.getChildren().length != SHADE_SIGNATURE_EXCLUDES.size()) {
      throw unsupported(SHADE_SIGNATURE_FILTER_ERROR);
    }
    requireAttributes(excludes, Set.of(), "Maven Shade Plugin filter excludes");
    requireBlankValue(excludes, "Maven Shade Plugin filter excludes");
    rejectMergeOverrides(excludes, "Maven Shade Plugin filter excludes");
    final List<String> values = new ArrayList<>();
    for (final Xpp3Dom exclude : excludes.getChildren()) {
      if (!"exclude".equals(exclude.getName())
          || exclude.getChildCount() != NO_ITEMS
          || exclude.getValue() == null) {
        throw unsupported(SHADE_SIGNATURE_FILTER_ERROR);
      }
      requireAttributes(exclude, Set.of(), "Maven Shade Plugin signature exclude");
      values.add(exclude.getValue());
    }
    if (!Set.copyOf(values).equals(Set.copyOf(SHADE_SIGNATURE_EXCLUDES))) {
      throw unsupported(SHADE_SIGNATURE_FILTER_ERROR);
    }
  }

  private static String valueOf(final Xpp3Dom parent, final String name) throws IOException {
    final Xpp3Dom child = parent.getChild(name);
    if (child == null || child.getChildCount() != NO_ITEMS) {
      return null;
    }
    requireAttributes(child, Set.of(), "Maven Shade Plugin filter artifact");
    return child.getValue();
  }

  private static void validateShadeExecutionConfiguration(final Object rawConfiguration)
      throws IOException {
    if (!(rawConfiguration instanceof Xpp3Dom configuration)) {
      throw unsupported("Maven Shade Plugin execution requires a built-in manifest transformer");
    }
    requireAttributes(configuration, Set.of(), "Maven Shade Plugin execution");
    requireBlankValue(configuration, "Maven Shade Plugin execution");
    rejectMergeOverrides(configuration, "Maven Shade Plugin execution");
    final Set<String> seen = new HashSet<>();
    Xpp3Dom transformers = null;
    for (final Xpp3Dom child : configuration.getChildren()) {
      if (!seen.add(child.getName())) {
        throw unsupported("duplicate Maven Shade Plugin execution option " + child.getName());
      }
      if (SHADE_TRANSFORMERS.equals(child.getName())) {
        transformers = child;
      } else {
        validateShadeRootOption(child);
      }
    }
    if (transformers == null || transformers.getChildren().length != ONE_ITEM) {
      throw unsupported("Maven Shade Plugin requires one built-in manifest transformer");
    }
    requireAttributes(transformers, Set.of(), "Maven Shade Plugin transformers");
    requireBlankValue(transformers, "Maven Shade Plugin transformers");
    rejectMergeOverrides(transformers, "Maven Shade Plugin transformers");
    final Xpp3Dom transformer = transformers.getChildren()[0];
    requireAttributes(transformer, Set.of("implementation"), "Maven Shade Plugin transformer");
    requireBlankValue(transformer, "Maven Shade Plugin transformer");
    rejectMergeOverrides(transformer, "Maven Shade Plugin transformer");
    if (!"transformer".equals(transformer.getName())
        || !MANIFEST_TRANSFORMER.equals(transformer.getAttribute("implementation"))
        || transformer.getChildren().length != ONE_ITEM) {
      throw unsupported("Maven Shade Plugin requires one built-in manifest transformer");
    }
    final Xpp3Dom mainClass = transformer.getChild("mainClass");
    if (mainClass == null
        || mainClass.getChildCount() != NO_ITEMS
        || mainClass.getValue() == null
        || !FULLY_QUALIFIED_CLASS.matcher(mainClass.getValue()).matches()) {
      throw unsupported("Maven Shade Plugin manifest mainClass must be a resolved class name");
    }
    requireAttributes(mainClass, Set.of(), "Maven Shade Plugin mainClass");
  }

  private static void requireBlankValue(final Xpp3Dom node, final String location)
      throws IOException {
    if (node.getValue() != null && !node.getValue().isBlank()) {
      throw unsupported(location + " has unmodeled text content");
    }
  }

  private static void requireAttributes(
      final Xpp3Dom node, final Set<String> allowed, final String location) throws IOException {
    if (!Set.copyOf(List.of(node.getAttributeNames())).equals(allowed)) {
      throw unsupported(location + " has unmodeled XML attributes");
    }
  }

  private static void rejectMergeOverrides(final Xpp3Dom configuration, final String location)
      throws IOException {
    if (configuration.getAttribute("combine.self") != null
        || configuration.getAttribute("combine.children") != null) {
      throw unsupported(location + " uses a Maven configuration merge override");
    }
    for (final Xpp3Dom child : configuration.getChildren()) {
      rejectMergeOverrides(child, location);
    }
  }

  private static void inspectJarPlugin(final Plugin plugin) throws IOException {
    rejectPluginDependencies(plugin.getDependencies(), "Maven JAR Plugin");
    if (plugin.getExecutions().size() > ONE_ITEM) {
      throw unsupported("custom Maven JAR Plugin executions can alter Shade inputs");
    }
    for (final PluginExecution execution : plugin.getExecutions()) {
      if (!isSafeDefaultJarExecution(execution)) {
        throw unsupported("custom Maven JAR Plugin executions can alter Shade inputs");
      }
      requireEmptyConfiguration(execution.getConfiguration(), "Maven JAR Plugin execution");
    }
    if (plugin.getConfiguration() != null
        && (!(plugin.getConfiguration() instanceof Xpp3Dom configuration)
            || configuration.getChildCount() != NO_ITEMS
            || !List.of(configuration.getAttributeNames()).isEmpty()
            || (configuration.getValue() != null && !configuration.getValue().isBlank()))) {
      throw unsupported("custom Maven JAR Plugin configuration can alter Shade inputs");
    }
  }

  private static boolean isSafeDefaultJarExecution(final PluginExecution execution) {
    return EXEC_DEFAULT_JAR.equals(execution.getId())
        && (execution.getPhase() == null || PHASE_PACKAGE.equals(execution.getPhase()))
        && List.of(GOAL_JAR).equals(execution.getGoals());
  }

  private static boolean isSafeDefaultCleanExecution(
      final Plugin plugin, final PluginExecution execution) throws IOException {
    final String group = plugin.getGroupId() == null ? MAVEN_GROUP : plugin.getGroupId();
    if (!MAVEN_GROUP.equals(group)
        || !CLEAN.equals(plugin.getArtifactId())
        || !EXEC_DEFAULT_CLEAN.equals(execution.getId())
        || !List.of(PHASE_CLEAN).equals(execution.getGoals())) {
      return false;
    }
    requireEmptyConfiguration(execution.getConfiguration(), "Maven Clean Plugin execution");
    return true;
  }

  private static void requireEmptyConfiguration(final Object rawConfiguration, final String label)
      throws IOException {
    if (rawConfiguration == null) {
      return;
    }
    if (!(rawConfiguration instanceof Xpp3Dom configuration)
        || configuration.getChildCount() != NO_ITEMS
        || !List.of(configuration.getAttributeNames()).isEmpty()
        || (configuration.getValue() != null && !configuration.getValue().isBlank())) {
      throw unsupported(label + " custom configuration is not modeled");
    }
  }

  private static void rejectPluginDependencies(
      final List<Dependency> dependencies, final String pluginName) throws IOException {
    if (dependencies != null && !dependencies.isEmpty()) {
      throw unsupported(pluginName + " dependencies can replace plugin behavior");
    }
  }

  private static void inspectPlugin(
      final Plugin plugin, final Build build, final int requestedPhaseIndex) throws IOException {
    final String group = plugin.getGroupId() == null ? MAVEN_GROUP : plugin.getGroupId();
    final String artifact = plugin.getArtifactId();
    if (plugin.isExtensions()) {
      throw unsupported("plugin extension " + group + ":" + artifact);
    }
    if (MAVEN_GROUP.equals(group) && SUREFIRE.equals(artifact)) {
      inspectSurefireExecutions(plugin, requestedPhaseIndex);
      return;
    }
    if (MAVEN_GROUP.equals(group) && JAR.equals(artifact)) {
      inspectJarPlugin(plugin);
      return;
    }
    inspectPluginDeclaration(plugin, build, group, artifact);
    inspectPluginExecutions(plugin, group, artifact, requestedPhaseIndex);
  }

  private static void inspectSurefireExecutions(final Plugin plugin, final int requestedPhaseIndex)
      throws IOException {
    if (requestedPhaseIndex < LIFECYCLE_PHASES.indexOf(PHASE_TEST)) {
      rejectSurefireExecutionsBeforeRequestedPhase(plugin, requestedPhaseIndex);
    }
  }

  private static void inspectPluginDeclaration(
      final Plugin plugin, final Build build, final String group, final String artifact)
      throws IOException {
    if (MAVEN_GROUP.equals(group) && CLEAN.equals(artifact)) {
      rejectPluginDependencies(plugin.getDependencies(), "Maven Clean Plugin");
      requireEmptyConfiguration(plugin.getConfiguration(), "Maven Clean Plugin");
    }
    if (MAVEN_GROUP.equals(group) && RESOURCES.equals(artifact)) {
      rejectPluginDependencies(plugin.getDependencies(), "Maven Resources Plugin");
      rejectCustomResourceConfiguration(plugin.getConfiguration(), LOCATION_PLUGIN);
      rejectManagedResourceConfiguration(build);
    }
    if (isEnforcer(group, artifact)) {
      rejectEnforcerDependencies(plugin.getDependencies());
      validateEnforcerConfiguration(plugin.getConfiguration(), LOCATION_PLUGIN);
    }
  }

  private static void inspectPluginExecutions(
      final Plugin plugin, final String group, final String artifact, final int requestedPhaseIndex)
      throws IOException {
    for (final PluginExecution execution : plugin.getExecutions()) {
      inspectPluginExecution(plugin, group, artifact, execution, requestedPhaseIndex);
    }
  }

  private static void inspectPluginExecution(
      final Plugin plugin,
      final String group,
      final String artifact,
      final PluginExecution execution,
      final int requestedPhaseIndex)
      throws IOException {
    final String phase = executionPhase(group, artifact, execution);
    final int phaseIndex = LIFECYCLE_PHASES.indexOf(phase);
    if (phaseIndex > NO_PHASE && phaseIndex > requestedPhaseIndex) {
      return;
    }
    if (PHASE_CLEAN.equals(phase) && isSafeDefaultCleanExecution(plugin, execution)) {
      return;
    }
    if (UNMODELED_CLEAN_SITE_PHASES.contains(phase)) {
      throw unsupported("clean/site lifecycle ordering is not modeled: " + phase);
    }
    if (phaseIndex <= NO_PHASE) {
      throw unsupported("unknown lifecycle phase " + phase);
    }
    if (phaseIndex < LIFECYCLE_PHASES.indexOf(PHASE_INITIALIZE)
        && isPreCaptureEnforcer(group, artifact, execution, phase)) {
      validateEnforcerConfiguration(execution.getConfiguration(), "execution");
      return;
    }
    requireSupportedExecution(group, artifact, execution);
  }

  private static void rejectManagedResourceConfiguration(final Build build) throws IOException {
    final PluginManagement management = build.getPluginManagement();
    if (management == null) {
      return;
    }
    for (final Plugin managed : management.getPlugins()) {
      if (isPlugin(managed, RESOURCES)) {
        rejectPluginDependencies(managed.getDependencies(), "Maven Resources Plugin management");
        rejectCustomResourceConfiguration(managed.getConfiguration(), LOCATION_PLUGIN_MANAGEMENT);
      }
    }
  }

  private static void rejectSurefireExecutionsBeforeRequestedPhase(
      final Plugin plugin, final int requestedPhaseIndex) throws IOException {
    for (final PluginExecution execution : plugin.getExecutions()) {
      final String phase =
          execution.getPhase() == null && EXEC_DEFAULT_TEST.equals(execution.getId())
              ? PHASE_TEST
              : execution.getPhase();
      final int phaseIndex = phase == null ? -1 : LIFECYCLE_PHASES.indexOf(phase);
      if (phaseIndex <= NO_PHASE || phaseIndex <= requestedPhaseIndex) {
        throw unsupported("Maven Surefire Plugin has an unmodeled pre-test execution");
      }
    }
  }

  private static boolean isPreCaptureEnforcer(
      final String group,
      final String artifact,
      final PluginExecution execution,
      final String phase) {
    return MAVEN_GROUP.equals(group)
        && ENFORCER.equals(artifact)
        && PHASE_VALIDATE.equals(phase)
        && execution.getGoals().equals(List.of(GOAL_ENFORCE));
  }

  private static String executionPhase(
      final String group, final String artifact, final PluginExecution execution)
      throws IOException {
    if (execution.getPhase() != null && !execution.getPhase().isBlank()) {
      return execution.getPhase();
    }
    final String executionId = execution.getId();
    final String resolved = defaultLifecyclePhase(group, artifact, executionId);
    if (resolved != null) {
      return resolved;
    }
    if (isEnforcer(group, artifact) && execution.getGoals().contains(GOAL_ENFORCE)) {
      return PHASE_VALIDATE;
    }
    throw unsupported("execution " + executionId + " has no recognized lifecycle phase");
  }

  private static String defaultLifecyclePhase(
      final String group, final String artifact, final String executionId) {
    if (!MAVEN_GROUP.equals(group)) {
      return null;
    }
    if (COMPILER.equals(artifact)) {
      return defaultCompilerPhase(executionId);
    }
    if (RESOURCES.equals(artifact)) {
      return defaultResourcesPhase(executionId);
    }
    if (CLEAN.equals(artifact) && EXEC_DEFAULT_CLEAN.equals(executionId)) {
      return PHASE_CLEAN;
    }
    if (JAR.equals(artifact) && EXEC_DEFAULT_JAR.equals(executionId)) {
      return PHASE_PACKAGE;
    }
    return null;
  }

  private static String defaultCompilerPhase(final String executionId) {
    if (EXEC_DEFAULT_COMPILE.equals(executionId)) {
      return PHASE_COMPILE;
    }
    return EXEC_DEFAULT_TEST_COMPILE.equals(executionId) ? "test-compile" : null;
  }

  private static String defaultResourcesPhase(final String executionId) {
    if (EXEC_DEFAULT_RESOURCES.equals(executionId)) {
      return "process-resources";
    }
    return EXEC_DEFAULT_TEST_RESOURCES.equals(executionId) ? "process-test-resources" : null;
  }

  private static void requireSupportedExecution(
      final String group, final String artifact, final PluginExecution execution)
      throws IOException {
    final Set<String> goals = executionGoals(group, artifact, execution);
    if (isPlugin(group, artifact, COMPILER)) {
      requireGoalSubset(goals, Set.of(PHASE_COMPILE, GOAL_TEST_COMPILE), "compiler");
      return;
    }
    if (isSupportedShadeExecution(group, artifact, goals, execution)) {
      return;
    }
    if (isPlugin(group, artifact, RESOURCES)) {
      requireGoalSubset(goals, Set.of(GOAL_RESOURCES, GOAL_TEST_RESOURCES), "resource");
      rejectCustomResourceConfiguration(execution.getConfiguration(), "execution");
      return;
    }
    if (isEnforcer(group, artifact)) {
      throw unsupported("maven-enforcer-plugin execution occurs after inventory capture");
    }
    if (ELIDER_GROUP.equals(group)
        && ELIDER.equals(artifact)
        && isEliderExecution(goals)
        && PHASE_INITIALIZE.equals(execution.getPhase())) {
      return;
    }
    throw unsupported("unmodeled plugin execution " + group + ":" + artifact + " goals " + goals);
  }

  private static boolean isSupportedShadeExecution(
      final String group,
      final String artifact,
      final Set<String> goals,
      final PluginExecution execution) {
    return isPlugin(group, artifact, SHADE)
        && goals.equals(Set.of(GOAL_SHADE))
        && PHASE_PACKAGE.equals(execution.getPhase());
  }

  private static boolean isEliderExecution(final Set<String> goals) {
    return !goals.isEmpty() && Set.of("elide", "analyze").containsAll(goals);
  }

  private static void requireGoalSubset(
      final Set<String> goals, final Set<String> supported, final String label) throws IOException {
    if (goals.isEmpty() || !supported.containsAll(goals)) {
      throw unsupported(label + " execution has unsupported goals " + goals);
    }
  }

  private static Set<String> executionGoals(
      final String group, final String artifact, final PluginExecution execution) {
    final Set<String> goals = new HashSet<>(execution.getGoals());
    if (MAVEN_GROUP.equals(group) && COMPILER.equals(artifact)) {
      if (EXEC_DEFAULT_COMPILE.equals(execution.getId())) {
        goals.add(PHASE_COMPILE);
      } else if (EXEC_DEFAULT_TEST_COMPILE.equals(execution.getId())) {
        goals.add(GOAL_TEST_COMPILE);
      }
    }
    if (MAVEN_GROUP.equals(group) && RESOURCES.equals(artifact)) {
      if (EXEC_DEFAULT_RESOURCES.equals(execution.getId())) {
        goals.add(GOAL_RESOURCES);
      } else if (EXEC_DEFAULT_TEST_RESOURCES.equals(execution.getId())) {
        goals.add(GOAL_TEST_RESOURCES);
      }
    }
    return Set.copyOf(goals);
  }

  private static boolean isEnforcer(final String group, final String artifact) {
    return MAVEN_GROUP.equals(group) && ENFORCER.equals(artifact);
  }

  private static void rejectEnforcerDependencies(final List<Dependency> dependencies)
      throws IOException {
    if (dependencies != null && !dependencies.isEmpty()) {
      throw unsupported("Enforcer plugin dependencies can provide custom rules");
    }
  }

  private static void validateEnforcerConfiguration(
      final Object rawConfiguration, final String location) throws IOException {
    if (rawConfiguration == null) {
      return;
    }
    if (!(rawConfiguration instanceof Xpp3Dom configuration)) {
      throw unsupported("unrecognized Enforcer configuration in " + location);
    }
    rejectRuleImplementation(configuration);
    final Xpp3Dom rules = configuration.getChild("rules");
    if (rules == null) {
      return;
    }
    for (final Xpp3Dom rule : rules.getChildren()) {
      if (!SUPPORTED_ENFORCER_RULES.contains(rule.getName())) {
        throw unsupported("unverified Enforcer rule " + rule.getName());
      }
    }
  }

  private static void rejectRuleImplementation(final Xpp3Dom configuration) throws IOException {
    for (final String name : RULE_IMPLEMENTATION_NAMES) {
      if (configuration.getChild(name) != null || configuration.getAttribute(name) != null) {
        throw unsupported("custom Enforcer rule implementation " + name);
      }
    }
    for (final Xpp3Dom child : configuration.getChildren()) {
      rejectRuleImplementation(child);
    }
  }

  private static void rejectCustomResourceConfiguration(
      final Object rawConfiguration, final String location) throws IOException {
    if (rawConfiguration == null) {
      return;
    }
    if (!(rawConfiguration instanceof Xpp3Dom configuration)) {
      throw unsupported("unrecognized resource configuration in " + location);
    }
    if (configuration.getChildCount() != NO_ITEMS
        || configuration.getAttribute("combine.self") != null
        || configuration.getAttribute("combine.children") != null) {
      throw unsupported("custom resource roots or output configuration in " + location);
    }
  }

  private static void rejectFilteredResources(final List<Resource> resources, final String scope)
      throws IOException {
    for (final Resource resource : resources) {
      if (resource.isFiltering()) {
        throw unsupported(scope + " Maven resources enable filtering");
      }
    }
  }

  private static IOException unsupported(final String detail) {
    return new IOException("Maven downstream provider generation is unsupported: " + detail);
  }
}
