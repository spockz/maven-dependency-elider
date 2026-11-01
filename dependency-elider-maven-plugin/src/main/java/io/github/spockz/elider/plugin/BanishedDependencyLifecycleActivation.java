// WHY: Captures and injects selected global exclusions before Maven resolves dependencies.

package io.github.spockz.elider.plugin;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.StringTokenizer;
import org.apache.maven.MavenExecutionException;
import org.apache.maven.execution.MavenExecutionRequest;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.model.Build;
import org.apache.maven.model.Plugin;
import org.apache.maven.model.PluginExecution;
import org.apache.maven.model.PluginManagement;
import org.apache.maven.plugin.MavenPluginManager;
import org.apache.maven.plugin.MojoExecution;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugin.descriptor.MojoDescriptor;
import org.apache.maven.plugin.prefix.DefaultPluginPrefixRequest;
import org.apache.maven.plugin.prefix.PluginPrefixResolver;
import org.apache.maven.plugin.version.DefaultPluginVersionRequest;
import org.apache.maven.plugin.version.PluginVersionResolver;
import org.apache.maven.project.MavenProject;
import org.codehaus.plexus.util.xml.Xpp3Dom;
import org.eclipse.aether.repository.RemoteRepository;

// WHY: Preflight checks every project policy before dependency models are mutated.
@SuppressWarnings({
  "PMD.CommentDefaultAccessModifier",
  "PMD.CommentRequired",
  "PMD.CouplingBetweenObjects",
  "PMD.GodClass",
  "PMD.CyclomaticComplexity",
  "PMD.CognitiveComplexity",
  "PMD.NPathComplexity",
  "PMD.TooManyMethods",
  "PMD.LawOfDemeter",
  "PMD.UseConcurrentHashMap",
  "PMD.AvoidInstantiatingObjectsInLoops"
})
final class BanishedDependencyLifecycleActivation {
  private static final String MAVEN_API_FAILURE_SUPPRESSION = "PMD.AvoidCatchingGenericException";
  static final String CAPTURE_STORE_KEY =
      BanishedDependencyLifecycleActivation.class.getName() + ".captureStore";

  private static final String ELIDER_GROUP_ID = "io.github.spockz";
  private static final String ELIDER_ARTIFACT_ID = "dependency-elider-maven-plugin";
  private static final String ELIDER_PREFIX = "dependency-elider";
  private static final String ELIDE_GOAL = "elide";
  private static final String ANALYZE_GOAL = "analyze";
  private static final String LEAF_ONLY_PARAMETER = "leafOnly";
  private static final String SKIP_PARAMETER = "skip";
  private static final String DEFAULT_CLI_EXECUTION_ID = "default-cli";
  private static final Set<String> NON_DEFAULT_LIFECYCLE_PHASES =
      Set.of("pre-clean", "clean", "post-clean", "pre-site", "site", "post-site", "site-deploy");
  private static final int COLON_DELIMITED_PREFIX_GOAL = 2;
  private static final int COLON_DELIMITED_COORDINATE_GOAL = 3;
  private static final int COLON_DELIMITED_VERSION_GOAL = 4;

  private final MavenPluginManager mavenPluginManager;
  private final PluginPrefixResolver pluginPrefixResolver;
  private final PluginVersionResolver pluginVersionResolver;

  BanishedDependencyLifecycleActivation(
      final MavenPluginManager mavenPluginManager,
      final PluginPrefixResolver pluginPrefixResolver,
      final PluginVersionResolver pluginVersionResolver) {
    this.mavenPluginManager = Objects.requireNonNull(mavenPluginManager, "mavenPluginManager");
    this.pluginPrefixResolver =
        Objects.requireNonNull(pluginPrefixResolver, "pluginPrefixResolver");
    this.pluginVersionResolver =
        Objects.requireNonNull(pluginVersionResolver, "pluginVersionResolver");
  }

  void activate(final MavenSession session) throws MavenExecutionException {
    Objects.requireNonNull(session, "session");
    final List<MavenProject> projects = selectedProjects(session);
    final List<String> goals = requestedGoals(session);
    if (!hasSelectedTasks(projects, goals)) {
      return;
    }
    final Map<MavenProject, List<SelectedExecution>> selected = new LinkedHashMap<>();
    for (final MavenProject project : projects) {
      final MavenSession projectSession = projectSession(session, project);
      selected.put(project, select(projectSession, goals));
    }
    preflightAndInject(session, selected);
  }

  static boolean hasSelectedTasks(
      final List<MavenProject> projects, final List<String> requestedGoals) {
    return !projects.isEmpty() && !requestedGoals.isEmpty();
  }

  // WHY: Malformed detached payloads must fail closed.
  @SuppressWarnings(MAVEN_API_FAILURE_SUPPRESSION)
  static void verifyMojoConfiguration(
      final MavenSession session,
      final MavenProject project,
      final MojoExecution execution,
      final List<String> configuredBans)
      throws MojoFailureException {
    final List<String> actual =
        BanishedDependencyPolicy.normalize(configuredBans).stream().map(Object::toString).toList();
    if (session == null || session.getRepositorySession() == null) {
      if (!actual.isEmpty()) {
        throw new MojoFailureException(
            "A nonempty ban policy cannot be verified without Maven selection state");
      }
      return;
    }
    final BanishedDependencyCaptureStore store;
    try {
      store =
          BanishedDependencyCaptureStore.fromPayload(
              EliderPreparationState.sessionData(session).get(CAPTURE_STORE_KEY));
    } catch (final RuntimeException exception) {
      throw new MojoFailureException("Cannot verify selected ban policy capture", exception);
    }
    if (project == null || execution == null) {
      if (!actual.isEmpty()) {
        throw new MojoFailureException(
            "A nonempty ban policy has no matching selected Maven execution");
      }
      return;
    }
    final BanishedDependencyOriginalModel model;
    try {
      model = store.find(BanishedDependencyOriginalModel.projectIdentity(project));
    } catch (final IllegalArgumentException exception) {
      if (!actual.isEmpty()) {
        throw new MojoFailureException(
            "Cannot identify the selected project ban policy", exception);
      }
      return;
    }
    if (model == null) {
      if (!actual.isEmpty()) {
        throw new MojoFailureException(
            "A nonempty ban policy was not captured during Maven selection preflight");
      }
      return;
    }
    final String goal = execution.getGoal();
    final String version = execution.getVersion();
    final String executionId = execution.getExecutionId();
    final String source = execution.getSource() == null ? "" : execution.getSource().name();
    final List<BanishedDependencyOriginalModel.ExecutionPolicy> matching =
        model.executions().stream()
            .filter(policy -> policy.executionId().equals(executionId))
            .filter(policy -> policy.goal().equals(goal))
            .filter(policy -> policy.pluginVersion().equals(version))
            .filter(policy -> policy.source().equals(source))
            .toList();
    if (matching.isEmpty() || matching.stream().anyMatch(policy -> !policy.bans().equals(actual))) {
      throw new MojoFailureException(
          "Maven injected a ban policy that does not match the frozen selected execution policy");
    }
  }

  private List<SelectedExecution> select(final MavenSession session, final List<String> goals)
      throws MavenExecutionException {
    final MavenProject project = session.getCurrentProject();
    final Plugin buildPlugin = configuredPlugin(project, false);
    final boolean hasLifecycleCandidate =
        buildPlugin != null
            && buildPlugin.getExecutions().stream()
                .anyMatch(execution -> !relevantGoals(execution.getGoals()).isEmpty());
    if (hasLifecycleCandidate
        && hasUnknownLifecycleTask(goals)
        && hasPotentialBanPolicy(session, project, buildPlugin)) {
      throw new MavenExecutionException(
          "Cannot determine selected dependency-elider ban policy for an unknown Maven task",
          session.getRequest().getPom());
    }
    final int lastLifecyclePhase =
        hasLifecycleCandidate
            ? lastLifecyclePhase(goals, EliderGoalOrder.DEFAULT_LIFECYCLE_PHASE_ORDER)
            : -1;
    final List<SelectedExecution> selected = new ArrayList<>();
    if (buildPlugin != null && lastLifecyclePhase >= 0) {
      for (final PluginExecution execution : buildPlugin.getExecutions()) {
        for (final String goal : relevantGoals(execution.getGoals())) {
          final Plugin resolvedPlugin = resolvedPlugin(session, project, buildPlugin, null);
          final MojoDescriptor descriptor = descriptor(session, project, resolvedPlugin, goal);
          final String phase = lifecyclePhase(execution, descriptor);
          final int phaseIndex = phaseIndex(phase, EliderGoalOrder.DEFAULT_LIFECYCLE_PHASE_ORDER);
          if (phaseIndex >= 0 && phaseIndex <= lastLifecyclePhase) {
            addIfSelected(
                selected,
                selectedExecution(
                    session,
                    project,
                    resolvedPlugin,
                    descriptor,
                    goal,
                    execution.getId(),
                    phase,
                    MojoExecution.Source.LIFECYCLE,
                    execution.getConfiguration()));
          }
        }
      }
    }
    for (final String goalToken : goals) {
      final DirectInvocation invocation = directInvocation(session, project, goalToken);
      if (invocation == null) {
        continue;
      }
      final Plugin sourcePlugin = configuredPlugin(project, true);
      final Plugin plugin = resolvedPlugin(session, project, sourcePlugin, invocation.version());
      final MojoDescriptor descriptor = descriptor(session, project, plugin, invocation.goal());
      final String executionId = executionId(invocation);
      final PluginExecution configuredExecution = findExecution(sourcePlugin, executionId);
      final Object configuration =
          configuredExecution == null
              ? sourcePlugin == null ? null : sourcePlugin.getConfiguration()
              : configuredExecution.getConfiguration();
      addIfSelected(
          selected,
          selectedExecution(
              session,
              project,
              plugin,
              descriptor,
              invocation.goal(),
              executionId,
              "cli",
              MojoExecution.Source.CLI,
              configuration));
    }
    return List.copyOf(selected);
  }

  private SelectedExecution selectedExecution(
      final MavenSession session,
      final MavenProject project,
      final Plugin plugin,
      final MojoDescriptor descriptor,
      final String goal,
      final String executionId,
      final String phase,
      final MojoExecution.Source source,
      final Object configuration)
      throws MavenExecutionException {
    final MojoExecution execution = new MojoExecution(descriptor, executionId, source);
    execution.setLifecyclePhase(phase);
    execution.setConfiguration(asConfiguration(configuration));
    final boolean leafOnly =
        BanishedDependencyMojoConfiguration.booleanParameter(
            session, execution, LEAF_ONLY_PARAMETER, true);
    final boolean skipRequested =
        BanishedDependencyMojoConfiguration.booleanParameter(
            session, execution, SKIP_PARAMETER, false);
    final boolean skip = skipApplies(goal, skipRequested);
    final boolean aggregatorOutsideRoot =
        descriptor.isAggregator() && !project.equals(session.getTopLevelProject());
    final boolean intermediateReactorModule =
        leafOnly && ReactorLeafModuleDetector.isIntermediateReactorModule(project, session);
    if (!activationEligible(skip, aggregatorOutsideRoot, intermediateReactorModule)) {
      return null;
    }
    final List<String> rawBans =
        BanishedDependencyMojoConfiguration.banishedDependencies(session, execution);
    final List<String> normalizedBans;
    try {
      normalizedBans =
          BanishedDependencyPolicy.normalize(rawBans).stream().map(Object::toString).toList();
    } catch (final MojoFailureException exception) {
      throw new MavenExecutionException("Invalid selected dependency-elider ban policy", exception);
    }
    if (source == MojoExecution.Source.LIFECYCLE
        && !normalizedBans.isEmpty()
        && !"initialize".equals(phase)
        && !"process-classes".equals(phase)) {
      throw EliderPluginConfiguration.failure(
          project,
          "Nonempty ban policies are supported only at initialize or process-classes; "
              + "selected phase was "
              + phase);
    }
    final List<String> retainedArtifacts =
        BanishedDependencyMojoConfiguration.stringListParameter(
            session, execution, "retainedArtifacts");
    final List<String> trimSkipArtifacts =
        BanishedDependencyMojoConfiguration.stringListParameter(
            session, execution, "trimSkipArtifacts");
    return new SelectedExecution(
        project,
        execution,
        goal,
        plugin.getVersion(),
        phase,
        source,
        normalizedBans,
        retainedArtifacts,
        trimSkipArtifacts);
  }

  static boolean activationEligible(
      final boolean skipped,
      final boolean aggregatorOutsideRoot,
      final boolean intermediateReactorModule) {
    return !skipped && !aggregatorOutsideRoot && !intermediateReactorModule;
  }

  static boolean skipApplies(final String goal, final boolean skipRequested) {
    return ELIDE_GOAL.equals(goal) && skipRequested;
  }

  private static void addIfSelected(
      final List<SelectedExecution> selected, final SelectedExecution candidate) {
    if (candidate != null) {
      selected.add(candidate);
    }
  }

  static void preflightAndInject(
      final MavenSession session, final Map<MavenProject, List<SelectedExecution>> selected)
      throws MavenExecutionException {
    final Map<MavenProject, List<String>> normalizedPolicies =
        validateSelectedProjectPolicies(selected);
    final BanishedDependencyCaptureStore existing = existingStore(session);
    final Map<MavenProject, BanishedDependencyOriginalModel> captures = new LinkedHashMap<>();
    final Map<MavenProject, List<org.apache.maven.model.Dependency>> injected =
        new LinkedHashMap<>();
    for (final Map.Entry<MavenProject, List<SelectedExecution>> entry : selected.entrySet()) {
      if (entry.getValue().isEmpty()) {
        continue;
      }
      final List<SelectedExecution> executions = entry.getValue();
      final List<String> normalizedBans = normalizedPolicies.get(entry.getKey());
      final BanishedDependencyOriginalModel model =
          BanishedDependencyOriginalModel.capture(
              entry.getKey(), executionPolicies(executions), normalizedBans);
      final BanishedDependencyOriginalModel previous = existing.find(model.project());
      if (previous != null && !previous.matchesCurrentModel(model)) {
        throw EliderPluginConfiguration.failure(
            entry.getKey(),
            "Selected ban exclusion source or policy changed after it was captured");
      }
      final BanishedDependencyOriginalModel source = previous == null ? model : previous;
      captures.put(entry.getKey(), source);
      if (previous == null && !normalizedBans.isEmpty()) {
        injected.put(entry.getKey(), injectExclusions(entry.getKey(), normalizedBans));
      }
    }
    if (captures.isEmpty()) {
      return;
    }
    for (final BanishedDependencyOriginalModel.ProjectIdentity project :
        existing.projects().keySet()) {
      if (captures.keySet().stream()
          .noneMatch(
              selectedProject ->
                  project.equals(
                      BanishedDependencyOriginalModel.projectIdentity(selectedProject)))) {
        throw new MavenExecutionException(
            "Selected dependency-elider executions changed after ban policy capture",
            session.getRequest().getPom());
      }
    }
    if (!existing.projects().isEmpty()) {
      if (captures.size() != existing.projects().size()) {
        throw new MavenExecutionException(
            "Selected dependency-elider projects changed after ban policy capture",
            session.getRequest().getPom());
      }
      return;
    }
    BanishedDependencyCaptureStore updated = existing;
    for (final BanishedDependencyOriginalModel model : captures.values()) {
      updated = updated.withModel(model);
    }
    final org.eclipse.aether.SessionData data = EliderPreparationState.sessionData(session);
    if (!data.set(
        CAPTURE_STORE_KEY,
        existing.projects().isEmpty() ? null : existing.toPayload(),
        updated.toPayload())) {
      throw new MavenExecutionException(
          "Ban exclusion capture state changed during preflight", session.getRequest().getPom());
    }
    for (final Map.Entry<MavenProject, List<org.apache.maven.model.Dependency>> mutation :
        injected.entrySet()) {
      mutation.getKey().setDependencies(mutation.getValue());
    }
  }

  static Map<MavenProject, List<String>> validateSelectedProjectPolicies(
      final Map<MavenProject, List<SelectedExecution>> selected) throws MavenExecutionException {
    final Map<MavenProject, List<String>> normalizedPolicies = new LinkedHashMap<>();
    for (final Map.Entry<MavenProject, List<SelectedExecution>> entry : selected.entrySet()) {
      if (entry.getValue().isEmpty()) {
        continue;
      }
      final List<String> normalizedBans = requireConsistentBans(entry.getKey(), entry.getValue());
      for (final SelectedExecution execution : entry.getValue()) {
        try {
          BanishedDependencyPolicy.resolve(
              execution.retainedArtifacts(),
              execution.bans(),
              entry.getKey().getDependencies() == null
                  ? List.of()
                  : entry.getKey().getDependencies(),
              execution.trimSkipArtifacts(),
              List.of(),
              List.of());
        } catch (final MojoFailureException exception) {
          throw new MavenExecutionException(
              "Invalid selected dependency-elider policy for "
                  + entry.getKey().getId()
                  + ": "
                  + exception.getMessage(),
              exception);
        }
      }
      normalizedPolicies.put(entry.getKey(), normalizedBans);
    }
    return Map.copyOf(normalizedPolicies);
  }

  static List<String> requireConsistentBans(
      final MavenProject project, final List<SelectedExecution> executions)
      throws MavenExecutionException {
    final List<String> expected = executions.getFirst().bans();
    if (executions.stream().anyMatch(execution -> !expected.equals(execution.bans()))) {
      throw EliderPluginConfiguration.failure(
          project,
          "Selected dependency-elider executions have conflicting normalized ban sets: "
              + executions.stream()
                  .map(execution -> execution.execution().getExecutionId() + "=" + execution.bans())
                  .toList());
    }
    return expected;
  }

  private static List<BanishedDependencyOriginalModel.ExecutionPolicy> executionPolicies(
      final List<SelectedExecution> executions) {
    return executions.stream()
        .sorted(
            Comparator.comparing(SelectedExecution::goal)
                .thenComparing(e -> e.execution().getExecutionId()))
        .map(
            execution ->
                new BanishedDependencyOriginalModel.ExecutionPolicy(
                    execution.execution().getExecutionId(),
                    execution.goal(),
                    execution.pluginVersion(),
                    execution.phase(),
                    execution.source().name(),
                    execution.bans()))
        .toList();
  }

  static List<org.apache.maven.model.Dependency> injectExclusions(
      final MavenProject project, final List<String> bans) {
    final List<org.apache.maven.model.Dependency> dependencies = new ArrayList<>();
    for (final org.apache.maven.model.Dependency dependency : project.getDependencies()) {
      final org.apache.maven.model.Dependency copy = dependency.clone();
      final List<org.apache.maven.model.Exclusion> exclusions = new ArrayList<>();
      for (final org.apache.maven.model.Exclusion exclusion : copy.getExclusions()) {
        exclusions.add(exclusion.clone());
      }
      for (final String ban : bans) {
        final String[] coordinate = ban.split(":", -1);
        final org.apache.maven.model.Exclusion exclusion = new org.apache.maven.model.Exclusion();
        exclusion.setGroupId(coordinate[0]);
        exclusion.setArtifactId(coordinate[1]);
        if (exclusions.stream()
            .noneMatch(
                existing ->
                    exclusion.getGroupId().equals(existing.getGroupId())
                        && exclusion.getArtifactId().equals(existing.getArtifactId()))) {
          exclusions.add(exclusion);
        }
      }
      copy.setExclusions(exclusions);
      dependencies.add(copy);
    }
    return List.copyOf(dependencies);
  }

  // WHY: Malformed session payloads must fail closed.
  @SuppressWarnings(MAVEN_API_FAILURE_SUPPRESSION)
  private static BanishedDependencyCaptureStore existingStore(final MavenSession session)
      throws MavenExecutionException {
    try {
      return BanishedDependencyCaptureStore.fromPayload(
          EliderPreparationState.sessionData(session).get(CAPTURE_STORE_KEY));
    } catch (final RuntimeException exception) {
      throw new MavenExecutionException("Cannot read ban exclusion capture state", exception);
    }
  }

  // WHY: Prefix resolution failures must block policy preflight.
  @SuppressWarnings(MAVEN_API_FAILURE_SUPPRESSION)
  private DirectInvocation directInvocation(
      final MavenSession session, final MavenProject project, final String token)
      throws MavenExecutionException {
    final String[] coordinates = token.split(":", -1);
    if (coordinates.length == COLON_DELIMITED_PREFIX_GOAL && ELIDER_PREFIX.equals(coordinates[0])) {
      final MavenSession projectSession = projectSession(session, project);
      final org.apache.maven.plugin.prefix.PluginPrefixResult result;
      try {
        result =
            pluginPrefixResolver.resolve(
                new DefaultPluginPrefixRequest(ELIDER_PREFIX, projectSession));
      } catch (final Exception exception) {
        throw new MavenExecutionException(
            "Cannot resolve Maven plugin prefix " + ELIDER_PREFIX, exception);
      }
      if (!ELIDER_GROUP_ID.equals(result.getGroupId())
          || !ELIDER_ARTIFACT_ID.equals(result.getArtifactId())) {
        throw EliderPluginConfiguration.failure(
            project, "dependency-elider prefix resolved to an unexpected Maven plugin");
      }
      return invocation(coordinates[1], null);
    }
    if (coordinates.length == COLON_DELIMITED_COORDINATE_GOAL
        && ELIDER_GROUP_ID.equals(coordinates[0])
        && ELIDER_ARTIFACT_ID.equals(coordinates[1])) {
      return invocation(coordinates[2], null);
    }
    if (coordinates.length == COLON_DELIMITED_VERSION_GOAL
        && ELIDER_GROUP_ID.equals(coordinates[0])
        && ELIDER_ARTIFACT_ID.equals(coordinates[1])) {
      return invocation(coordinates[3], coordinates[2]);
    }
    return null;
  }

  static DirectInvocation invocation(final String goalToken, final String version) {
    final String[] selection = goalToken.split("@", -1);
    if (selection.length > 2 || selection[0].isBlank()) {
      return null;
    }
    final String executionId = selection.length == 2 ? selection[1] : null;
    final String goal = selection[0];
    return ELIDE_GOAL.equals(goal) || ANALYZE_GOAL.equals(goal)
        ? new DirectInvocation(goal, executionId, version)
        : null;
  }

  static String executionId(final DirectInvocation invocation) {
    return invocation.executionId() == null ? DEFAULT_CLI_EXECUTION_ID : invocation.executionId();
  }

  private Plugin configuredPlugin(final MavenProject project, final boolean includeManagement) {
    final Build build = project.getBuild();
    if (build == null) {
      return null;
    }
    final Plugin plugin = findPlugin(build.getPlugins(), ELIDER_GROUP_ID, ELIDER_ARTIFACT_ID);
    if (plugin != null || !includeManagement) {
      return plugin;
    }
    final PluginManagement management = build.getPluginManagement();
    return management == null
        ? null
        : findPlugin(management.getPlugins(), ELIDER_GROUP_ID, ELIDER_ARTIFACT_ID);
  }

  private static Plugin findPlugin(
      final List<Plugin> plugins, final String groupId, final String artifactId) {
    return plugins.stream()
        .filter(plugin -> groupId.equals(plugin.getGroupId()))
        .filter(plugin -> artifactId.equals(plugin.getArtifactId()))
        .findFirst()
        .orElse(null);
  }

  // WHY: Version resolution failures must block policy preflight.
  @SuppressWarnings(MAVEN_API_FAILURE_SUPPRESSION)
  private Plugin resolvedPlugin(
      final MavenSession session,
      final MavenProject project,
      final Plugin configured,
      final String requestedVersion)
      throws MavenExecutionException {
    final Plugin plugin = configured == null ? new Plugin() : configured.clone();
    plugin.setGroupId(ELIDER_GROUP_ID);
    plugin.setArtifactId(ELIDER_ARTIFACT_ID);
    if (requestedVersion != null) {
      plugin.setVersion(requestedVersion);
    }
    if (plugin.getVersion() == null || plugin.getVersion().isBlank()) {
      try {
        plugin.setVersion(
            pluginVersionResolver
                .resolve(new DefaultPluginVersionRequest(plugin, projectSession(session, project)))
                .getVersion());
      } catch (final Exception exception) {
        throw new MavenExecutionException(
            "Cannot resolve dependency-elider plugin version for ban policy preflight", exception);
      }
    }
    if (plugin.getVersion() == null || plugin.getVersion().isBlank()) {
      throw EliderPluginConfiguration.failure(
          project, "Cannot resolve dependency-elider plugin version for ban policy preflight");
    }
    return plugin;
  }

  // WHY: Descriptor resolution failures must block policy preflight.
  @SuppressWarnings(MAVEN_API_FAILURE_SUPPRESSION)
  private MojoDescriptor descriptor(
      final MavenSession session,
      final MavenProject project,
      final Plugin plugin,
      final String goal)
      throws MavenExecutionException {
    try {
      final List<RemoteRepository> repositories =
          project.getRemotePluginRepositories() == null
              ? List.of()
              : project.getRemotePluginRepositories();
      final MojoDescriptor descriptor =
          mavenPluginManager.getMojoDescriptor(
              plugin, goal, repositories, projectSession(session, project).getRepositorySession());
      final String descriptorVersion =
          descriptor.getPluginDescriptor() == null
                  || descriptor.getPluginDescriptor().getPluginArtifact() == null
              ? null
              : descriptor.getPluginDescriptor().getPluginArtifact().getVersion();
      if (!plugin.getVersion().equals(descriptorVersion)) {
        throw EliderPluginConfiguration.failure(
            project,
            "Resolved dependency-elider descriptor version "
                + descriptorVersion
                + " does not match selected version "
                + plugin.getVersion());
      }
      return descriptor;
    } catch (final MavenExecutionException exception) {
      throw exception;
    } catch (final Exception exception) {
      throw new MavenExecutionException(
          "Cannot resolve dependency-elider:" + goal + " descriptor for ban policy preflight",
          exception);
    }
  }

  static String lifecyclePhase(final PluginExecution execution, final MojoDescriptor descriptor) {
    final String configured = execution.getPhase();
    if (configured != null) {
      return configured;
    }
    return descriptor.getPhase() == null ? "" : descriptor.getPhase();
  }

  static int lastLifecyclePhase(final List<String> goals, final List<String> phaseOrder) {
    Objects.requireNonNull(phaseOrder, "phaseOrder");
    int last = -1;
    for (final String goal : goals) {
      final int index = phaseOrder.indexOf(goal);
      last = Math.max(last, index);
    }
    return last;
  }

  static int phaseIndex(final String phase, final List<String> phaseOrder) {
    if (phase == null || phase.isBlank() || "none".equals(phase)) {
      return -1;
    }
    return Objects.requireNonNull(phaseOrder, "phaseOrder").indexOf(phase);
  }

  private static boolean isNonDefaultTask(final String task) {
    return task.contains(":") || "help".equals(task) || NON_DEFAULT_LIFECYCLE_PHASES.contains(task);
  }

  static boolean hasDefaultLifecycleTask(final List<String> goals) {
    return goals.stream().anyMatch(goal -> !isNonDefaultTask(goal));
  }

  private static boolean hasUnknownLifecycleTask(final List<String> goals) {
    return goals.stream()
        .anyMatch(
            goal ->
                !isNonDefaultTask(goal)
                    && !EliderGoalOrder.DEFAULT_LIFECYCLE_PHASE_ORDER.contains(goal));
  }

  private static boolean hasPotentialBanPolicy(
      final MavenSession session, final MavenProject project, final Plugin plugin) {
    if (hasNonemptyProperty(session.getUserProperties().getProperty("elide.banishedDependencies"))
        || hasNonemptyProperty(
            session.getSystemProperties().getProperty("elide.banishedDependencies"))
        || hasNonemptyProperty(project.getProperties().getProperty("elide.banishedDependencies"))) {
      return true;
    }
    if (plugin == null) {
      return false;
    }
    return hasBanParameter(plugin.getConfiguration())
        || plugin.getExecutions().stream()
            .filter(execution -> !relevantGoals(execution.getGoals()).isEmpty())
            .anyMatch(execution -> hasBanParameter(execution.getConfiguration()));
  }

  private static boolean hasBanParameter(final Object configuration) {
    if (!(configuration instanceof Xpp3Dom root)) {
      return false;
    }
    final Xpp3Dom parameter = root.getChild("banishedDependencies");
    return parameter != null
        && ((parameter.getChildren() != null && parameter.getChildren().length > 0)
            || hasNonemptyProperty(parameter.getValue()));
  }

  private static boolean hasNonemptyProperty(final String value) {
    return value != null && !value.isBlank();
  }

  private static List<String> relevantGoals(final List<String> goals) {
    return goals.stream()
        .filter(goal -> ELIDE_GOAL.equals(goal) || ANALYZE_GOAL.equals(goal))
        .toList();
  }

  private static List<MavenProject> selectedProjects(final MavenSession session) {
    if (session.getProjects() != null && !session.getProjects().isEmpty()) {
      return List.copyOf(session.getProjects());
    }
    return session.getTopLevelProject() == null ? List.of() : List.of(session.getTopLevelProject());
  }

  static List<String> requestedGoals(final MavenSession session) {
    final MavenExecutionRequest request = session.getRequest();
    if (request == null) {
      return List.of();
    }
    if (request.getGoals() != null && !request.getGoals().isEmpty()) {
      return List.copyOf(request.getGoals());
    }
    final MavenProject root = session.getTopLevelProject();
    final Build build = root == null ? null : root.getBuild();
    final String defaultGoal = build == null ? null : build.getDefaultGoal();
    if (defaultGoal == null || defaultGoal.isBlank()) {
      return List.of();
    }
    final List<String> tokens = new ArrayList<>();
    final StringTokenizer tokenizer = new StringTokenizer(defaultGoal);
    while (tokenizer.hasMoreTokens()) {
      tokens.add(tokenizer.nextToken());
    }
    return List.copyOf(tokens);
  }

  private static MavenSession projectSession(
      final MavenSession session, final MavenProject project) {
    final MavenSession clone = session.clone();
    clone.setCurrentProject(project);
    return clone;
  }

  static PluginExecution findExecution(final Plugin plugin, final String executionId) {
    if (plugin == null || executionId == null) {
      return null;
    }
    return plugin.getExecutions().stream()
        .filter(execution -> executionId.equals(execution.getId()))
        .findFirst()
        .orElse(null);
  }

  private static Xpp3Dom asConfiguration(final Object configuration) {
    return configuration instanceof Xpp3Dom dom ? new Xpp3Dom(dom) : null;
  }

  record DirectInvocation(String goal, String executionId, String version) {}

  record SelectedExecution(
      MavenProject project,
      MojoExecution execution,
      String goal,
      String pluginVersion,
      String phase,
      MojoExecution.Source source,
      List<String> bans,
      List<String> retainedArtifacts,
      List<String> trimSkipArtifacts) {
    SelectedExecution {
      bans = List.copyOf(bans);
      retainedArtifacts = List.copyOf(retainedArtifacts);
      trimSkipArtifacts = List.copyOf(trimSkipArtifacts);
    }
  }
}
