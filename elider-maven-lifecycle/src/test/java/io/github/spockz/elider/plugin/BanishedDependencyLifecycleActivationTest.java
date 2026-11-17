// WHY: Proves Maven's selected-goal activation rules without executing resolver work.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.apache.maven.MavenExecutionException;
import org.apache.maven.execution.DefaultMavenExecutionRequest;
import org.apache.maven.execution.DefaultMavenExecutionResult;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.model.Build;
import org.apache.maven.model.Dependency;
import org.apache.maven.model.Exclusion;
import org.apache.maven.model.Model;
import org.apache.maven.model.Plugin;
import org.apache.maven.model.PluginExecution;
import org.apache.maven.plugin.MojoExecution;
import org.apache.maven.plugin.descriptor.MojoDescriptor;
import org.apache.maven.project.MavenProject;
import org.eclipse.aether.DefaultRepositorySystemSession;
import org.junit.jupiter.api.Test;

/** Tests selected goal, lifecycle phase, skip, and exact execution-id rules. */
@SuppressWarnings({"PMD.AtLeastOneConstructor", "PMD.LawOfDemeter", "PMD.TooManyMethods"})
final class BanishedDependencyLifecycleActivationTest {
  /** Direct elision goal token. */
  private static final String ELIDE_GOAL = "elide";

  /** Direct analysis goal token. */
  private static final String ANALYZE_GOAL = "analyze";

  /** First relevant lifecycle endpoint. */
  private static final String INITIALIZE_PHASE = "initialize";

  /** Trusted lifecycle endpoint after production compilation. */
  private static final String PROCESS_CLASSES_PHASE = "process-classes";

  @Test
  void explicitGoalsTakePrecedenceOverDefaultGoalAndEmptyRequestsUseDefaultGoal() {
    final MavenProject project = project();
    project.getBuild().setDefaultGoal("validate dependency-elider:analyze");
    final DefaultMavenExecutionRequest explicit = new DefaultMavenExecutionRequest();
    explicit.setGoals(List.of(PROCESS_CLASSES_PHASE));
    final MavenSession explicitSession = new MavenSession(null, explicit, null, project);
    final MavenSession defaultSession =
        new MavenSession(null, new DefaultMavenExecutionRequest(), null, project);

    assertAll(
        "Only an empty request falls back to the root project's defaultGoal",
        () ->
            assertThat(BanishedDependencyLifecycleActivation.requestedGoals(explicitSession))
                .containsExactly(PROCESS_CLASSES_PHASE),
        () ->
            assertThat(BanishedDependencyLifecycleActivation.requestedGoals(defaultSession))
                .containsExactly("validate", "dependency-elider:analyze"));
  }

  @Test
  void declaredPluginExecutionIsInactiveUntilTreePromotion() throws Exception {
    final MavenProject project = projectWithElideExecution(PROCESS_CLASSES_PHASE);
    final DefaultMavenExecutionRequest inactiveRequest = new DefaultMavenExecutionRequest();
    final MavenSession inactiveSession = new MavenSession(null, inactiveRequest, null, project);
    inactiveSession.setProjects(List.of(project));

    final MavenProject promotedProject = projectWithElideExecution(PROCESS_CLASSES_PHASE);
    final DefaultMavenExecutionRequest treeRequest = new DefaultMavenExecutionRequest();
    treeRequest.setGoals(List.of("dependency:tree"));
    final MavenSession treeSession = new MavenSession(null, treeRequest, null, promotedProject);
    treeSession.setProjects(List.of(promotedProject));

    EliderTreePreparation.schedule(treeSession);

    assertAll(
        "Declared executions activate only through selected goals or scheduler promotion",
        () ->
            assertThat(
                    BanishedDependencyLifecycleActivation.hasSelectedTasks(
                        inactiveSession.getProjects(),
                        BanishedDependencyLifecycleActivation.requestedGoals(inactiveSession)))
                .isFalse(),
        () ->
            assertThat(BanishedDependencyLifecycleActivation.requestedGoals(treeSession))
                .containsExactly(PROCESS_CLASSES_PHASE, "dependency:tree"),
        () ->
            assertThat(
                    BanishedDependencyLifecycleActivation.hasSelectedTasks(
                        treeSession.getProjects(),
                        BanishedDependencyLifecycleActivation.requestedGoals(treeSession)))
                .isTrue());
  }

  @Test
  void lifecyclePhaseDefaultAndExplicitInactiveValuesRemainDistinct() {
    final MojoDescriptor defaultInitialize = new MojoDescriptor();
    defaultInitialize.setPhase(INITIALIZE_PHASE);
    final MojoDescriptor noDefault = new MojoDescriptor();
    final PluginExecution missing = new PluginExecution();
    final PluginExecution blank = new PluginExecution();
    blank.setPhase("");
    final PluginExecution none = new PluginExecution();
    none.setPhase("none");

    assertAll(
        "Only a missing phase may inherit the Mojo descriptor default",
        () ->
            assertThat(
                    BanishedDependencyLifecycleActivation.lifecyclePhase(
                        missing, defaultInitialize))
                .isEqualTo(INITIALIZE_PHASE),
        () ->
            assertThat(
                    BanishedDependencyLifecycleActivation.lifecyclePhase(blank, defaultInitialize))
                .isEmpty(),
        () ->
            assertThat(
                    BanishedDependencyLifecycleActivation.lifecyclePhase(none, defaultInitialize))
                .isEqualTo("none"),
        () ->
            assertThat(BanishedDependencyLifecycleActivation.lifecyclePhase(missing, noDefault))
                .isEmpty());
  }

  @Test
  void selectedLifecycleEndpointIncludesEarlierPhasesOnly() {
    final List<String> lifecycles = EliderGoalOrder.DEFAULT_LIFECYCLE_PHASE_ORDER;
    final int endpoint =
        BanishedDependencyLifecycleActivation.lastLifecyclePhase(
            List.of(PROCESS_CLASSES_PHASE), lifecycles);

    assertAll(
        "Lifecycle bound goals are selected only when their phase is reached",
        () ->
            assertThat(
                    BanishedDependencyLifecycleActivation.phaseIndex(INITIALIZE_PHASE, lifecycles))
                .isLessThanOrEqualTo(endpoint),
        () ->
            assertThat(
                    BanishedDependencyLifecycleActivation.phaseIndex(
                        PROCESS_CLASSES_PHASE, lifecycles))
                .isEqualTo(endpoint),
        () ->
            assertThat(BanishedDependencyLifecycleActivation.phaseIndex("validate", lifecycles))
                .isLessThanOrEqualTo(endpoint),
        () ->
            assertThat(BanishedDependencyLifecycleActivation.phaseIndex("verify", lifecycles))
                .isGreaterThan(endpoint),
        () ->
            assertThat(
                    BanishedDependencyLifecycleActivation.lastLifecyclePhase(
                        List.of("dependency-elider:elide"), lifecycles))
                .isEqualTo(-1));
  }

  @Test
  void directAndOtherLifecycleTasksDoNotCountAsDefaultLifecyclePhases() {
    assertAll(
        "Default lifecycle selection recognizes the task without looking up a Lifecycle component",
        () ->
            assertThat(
                    BanishedDependencyLifecycleActivation.hasDefaultLifecycleTask(
                        List.of("dependency-elider:elide")))
                .isFalse(),
        () ->
            assertThat(
                    BanishedDependencyLifecycleActivation.hasDefaultLifecycleTask(
                        List.of("clean", "site")))
                .isFalse(),
        () ->
            assertThat(
                    BanishedDependencyLifecycleActivation.hasDefaultLifecycleTask(
                        List.of("process-classes")))
                .isTrue(),
        () ->
            assertThat(
                    BanishedDependencyLifecycleActivation.hasDefaultLifecycleTask(
                        List.of("custom-phase")))
                .isTrue());
  }

  @Test
  void directGoalIdSelectsOnlyThatExecutionAndMissingIdFallsBackToPluginConfig() {
    final BanishedDependencyLifecycleActivation.DirectInvocation named =
        BanishedDependencyLifecycleActivation.invocation(ELIDE_GOAL + "@named", null);
    final BanishedDependencyLifecycleActivation.DirectInvocation defaultCliInvocation =
        BanishedDependencyLifecycleActivation.invocation(ANALYZE_GOAL, null);
    final Plugin plugin = new Plugin();
    final PluginExecution other = new PluginExecution();
    other.setId("other");
    other.addGoal(ELIDE_GOAL);
    final PluginExecution selected = new PluginExecution();
    selected.setId("named");
    final PluginExecution defaultCliExecution = new PluginExecution();
    defaultCliExecution.setId("default-cli");
    plugin.addExecution(other);
    plugin.addExecution(selected);
    plugin.addExecution(defaultCliExecution);

    assertAll(
        "A named direct request never borrows another execution's configuration",
        () -> assertThat(named.executionId()).isEqualTo("named"),
        () -> assertThat(defaultCliInvocation.executionId()).isNull(),
        () ->
            assertThat(BanishedDependencyLifecycleActivation.executionId(defaultCliInvocation))
                .isEqualTo("default-cli"),
        () ->
            assertThat(
                    BanishedDependencyLifecycleActivation.findExecution(
                        plugin, named.executionId()))
                .isSameAs(selected),
        () ->
            assertThat(
                    BanishedDependencyLifecycleActivation.findExecution(
                        plugin,
                        BanishedDependencyLifecycleActivation.executionId(defaultCliInvocation)))
                .isSameAs(defaultCliExecution),
        () ->
            assertThat(BanishedDependencyLifecycleActivation.findExecution(plugin, "missing"))
                .isNull(),
        () ->
            assertThat(BanishedDependencyLifecycleActivation.findExecution(plugin, null)).isNull());
  }

  @Test
  void skipSuppressesElideOnlyAndLeafOrAggregatorFiltersRemainIndependent() {
    assertAll(
        "Analyze remains selected when elide.skip is true",
        () ->
            assertThat(BanishedDependencyLifecycleActivation.skipApplies(ELIDE_GOAL, true))
                .isTrue(),
        () ->
            assertThat(BanishedDependencyLifecycleActivation.skipApplies("analyze", true))
                .isFalse(),
        () ->
            assertThat(
                    BanishedDependencyLifecycleActivation.activationEligible(false, false, false))
                .isTrue(),
        () ->
            assertThat(BanishedDependencyLifecycleActivation.activationEligible(false, false, true))
                .isFalse(),
        () ->
            assertThat(BanishedDependencyLifecycleActivation.activationEligible(false, true, false))
                .isFalse(),
        () ->
            assertThat(BanishedDependencyLifecycleActivation.activationEligible(true, false, false))
                .isFalse());
  }

  @Test
  @SuppressWarnings("PMD.AvoidDuplicateLiterals")
  void conflictingSelectedBanSetsFailBeforeProjectDependenciesChange() {
    final MavenProject project = project();
    final Dependency original = new Dependency();
    original.setGroupId("org.example");
    original.setArtifactId("direct");
    original.setVersion("1.0");
    project.setDependencies(List.of(original));
    final List<BanishedDependencyLifecycleActivation.SelectedExecution> selected =
        List.of(
            selectedExecution(project, ELIDE_GOAL, "first", List.of("org.one:a")),
            selectedExecution(project, ANALYZE_GOAL, "second", List.of("org.two:b")));

    assertAll(
        "Conflicting selected execution policies are rejected during preflight",
        () ->
            assertThatThrownBy(
                    () ->
                        BanishedDependencyLifecycleActivation.requireConsistentBans(
                            project, selected))
                .isInstanceOf(MavenExecutionException.class)
                .hasMessageContaining("conflicting normalized ban sets"),
        () -> assertThat(project.getDependencies()).containsExactly(original));
  }

  @Test
  @SuppressWarnings("PMD.AvoidDuplicateLiterals")
  void injectedExclusionsPreserveUserEntriesAndAreIdempotentOnCopiedDependencies() {
    final MavenProject project = project();
    final Dependency original = new Dependency();
    original.setGroupId("org.example");
    original.setArtifactId("direct");
    original.setVersion("1.0");
    final Exclusion userExclusion = new Exclusion();
    userExclusion.setGroupId("org.user");
    userExclusion.setArtifactId("existing");
    original.addExclusion(userExclusion);
    final Dependency secondOriginal = new Dependency();
    secondOriginal.setGroupId("org.example");
    secondOriginal.setArtifactId("second-direct");
    secondOriginal.setVersion("1.0");
    project.setDependencies(List.of(original, secondOriginal));

    final List<Dependency> firstPass =
        BanishedDependencyLifecycleActivation.injectExclusions(
            project, List.of("org.banned:library", "org.banned:library"));
    project.setDependencies(firstPass);
    final List<Dependency> secondPass =
        BanishedDependencyLifecycleActivation.injectExclusions(
            project, List.of("org.banned:library"));

    assertAll(
        "Injection keeps declared exclusions and only mutates cloned dependencies",
        () -> assertThat(original.getExclusions()).containsExactly(userExclusion),
        () -> assertThat(firstPass).hasSize(2),
        () -> assertThat(firstPass.getFirst()).isNotSameAs(original),
        () ->
            assertThat(firstPass.getFirst().getExclusions())
                .extracting(Exclusion::getGroupId, Exclusion::getArtifactId)
                .containsExactly(
                    org.assertj.core.groups.Tuple.tuple("org.user", "existing"),
                    org.assertj.core.groups.Tuple.tuple("org.banned", "library")),
        () ->
            assertThat(firstPass.get(1).getExclusions())
                .extracting(Exclusion::getGroupId, Exclusion::getArtifactId)
                .containsExactly(org.assertj.core.groups.Tuple.tuple("org.banned", "library")),
        () -> assertThat(secondPass).usingRecursiveComparison().isEqualTo(firstPass));
  }

  @Test
  void repeatedCoordinatorActivationKeepsInjectedPolicyAndCaptureStable() throws Exception {
    final MavenProject project = project();
    project.setFile(Path.of("/tmp", "policy-capture-replay", "pom.xml").toFile());
    final Dependency first = dependency("first", "org.example");
    first.addExclusion(exclusion("legacy", "blocked"));
    final Dependency second = dependency("second", "org.example");
    project.setDependencies(List.of(first, second));
    final DefaultRepositorySystemSession repositorySession = new DefaultRepositorySystemSession();
    final MavenSession session =
        new MavenSession(
            null,
            repositorySession,
            new DefaultMavenExecutionRequest(),
            new DefaultMavenExecutionResult());
    session.setCurrentProject(project);
    final Map<MavenProject, List<BanishedDependencyLifecycleActivation.SelectedExecution>>
        selected =
            Map.of(
                project,
                List.of(
                    selectedExecution(
                        project, ELIDE_GOAL, "replay", List.of("org.banned:library"))));

    BanishedDependencyLifecycleActivation.preflightAndInject(session, selected);
    final Object firstPayload =
        repositorySession.getData().get(BanishedDependencyLifecycleActivation.CAPTURE_STORE_KEY);
    final List<Dependency> firstInjection = project.getDependencies();
    BanishedDependencyLifecycleActivation.preflightAndInject(session, selected);
    final Object replayPayload =
        repositorySession.getData().get(BanishedDependencyLifecycleActivation.CAPTURE_STORE_KEY);

    assertAll(
        "Repeated participant activation is idempotent and preserves its original capture",
        () -> assertThat(project.getDependencies()).hasSize(2),
        () -> assertThat(project.getDependencies()).containsExactlyElementsOf(firstInjection),
        () -> assertBanExclusionCount(firstInjection.getFirst(), 1),
        () -> assertBanExclusionCount(firstInjection.get(1), 1),
        () ->
            assertThat(firstInjection.getFirst().getExclusions())
                .extracting(Exclusion::getGroupId, Exclusion::getArtifactId)
                .containsExactly(
                    org.assertj.core.groups.Tuple.tuple("legacy", "blocked"),
                    org.assertj.core.groups.Tuple.tuple("org.banned", "library")),
        () -> assertThat(replayPayload).isEqualTo(firstPayload),
        () ->
            assertThat(capturedSourceFingerprint(replayPayload, project))
                .isEqualTo(capturedSourceFingerprint(firstPayload, project)));
  }

  @Test
  void analyzeOnlyCapturesBanPolicyWithoutInjectingProjectExclusions() throws Exception {
    final MavenProject project = project();
    project.setFile(Path.of("/tmp", "policy-capture-analyze", "pom.xml").toFile());
    final Dependency original = dependency("direct", "org.example");
    project.setDependencies(List.of(original));
    final DefaultRepositorySystemSession repositorySession = new DefaultRepositorySystemSession();
    final MavenSession session =
        new MavenSession(
            null,
            repositorySession,
            new DefaultMavenExecutionRequest(),
            new DefaultMavenExecutionResult());
    session.setCurrentProject(project);

    BanishedDependencyLifecycleActivation.preflightAndInject(
        session,
        Map.of(
            project,
            List.of(
                selectedExecution(
                    project, ANALYZE_GOAL, "analyze-only", List.of("org.banned:library")))));

    final Object capture =
        repositorySession.getData().get(BanishedDependencyLifecycleActivation.CAPTURE_STORE_KEY);
    assertAll(
        "Analyze captures original input for prediction without changing the live Maven model",
        () -> assertThat(project.getDependencies()).containsExactly(original),
        () -> assertThat(original.getExclusions()).isEmpty(),
        () -> assertThat(capture).isNotNull(),
        () ->
            assertThat(
                    BanishedDependencyCaptureStore.fromPayload(capture)
                        .find(BanishedDependencyOriginalModel.projectIdentity(project)))
                .isNotNull());
  }

  @Test
  void analyzeSelectedWithElideUsesTheEnforcedModelForTheSharedInvocation() throws Exception {
    final MavenProject project = project();
    project.setFile(Path.of("/tmp", "policy-capture-mixed", "pom.xml").toFile());
    project.setDependencies(List.of(dependency("direct", "org.example")));
    final DefaultRepositorySystemSession repositorySession = new DefaultRepositorySystemSession();
    final MavenSession session =
        new MavenSession(
            null,
            repositorySession,
            new DefaultMavenExecutionRequest(),
            new DefaultMavenExecutionResult());
    session.setCurrentProject(project);
    final List<BanishedDependencyLifecycleActivation.SelectedExecution> executions =
        List.of(
            selectedExecution(project, ANALYZE_GOAL, "analyze", List.of("org.banned:library")),
            selectedExecution(project, ELIDE_GOAL, ELIDE_GOAL, List.of("org.banned:library")));

    BanishedDependencyLifecycleActivation.preflightAndInject(session, Map.of(project, executions));

    final BanishedDependencyOriginalModel capture =
        BanishedDependencyCaptureStore.fromPayload(
                repositorySession
                    .getData()
                    .get(BanishedDependencyLifecycleActivation.CAPTURE_STORE_KEY))
            .find(BanishedDependencyOriginalModel.projectIdentity(project));
    final BanishedDependencyOriginalModel current =
        BanishedDependencyOriginalModel.capture(
            project, capture.executions(), capture.banishedDependencies());
    assertAll(
        "The shared invocation injects exclusions because Elide is selected",
        () -> assertBanExclusionCount(project.getDependencies().getFirst(), 1),
        () -> assertThat(capture.matchesInjectedModel(current)).isTrue(),
        () -> assertThat(capture.matchesCurrentModel(current)).isTrue());
  }

  private static String capturedSourceFingerprint(
      final Object payload, final MavenProject project) {
    return BanishedDependencyCaptureStore.fromPayload(payload)
        .find(BanishedDependencyOriginalModel.projectIdentity(project))
        .sourceFingerprint();
  }

  private static void assertBanExclusionCount(final Dependency dependency, final int expected) {
    assertThat(dependency.getExclusions())
        .filteredOn(
            exclusion ->
                "org.banned".equals(exclusion.getGroupId())
                    && "library".equals(exclusion.getArtifactId()))
        .hasSize(expected);
  }

  @Test
  @SuppressWarnings("PMD.UseConcurrentHashMap")
  void policyPreflightChecksLaterProjectsBeforeAnyMutation() {
    final MavenProject firstProject = project();
    final Dependency firstDependency = dependency("first-direct", "org.example");
    firstProject.setDependencies(List.of(firstDependency));
    final MavenProject laterProject = project();
    laterProject.getModel().setArtifactId("later-consumer");
    final Dependency laterDependency = dependency("library", "org.banned");
    laterProject.setDependencies(List.of(laterDependency));
    final Map<MavenProject, List<BanishedDependencyLifecycleActivation.SelectedExecution>>
        directConflict = new LinkedHashMap<>();
    directConflict.put(
        firstProject,
        List.of(
            selectedExecution(firstProject, ELIDE_GOAL, "first", List.of("org.banned:library"))));
    directConflict.put(
        laterProject,
        List.of(
            selectedExecution(laterProject, ELIDE_GOAL, "later", List.of("org.banned:library"))));
    final DefaultRepositorySystemSession repositorySession = new DefaultRepositorySystemSession();
    final MavenSession mavenSession =
        new MavenSession(
            null,
            repositorySession,
            new DefaultMavenExecutionRequest(),
            new DefaultMavenExecutionResult());
    mavenSession.setCurrentProject(firstProject);

    final MavenProject policyProject = project();
    final Dependency policyDependency = dependency("unrelated", "org.example");
    policyProject.setDependencies(List.of(policyDependency));
    final Map<MavenProject, List<BanishedDependencyLifecycleActivation.SelectedExecution>>
        retainedConflict =
            Map.of(
                policyProject,
                List.of(
                    selectedExecution(
                        policyProject,
                        ELIDE_GOAL,
                        "retained",
                        List.of("org.banned:library"),
                        List.of("org.banned:library"),
                        List.of())));
    final Map<MavenProject, List<BanishedDependencyLifecycleActivation.SelectedExecution>>
        trimSkipConflict =
            Map.of(
                policyProject,
                List.of(
                    selectedExecution(
                        policyProject,
                        ELIDE_GOAL,
                        "trim-skip",
                        List.of("org.banned:library"),
                        List.of(),
                        List.of("org.banned:library:jar"))));

    assertAll(
        "Direct declaration and policy conflicts fail before capture or dependency mutation",
        () ->
            assertThatThrownBy(
                    () ->
                        BanishedDependencyLifecycleActivation.preflightAndInject(
                            mavenSession, directConflict))
                .isInstanceOf(MavenExecutionException.class)
                .hasMessageContaining("direct first-level dependency"),
        () -> assertThat(firstProject.getDependencies()).containsExactly(firstDependency),
        () -> assertThat(laterProject.getDependencies()).containsExactly(laterDependency),
        () ->
            assertThat(
                    repositorySession
                        .getData()
                        .get(BanishedDependencyLifecycleActivation.CAPTURE_STORE_KEY))
                .isNull(),
        () ->
            assertThatThrownBy(
                    () ->
                        BanishedDependencyLifecycleActivation.validateSelectedProjectPolicies(
                            retainedConflict))
                .isInstanceOf(MavenExecutionException.class)
                .hasMessageContaining("retainedArtifacts"),
        () -> assertThat(policyProject.getDependencies()).containsExactly(policyDependency),
        () ->
            assertThatThrownBy(
                    () ->
                        BanishedDependencyLifecycleActivation.validateSelectedProjectPolicies(
                            trimSkipConflict))
                .isInstanceOf(MavenExecutionException.class)
                .hasMessageContaining("trimSkipArtifacts"),
        () -> assertThat(policyProject.getDependencies()).containsExactly(policyDependency));
  }

  private static Dependency dependency(final String artifactId, final String groupId) {
    final Dependency dependency = new Dependency();
    dependency.setGroupId(groupId);
    dependency.setArtifactId(artifactId);
    dependency.setVersion("1.0");
    return dependency;
  }

  private static Exclusion exclusion(final String groupId, final String artifactId) {
    final Exclusion exclusion = new Exclusion();
    exclusion.setGroupId(groupId);
    exclusion.setArtifactId(artifactId);
    return exclusion;
  }

  private static MavenProject project() {
    final Model model = new Model();
    model.setGroupId("org.example");
    model.setArtifactId("consumer");
    model.setVersion("1.0");
    final MavenProject project = new MavenProject(model);
    project.setBuild(new Build());
    return project;
  }

  private static MavenProject projectWithElideExecution(final String phase) {
    final MavenProject project = project();
    final Plugin plugin = new Plugin();
    plugin.setGroupId("io.github.spockz");
    plugin.setArtifactId("dependency-elider-maven-plugin");
    plugin.setVersion("1.0.0");
    final PluginExecution execution = new PluginExecution();
    execution.setId("selected-elide");
    execution.setPhase(phase);
    execution.addGoal(ELIDE_GOAL);
    plugin.addExecution(execution);
    project.getBuild().addPlugin(plugin);
    return project;
  }

  private static BanishedDependencyLifecycleActivation.SelectedExecution selectedExecution(
      final MavenProject project,
      final String goal,
      final String executionId,
      final List<String> bans) {
    return selectedExecution(project, goal, executionId, bans, List.of(), List.of());
  }

  private static BanishedDependencyLifecycleActivation.SelectedExecution selectedExecution(
      final MavenProject project,
      final String goal,
      final String executionId,
      final List<String> bans,
      final List<String> retainedArtifacts,
      final List<String> trimSkipArtifacts) {
    return new BanishedDependencyLifecycleActivation.SelectedExecution(
        project,
        new MojoExecution(null, executionId, MojoExecution.Source.LIFECYCLE),
        goal,
        "1.0.0",
        INITIALIZE_PHASE,
        MojoExecution.Source.LIFECYCLE,
        bans,
        retainedArtifacts,
        trimSkipArtifacts);
  }
}
