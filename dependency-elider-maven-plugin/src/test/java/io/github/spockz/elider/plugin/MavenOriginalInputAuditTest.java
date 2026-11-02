// WHY: Proves audit reconstruction is isolated from Maven's live views and shared graph state.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.io.IOException;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.model.Dependency;
import org.apache.maven.model.DependencyManagement;
import org.apache.maven.model.Exclusion;
import org.apache.maven.model.Model;
import org.apache.maven.project.DependencyResolutionRequest;
import org.apache.maven.project.DependencyResolutionResult;
import org.apache.maven.project.MavenProject;
import org.apache.maven.project.ProjectDependenciesResolver;
import org.eclipse.aether.DefaultRepositoryCache;
import org.eclipse.aether.DefaultRepositorySystemSession;
import org.eclipse.aether.RepositoryException;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.eclipse.aether.collection.DependencyGraphTransformationContext;
import org.eclipse.aether.collection.DependencyGraphTransformer;
import org.eclipse.aether.graph.DefaultDependencyNode;
import org.eclipse.aether.graph.DependencyNode;
import org.eclipse.aether.repository.WorkspaceReader;
import org.eclipse.aether.repository.WorkspaceRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Exercises the frozen model and isolated resolver audit. */
@SuppressWarnings({
  "PMD.AtLeastOneConstructor",
  "PMD.CommentDefaultAccessModifier",
  "PMD.CouplingBetweenObjects",
  "PMD.ExcessiveImports",
  "PMD.LawOfDemeter",
  "PMD.TooManyMethods"
})
final class MavenOriginalInputAuditTest {
  /** Supplies one synthetic Maven group across the fixture graph. */
  private static final String GROUP = "org.example";

  /** Identifies the dependency whose exclusion is injected by the captured policy. */
  private static final String BANNED = "banned";

  /** Root whose original exclusion survives reconstruction. */
  private static final String LIBRARY = "library";

  /** Supplies the isolated Maven project and artifact bytes for each test. */
  @TempDir Path temporaryDirectory;

  /** Maven coordinate version used by all synthetic artifacts. */
  private static final String VERSION = "1.0";

  /** Default extension for supported fixture artifacts. */
  private static final String JAR = "jar";

  /** Effective scope for supported fixture providers. */
  private static final String COMPILE = "compile";

  @Test
  void rejectsUnsupportedOriginalMatchesEvenWhenInjectionHidesThemOrSupportedMatchesExist()
      throws IOException {
    final MavenProject project = project(temporaryDirectory);
    project.setDependencies(new ArrayList<>(List.of(dependency(LIBRARY))));
    final List<String> bans = List.of(GROUP + ":" + BANNED);
    final BanishedDependencyOriginalModel captured =
        BanishedDependencyOriginalModel.capture(
            project,
            List.of(
                new BanishedDependencyOriginalModel.ExecutionPolicy(
                    "run-elide", "elide", "1.0.0", "initialize", "LIFECYCLE", bans)),
            bans);
    final DefaultRepositorySystemSession repositorySession = new DefaultRepositorySystemSession();
    repositorySession
        .getData()
        .set(
            BanishedDependencyLifecycleActivation.CAPTURE_STORE_KEY,
            BanishedDependencyCaptureStore.empty().withModel(captured).toPayload());
    project.setDependencies(BanishedDependencyLifecycleActivation.injectExclusions(project, bans));
    project.setArtifacts(Set.of());
    final MavenSession session = session(project, repositorySession);
    MavenOriginalInputAudit.markHookPresent(session);
    final Path provider = temporaryDirectory.resolve("original-provider.jar");
    Files.writeString(provider, "original provider");
    final org.eclipse.aether.graph.Dependency library = resolvedLibrary(temporaryDirectory);
    final List<UnsupportedOriginal> cases =
        List.of(
            new UnsupportedOriginal("test", JAR, JAR),
            new UnsupportedOriginal("provided", JAR, JAR),
            new UnsupportedOriginal("system", JAR, JAR),
            new UnsupportedOriginal("runtime", "zip", "zip"),
            new UnsupportedOriginal("runtime", JAR, "zip"),
            new UnsupportedOriginal("compile", "test-jar", JAR));

    assertAll(
        "unsupported original TEST-context matches cannot disappear behind injected exclusions",
        cases.stream()
            .map(
                scenario ->
                    () -> {
                      final org.eclipse.aether.graph.Dependency unsupported =
                          new org.eclipse.aether.graph.Dependency(
                              new DefaultArtifact(
                                      GROUP, BANNED, "unsupported", scenario.extension(), VERSION)
                                  .setProperties(Map.of("type", scenario.mavenType()))
                                  .setFile(provider.toFile()),
                              scenario.scope());
                      final org.eclipse.aether.graph.Dependency supported =
                          new org.eclipse.aether.graph.Dependency(
                              new DefaultArtifact(GROUP, BANNED, "supported", JAR, VERSION)
                                  .setFile(provider.toFile()),
                              "compile");
                      assertAll(
                          scenario.toString(),
                          List.of(
                                  List.of(library, unsupported),
                                  List.of(library, supported, unsupported))
                              .stream()
                              .map(
                                  original ->
                                      () -> {
                                        final DependencyNode originalGraph = graph();
                                        for (final org.eclipse.aether.graph.Dependency dependency :
                                            original.subList(1, original.size())) {
                                          originalGraph
                                              .getChildren()
                                              .getFirst()
                                              .getChildren()
                                              .add(new DefaultDependencyNode(dependency));
                                        }
                                        final RecordingResolver resolver =
                                            new RecordingResolver(
                                                result(
                                                    originalGraph,
                                                    original,
                                                    List.of(),
                                                    List.of(),
                                                    Map.of()));
                                        final Throwable failure =
                                            org.assertj.core.api.Assertions.catchThrowable(
                                                () ->
                                                    MavenOriginalInputAudit.audit(
                                                        project, session, resolver));
                                        assertAll(
                                            () ->
                                                assertThat(failure)
                                                    .isInstanceOf(IOException.class)
                                                    .hasMessageContaining(
                                                        "unsupported resolved artifact")
                                                    .hasMessageContaining(
                                                        "Maven type: " + scenario.mavenType())
                                                    .hasMessageContaining(
                                                        "(" + scenario.scope() + ")"),
                                            () ->
                                                assertThat(resolver.request.getResolutionFilter())
                                                    .isNull(),
                                            () ->
                                                assertThat(
                                                        resolver
                                                            .request
                                                            .getMavenProject()
                                                            .getDependencies()
                                                            .getFirst()
                                                            .getExclusions())
                                                    .isEmpty(),
                                            () -> assertThat(project.getArtifacts()).isEmpty());
                                      }));
                    }));
  }

  @Test
  void preservesSupportedAuditMatchesAndUnmatchedRequestsWithoutClaimingRemoval() throws Exception {
    final MavenProject project = project(temporaryDirectory);
    project.setDependencies(new ArrayList<>(List.of(dependency(LIBRARY))));
    final DefaultRepositorySystemSession repositorySession = new DefaultRepositorySystemSession();
    final MavenSession session = sessionWithCapture(project, repositorySession);
    final MavenOriginalInputAudit.Inventory inventory =
        MavenOriginalInputAudit.audit(
            project,
            session,
            new RecordingResolver(
                result(
                    graph(),
                    List.of(resolvedLibrary(temporaryDirectory)),
                    List.of(),
                    List.of(),
                    Map.of())));
    final BanishedDependencyOriginalAuditPolicy.Resolution resolution =
        BanishedDependencyOriginalAuditPolicy.resolve(
            List.of(GROUP + ":" + LIBRARY, GROUP + ":missing"), inventory.resolvedArtifacts());
    final MavenOriginalInputAudit.AuditArtifact artifact = inventory.resolvedArtifacts().getFirst();
    final MavenOriginalInputAudit.Inventory changedType =
        new MavenOriginalInputAudit.Inventory(
            inventory.project(),
            inventory.sourceFingerprint(),
            inventory.graphPair(),
            List.of(
                new MavenOriginalInputAudit.AuditArtifact(
                    artifact.coordinate(), "test-jar", artifact.filePath(), artifact.sha256())),
            inventory.directArtifacts(),
            null);
    assertAll(
        () ->
            assertThat(resolution.unmatched())
                .containsExactly(new BanishedDependency(GROUP, "missing")),
        () -> assertThat(resolution.matches().getFirst().artifacts()).containsExactly(artifact),
        () -> assertThat(artifact.mavenType()).isEqualTo(JAR),
        () -> assertThat(changedType.fingerprint()).isNotEqualTo(inventory.fingerprint()));
  }

  private record UnsupportedOriginal(String scope, String mavenType, String extension) {}

  @Test
  void resolvesFrozenPreInjectionModelOnDetachedProjectAndSession() throws Exception {
    final MavenProject liveProject = project(temporaryDirectory);
    final Dependency sourceDependency = dependency(LIBRARY);
    sourceDependency.addExclusion(exclusion("user", "excluded"));
    liveProject.setDependencies(new ArrayList<>(List.of(sourceDependency)));
    final DependencyManagement sourceManagement = new DependencyManagement();
    sourceManagement.setDependencies(new ArrayList<>(List.of(dependency("managed"))));
    liveProject.getModel().setDependencyManagement(sourceManagement);
    final BanishedDependencyOriginalModel captured =
        BanishedDependencyOriginalModel.capture(
            liveProject,
            List.of(
                new BanishedDependencyOriginalModel.ExecutionPolicy(
                    "run",
                    "elide",
                    VERSION,
                    "initialize",
                    "LIFECYCLE",
                    List.of(GROUP + ":" + BANNED))),
            List.of(GROUP + ":" + BANNED));
    final Dependency injectedDependency = dependency(LIBRARY);
    injectedDependency.addExclusion(exclusion("user", "excluded"));
    injectedDependency.addExclusion(exclusion(GROUP, BANNED));
    liveProject.setDependencies(new ArrayList<>(List.of(injectedDependency)));
    final Artifact liveDirect = artifact(LIBRARY);
    final Artifact liveResolved = artifact("transitive");
    liveProject.setDependencyArtifacts(new LinkedHashSet<>(List.of(liveDirect)));
    liveProject.setArtifacts(new LinkedHashSet<>(List.of(liveDirect, liveResolved)));
    final DefaultRepositorySystemSession repositorySession = new DefaultRepositorySystemSession();
    final DefaultRepositoryCache sharedCache = new DefaultRepositoryCache();
    final Object sharedCacheKey = new Object();
    final Object sharedCacheValue = new Object();
    sharedCache.put(repositorySession, sharedCacheKey, sharedCacheValue);
    repositorySession.setCache(sharedCache);
    final WorkspaceReader originalReader = emptyWorkspaceReader();
    repositorySession.setWorkspaceReader(originalReader);
    repositorySession
        .getData()
        .set(
            BanishedDependencyLifecycleActivation.CAPTURE_STORE_KEY,
            BanishedDependencyCaptureStore.empty().withModel(captured).toPayload());
    final String projectKey = BanishedDependencyCaptureStore.projectKey(captured.project());
    final ResolverArtifactGraphSnapshotStore originalGraphStore =
        ResolverArtifactGraphSnapshotStore.empty()
            .append(
                ResolverArtifactGraphSnapshot.capture(graph(), projectKey, false, null, 0L, 0L)
                    .withCaptureGeneration(1L));
    repositorySession
        .getData()
        .set(EliderMediatedGraphCaptureDecorator.SESSION_DATA_KEY, originalGraphStore.toPayload());
    final AtomicInteger originalTransformCalls = new AtomicInteger();
    repositorySession.setDependencyGraphTransformer(
        (root, context) -> {
          originalTransformCalls.incrementAndGet();
          return graph();
        });
    final Path plannedFile = temporaryDirectory.resolve("planned-library.jar");
    Files.writeString(plannedFile, "planned library bytes");
    final ResolverArtifactPlan.ProjectIdentity planProject =
        new ResolverArtifactPlan.ProjectIdentity(
            liveProject.getBasedir().toPath(), GROUP, "consumer", VERSION);
    final ResolverArtifactPlan.ArtifactIdentity planArtifact =
        new ResolverArtifactPlan.ArtifactIdentity(GROUP, LIBRARY, VERSION, JAR, "");
    final ResolverArtifactPlan plan =
        new ResolverArtifactPlan(
            planProject,
            Map.of(
                planArtifact,
                new ResolverArtifactPlan.Replacement(
                    plannedFile, ArtifactFileDigest.sha256(plannedFile))));
    repositorySession
        .getData()
        .set(
            ResolverArtifactPlanPublisher.SESSION_DATA_KEY,
            ResolverArtifactPlanStore.empty().withPlan(plan).toPayload());
    final RepositorySystemSession withPlannedReader =
        new EliderRepositorySessionDecorator().decorate(liveProject, repositorySession);
    final RepositorySystemSession decoratedSession =
        new EliderMediatedGraphCaptureDecorator().decorate(liveProject, withPlannedReader);
    final MavenSession session = session(liveProject, decoratedSession);
    MavenOriginalInputAudit.markHookPresent(session);
    final DependencyResolutionResult result =
        result(
            graph("pre-transform"),
            List.of(resolvedLibrary(temporaryDirectory)),
            List.of(),
            List.of(),
            Map.of());
    final RecordingResolver resolver = new RecordingResolver(result);
    final Object graphCaptureBefore =
        decoratedSession.getData().get(EliderMediatedGraphCaptureDecorator.SESSION_DATA_KEY);
    final Object planBefore =
        decoratedSession.getData().get(ResolverArtifactPlanPublisher.SESSION_DATA_KEY);
    final List<String> liveExclusionsBefore =
        liveProject.getDependencies().getFirst().getExclusions().stream()
            .map(exclusion -> exclusion.getGroupId() + ":" + exclusion.getArtifactId())
            .toList();
    final Set<Artifact> directArtifactsBefore =
        new LinkedHashSet<>(liveProject.getDependencyArtifacts());
    final Set<Artifact> resolvedArtifactsBefore = new LinkedHashSet<>(liveProject.getArtifacts());

    final MavenOriginalInputAudit.Inventory inventory =
        MavenOriginalInputAudit.audit(liveProject, session, resolver);

    final MavenProject auditProject = resolver.request.getMavenProject();
    final RepositorySystemSession auditSession = resolver.request.getRepositorySession();
    final org.eclipse.aether.artifact.Artifact plannedArtifact =
        new DefaultArtifact(GROUP, LIBRARY, "", JAR, VERSION);
    assertAll(
        "audit resolves from the frozen model without changing Maven's live resolution state",
        () -> assertThat(auditProject).isNotSameAs(liveProject),
        () ->
            assertThat(auditProject.getDependencies().getFirst().getExclusions())
                .extracting(exclusion -> exclusion.getGroupId() + ":" + exclusion.getArtifactId())
                .containsExactly("user:excluded"),
        () ->
            assertThat(auditProject.getModel().getDependencyManagement().getDependencies())
                .extracting(Dependency::getArtifactId)
                .containsExactly("managed"),
        () -> assertThat(liveProject.getDependencies().getFirst().getExclusions()).hasSize(2),
        () -> assertThat(liveProject.getArtifacts()).isEqualTo(resolvedArtifactsBefore),
        () -> assertThat(liveProject.getDependencyArtifacts()).isEqualTo(directArtifactsBefore),
        () ->
            assertThat(
                    liveProject.getDependencies().getFirst().getExclusions().stream()
                        .map(exclusion -> exclusion.getGroupId() + ":" + exclusion.getArtifactId())
                        .toList())
                .isEqualTo(liveExclusionsBefore),
        () -> assertThat(auditProject.getDependencyArtifacts()).isNull(),
        () -> assertThat(auditSession).isNotSameAs(repositorySession),
        () -> assertThat(auditSession.getData()).isNotSameAs(repositorySession.getData()),
        () -> assertThat(auditSession.getCache()).isNotSameAs(sharedCache),
        () -> assertThat(auditSession.getCache().get(auditSession, sharedCacheKey)).isNull(),
        () ->
            assertThat(sharedCache.get(repositorySession, sharedCacheKey))
                .isSameAs(sharedCacheValue),
        () -> assertThat(auditSession.getWorkspaceReader()).isSameAs(originalReader),
        () -> assertThat(auditSession.getWorkspaceReader().findArtifact(plannedArtifact)).isNull(),
        () -> assertThat(decoratedSession.getWorkspaceReader()).isNotSameAs(originalReader),
        () ->
            assertThat(decoratedSession.getWorkspaceReader().findArtifact(plannedArtifact))
                .isEqualTo(plannedFile.toFile()),
        () -> assertThat(session.getRepositorySession()).isSameAs(decoratedSession),
        () -> assertThat(MavenOriginalInputAudit.isAuditMode(auditSession)).isTrue(),
        () -> assertThat(MavenOriginalInputAudit.isAuditMode(repositorySession)).isFalse(),
        () ->
            assertThat(inventory.resolvedArtifacts())
                .extracting(MavenOriginalInputAudit.AuditArtifact::coordinate)
                .containsExactly(ArtifactCoordinate.of(GROUP, LIBRARY, "1.0")),
        () -> assertThat(inventory.resolvedArtifacts().getFirst().sha256()).hasSize(64),
        () ->
            assertThat(Path.of(inventory.resolvedArtifacts().getFirst().filePath()))
                .isRegularFile(),
        () ->
            assertThat(inventory.resolvedArtifacts().getFirst().sha256())
                .isEqualTo(
                    ArtifactFileDigest.sha256(
                        Path.of(inventory.resolvedArtifacts().getFirst().filePath()))),
        () ->
            assertThat(inventory.directArtifacts())
                .containsExactly(ArtifactCoordinate.of(GROUP, LIBRARY, "1.0")),
        () -> assertThat(inventory.graph().nodes()).isNotEmpty(),
        () ->
            assertThat(inventory.graphBeforeTransformation().graphFingerprint())
                .isNotEqualTo(inventory.graph().graphFingerprint()),
        () -> assertThat(originalTransformCalls).hasValue(1),
        () -> assertThat(inventory.sourceFingerprint()).isEqualTo(captured.sourceFingerprint()),
        () -> assertThat(inventory.fingerprint()).hasSize(64),
        () ->
            assertThat(
                    decoratedSession
                        .getData()
                        .get(EliderMediatedGraphCaptureDecorator.SESSION_DATA_KEY))
                .isEqualTo(graphCaptureBefore),
        () ->
            assertThat(
                    decoratedSession.getData().get(ResolverArtifactPlanPublisher.SESSION_DATA_KEY))
                .isEqualTo(planBefore));
  }

  @Test
  void distinguishesMissingHookFromMissingCaptureAndRejectsPartialResolverResults()
      throws IOException {
    final MavenProject project = project(temporaryDirectory);
    final DefaultRepositorySystemSession repositorySession = new DefaultRepositorySystemSession();
    final MavenSession session = session(project, repositorySession);
    final BanishedDependencyOriginalModel captured =
        BanishedDependencyOriginalModel.capture(project, List.of(), List.of());
    repositorySession
        .getData()
        .set(
            BanishedDependencyLifecycleActivation.CAPTURE_STORE_KEY,
            BanishedDependencyCaptureStore.empty().withModel(captured).toPayload());
    final ProjectDependenciesResolver resolver =
        new RecordingResolver(
            result(
                graph(),
                List.of(resolvedLibrary(temporaryDirectory)),
                List.of(),
                List.of(),
                Map.of()));

    assertAll(
        "hook, capture, artifact, and resolver completeness are distinct audit prerequisites",
        () ->
            assertThatThrownBy(() -> MavenOriginalInputAudit.audit(project, session, resolver))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("active lifecycle extension hook"),
        () -> {
          MavenOriginalInputAudit.markHookPresent(session);
          repositorySession
              .getData()
              .set(
                  BanishedDependencyLifecycleActivation.CAPTURE_STORE_KEY,
                  BanishedDependencyCaptureStore.empty().toPayload());
          assertThatThrownBy(() -> MavenOriginalInputAudit.audit(project, session, resolver))
              .isInstanceOf(IOException.class)
              .hasMessageContaining("no frozen project capture");
        },
        () -> {
          repositorySession
              .getData()
              .set(
                  BanishedDependencyLifecycleActivation.CAPTURE_STORE_KEY,
                  BanishedDependencyCaptureStore.empty().withModel(captured).toPayload());
          final org.eclipse.aether.graph.Dependency withoutFile =
              new org.eclipse.aether.graph.Dependency(
                  new DefaultArtifact(GROUP, LIBRARY, "", JAR, VERSION), COMPILE);
          final org.eclipse.aether.graph.Dependency resolved = resolvedLibrary(temporaryDirectory);
          assertAll(
              "audit rejects incomplete resolver results and supported providers without bytes",
              () ->
                  assertThatThrownBy(
                          () ->
                              MavenOriginalInputAudit.audit(
                                  project,
                                  session,
                                  new RecordingResolver(
                                      result(
                                          graph(),
                                          List.of(withoutFile),
                                          List.of(),
                                          List.of(),
                                          Map.of()))))
                      .isInstanceOf(IOException.class)
                      .hasMessageContaining("no artifact file"),
              () ->
                  assertThatThrownBy(
                          () ->
                              MavenOriginalInputAudit.audit(
                                  project,
                                  session,
                                  new RecordingResolver(
                                      result(
                                          graph(),
                                          List.of(),
                                          List.of(new Exception("collection failed")),
                                          List.of(),
                                          Map.of()))))
                      .isInstanceOf(IOException.class)
                      .hasMessageContaining("partial dependency result"),
              () ->
                  assertThatThrownBy(
                          () ->
                              MavenOriginalInputAudit.audit(
                                  project,
                                  session,
                                  new RecordingResolver(
                                      result(
                                          graph(),
                                          List.of(resolved),
                                          List.of(),
                                          List.of(resolved),
                                          Map.of()))))
                      .isInstanceOf(IOException.class)
                      .hasMessageContaining("partial dependency result"),
              () ->
                  assertThatThrownBy(
                          () ->
                              MavenOriginalInputAudit.audit(
                                  project,
                                  session,
                                  new RecordingResolver(
                                      result(
                                          graph(),
                                          List.of(resolved),
                                          List.of(),
                                          List.of(),
                                          Map.of(
                                              resolved,
                                              List.of(new Exception("resolution failed")))))))
                      .isInstanceOf(IOException.class)
                      .hasMessageContaining("partial dependency result"),
              () ->
                  assertThatThrownBy(
                          () ->
                              MavenOriginalInputAudit.audit(
                                  project,
                                  session,
                                  new RecordingResolver(
                                      result(
                                          graph(),
                                          List.of(resolved),
                                          List.of(),
                                          List.of(),
                                          Map.of()),
                                      false,
                                      false)))
                      .isInstanceOf(IOException.class)
                      .hasMessageContaining("did not invoke the audit graph transformer"),
              () ->
                  assertThatThrownBy(
                          () ->
                              MavenOriginalInputAudit.audit(
                                  project,
                                  session,
                                  new RecordingResolver(
                                      result(
                                          graph(),
                                          List.of(resolved),
                                          List.of(),
                                          List.of(),
                                          Map.of()),
                                      true,
                                      true)))
                      .isInstanceOf(IOException.class)
                      .hasMessageContaining("does not match the captured audit graph"),
              () ->
                  assertThatThrownBy(
                          () -> MavenOriginalInputAudit.audit(project, session, request -> null))
                      .isInstanceOf(IOException.class)
                      .hasMessageContaining("returned no result"));
        });
  }

  @Test
  void rejectsRepeatedGraphTransformBeforeCallingTheDelegateTwice() throws IOException {
    final MavenProject project = project(temporaryDirectory);
    project.setDependencies(new ArrayList<>(List.of(dependency(LIBRARY))));
    final DefaultRepositorySystemSession repositorySession = new DefaultRepositorySystemSession();
    final MavenSession session = sessionWithCapture(project, repositorySession);
    final AtomicInteger delegateCalls = new AtomicInteger();
    repositorySession.setDependencyGraphTransformer(
        (root, context) -> {
          delegateCalls.incrementAndGet();
          return root;
        });
    final RecordingResolver resolver =
        new RecordingResolver(
            result(
                graph(),
                List.of(resolvedLibrary(temporaryDirectory)),
                List.of(),
                List.of(),
                Map.of()),
            true,
            false,
            true);

    final Throwable failure =
        org.assertj.core.api.Assertions.catchThrowable(
            () -> MavenOriginalInputAudit.audit(project, session, resolver));

    assertAll(
        "repeated resolver callbacks invalidate audit evidence before a second delegate call",
        () -> assertThat(failure).isInstanceOf(IOException.class),
        () -> assertThat(delegateCalls).hasValue(1));
  }

  @Test
  void invalidatesAuditEvidenceWhenTheOriginalTransformerFails() throws IOException {
    final MavenProject project = project(temporaryDirectory);
    project.setDependencies(new ArrayList<>(List.of(dependency(LIBRARY))));
    final DefaultRepositorySystemSession repositorySession = new DefaultRepositorySystemSession();
    final MavenSession session = sessionWithCapture(project, repositorySession);
    final AtomicInteger delegateCalls = new AtomicInteger();
    repositorySession.setDependencyGraphTransformer(
        (root, context) -> {
          delegateCalls.incrementAndGet();
          throw new RepositoryException("fixture delegate failure");
        });
    final RecordingResolver resolver =
        new RecordingResolver(
            result(
                graph(),
                List.of(resolvedLibrary(temporaryDirectory)),
                List.of(),
                List.of(),
                Map.of()));

    final Throwable failure =
        org.assertj.core.api.Assertions.catchThrowable(
            () -> MavenOriginalInputAudit.audit(project, session, resolver));

    assertAll(
        "a failed original transform cannot return audit evidence",
        () -> assertThat(failure).isInstanceOf(IOException.class),
        () -> assertThat(delegateCalls).hasValue(1));
  }

  private static MavenProject project(final Path directory) {
    final Model model = new Model();
    model.setGroupId(GROUP);
    model.setArtifactId("consumer");
    model.setVersion(VERSION);
    final MavenProject project = new MavenProject(model);
    project.setFile(directory.resolve("pom.xml").toFile());
    return project;
  }

  private static MavenSession session(
      final MavenProject project, final RepositorySystemSession repositorySession) {
    final MavenSession session =
        new MavenSession(
            null,
            repositorySession,
            new org.apache.maven.execution.DefaultMavenExecutionRequest(),
            null);
    session.setCurrentProject(project);
    return session;
  }

  private static MavenSession sessionWithCapture(
      final MavenProject project, final DefaultRepositorySystemSession repositorySession) {
    final BanishedDependencyOriginalModel captured =
        BanishedDependencyOriginalModel.capture(project, List.of(), List.of());
    repositorySession
        .getData()
        .set(
            BanishedDependencyLifecycleActivation.CAPTURE_STORE_KEY,
            BanishedDependencyCaptureStore.empty().withModel(captured).toPayload());
    final MavenSession session = session(project, repositorySession);
    MavenOriginalInputAudit.markHookPresent(session);
    return session;
  }

  private static WorkspaceReader emptyWorkspaceReader() {
    final WorkspaceRepository repository = new WorkspaceRepository("original-audit-reader");
    final InvocationHandler handler =
        (proxy, method, arguments) ->
            switch (method.getName()) {
              case "getRepository" -> repository;
              case "findArtifact" -> null;
              case "findVersions" -> List.of();
              case "toString" -> "original audit workspace reader";
              default -> throw new UnsupportedOperationException(method.getName());
            };
    return (WorkspaceReader)
        Proxy.newProxyInstance(
            Thread.currentThread().getContextClassLoader(),
            new Class<?>[] {WorkspaceReader.class},
            handler);
  }

  private static Dependency dependency(final String artifactId) {
    final Dependency dependency = new Dependency();
    dependency.setGroupId(GROUP);
    dependency.setArtifactId(artifactId);
    dependency.setVersion(VERSION);
    dependency.setType(JAR);
    dependency.setScope(COMPILE);
    return dependency;
  }

  private static Exclusion exclusion(final String groupId, final String artifactId) {
    final Exclusion exclusion = new Exclusion();
    exclusion.setGroupId(groupId);
    exclusion.setArtifactId(artifactId);
    return exclusion;
  }

  private static Artifact artifact(final String artifactId) {
    return new org.apache.maven.artifact.DefaultArtifact(
        GROUP, artifactId, VERSION, COMPILE, JAR, null, new DefaultArtifactHandler(JAR));
  }

  private static DependencyNode graph() {
    return graph(LIBRARY);
  }

  private static DependencyNode graph(final String childArtifactId) {
    final DefaultDependencyNode root =
        new DefaultDependencyNode(new DefaultArtifact(GROUP, "consumer", "", "pom", VERSION));
    root.getChildren()
        .add(
            new DefaultDependencyNode(
                new org.eclipse.aether.graph.Dependency(
                    new DefaultArtifact(GROUP, childArtifactId, "", JAR, VERSION), COMPILE)));
    return root;
  }

  private static org.eclipse.aether.graph.Dependency resolvedLibrary(final Path directory)
      throws IOException {
    final Path file = directory.resolve("audit-library.jar");
    Files.writeString(file, "audit-library-bytes");
    final org.eclipse.aether.artifact.Artifact artifact =
        new DefaultArtifact(GROUP, LIBRARY, "", JAR, VERSION).setFile(file.toFile());
    return new org.eclipse.aether.graph.Dependency(artifact, COMPILE);
  }

  private static DependencyResolutionResult result(
      final DependencyNode graph,
      final List<org.eclipse.aether.graph.Dependency> resolved,
      final List<Exception> collectionErrors,
      final List<org.eclipse.aether.graph.Dependency> unresolved,
      final Map<org.eclipse.aether.graph.Dependency, List<Exception>> resolutionErrors) {
    final InvocationHandler handler =
        (proxy, method, arguments) ->
            switch (method.getName()) {
              case "getDependencyGraph" -> graph;
              case "getResolvedDependencies" -> resolved;
              case "getCollectionErrors" -> collectionErrors;
              case "getUnresolvedDependencies" -> unresolved;
              case "getResolutionErrors" ->
                  resolutionErrors.getOrDefault(
                      (org.eclipse.aether.graph.Dependency) arguments[0], List.of());
              case "toString" -> "fixture dependency resolution result";
              default -> throw new UnsupportedOperationException(method.getName());
            };
    return (DependencyResolutionResult)
        Proxy.newProxyInstance(
            Thread.currentThread().getContextClassLoader(),
            new Class<?>[] {DependencyResolutionResult.class},
            handler);
  }

  /** Delegates no shared state and invokes the supplied transformer once. */
  private static final class RecordingResolver implements ProjectDependenciesResolver {
    /** Returns this result after applying the requested audit transformer. */
    private final DependencyResolutionResult result;

    /** Controls transformer invocation and graph mismatch behavior. */
    private final boolean transformGraph;

    /** Enables a mismatching graph result. */
    private final boolean mismatchResultGraph;

    /** Controls whether the audit transform is invoked a second time. */
    private final boolean repeatTransform;

    /** Records the detached project and Resolver session submitted by production code. */
    private DependencyResolutionRequest request;

    private RecordingResolver(final DependencyResolutionResult result) {
      this(result, true, false, false);
    }

    private RecordingResolver(
        final DependencyResolutionResult result,
        final boolean transformGraph,
        final boolean mismatchResultGraph) {
      this(result, transformGraph, mismatchResultGraph, false);
    }

    private RecordingResolver(
        final DependencyResolutionResult result,
        final boolean transformGraph,
        final boolean mismatchResultGraph,
        final boolean repeatTransform) {
      this.result = result;
      this.transformGraph = transformGraph;
      this.mismatchResultGraph = mismatchResultGraph;
      this.repeatTransform = repeatTransform;
    }

    @Override
    @SuppressWarnings("PMD.UseConcurrentHashMap")
    public DependencyResolutionResult resolve(final DependencyResolutionRequest request) {
      this.request = request;
      final DependencyGraphTransformer transformer =
          request.getRepositorySession().getDependencyGraphTransformer();
      DependencyNode transformed = result.getDependencyGraph();
      if (transformGraph) {
        try {
          transformed =
              transformer.transformGraph(
                  transformed,
                  new DependencyGraphTransformationContext() {
                    @Override
                    public RepositorySystemSession getSession() {
                      return request.getRepositorySession();
                    }

                    @Override
                    public Object get(final Object key) {
                      return null;
                    }

                    @Override
                    public Object put(final Object key, final Object value) {
                      return null;
                    }
                  });
          if (repeatTransform) {
            transformer.transformGraph(
                transformed,
                new DependencyGraphTransformationContext() {
                  @Override
                  public RepositorySystemSession getSession() {
                    return request.getRepositorySession();
                  }

                  @Override
                  public Object get(final Object key) {
                    return null;
                  }

                  @Override
                  public Object put(final Object key, final Object value) {
                    return null;
                  }
                });
          }
        } catch (final RepositoryException exception) {
          throw new IllegalStateException(
              "Fixture resolver graph transformation failed", exception);
        }
      }
      final DependencyNode resultGraph = mismatchResultGraph ? graph("different") : transformed;
      final Map<org.eclipse.aether.graph.Dependency, List<Exception>> errors = new HashMap<>();
      result
          .getResolvedDependencies()
          .forEach(dependency -> errors.put(dependency, result.getResolutionErrors(dependency)));
      return result(
          resultGraph,
          result.getResolvedDependencies(),
          result.getCollectionErrors(),
          result.getUnresolvedDependencies(),
          errors);
    }
  }
}
