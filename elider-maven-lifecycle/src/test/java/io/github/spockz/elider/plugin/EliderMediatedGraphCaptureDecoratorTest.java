/* WHY: Proves mediated graph capture delegates once and stores detached project snapshots. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.apache.maven.project.MavenProject;
import org.eclipse.aether.DefaultRepositorySystemSession;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.collection.DependencyGraphTransformationContext;
import org.eclipse.aether.collection.DependencyGraphTransformer;
import org.eclipse.aether.graph.DependencyNode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Exercises the separate post-mediation graph capture decorator. */
@SuppressWarnings({
  "PMD.CommentDefaultAccessModifier",
  "PMD.LawOfDemeter",
  "PMD.CouplingBetweenObjects"
})
final class EliderMediatedGraphCaptureDecoratorTest {
  /** Test-specific Maven project root. */
  @TempDir Path temporaryDirectory;

  /** Creates the test fixture. */
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  EliderMediatedGraphCaptureDecoratorTest() {
    super();
  }

  @Test
  void auditModeBypassesGraphCaptureWithoutObservingSharedPlanOrCaptureState() throws IOException {
    final MavenProject project =
        EliderMediatedGraphCaptureDecoratorTestSupport.project(temporaryDirectory, "consumer");
    final DefaultRepositorySystemSession session = new DefaultRepositorySystemSession();
    session.setConfigProperties(Map.of(MavenOriginalInputAudit.AUDIT_MODE_CONFIG_KEY, true));
    session.getData().set(ResolverArtifactPlanPublisher.SESSION_DATA_KEY, "invalid shared plan");
    session
        .getData()
        .set(EliderMediatedGraphCaptureDecorator.SESSION_DATA_KEY, "invalid graph state");

    assertThat(new EliderMediatedGraphCaptureDecorator().decorate(project, session))
        .isSameAs(session);
  }

  @Test
  void delegatesOnceReturnsReplacementRootAndCapturesDecorationTimeProvenance()
      throws IOException, org.eclipse.aether.RepositoryException {
    final MavenProject project =
        EliderMediatedGraphCaptureDecoratorTestSupport.project(temporaryDirectory, "consumer");
    final DefaultRepositorySystemSession session = new DefaultRepositorySystemSession();
    final DependencyNode input = EliderMediatedGraphCaptureDecoratorTestSupport.node("input");
    final DependencyNode replacement =
        EliderMediatedGraphCaptureDecoratorTestSupport.node("replacement");
    final AtomicInteger delegateCalls = new AtomicInteger();
    final AtomicReference<DependencyGraphTransformationContext> expectedContext =
        new AtomicReference<>(EliderMediatedGraphCaptureDecoratorTestSupport.context(session));
    final DependencyGraphTransformer delegate =
        (root, transformationContext) -> {
          delegateCalls.incrementAndGet();
          assertThat(root).isSameAs(input);
          assertThat(transformationContext).isSameAs(expectedContext.get());
          return replacement;
        };
    session.setDependencyGraphTransformer(delegate);
    final RepositorySystemSession decorated =
        new EliderMediatedGraphCaptureDecorator().decorate(project, session);
    final ResolverArtifactPlan plan =
        EliderMediatedGraphCaptureDecoratorTestSupport.emptyPlan(project);
    session
        .getData()
        .set(
            ResolverArtifactPlanPublisher.SESSION_DATA_KEY,
            ResolverArtifactPlanStore.empty().withPlan(plan).toPayload());

    final DependencyNode returned =
        decorated.getDependencyGraphTransformer().transformGraph(input, expectedContext.get());
    final ResolverArtifactGraphSnapshotStore store =
        EliderMediatedGraphCaptureDecoratorTestSupport.graphStore(decorated);
    final Map<String, Object> snapshot =
        store
            .snapshots()
            .get(EliderMediatedGraphCaptureDecoratorTestSupport.projectKey(project))
            .getFirst();
    final ResolverArtifactGraphCapturePair pair =
        store
            .capturePairs(EliderMediatedGraphCaptureDecoratorTestSupport.projectKey(project))
            .getFirst();

    assertThat(decorated).isNotSameAs(session);
    assertThat(returned).isSameAs(replacement);
    assertThat(delegateCalls).hasValue(1);
    assertThat(snapshot)
        .containsEntry(ResolverArtifactGraphSnapshotSchema.PLAN_PRESENT, false)
        .containsEntry(ResolverArtifactGraphSnapshotSchema.PLAN_FINGERPRINT, null)
        .containsEntry(ResolverArtifactGraphSnapshotSchema.ROOT_NODE_ID, "n0");
    assertThat((List<?>) snapshot.get("nodes")).hasSize(1);
    final Map<?, ?> rootArtifact =
        (Map<?, ?>) ((Map<?, ?>) ((List<?>) snapshot.get("nodes")).getFirst()).get("artifact");
    assertThat(rootArtifact.get("artifactId")).isEqualTo("replacement");
    assertThat(((Map<?, ?>) pair.before().nodes().getFirst().get("artifact")).get("artifactId"))
        .isEqualTo("input");
    assertThat(((Map<?, ?>) pair.after().nodes().getFirst().get("artifact")).get("artifactId"))
        .isEqualTo("replacement");
    assertThat(pair.before().captureGeneration()).isEqualTo(pair.after().captureGeneration());
    assertThat(pair.captureToken()).isNotBlank();

    final RepositorySystemSession laterDecorated =
        new EliderMediatedGraphCaptureDecorator().decorate(project, session);
    expectedContext.set(EliderMediatedGraphCaptureDecoratorTestSupport.context(laterDecorated));
    laterDecorated.getDependencyGraphTransformer().transformGraph(input, expectedContext.get());
    final List<Map<String, Object>> snapshots =
        EliderMediatedGraphCaptureDecoratorTestSupport.graphStore(session)
            .snapshots()
            .get(EliderMediatedGraphCaptureDecoratorTestSupport.projectKey(project));

    assertThat(delegateCalls).hasValue(2);
    assertThat(snapshots).hasSize(2);
    assertThat(snapshots.get(0))
        .containsEntry(ResolverArtifactGraphSnapshotSchema.PLAN_PRESENT, false)
        .containsEntry(ResolverArtifactGraphSnapshotSchema.PLAN_GENERATION, 0L)
        .containsEntry(ResolverArtifactGraphSnapshotSchema.CAPTURE_GENERATION, 1L);
    assertThat(snapshots.get(1))
        .containsEntry(ResolverArtifactGraphSnapshotSchema.PLAN_PRESENT, true)
        .containsEntry(ResolverArtifactGraphSnapshotSchema.PLAN_GENERATION, 1L)
        .containsEntry(ResolverArtifactGraphSnapshotSchema.CAPTURE_GENERATION, 2L);
    assertThat(snapshots.get(1).get("planFingerprint")).isNotNull();
    assertThat(snapshots.get(0).get("graphFingerprint"))
        .isEqualTo(snapshots.get(1).get("graphFingerprint"));
    assertThat(
            EliderMediatedGraphCaptureDecoratorTestSupport.graphStore(session)
                .capturePairs(EliderMediatedGraphCaptureDecoratorTestSupport.projectKey(project)))
        .extracting(ResolverArtifactGraphCapturePair::captureToken)
        .doesNotHaveDuplicates();
  }

  @Test
  void propagatesDelegateFailureWithoutAppendingSnapshot() throws IOException {
    final MavenProject project =
        EliderMediatedGraphCaptureDecoratorTestSupport.project(temporaryDirectory, "failure");
    final DefaultRepositorySystemSession session = new DefaultRepositorySystemSession();
    final org.eclipse.aether.RepositoryException failure =
        new org.eclipse.aether.RepositoryException("delegate failure");
    session.setDependencyGraphTransformer(
        (root, context) -> {
          throw failure;
        });
    final RepositorySystemSession decorated =
        new EliderMediatedGraphCaptureDecorator().decorate(project, session);

    assertThatThrownBy(
            () ->
                decorated
                    .getDependencyGraphTransformer()
                    .transformGraph(
                        EliderMediatedGraphCaptureDecoratorTestSupport.node("input"),
                        EliderMediatedGraphCaptureDecoratorTestSupport.context(decorated)))
        .isSameAs(failure);
    assertThat(EliderMediatedGraphCaptureDecoratorTestSupport.graphStore(decorated).snapshots())
        .isEmpty();
  }

  @Test
  @SuppressWarnings({"PMD.DoNotUseThreads"})
  void appendsConcurrentGraphInvocationsAndPreservesRepeatedGraph() throws Exception {
    final MavenProject project =
        EliderMediatedGraphCaptureDecoratorTestSupport.project(
            temporaryDirectory, "shared-project");
    final DefaultRepositorySystemSession session = new DefaultRepositorySystemSession();
    final RepositorySystemSession decorated =
        new EliderMediatedGraphCaptureDecorator().decorate(project, session);
    final CountDownLatch start = new CountDownLatch(1);
    try (ExecutorService executor = Executors.newFixedThreadPool(4)) {
      final List<Future<?>> futures = new java.util.ArrayList<>();
      for (int index = 0; index < 4; index++) {
        final int graphIndex = index;
        futures.add(
            executor.submit(
                () -> {
                  start.await();
                  decorated
                      .getDependencyGraphTransformer()
                      .transformGraph(
                          EliderMediatedGraphCaptureDecoratorTestSupport.node(
                              "distinct-" + graphIndex),
                          EliderMediatedGraphCaptureDecoratorTestSupport.context(decorated));
                  return null;
                }));
      }
      start.countDown();
      for (final Future<?> future : futures) {
        future.get();
      }
      executor.shutdown();
      assertThat(executor.awaitTermination(10, TimeUnit.SECONDS)).isTrue();
      decorated
          .getDependencyGraphTransformer()
          .transformGraph(
              EliderMediatedGraphCaptureDecoratorTestSupport.node("distinct-0"),
              EliderMediatedGraphCaptureDecoratorTestSupport.context(decorated));
    }

    final ResolverArtifactGraphSnapshotStore store =
        EliderMediatedGraphCaptureDecoratorTestSupport.graphStore(session);
    final String projectKey = EliderMediatedGraphCaptureDecoratorTestSupport.projectKey(project);
    assertThat(store.snapshots()).containsKey(projectKey);
    assertThat(store.snapshots().get(projectKey)).hasSize(5);
    assertThat(store.generations()).containsEntry(projectKey, 5L);
    assertThat(
            store.snapshots().get(projectKey).stream()
                .map(snapshot -> snapshot.get("graphFingerprint"))
                .distinct())
        .hasSize(4);
    assertThat(store.capturePairs(projectKey))
        .extracting(ResolverArtifactGraphCapturePair::captureToken)
        .doesNotHaveDuplicates();
    assertThat(store.toPayload().values())
        .allSatisfy(EliderMediatedGraphCaptureDecoratorTestSupport::assertJdkValue);
  }

  @Test
  @SuppressWarnings({"PMD.DoNotUseThreads"})
  void isolatesPlanGenerationAcrossConcurrentSessionsForTheSameProject() throws Exception {
    final MavenProject project =
        EliderMediatedGraphCaptureDecoratorTestSupport.project(
            temporaryDirectory, "shared-project");
    final DefaultRepositorySystemSession absentSession = new DefaultRepositorySystemSession();
    final DefaultRepositorySystemSession presentSession = new DefaultRepositorySystemSession();
    presentSession
        .getData()
        .set(
            ResolverArtifactPlanPublisher.SESSION_DATA_KEY,
            ResolverArtifactPlanStore.empty()
                .withPlan(EliderMediatedGraphCaptureDecoratorTestSupport.emptyPlan(project))
                .toPayload());
    final CountDownLatch start = new CountDownLatch(1);
    final AtomicReference<RepositorySystemSession> absentDecorated = new AtomicReference<>();
    final AtomicReference<RepositorySystemSession> presentDecorated = new AtomicReference<>();
    try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
      final Future<?> absent =
          executor.submit(
              () -> {
                start.await();
                absentDecorated.set(
                    new EliderMediatedGraphCaptureDecorator().decorate(project, absentSession));
                return null;
              });
      final Future<?> present =
          executor.submit(
              () -> {
                start.await();
                presentDecorated.set(
                    new EliderMediatedGraphCaptureDecorator().decorate(project, presentSession));
                return null;
              });
      start.countDown();
      absent.get();
      present.get();
    }
    absentDecorated
        .get()
        .getDependencyGraphTransformer()
        .transformGraph(
            EliderMediatedGraphCaptureDecoratorTestSupport.node("absent"),
            EliderMediatedGraphCaptureDecoratorTestSupport.context(absentDecorated.get()));
    presentDecorated
        .get()
        .getDependencyGraphTransformer()
        .transformGraph(
            EliderMediatedGraphCaptureDecoratorTestSupport.node("present"),
            EliderMediatedGraphCaptureDecoratorTestSupport.context(presentDecorated.get()));

    final Map<String, Object> absentSnapshot =
        EliderMediatedGraphCaptureDecoratorTestSupport.graphStore(absentSession)
            .snapshots()
            .get(EliderMediatedGraphCaptureDecoratorTestSupport.projectKey(project))
            .getFirst();
    final Map<String, Object> presentSnapshot =
        EliderMediatedGraphCaptureDecoratorTestSupport.graphStore(presentSession)
            .snapshots()
            .get(EliderMediatedGraphCaptureDecoratorTestSupport.projectKey(project))
            .getFirst();
    assertThat(absentSnapshot)
        .containsEntry(ResolverArtifactGraphSnapshotSchema.PLAN_PRESENT, false)
        .containsEntry(ResolverArtifactGraphSnapshotSchema.PLAN_GENERATION, 0L)
        .containsEntry(ResolverArtifactGraphSnapshotSchema.CAPTURE_GENERATION, 1L);
    assertThat(presentSnapshot)
        .containsEntry(ResolverArtifactGraphSnapshotSchema.PLAN_PRESENT, true)
        .containsEntry(ResolverArtifactGraphSnapshotSchema.PLAN_GENERATION, 1L)
        .containsEntry(ResolverArtifactGraphSnapshotSchema.CAPTURE_GENERATION, 1L);
    assertThat(
            EliderMediatedGraphCaptureDecoratorTestSupport.graphStore(absentSession)
                .observations()
                .get(EliderMediatedGraphCaptureDecoratorTestSupport.projectKey(project))
                .present())
        .isFalse();
    assertThat(
            EliderMediatedGraphCaptureDecoratorTestSupport.graphStore(presentSession)
                .observations()
                .get(EliderMediatedGraphCaptureDecoratorTestSupport.projectKey(project))
                .present())
        .isTrue();
  }

  @Test
  void reusesTrustedHistoryAcrossMultiProjectTransformCyclesAndRejectsTamperedPayload()
      throws Exception {
    final MavenProject projectA =
        EliderMediatedGraphCaptureDecoratorTestSupport.project(temporaryDirectory, "proj-a");
    final MavenProject projectB =
        EliderMediatedGraphCaptureDecoratorTestSupport.project(temporaryDirectory, "proj-b");
    final DefaultRepositorySystemSession session = new DefaultRepositorySystemSession();
    final EliderMediatedGraphCaptureDecorator decorator = new EliderMediatedGraphCaptureDecorator();
    final RepositorySystemSession decoratedA = decorator.decorate(projectA, session);
    final RepositorySystemSession decoratedB = decorator.decorate(projectB, session);

    decoratedA
        .getDependencyGraphTransformer()
        .transformGraph(
            EliderMediatedGraphCaptureDecoratorTestSupport.node("a1"),
            EliderMediatedGraphCaptureDecoratorTestSupport.context(decoratedA));
    final Map<String, Object> firstSnapshotA =
        EliderMediatedGraphCaptureDecoratorTestSupport.graphStore(session)
            .snapshots()
            .get(EliderMediatedGraphCaptureDecoratorTestSupport.projectKey(projectA))
            .getFirst();
    final String keyA = EliderMediatedGraphCaptureDecoratorTestSupport.projectKey(projectA);
    final String keyB = EliderMediatedGraphCaptureDecoratorTestSupport.projectKey(projectB);
    final Map<String, Object> rawFirstSnapshotBefore = rawFirstSnapshot(session, keyA);

    decoratedB
        .getDependencyGraphTransformer()
        .transformGraph(
            EliderMediatedGraphCaptureDecoratorTestSupport.node("b1"),
            EliderMediatedGraphCaptureDecoratorTestSupport.context(decoratedB));
    decoratedA
        .getDependencyGraphTransformer()
        .transformGraph(
            EliderMediatedGraphCaptureDecoratorTestSupport.node("a2"),
            EliderMediatedGraphCaptureDecoratorTestSupport.context(decoratedA));

    final ResolverArtifactGraphSnapshotStore storeAfter =
        EliderMediatedGraphCaptureDecoratorTestSupport.graphStore(session);
    final Map<String, Object> rawFirstSnapshotAfter = rawFirstSnapshot(session, keyA);

    assertThat(storeAfter.snapshots().get(keyA)).hasSize(2);
    assertThat(storeAfter.snapshots().get(keyB)).hasSize(1);
    assertThat(storeAfter.snapshots().get(keyA).getFirst())
        .as("trusted session round-trip should preserve historical snapshot values")
        .isEqualTo(firstSnapshotA);
    assertThat(rawFirstSnapshotAfter)
        .as("trusted session reuse should preserve raw historical snapshot map identity")
        .isSameAs(rawFirstSnapshotBefore);

    final Map<String, Object> tampered =
        new java.util.concurrent.ConcurrentHashMap<>(
            (Map<String, Object>)
                session.getData().get(EliderMediatedGraphCaptureDecorator.SESSION_DATA_KEY));
    tampered.put("schemaVersion", 99);
    session.getData().set(EliderMediatedGraphCaptureDecorator.SESSION_DATA_KEY, tampered);
    assertThatThrownBy(
            () ->
                decoratedA
                    .getDependencyGraphTransformer()
                    .transformGraph(
                        EliderMediatedGraphCaptureDecoratorTestSupport.node("a3"),
                        EliderMediatedGraphCaptureDecoratorTestSupport.context(decoratedA)))
        .isInstanceOf(IllegalStateException.class);
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> rawFirstSnapshot(
      final DefaultRepositorySystemSession session, final String projectKey) {
    final Map<String, Object> root =
        (Map<String, Object>)
            session.getData().get(EliderMediatedGraphCaptureDecorator.SESSION_DATA_KEY);
    final Map<String, List<Map<String, Object>>> snapshots =
        (Map<String, List<Map<String, Object>>>) root.get("snapshots");
    return snapshots.get(projectKey).getFirst();
  }

  @Test
  @SuppressWarnings("unchecked")
  void rejectsMutatedForeignPayloadAfterUnchangedPlanObservation() throws Exception {
    final EliderMediatedGraphCaptureDecorator decorator = new EliderMediatedGraphCaptureDecorator();
    final DefaultRepositorySystemSession session =
        EliderMediatedGraphCaptureDecoratorTestSupport.session();
    final MavenProject project =
        EliderMediatedGraphCaptureDecoratorTestSupport.project(
            temporaryDirectory, "foreign-mutation");
    final RepositorySystemSession decorated = decorator.decorate(project, session);
    decorated
        .getDependencyGraphTransformer()
        .transformGraph(
            EliderMediatedGraphCaptureDecoratorTestSupport.node("n1"),
            EliderMediatedGraphCaptureDecoratorTestSupport.context(decorated));

    final Map<String, Object> foreignMutable =
        new java.util.concurrent.ConcurrentHashMap<>(
            (Map<String, Object>)
                session.getData().get(EliderMediatedGraphCaptureDecorator.SESSION_DATA_KEY));
    session.getData().set(EliderMediatedGraphCaptureDecorator.SESSION_DATA_KEY, foreignMutable);

    // Decorate with unchanged plan, then mutate the foreign map in place.
    final RepositorySystemSession redecorated = decorator.decorate(project, session);
    foreignMutable.put("schemaVersion", 99);

    assertThatThrownBy(
            () ->
                redecorated
                    .getDependencyGraphTransformer()
                    .transformGraph(
                        EliderMediatedGraphCaptureDecoratorTestSupport.node("n2"),
                        EliderMediatedGraphCaptureDecoratorTestSupport.context(redecorated)))
        .isInstanceOf(IllegalStateException.class);
  }
}
