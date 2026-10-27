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
@SuppressWarnings({"PMD.CommentDefaultAccessModifier", "PMD.LawOfDemeter"})
final class EliderMediatedGraphCaptureDecoratorTest {
  /** PMD key reused in assertion annotations for multi-field session evidence. */
  private static final String TOO_MANY_ASSERTS = "PMD.UnitTestContainsTooManyAsserts";

  /** Test-specific Maven project root. */
  @TempDir Path temporaryDirectory;

  /** Creates the test fixture. */
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  EliderMediatedGraphCaptureDecoratorTest() {
    super();
  }

  @Test
  @SuppressWarnings(TOO_MANY_ASSERTS)
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
  }

  @Test
  @SuppressWarnings(TOO_MANY_ASSERTS)
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
  @SuppressWarnings({TOO_MANY_ASSERTS, "PMD.DoNotUseThreads"})
  void appendsConcurrentProjectCapturesAndDeduplicatesRepeatedGraph() throws Exception {
    final MavenProject firstProject =
        EliderMediatedGraphCaptureDecoratorTestSupport.project(temporaryDirectory, "first");
    final MavenProject secondProject =
        EliderMediatedGraphCaptureDecoratorTestSupport.project(temporaryDirectory, "second");
    final DefaultRepositorySystemSession session = new DefaultRepositorySystemSession();
    final RepositorySystemSession firstDecorated =
        new EliderMediatedGraphCaptureDecorator().decorate(firstProject, session);
    final RepositorySystemSession secondDecorated =
        new EliderMediatedGraphCaptureDecorator().decorate(secondProject, session);
    final DependencyNode repeated = EliderMediatedGraphCaptureDecoratorTestSupport.node("same");
    final CountDownLatch start = new CountDownLatch(1);
    try (ExecutorService executor = Executors.newFixedThreadPool(4)) {
      final List<Future<?>> futures = new java.util.ArrayList<>();
      for (int index = 0; index < 4; index++) {
        futures.add(
            executor.submit(
                () -> {
                  start.await();
                  firstDecorated
                      .getDependencyGraphTransformer()
                      .transformGraph(
                          repeated,
                          EliderMediatedGraphCaptureDecoratorTestSupport.context(firstDecorated));
                  return null;
                }));
      }
      start.countDown();
      for (final Future<?> future : futures) {
        future.get();
      }
      executor.shutdown();
      assertThat(executor.awaitTermination(10, TimeUnit.SECONDS)).isTrue();
      secondDecorated
          .getDependencyGraphTransformer()
          .transformGraph(
              EliderMediatedGraphCaptureDecoratorTestSupport.node("other"),
              EliderMediatedGraphCaptureDecoratorTestSupport.context(secondDecorated));
    }

    final ResolverArtifactGraphSnapshotStore store =
        EliderMediatedGraphCaptureDecoratorTestSupport.graphStore(session);
    assertThat(store.snapshots())
        .containsKeys(
            EliderMediatedGraphCaptureDecoratorTestSupport.projectKey(firstProject),
            EliderMediatedGraphCaptureDecoratorTestSupport.projectKey(secondProject));
    assertThat(
            store
                .snapshots()
                .get(EliderMediatedGraphCaptureDecoratorTestSupport.projectKey(firstProject)))
        .hasSize(1);
    assertThat(
            store
                .snapshots()
                .get(EliderMediatedGraphCaptureDecoratorTestSupport.projectKey(secondProject)))
        .hasSize(1);
    assertThat(store.generations())
        .containsEntry(EliderMediatedGraphCaptureDecoratorTestSupport.projectKey(firstProject), 1L)
        .containsEntry(
            EliderMediatedGraphCaptureDecoratorTestSupport.projectKey(secondProject), 1L);
    assertThat(store.toPayload().values())
        .allSatisfy(EliderMediatedGraphCaptureDecoratorTestSupport::assertJdkValue);
  }

  @Test
  @SuppressWarnings({TOO_MANY_ASSERTS, "PMD.DoNotUseThreads"})
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
}
