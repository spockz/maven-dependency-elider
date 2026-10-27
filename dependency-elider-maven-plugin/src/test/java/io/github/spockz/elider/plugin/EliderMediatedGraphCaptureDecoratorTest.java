/* WHY: Proves mediated graph capture delegates once and stores detached project snapshots. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.nio.file.Files;
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
import org.eclipse.aether.graph.DefaultDependencyNode;
import org.eclipse.aether.graph.DependencyNode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Exercises the separate post-mediation graph capture decorator. */
@SuppressWarnings({"PMD.CommentDefaultAccessModifier", "PMD.LawOfDemeter"})
final class EliderMediatedGraphCaptureDecoratorTest {
  /** Test-specific Maven project root. */
  @TempDir Path temporaryDirectory;

  /** Creates the test fixture. */
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  EliderMediatedGraphCaptureDecoratorTest() {
    super();
  }

  @Test
  @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
  void delegatesOnceReturnsReplacementRootAndCapturesDecorationTimeProvenance()
      throws IOException, org.eclipse.aether.RepositoryException {
    final MavenProject project = project(temporaryDirectory, "consumer");
    final DefaultRepositorySystemSession session = new DefaultRepositorySystemSession();
    final DependencyNode input = node("input");
    final DependencyNode replacement = node("replacement");
    final AtomicInteger delegateCalls = new AtomicInteger();
    final AtomicReference<DependencyGraphTransformationContext> expectedContext =
        new AtomicReference<>(context(session));
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
    final ResolverArtifactPlan plan = emptyPlan(project);
    session
        .getData()
        .set(
            ResolverArtifactPlanPublisher.SESSION_DATA_KEY,
            ResolverArtifactPlanStore.empty().withPlan(plan).toPayload());

    final DependencyNode returned =
        decorated.getDependencyGraphTransformer().transformGraph(input, expectedContext.get());
    final ResolverArtifactGraphSnapshotStore store = graphStore(decorated);
    final Map<String, Object> snapshot = store.snapshots().get(projectKey(project)).getFirst();

    assertThat(decorated).isNotSameAs(session);
    assertThat(returned).isSameAs(replacement);
    assertThat(delegateCalls).hasValue(1);
    assertThat(snapshot)
        .containsEntry("planPresent", false)
        .containsEntry("planFingerprint", null)
        .containsEntry("rootNodeId", "n0");
    assertThat((List<?>) snapshot.get("nodes")).hasSize(1);

    final RepositorySystemSession laterDecorated =
        new EliderMediatedGraphCaptureDecorator().decorate(project, session);
    expectedContext.set(context(laterDecorated));
    laterDecorated.getDependencyGraphTransformer().transformGraph(input, expectedContext.get());
    final List<Map<String, Object>> snapshots =
        graphStore(session).snapshots().get(projectKey(project));

    assertThat(delegateCalls).hasValue(2);
    assertThat(snapshots).hasSize(2);
    assertThat(snapshots.get(0))
        .containsEntry("planPresent", false)
        .containsEntry("planGeneration", 0L)
        .containsEntry("captureGeneration", 1L);
    assertThat(snapshots.get(1))
        .containsEntry("planPresent", true)
        .containsEntry("planGeneration", 1L)
        .containsEntry("captureGeneration", 2L);
    assertThat(snapshots.get(1).get("planFingerprint")).isNotNull();
    assertThat(snapshots.get(0).get("graphFingerprint"))
        .isEqualTo(snapshots.get(1).get("graphFingerprint"));
  }

  @Test
  @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
  void propagatesDelegateFailureWithoutAppendingSnapshot() throws IOException {
    final MavenProject project = project(temporaryDirectory, "failure");
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
                    .transformGraph(node("input"), context(decorated)))
        .isSameAs(failure);
    assertThat(decorated.getData().get(EliderMediatedGraphCaptureDecorator.SESSION_DATA_KEY))
        .isNull();
  }

  @Test
  @SuppressWarnings({"PMD.UnitTestContainsTooManyAsserts", "PMD.DoNotUseThreads"})
  void appendsConcurrentProjectCapturesAndDeduplicatesRepeatedGraph() throws Exception {
    final MavenProject firstProject = project(temporaryDirectory, "first");
    final MavenProject secondProject = project(temporaryDirectory, "second");
    final DefaultRepositorySystemSession session = new DefaultRepositorySystemSession();
    final RepositorySystemSession firstDecorated =
        new EliderMediatedGraphCaptureDecorator().decorate(firstProject, session);
    final RepositorySystemSession secondDecorated =
        new EliderMediatedGraphCaptureDecorator().decorate(secondProject, session);
    final DependencyNode repeated = node("same");
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
                      .transformGraph(repeated, context(firstDecorated));
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
          .transformGraph(node("other"), context(secondDecorated));
    }

    final ResolverArtifactGraphSnapshotStore store = graphStore(session);
    assertThat(store.snapshots()).containsKeys(projectKey(firstProject), projectKey(secondProject));
    assertThat(store.snapshots().get(projectKey(firstProject))).hasSize(1);
    assertThat(store.snapshots().get(projectKey(secondProject))).hasSize(1);
    assertThat(store.generations())
        .containsEntry(projectKey(firstProject), 1L)
        .containsEntry(projectKey(secondProject), 1L);
    assertThat(store.toPayload().values())
        .allSatisfy(EliderMediatedGraphCaptureDecoratorTest::assertJdkValue);
  }

  private static MavenProject project(final Path directory, final String artifactId)
      throws IOException {
    final Path projectDirectory = Files.createDirectory(directory.resolve(artifactId));
    final MavenProject project = new MavenProject();
    project.setFile(Files.createFile(projectDirectory.resolve("pom.xml")).toFile());
    project.setGroupId("fixture");
    project.setArtifactId(artifactId);
    project.setVersion("1.0");
    return project;
  }

  private static ResolverArtifactPlan emptyPlan(final MavenProject project) {
    return new ResolverArtifactPlan(
        new ResolverArtifactPlan.ProjectIdentity(
            project.getBasedir().toPath(),
            project.getGroupId(),
            project.getArtifactId(),
            project.getVersion()),
        Map.of());
  }

  private static String projectKey(final MavenProject project) {
    return ResolverArtifactPlanStore.projectKey(
        new ResolverArtifactPlan.ProjectIdentity(
            project.getBasedir().toPath(),
            project.getGroupId(),
            project.getArtifactId(),
            project.getVersion()));
  }

  private static DependencyNode node(final String artifactId) {
    return new DefaultDependencyNode(
        new org.eclipse.aether.artifact.DefaultArtifact("fixture", artifactId, "", "jar", "1.0"));
  }

  private static DependencyGraphTransformationContext context(
      final RepositorySystemSession session) {
    return new DependencyGraphTransformationContext() {
      @Override
      public RepositorySystemSession getSession() {
        return session;
      }

      @Override
      public Object get(final Object key) {
        return null;
      }

      @Override
      public Object put(final Object key, final Object value) {
        return null;
      }
    };
  }

  private static ResolverArtifactGraphSnapshotStore graphStore(
      final RepositorySystemSession session) {
    return ResolverArtifactGraphSnapshotStore.fromPayload(
        session.getData().get(EliderMediatedGraphCaptureDecorator.SESSION_DATA_KEY));
  }

  private static void assertJdkValue(final Object value) {
    if (value instanceof Map<?, ?> map) {
      map.values().forEach(EliderMediatedGraphCaptureDecoratorTest::assertJdkValue);
      return;
    }
    if (value instanceof List<?> list) {
      list.forEach(EliderMediatedGraphCaptureDecoratorTest::assertJdkValue);
      return;
    }
    assertThat(
            value == null
                || value instanceof String
                || value instanceof Boolean
                || value instanceof Integer
                || value instanceof Long)
        .isTrue();
  }
}
