// WHY: Verifies a plan for one mediated graph cannot mutate another graph.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.apache.maven.project.MavenProject;
import org.eclipse.aether.DefaultRepositorySystemSession;
import org.eclipse.aether.RepositoryException;
import org.eclipse.aether.collection.DependencyGraphTransformer;
import org.eclipse.aether.graph.DefaultDependencyNode;
import org.eclipse.aether.graph.DependencyNode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Checks source-fingerprint rejection before the decorator changes graph edges. */
final class ResolverArtifactGraphProjectionMismatchTest {
  /** Root artifact ID used by the graph fixtures. */
  private static final String CONSUMER = "consumer";

  /** Candidate node removed by the projection. */
  private static final String DROP = "drop";

  /** Candidate node retained by the projection. */
  private static final String KEEP = "keep";

  /** Temporary project root used to bind plans to one project. */
  @TempDir private Path temporaryDirectory;

  /** Creates the graph mismatch fixture. */
  @SuppressWarnings({"PMD.UncommentedEmptyConstructor", "PMD.CommentDefaultAccessModifier"})
  ResolverArtifactGraphProjectionMismatchTest() {}

  @Test
  @SuppressWarnings({"PMD.UnitTestContainsTooManyAsserts", "PMD.LawOfDemeter"})
  // The assertions verify failure occurs before this resolver graph is mutated.
  void mismatchedTestGraphFailsBeforeChangingItsChildren() throws IOException {
    final MavenProject project = project();
    final String projectKey = EliderMediatedGraphCaptureDecoratorTestSupport.projectKey(project);
    final DependencyNode sourceRoot = node(CONSUMER);
    sourceRoot.setChildren(List.of(node(DROP), node(KEEP)));
    final ResolverArtifactGraphSnapshot source =
        ResolverArtifactGraphSnapshot.capture(sourceRoot, projectKey, false, null, 0L, 0L);
    final ResolverArtifactGraphProjection projection =
        new ResolverArtifactGraphProjection(
            "source-capture",
            source.graphFingerprint(),
            ResolverArtifactGraphProjection.projectedFingerprint(source, List.of("n1")),
            List.of("n1"));
    final ResolverArtifactPlan plan =
        new ResolverArtifactPlan(
            new ResolverArtifactPlan.ProjectIdentity(
                project.getBasedir().toPath(),
                project.getGroupId(),
                project.getArtifactId(),
                project.getVersion()),
            Map.of(),
            projection);
    final DefaultRepositorySystemSession session = new DefaultRepositorySystemSession();
    session
        .getData()
        .set(
            ResolverArtifactPlanPublisher.SESSION_DATA_KEY,
            ResolverArtifactPlanStore.empty().withPlan(plan).toPayload());
    final DependencyGraphTransformer transformer =
        new EliderMediatedGraphCaptureDecorator()
            .decorate(project, session)
            .getDependencyGraphTransformer();
    final DependencyNode actualRoot = node(CONSUMER);
    final DependencyNode actualKeep = node(KEEP);
    actualRoot.setChildren(List.of(actualKeep));
    final List<DependencyNode> originalChildren = List.copyOf(actualRoot.getChildren());

    assertThatThrownBy(
            () ->
                transformer.transformGraph(
                    actualRoot, EliderMediatedGraphCaptureDecoratorTestSupport.context(session)))
        .isInstanceOf(RepositoryException.class)
        .hasMessageContaining("does not match the elision projection source fingerprint");
    assertThat(actualRoot.getChildren()).containsExactlyElementsOf(originalChildren);
    assertThat(actualRoot.getChildren().getFirst()).isSameAs(actualKeep);
  }

  @Test
  @SuppressWarnings({"PMD.UnitTestContainsTooManyAsserts", "PMD.LawOfDemeter"})
  // Checks rollback restores the original child-list object and contents.
  void projectedFingerprintMismatchRestoresTheOriginalChildListObjects() throws IOException {
    final MavenProject project = project();
    final String projectKey = EliderMediatedGraphCaptureDecoratorTestSupport.projectKey(project);
    final DependencyNode sourceRoot = node(CONSUMER);
    sourceRoot.setChildren(List.of(node(DROP), node(KEEP)));
    final ResolverArtifactGraphSnapshot source =
        ResolverArtifactGraphSnapshot.capture(sourceRoot, projectKey, false, null, 0L, 0L);
    final ResolverArtifactGraphProjection projection =
        new ResolverArtifactGraphProjection(
            "source-capture", source.graphFingerprint(), "f".repeat(64), List.of("n1"));
    final ResolverArtifactPlan plan =
        new ResolverArtifactPlan(
            new ResolverArtifactPlan.ProjectIdentity(
                project.getBasedir().toPath(),
                project.getGroupId(),
                project.getArtifactId(),
                project.getVersion()),
            Map.of(),
            projection);
    final DefaultRepositorySystemSession session = new DefaultRepositorySystemSession();
    session
        .getData()
        .set(
            ResolverArtifactPlanPublisher.SESSION_DATA_KEY,
            ResolverArtifactPlanStore.empty().withPlan(plan).toPayload());
    final DependencyGraphTransformer transformer =
        new EliderMediatedGraphCaptureDecorator()
            .decorate(project, session)
            .getDependencyGraphTransformer();
    final DependencyNode actualRoot = node(CONSUMER);
    final DependencyNode actualDrop = node(DROP);
    final DependencyNode actualKeep = node(KEEP);
    actualRoot.setChildren(new java.util.ArrayList<>(List.of(actualDrop, actualKeep)));
    final List<DependencyNode> originalChildren = actualRoot.getChildren();

    assertThatThrownBy(
            () ->
                transformer.transformGraph(
                    actualRoot, EliderMediatedGraphCaptureDecoratorTestSupport.context(session)))
        .isInstanceOf(RepositoryException.class)
        .hasMessageContaining("Cannot apply the validated elision graph projection")
        .hasRootCauseMessage("Projected graph does not match its expected fingerprint");
    assertThat(actualRoot.getChildren()).isSameAs(originalChildren);
    assertThat(actualRoot.getChildren()).containsExactly(actualDrop, actualKeep);
  }

  private MavenProject project() throws IOException {
    final Path projectDirectory = Files.createDirectory(temporaryDirectory.resolve("consumer"));
    final MavenProject project = new MavenProject();
    project.setFile(Files.createFile(projectDirectory.resolve("pom.xml")).toFile());
    project.setGroupId("fixture");
    project.setArtifactId("consumer");
    project.setVersion("1.0");
    return project;
  }

  private static DependencyNode node(final String artifactId) {
    return new DefaultDependencyNode(
        new org.eclipse.aether.artifact.DefaultArtifact("fixture", artifactId, "", "jar", "1.0"));
  }
}
