/* WHY: Keeps fixture construction out of the focused graph decorator behavior tests. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.apache.maven.project.MavenProject;
import org.eclipse.aether.DefaultRepositorySystemSession;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.collection.DependencyGraphTransformationContext;
import org.eclipse.aether.graph.DefaultDependencyNode;
import org.eclipse.aether.graph.DependencyNode;

/** Small fixture factories shared by the capture decorator tests. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class EliderMediatedGraphCaptureDecoratorTestSupport {
  private EliderMediatedGraphCaptureDecoratorTestSupport() {
    throw new AssertionError("No instances");
  }

  static MavenProject project(final Path directory, final String artifactId) throws IOException {
    final Path projectDirectory = Files.createDirectory(directory.resolve(artifactId));
    final MavenProject project = new MavenProject();
    project.setFile(Files.createFile(projectDirectory.resolve("pom.xml")).toFile());
    project.setGroupId("fixture");
    project.setArtifactId(artifactId);
    project.setVersion("1.0");
    return project;
  }

  static ResolverArtifactPlan emptyPlan(final MavenProject project) {
    final Path basedir = basedir(project);
    return new ResolverArtifactPlan(
        new ResolverArtifactPlan.ProjectIdentity(
            basedir, project.getGroupId(), project.getArtifactId(), project.getVersion()),
        Map.of());
  }

  static String projectKey(final MavenProject project) {
    final Path basedir = basedir(project);
    return ResolverArtifactPlanStore.projectKey(
        new ResolverArtifactPlan.ProjectIdentity(
            basedir, project.getGroupId(), project.getArtifactId(), project.getVersion()));
  }

  static DependencyNode node(final String artifactId) {
    return new DefaultDependencyNode(
        new org.eclipse.aether.artifact.DefaultArtifact("fixture", artifactId, "", "jar", "1.0"));
  }

  static DependencyGraphTransformationContext context(final RepositorySystemSession session) {
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

  // The fixture reads the session payload through Aether's session API.
  @SuppressWarnings("PMD.LawOfDemeter")
  static ResolverArtifactGraphSnapshotStore graphStore(final RepositorySystemSession session) {
    final org.eclipse.aether.SessionData sessionData = session.getData();
    return ResolverArtifactGraphSnapshotStore.fromPayload(
        sessionData.get(EliderMediatedGraphCaptureDecorator.SESSION_DATA_KEY));
  }

  // Project identity is available only through MavenProject getters.
  @SuppressWarnings("PMD.LawOfDemeter")
  private static Path basedir(final MavenProject project) {
    final File basedirFile = project.getBasedir();
    return basedirFile.toPath();
  }

  static DefaultRepositorySystemSession session() {
    return new DefaultRepositorySystemSession();
  }

  static void assertJdkValue(final Object value) {
    if (value instanceof Map<?, ?> map) {
      map.values().forEach(EliderMediatedGraphCaptureDecoratorTestSupport::assertJdkValue);
      return;
    }
    if (value instanceof List<?> list) {
      list.forEach(EliderMediatedGraphCaptureDecoratorTestSupport::assertJdkValue);
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
