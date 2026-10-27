/* WHY: Verifies which project view invalidates Maven core 3.9.9's lifecycle cache. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.apache.maven.lifecycle.internal.DependencyContext;
import org.apache.maven.project.MavenProject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Verifies the lifecycle cache key in the Maven core 3.9.9 test dependency. */
@SuppressWarnings({
  "PMD.AvoidDuplicateLiterals",
  "PMD.LawOfDemeter",
  "PMD.UnitTestContainsTooManyAsserts"
})
final class DependencyContextReResolutionTest {
  /** Temporary files representing original and transformed dependencies. */
  @TempDir private Path tempDir;

  /** Creates the focused diagnostic fixture. */
  @SuppressWarnings({"PMD.UncommentedEmptyConstructor", "PMD.CommentDefaultAccessModifier"})
  DependencyContextReResolutionTest() {}

  @Test
  void resolvedViewMutationDoesNotInvalidateDirectArtifactResolutionCache() throws Exception {
    final Artifact direct = artifact("direct", "original-direct.jar");
    final Artifact transitive = artifact("transitive", "original-transitive.jar");
    final MavenProject project = project(Set.of(direct), Set.of(direct, transitive));
    final DependencyContext context = context(project);
    context.synchronizeWithProjectState();

    final Artifact transformed = artifact("direct", "trimmed-direct.jar");
    project.setArtifacts(new LinkedHashSet<>(List.of(transformed)));

    final ArtifactViews views = snapshot(project);

    assertThat(views.direct()).hasSize(1);
    assertThat(views.resolved()).hasSize(1);
    assertThat(views.direct().getFirst().coordinate()).isEqualTo("org.example:direct:1.0:jar");
    assertThat(views.direct().getFirst().artifact()).isSameAs(direct);
    assertThat(views.direct().getFirst().fileHash())
        .isNotEqualTo(views.resolved().getFirst().fileHash());
    assertThat(views.direct().getFirst().filePath()).endsWith("original-direct.jar");
    assertThat(views.resolved().getFirst().filePath()).endsWith("trimmed-direct.jar");
    assertThat(context.isResolutionRequiredForCurrentProject()).isFalse();
  }

  @Test
  void replacingDirectViewInvalidatesCacheEvenWhenContentsHaveSameSize() throws Exception {
    final Artifact direct = artifact("direct", "direct.jar");
    final Artifact transitive = artifact("transitive", "transitive.jar");
    final MavenProject project = project(Set.of(direct), Set.of(direct, transitive));
    final DependencyContext context = context(project);
    context.synchronizeWithProjectState();
    final ArtifactViews before = snapshot(project);

    project.setDependencyArtifacts(new LinkedHashSet<>(List.of(direct)));
    final ArtifactViews after = snapshot(project);

    assertThat(after.direct()).hasSize(before.direct().size());
    assertThat(after.direct().getFirst().coordinate())
        .isEqualTo(before.direct().getFirst().coordinate());
    assertThat(after.directCollection()).isNotSameAs(before.directCollection());
    assertThat(context.isResolutionRequiredForCurrentProject()).isTrue();
  }

  @Test
  void pruningDirectViewInPlaceInvalidatesCacheBySize() throws Exception {
    final Artifact direct = artifact("direct", "direct.jar");
    final Artifact secondDirect = artifact("second-direct", "second-direct.jar");
    final Artifact transitive = artifact("transitive", "transitive.jar");
    final Set<Artifact> directArtifacts = new LinkedHashSet<>(List.of(direct, secondDirect));
    final MavenProject project = project(directArtifacts, Set.of(direct, secondDirect, transitive));
    final DependencyContext context = context(project);
    context.synchronizeWithProjectState();

    directArtifacts.remove(secondDirect);
    final ArtifactViews views = snapshot(project);

    assertThat(views.direct()).hasSize(1);
    assertThat(views.resolved()).hasSize(3);
    assertThat(context.isResolutionRequiredForCurrentProject()).isTrue();
    context.synchronizeWithProjectState();
    assertThat(context.isResolutionRequiredForCurrentProject()).isFalse();
  }

  private Artifact artifact(final String artifactId, final String fileName) throws IOException {
    final Path file = tempDir.resolve(fileName);
    Files.writeString(file, "fixture:" + artifactId + ":" + fileName);
    final Artifact artifact =
        new DefaultArtifact(
            "org.example",
            artifactId,
            "1.0",
            "compile",
            "jar",
            null,
            new DefaultArtifactHandler("jar"));
    artifact.setFile(file.toFile());
    return artifact;
  }

  private static MavenProject project(
      final Set<Artifact> directArtifacts, final Set<Artifact> resolvedArtifacts) {
    final MavenProject project = new MavenProject();
    project.setDependencyArtifacts(directArtifacts);
    project.setArtifacts(resolvedArtifacts);
    return project;
  }

  private static DependencyContext context(final MavenProject project) {
    return new DependencyContext(project, List.of("compile"), List.of("compile"));
  }

  private static ArtifactViews snapshot(final MavenProject project) throws IOException {
    final Set<Artifact> directArtifacts = project.getDependencyArtifacts();
    final Set<Artifact> resolvedArtifacts = project.getArtifacts();
    return new ArtifactViews(
        directArtifacts, snapshots(directArtifacts), snapshots(resolvedArtifacts));
  }

  private static List<ArtifactState> snapshots(final Set<Artifact> artifacts) throws IOException {
    final List<ArtifactState> states = new ArrayList<>();
    for (final Artifact artifact : artifacts) {
      final Path path = artifact.getFile().toPath().toAbsolutePath().normalize();
      states.add(
          new ArtifactState(
              artifact,
              artifact.getGroupId()
                  + ":"
                  + artifact.getArtifactId()
                  + ":"
                  + artifact.getVersion()
                  + ":"
                  + artifact.getType(),
              path.toString(),
              sha256(path)));
    }
    states.sort(Comparator.comparing(ArtifactState::coordinate));
    return List.copyOf(states);
  }

  private static String sha256(final Path path) throws IOException {
    try {
      return HexFormat.of()
          .formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(path)));
    } catch (NoSuchAlgorithmException exception) {
      throw new IllegalStateException("Java runtime does not provide SHA-256", exception);
    }
  }

  private record ArtifactState(
      Artifact artifact, String coordinate, String filePath, String fileHash) {}

  private record ArtifactViews(
      Set<Artifact> directCollection, List<ArtifactState> direct, List<ArtifactState> resolved) {}
}
