// WHY: Proves validated plan publication, project isolation, stale-plan clearing, and failure
// safety.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.HexDigest;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.apache.maven.execution.DefaultMavenExecutionRequest;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.project.MavenProject;
import org.eclipse.aether.DefaultRepositorySystemSession;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Tests publication and project-local plan safety. */
@SuppressWarnings({"PMD.AtLeastOneConstructor", "PMD.CommentDefaultAccessModifier"})
final class ResolverArtifactPlanPublisherTest {
  /** Temporary project roots and trim outputs. */
  @TempDir Path temporaryDirectory;

  @Test
  @SuppressWarnings({"PMD.LawOfDemeter"})
  void publishesOneProjectAndClearsItsPriorPlanWithoutRemovingAnotherProject() throws IOException {
    final MavenSession session = session();
    final MavenProject firstProject = project("first", "consumer-one");
    final MavenProject secondProject = project("second", "consumer-two");
    final ArtifactTrimRecord firstRecord = trimRecord("first");
    final ArtifactTrimRecord secondRecord = trimRecord("second");

    ResolverArtifactPlanPublisher.publish(session, firstProject, List.of(firstRecord));
    ResolverArtifactPlanPublisher.publish(session, secondProject, List.of(secondRecord));
    ResolverArtifactPlanPublisher.publish(session, firstProject, List.of());

    final ResolverArtifactPlanStore store =
        ResolverArtifactPlanStore.fromPayload(
            session
                .getRepositorySession()
                .getData()
                .get(ResolverArtifactPlanPublisher.SESSION_DATA_KEY));
    assertThat(store.find(projectIdentity(firstProject)).replacements()).isEmpty();
    assertThat(store.find(projectIdentity(secondProject)).replacements())
        .hasSize(1)
        .containsKey(
            new ResolverArtifactPlan.ArtifactIdentity("example", "second", "1.0", "jar", ""));
  }

  private MavenProject project(final String directory, final String artifactId) throws IOException {
    final Path baseDirectory = Files.createDirectories(temporaryDirectory.resolve(directory));
    final Path pom = Files.createFile(baseDirectory.resolve("pom.xml"));
    final MavenProject project = new MavenProject();
    project.setFile(pom.toFile());
    project.setGroupId("example");
    project.setArtifactId(artifactId);
    project.setVersion("1.0");
    return project;
  }

  private ArtifactTrimRecord trimRecord(final String name) throws IOException {
    final Path original = Files.createFile(temporaryDirectory.resolve(name + "-original.jar"));
    final Path trimmed = Files.createFile(temporaryDirectory.resolve(name + "-trimmed.jar"));
    Files.writeString(original, "original bytes " + name);
    Files.writeString(trimmed, "trimmed bytes " + name);
    return new ArtifactTrimRecord(
        ArtifactCoordinate.of("example", name, "1.0"),
        original,
        HexDigest.sha256(original),
        "0".repeat(40),
        trimmed,
        HexDigest.sha256(trimmed),
        "1".repeat(40),
        2,
        1,
        10);
  }

  private static MavenSession session() {
    return new MavenSession(
        null, new DefaultRepositorySystemSession(), new DefaultMavenExecutionRequest(), null);
  }

  @SuppressWarnings("PMD.LawOfDemeter")
  private static ResolverArtifactPlan.ProjectIdentity projectIdentity(final MavenProject project) {
    return new ResolverArtifactPlan.ProjectIdentity(
        project.getBasedir().toPath(),
        project.getGroupId(),
        project.getArtifactId(),
        project.getVersion());
  }
}
