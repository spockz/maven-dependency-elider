// WHY: Verifies the production decorator copies sessions only for exact planned artifact paths.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.apache.maven.model.Model;
import org.apache.maven.project.MavenProject;
import org.apache.maven.repository.internal.MavenWorkspaceReader;
import org.eclipse.aether.DefaultRepositorySystemSession;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.artifact.Artifact;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.eclipse.aether.repository.WorkspaceReader;
import org.eclipse.aether.repository.WorkspaceRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Exercises session identity, exact GAVCE replacement, and workspace delegation. */
@SuppressWarnings({
  "PMD.AtLeastOneConstructor",
  "PMD.CommentDefaultAccessModifier",
  "PMD.CommentRequired",
  "PMD.LawOfDemeter",
  "PMD.UnitTestContainsTooManyAsserts"
})
final class EliderRepositorySessionDecoratorTest {
  private static final String GROUP = "example";

  private static final String ARTIFACT = "keep";

  private static final String VERSION = "1.0";

  private static final String EXTENSION = "jar";

  private static final String CLASSIFIER = "";

  private static final ResolverArtifactPlan.ArtifactIdentity KEEP_IDENTITY =
      new ResolverArtifactPlan.ArtifactIdentity(GROUP, ARTIFACT, VERSION, EXTENSION, CLASSIFIER);

  private static final List<String> DELEGATED_VERSIONS = List.of("2.0", "2.1");

  @TempDir Path temporaryDirectory;

  @Test
  void returnsOriginalSessionWhenNoProjectPlanExists() throws IOException {
    final MavenProject project = project(temporaryDirectory);
    final DefaultRepositorySystemSession session = new DefaultRepositorySystemSession();

    assertThat(new EliderRepositorySessionDecorator().decorate(project, session)).isSameAs(session);
  }

  @Test
  void copiesSessionAndReplacesOnlyExactArtifactIdentity() throws IOException {
    final MavenProject project = project(temporaryDirectory);
    final Path replacement = temporaryDirectory.resolve("trimmed.jar");
    Files.writeString(replacement, "trimmed artifact bytes");
    final ResolverArtifactPlan.ProjectIdentity projectIdentity = projectIdentity(project);
    final ResolverArtifactPlan plan =
        new ResolverArtifactPlan(
            projectIdentity,
            Map.of(
                KEEP_IDENTITY,
                new ResolverArtifactPlan.Replacement(
                    replacement, ArtifactFileDigest.sha256(replacement))));
    final DefaultRepositorySystemSession session = new DefaultRepositorySystemSession();
    session
        .getData()
        .set(
            ResolverArtifactPlanPublisher.SESSION_DATA_KEY,
            ResolverArtifactPlanStore.empty().withPlan(plan).toPayload());
    final RecordingWorkspaceReader delegate = new RecordingWorkspaceReader();
    session.setWorkspaceReader(delegate);

    final RepositorySystemSession decorated =
        new EliderRepositorySessionDecorator().decorate(project, session);
    final WorkspaceReader reader = decorated.getWorkspaceReader();
    final Artifact keep = new DefaultArtifact(GROUP, ARTIFACT, CLASSIFIER, EXTENSION, VERSION);
    final List<Artifact> nonMatches =
        List.of(
            new DefaultArtifact("other", ARTIFACT, CLASSIFIER, EXTENSION, VERSION),
            new DefaultArtifact(GROUP, "other", CLASSIFIER, EXTENSION, VERSION),
            new DefaultArtifact(GROUP, ARTIFACT, CLASSIFIER, EXTENSION, "1.1"),
            new DefaultArtifact(GROUP, ARTIFACT, "tests", EXTENSION, VERSION),
            new DefaultArtifact(GROUP, ARTIFACT, CLASSIFIER, "pom", VERSION));

    assertThat(decorated).isNotSameAs(session);
    assertThat(reader).isNotSameAs(delegate);
    assertThat(reader.getRepository()).isSameAs(delegate.repository);
    assertThat(reader.findArtifact(keep)).isEqualTo(replacement.toFile());
    assertThat(reader.findVersions(keep)).containsExactly(VERSION);
    assertThat(((MavenWorkspaceReader) reader).findModel(keep)).isSameAs(delegate.model);
    for (final Artifact artifact : nonMatches) {
      assertThat(reader.findArtifact(artifact)).isEqualTo(delegate.file);
      assertThat(reader.findVersions(artifact)).containsExactlyElementsOf(DELEGATED_VERSIONS);
    }
    assertThat(delegate.artifacts).containsExactlyElementsOf(nonMatches);
    assertThat(delegate.versionQueries).containsExactlyElementsOf(nonMatches);
    Files.writeString(replacement, "changed artifact bytes");
    assertThatThrownBy(() -> reader.findArtifact(keep))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("changed after validation");
  }

  private static MavenProject project(final Path baseDirectory) throws IOException {
    final File pom = Files.createFile(baseDirectory.resolve("pom.xml")).toFile();
    final MavenProject project = new MavenProject();
    project.setFile(pom);
    project.setGroupId("consumer");
    project.setArtifactId("app");
    project.setVersion(VERSION);
    return project;
  }

  private static ResolverArtifactPlan.ProjectIdentity projectIdentity(final MavenProject project) {
    return new ResolverArtifactPlan.ProjectIdentity(
        project.getBasedir().toPath(),
        project.getGroupId(),
        project.getArtifactId(),
        project.getVersion());
  }

  private static final class RecordingWorkspaceReader implements MavenWorkspaceReader {
    private final WorkspaceRepository repository = new WorkspaceRepository("delegate");

    private final File file = new File("delegated.jar");

    private final List<Artifact> artifacts = new ArrayList<>();

    private final List<Artifact> versionQueries = new ArrayList<>();

    private final Model model = new Model();

    @Override
    public WorkspaceRepository getRepository() {
      return repository;
    }

    @Override
    public File findArtifact(final Artifact artifact) {
      artifacts.add(artifact);
      return file;
    }

    @Override
    public Model findModel(final Artifact artifact) {
      return model;
    }

    @Override
    public List<String> findVersions(final Artifact artifact) {
      versionQueries.add(artifact);
      return DELEGATED_VERSIONS;
    }
  }
}
