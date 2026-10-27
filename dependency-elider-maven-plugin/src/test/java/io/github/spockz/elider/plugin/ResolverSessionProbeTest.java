/* WHY: Verifies the test-only workspace reader's exact override and fallback contract. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.spockz.elider.test.resolver.ResolverSessionProbe;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import org.eclipse.aether.artifact.Artifact;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.eclipse.aether.repository.WorkspaceReader;
import org.eclipse.aether.repository.WorkspaceRepository;
import org.junit.jupiter.api.Test;

/** Checks that the planned reader delegates every non-target workspace lookup. */
@SuppressWarnings({
  "PMD.AtLeastOneConstructor",
  "PMD.CommentRequired",
  "PMD.UnitTestContainsTooManyAsserts"
})
final class ResolverSessionProbeTest {
  private static final String KEEP_GROUP = "io.github.spockz.elider.test";

  private static final String KEEP_ARTIFACT = "keep-library";

  private static final String KEEP_VERSION = "1.0.0";

  private static final String JAR_EXTENSION = "jar";

  private static final List<String> DELEGATED_VERSIONS = List.of("2.0", "2.1");

  private static final File REPLACEMENT = new File("replacement.jar");

  @Test
  void delegatesOtherArtifactsAndPreservesWorkspaceRepository() {
    final RecordingWorkspaceReader delegate = new RecordingWorkspaceReader();
    final ResolverSessionProbe.PlannedWorkspaceReader reader =
        new ResolverSessionProbe.PlannedWorkspaceReader(delegate, REPLACEMENT.getPath(), 12);
    final Artifact other =
        new DefaultArtifact("org.example", "other", "tests", "zip", DELEGATED_VERSIONS.get(0));

    assertThat(reader.findArtifact(other)).isEqualTo(delegate.file);
    assertThat(reader.findVersions(other)).containsExactlyElementsOf(DELEGATED_VERSIONS);
    assertThat(reader.getRepository()).isSameAs(delegate.repository);
    assertThat(delegate.artifacts).containsExactly(other);
    assertThat(delegate.versionQueries).containsExactly(other);
  }

  @Test
  void replacesOnlyTheExactKeepLibraryGavce() {
    final RecordingWorkspaceReader delegate = new RecordingWorkspaceReader();
    final ResolverSessionProbe.PlannedWorkspaceReader reader =
        new ResolverSessionProbe.PlannedWorkspaceReader(delegate, REPLACEMENT.getPath(), 13);
    final Artifact keep =
        new DefaultArtifact(KEEP_GROUP, KEEP_ARTIFACT, "", JAR_EXTENSION, KEEP_VERSION);
    final Artifact otherVersion =
        new DefaultArtifact(KEEP_GROUP, KEEP_ARTIFACT, "", JAR_EXTENSION, "1.0.1");
    final List<Artifact> nonMatchingArtifacts =
        List.of(
            new DefaultArtifact("org.example", KEEP_ARTIFACT, "", JAR_EXTENSION, KEEP_VERSION),
            new DefaultArtifact(KEEP_GROUP, "other-library", "", JAR_EXTENSION, KEEP_VERSION),
            new DefaultArtifact(KEEP_GROUP, KEEP_ARTIFACT, "tests", JAR_EXTENSION, KEEP_VERSION),
            new DefaultArtifact(KEEP_GROUP, KEEP_ARTIFACT, "", "pom", KEEP_VERSION),
            otherVersion);

    assertThat(reader.findArtifact(keep)).isEqualTo(REPLACEMENT);
    assertThat(reader.findVersions(keep)).containsExactly(KEEP_VERSION);
    for (final Artifact artifact : nonMatchingArtifacts) {
      assertThat(reader.findArtifact(artifact)).isEqualTo(delegate.file);
      assertThat(reader.findVersions(artifact)).containsExactlyElementsOf(DELEGATED_VERSIONS);
    }
    assertThat(delegate.artifacts).containsExactlyElementsOf(nonMatchingArtifacts);
    assertThat(delegate.versionQueries).containsExactlyElementsOf(nonMatchingArtifacts);
  }

  private static final class RecordingWorkspaceReader implements WorkspaceReader {
    private final WorkspaceRepository repository = new WorkspaceRepository("delegate-reader");

    private final File file = new File("delegate.jar");

    private final List<Artifact> artifacts = new ArrayList<>();

    private final List<Artifact> versionQueries = new ArrayList<>();

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
    public List<String> findVersions(final Artifact artifact) {
      versionQueries.add(artifact);
      return List.of("2.0", "2.1");
    }
  }
}
