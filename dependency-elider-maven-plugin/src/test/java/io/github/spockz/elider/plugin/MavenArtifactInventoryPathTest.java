/* WHY: Verifies symlinked artifact paths match ArtifactFileRef real paths. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ArtifactFileRef;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.ArtifactSnapshot;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import org.apache.maven.artifact.Artifact;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Verifies symlinked artifact paths normalize to real paths. */
@SuppressWarnings({"PMD.AtLeastOneConstructor", "PMD.CommentRequired"})
final class MavenArtifactInventoryPathTest {
  @TempDir private Path tempDir;

  @Test
  void snapshotsResolveSymlinkedPathsToMatchArtifactFileRef() throws Exception {
    final Path realDir = Files.createDirectories(tempDir.resolve("real"));
    final Path linkDir = Files.createSymbolicLink(tempDir.resolve("link"), realDir);
    final Path realJar = realDir.resolve("sample.jar");
    try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(realJar))) {
      output.putNextEntry(new JarEntry("META-INF/MANIFEST.MF"));
      output.write("Manifest-Version: 1.0\n".getBytes(java.nio.charset.StandardCharsets.UTF_8));
      output.closeEntry();
    }
    final Path linkedJar = linkDir.resolve("sample.jar");
    final Artifact mavenArtifact = MavenBanAuditTestSupport.mavenArtifact("sample", linkedJar);
    final ArtifactCoordinate coordinate = MavenBanAuditTestSupport.coordinate("sample");
    final ArtifactSnapshot snapshot =
        MavenArtifactInventory.snapshots(List.of(mavenArtifact)).getFirst();
    final ArtifactFileRef fileRef = ArtifactFileRef.fromPath(coordinate, linkedJar);
    assertThat(snapshot.filePath()).isEqualTo(fileRef.filePath());
  }
}
