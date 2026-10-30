// WHY: Rejects conflicting files before mutable Maven artifact views can
// publish a plan.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.plugin.ElisionAnalysisModel.ArtifactSnapshot;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Checks file consistency across scope-independent artifact identities. */
final class MavenArtifactPathValidation {
  private MavenArtifactPathValidation() {}

  /* package */ static void validateIdentityPaths(final List<ArtifactSnapshot> snapshots)
      throws IOException {
    final Map<MavenArtifactIdentity, Path> paths = LinkedHashMap.newLinkedHashMap(snapshots.size());
    for (final ArtifactSnapshot snapshot : snapshots) {
      if (!"jar".equals(snapshot.coordinate().type())) {
        continue;
      }
      final Path file = requiredJarFile(snapshot);
      final MavenArtifactIdentity identity = MavenArtifactIdentity.from(snapshot.coordinate());
      final Path previous = paths.putIfAbsent(identity, file);
      if (previous != null && !previous.equals(file)) {
        throw new IOException("Conflicting files for artifact identity " + identity);
      }
    }
  }

  private static Path requiredJarFile(final ArtifactSnapshot snapshot) throws IOException {
    final Path file = snapshot.filePath();
    if (file == null) {
      throw missingJar(snapshot);
    }
    final Path fileName = file.getFileName();
    if (fileName == null || !Files.isRegularFile(file) || !fileName.toString().endsWith(".jar")) {
      throw missingJar(snapshot);
    }
    return file;
  }

  private static IOException missingJar(final ArtifactSnapshot snapshot) {
    return new IOException("Resolved artifact has no regular JAR file: " + snapshot.coordinate());
  }

  /* package */ static void validateDirectPaths(
      final Collection<ArtifactSnapshot> resolved, final Collection<ArtifactSnapshot> direct)
      throws IOException {
    final Map<MavenArtifactIdentity, Path> resolvedPaths =
        LinkedHashMap.newLinkedHashMap(resolved.size());
    for (final ArtifactSnapshot snapshot : resolved) {
      if ("jar".equals(snapshot.coordinate().type()) && snapshot.filePath() != null) {
        resolvedPaths.put(MavenArtifactIdentity.from(snapshot.coordinate()), snapshot.filePath());
      }
    }
    for (final ArtifactSnapshot snapshot : direct) {
      final MavenArtifactIdentity identity = MavenArtifactIdentity.from(snapshot.coordinate());
      final Path resolvedPath = resolvedPaths.get(identity);
      final Path file = snapshot.filePath();
      if (resolvedPath != null && file != null && !resolvedPath.equals(file)) {
        throw new IOException("Conflicting direct artifact file for identity " + identity);
      }
    }
  }
}
