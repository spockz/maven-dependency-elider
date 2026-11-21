/* WHY: Shares normalized archive digests within a trim operation so keys and
 * provenance describe the same bytes. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactDigests;
import io.github.spockz.elider.trimmer.MultiReleaseArchivePlan;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

/** Reads shared normalized archive digests for keys and provenance. */
final class TrimInputDigests {
  private TrimInputDigests() {}

  /* package */ static Map<Path, ArtifactDigests> inputDigests(final List<Path> inputPaths)
      throws IOException {
    return inputDigests(inputPaths, Map.of());
  }

  /* package */ static Map<Path, ArtifactDigests> inputDigests(
      final List<Path> inputPaths,
      final Map<Path, MultiReleaseArchivePlan.SourceData> sharedSources)
      throws IOException {
    final Map<Path, ArtifactDigests> digests = TrimCollections.orderedMap();
    for (final Path inputPath : inputPaths) {
      final Path normalizedPath = inputPath.toAbsolutePath().normalize();
      if (!digests.containsKey(normalizedPath)) {
        final MultiReleaseArchivePlan.SourceData shared = sharedSources.get(normalizedPath);
        if (shared == null) {
          MultiReleaseWorkObserver.recordDigestRead(normalizedPath);
          digests.put(normalizedPath, ArtifactDigests.read(normalizedPath));
        } else {
          digests.put(normalizedPath, shared.digests());
        }
      }
    }
    return Map.copyOf(digests);
  }

  /* package */ static ArtifactDigests requiredInputDigest(
      final Map<Path, ArtifactDigests> inputDigests, final Path inputPath) {
    final Path normalizedPath = inputPath.toAbsolutePath().normalize();
    final ArtifactDigests digest = inputDigests.get(normalizedPath);
    if (digest == null) {
      throw new IllegalStateException(
          "Missing input digest for retained archive: " + normalizedPath);
    }
    return digest;
  }
}
