/* WHY: Binds Maven artifact files independently from the path-free resolver
 * graph snapshot. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.HexDigest;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Fingerprints the resolved Maven artifact files and their resolver extensions. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class ResolvedArtifactInventoryFingerprint {
  /** Resolver extension required for bytecode inputs. */
  private static final String JAR_EXTENSION = "jar";

  private ResolvedArtifactInventoryFingerprint() {
    throw new AssertionError("No instances");
  }

  static String fingerprint(final List<ElisionAnalysisModel.ArtifactSnapshot> inventory)
      throws IOException {
    return fingerprint(inventory, new HashMap<>());
  }

  static String fingerprint(
      final List<ElisionAnalysisModel.ArtifactSnapshot> inventory,
      final Map<Path, String> contentDigests)
      throws IOException {
    final List<String> entries = new ArrayList<>();
    final Set<String> identities = new HashSet<>();
    for (final ElisionAnalysisModel.ArtifactSnapshot snapshot : inventory) {
      final ArtifactCoordinate coordinate = snapshot.coordinate();
      final String extension = resolverExtension(snapshot);
      if (extension == null || extension.isBlank()) {
        throw new IOException(
            "Cannot map Maven artifact type to resolver extension: " + coordinate);
      }
      final String identity = identity(coordinate, extension);
      if (!identities.add(identity)) {
        throw new IOException(
            "Duplicate resolved artifact identity cannot bind graph pair: " + identity);
      }
      entries.add(inventoryEntry(snapshot, extension, contentDigests));
    }
    entries.sort(Comparator.naturalOrder());
    return HexDigest.sha256LengthPrefixed(entries);
  }

  /** Reads the resolver extension through Maven's artifact handler. */
  @SuppressWarnings("PMD.LawOfDemeter")
  static String resolverExtension(final ElisionAnalysisModel.ArtifactSnapshot snapshot) {
    final org.apache.maven.artifact.Artifact artifact = snapshot.artifact();
    final org.apache.maven.artifact.handler.ArtifactHandler handler = artifact.getArtifactHandler();
    if (handler == null) {
      return null;
    }
    return handler.getExtension();
  }

  private static String inventoryEntry(
      final ElisionAnalysisModel.ArtifactSnapshot snapshot,
      final String extension,
      final Map<Path, String> contentDigests)
      throws IOException {
    final String path = snapshot.filePath() == null ? "<missing>" : snapshot.filePath().toString();
    final String digest = digest(snapshot, extension, contentDigests);
    return snapshot.coordinate() + "\t" + extension + "\t" + path + "\t" + digest;
  }

  private static String digest(
      final ElisionAnalysisModel.ArtifactSnapshot snapshot,
      final String extension,
      final Map<Path, String> contentDigests)
      throws IOException {
    if (snapshot.filePath() != null && Files.isRegularFile(snapshot.filePath())) {
      final Path path = snapshot.filePath();
      final String cachedDigest = contentDigests.get(path);
      if (cachedDigest != null) {
        return cachedDigest;
      }
      final String digest = HexDigest.sha256(path);
      contentDigests.put(path, digest);
      return digest;
    }
    if (JAR_EXTENSION.equals(extension)) {
      throw new IOException("Resolved JAR has no file path: " + snapshot.coordinate());
    }
    return "<missing>";
  }

  private static String identity(final ArtifactCoordinate coordinate, final String extension) {
    return coordinate.groupId()
        + ":"
        + coordinate.artifactId()
        + ":"
        + coordinate.version()
        + ":"
        + extension
        + ":"
        + coordinate.classifier();
  }
}
