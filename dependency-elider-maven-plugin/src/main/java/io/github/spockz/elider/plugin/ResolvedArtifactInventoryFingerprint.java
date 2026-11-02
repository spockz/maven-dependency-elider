/* WHY: Binds Maven artifact files independently from the path-free resolver
 * graph snapshot. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.trimmer.ArtifactDigests;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
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

  private static String fingerprint(
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
    return sha256(entries);
  }

  static void verifyFingerprint(
      final List<ElisionAnalysisModel.ArtifactSnapshot> inventory, final String expectedFingerprint)
      throws IOException {
    verifyFingerprint(inventory, expectedFingerprint, new HashMap<>());
  }

  private static void verifyFingerprint(
      final List<ElisionAnalysisModel.ArtifactSnapshot> inventory,
      final String expectedFingerprint,
      final Map<Path, String> contentDigests)
      throws IOException {
    if (expectedFingerprint == null
        || !expectedFingerprint.equals(fingerprint(inventory, contentDigests))) {
      throw new IOException("Resolved artifact inventory changed after fingerprinting");
    }
  }

  // WHY: The map is local to one call and never shared between threads.
  @SuppressWarnings("PMD.UseConcurrentHashMap")
  static void verifyFingerprints(
      final List<ElisionAnalysisModel.ArtifactSnapshot> firstInventory,
      final String firstExpectedFingerprint,
      final List<ElisionAnalysisModel.ArtifactSnapshot> secondInventory,
      final String secondExpectedFingerprint)
      throws IOException {
    final Map<Path, String> contentDigests = new HashMap<>();
    verifyFingerprint(firstInventory, firstExpectedFingerprint, contentDigests);
    verifyFingerprint(secondInventory, secondExpectedFingerprint, contentDigests);
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
      final String digest = ArtifactDigests.read(path).sha256();
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

  private static String sha256(final List<String> values) {
    try {
      final MessageDigest digest = MessageDigest.getInstance("SHA-256");
      for (final String value : values) {
        final byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        digest.update(Integer.toString(bytes.length).getBytes(StandardCharsets.US_ASCII));
        digest.update((byte) ':');
        digest.update(bytes);
      }
      return java.util.HexFormat.of().formatHex(digest.digest());
    } catch (final NoSuchAlgorithmException exception) {
      throw new AssertionError("SHA-256 is unavailable", exception);
    }
  }
}
