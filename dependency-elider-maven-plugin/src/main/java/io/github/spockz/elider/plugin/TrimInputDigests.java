/* WHY: Shares normalized archive digests within a trim operation so keys and
 * provenance describe the same bytes. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.trimmer.ArtifactDigests;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

/** Reads shared normalized archive digests for keys and provenance. */
final class TrimInputDigests {
  private TrimInputDigests() {}

  /* package */ static Map<Path, ArtifactDigests> inputDigests(final List<Path> inputPaths)
      throws IOException {
    final Map<Path, ArtifactDigests> digests = TrimCollections.orderedMap();
    for (final Path inputPath : inputPaths) {
      final Path normalizedPath = inputPath.toAbsolutePath().normalize();
      if (!digests.containsKey(normalizedPath)) {
        digests.put(normalizedPath, ArtifactDigests.read(normalizedPath));
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

  /* package */ static String sha256(final Path path) throws IOException {
    try (InputStream input = Files.newInputStream(path)) {
      final MessageDigest digest = MessageDigest.getInstance("SHA-256");
      final byte[] buffer = new byte[8192];
      while (true) {
        final int count = input.read(buffer);
        if (count < 0) {
          return HexFormat.of().formatHex(digest.digest());
        }
        digest.update(buffer, 0, count);
      }
    } catch (final NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is unavailable", exception);
    }
  }

  /* package */ static String hash(final byte[] bytes) {
    try {
      return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    } catch (final NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is unavailable", exception);
    }
  }
}
