/* WHY: Computes stable SHA-1 and SHA-256 provenance together from one archive read. */

package io.github.spockz.elider.trimmer;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/** Immutable SHA-256 and SHA-1 provenance captured for one artifact file. */
public record ArtifactDigests(String sha256, String sha1) {
  /** Validates the SHA-256 and SHA-1 encodings. */
  public ArtifactDigests {
    requireDigest(sha256, 64, "sha256");
    requireDigest(sha1, 40, "sha1");
  }

  /** Reads both digest algorithms from one stable file pass. */
  public static ArtifactDigests read(final Path path) throws IOException {
    final MessageDigest sha256 = digest("SHA-256");
    final MessageDigest sha1 = digest("SHA-1");
    try (InputStream input = Files.newInputStream(path)) {
      final byte[] buffer = new byte[8192];
      while (true) {
        final int count = input.read(buffer);
        if (count < 0) {
          break;
        }
        sha256.update(buffer, 0, count);
        sha1.update(buffer, 0, count);
      }
    }
    return new ArtifactDigests(
        HexFormat.of().formatHex(sha256.digest()), HexFormat.of().formatHex(sha1.digest()));
  }

  private static MessageDigest digest(final String algorithm) {
    try {
      return MessageDigest.getInstance(algorithm);
    } catch (final NoSuchAlgorithmException exception) {
      throw new IllegalStateException(
          "Required digest algorithm is unavailable: " + algorithm, exception);
    }
  }

  private static void requireDigest(final String value, final int length, final String name) {
    if (value == null || !value.matches("[0-9a-f]{" + length + "}")) {
      throw new IllegalArgumentException(name + " must be a lowercase hexadecimal digest");
    }
  }
}
