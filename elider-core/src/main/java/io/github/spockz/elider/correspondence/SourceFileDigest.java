// WHY: Hashes source-reproduction artifacts in core without depending on plugin utilities.

package io.github.spockz.elider.correspondence;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/** Computes a canonical SHA-256 for one regular artifact file. */
final class SourceFileDigest {
  /** Small fixed buffer keeps hashing memory independent of archive size. */
  private static final int BUFFER_SIZE = 8192;

  /** Canonical lowercase digest form used by the reproduction DTOs. */
  private static final String SHA256_PATTERN = "[0-9a-f]{64}";

  private SourceFileDigest() {}

  /* default */ static String sha256(final Path path) throws IOException {
    try {
      final MessageDigest digest = MessageDigest.getInstance("SHA-256");
      final byte[] buffer = new byte[BUFFER_SIZE];
      try (InputStream input = Files.newInputStream(path)) {
        while (true) {
          final int count = input.read(buffer);
          if (count < 0) {
            break;
          }
          if (count > 0) {
            digest.update(buffer, 0, count);
          }
        }
      }
      return HexFormat.of().formatHex(digest.digest());
    } catch (final NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is unavailable", exception);
    }
  }

  /* default */ static boolean isCanonicalSha256(final String value) {
    return value != null && value.matches(SHA256_PATTERN);
  }
}
