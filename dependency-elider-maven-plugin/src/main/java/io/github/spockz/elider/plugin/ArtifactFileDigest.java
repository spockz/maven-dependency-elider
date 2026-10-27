// WHY: Revalidates detached artifact output files before publishing or returning them to Maven.

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/** Computes a streaming SHA-256 digest for a validated artifact file. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class ArtifactFileDigest {
  private ArtifactFileDigest() {}

  static String sha256(final Path path) throws IOException {
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
}
