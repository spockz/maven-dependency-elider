/* WHY: Binds external Native Image parsing to the exact files prepared for later publication. */

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collection;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;

/** Digest and canonical path for an external descriptor or sibling bytecode file. */
record NativeImageConsumedInput(
    Path logicalPath, Path canonicalPath, String role, long byteLength, String sha256) {
  NativeImageConsumedInput {
    logicalPath = logicalPath.toAbsolutePath().normalize();
    canonicalPath = canonicalPath.toAbsolutePath().normalize();
    if (role == null || role.isBlank() || sha256 == null || sha256.isBlank() || byteLength < 0) {
      throw new IllegalArgumentException("Invalid consumed native-image input snapshot");
    }
  }

  /* package */
  static List<NativeImageConsumedInput> ordered(final Collection<NativeImageConsumedInput> inputs) {
    return inputs.stream()
        .distinct()
        .sorted(Comparator.comparing(NativeImageConsumedInput::identity))
        .toList();
  }

  /* package */
  static void verifyAll(final Collection<NativeImageConsumedInput> inputs) throws IOException {
    for (final NativeImageConsumedInput input : ordered(inputs)) {
      input.verify();
    }
  }

  /* package */
  String identity() {
    return frame(role)
        + frame(logicalPath.toString())
        + frame(canonicalPath.toString())
        + frame(Long.toString(byteLength))
        + frame(sha256);
  }

  private static String frame(final String value) {
    return value.length() + ":" + value;
  }

  private void verify() throws IOException {
    final Path currentCanonical = logicalPath.toRealPath();
    if (!canonicalPath.equals(currentCanonical)) {
      throw new IOException("Native-image input target changed after preparation: " + logicalPath);
    }
    final String currentDigest = digest(Files.readAllBytes(currentCanonical));
    if (!sha256.equals(currentDigest)) {
      throw new IOException("Native-image input content changed after preparation: " + logicalPath);
    }
  }

  /* package */
  static String digest(final byte[] bytes) {
    try {
      return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    } catch (final NoSuchAlgorithmException exception) {
      throw new AssertionError("SHA-256 is unavailable", exception);
    }
  }
}
