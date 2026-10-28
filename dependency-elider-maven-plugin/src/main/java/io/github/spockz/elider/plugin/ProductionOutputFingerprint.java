// WHY: Binds cacheable trimming to the exact production class bytes used by bytecode scanning.

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.stream.Stream;

/** Computes a stable digest of the class files in one production output directory. */
final class ProductionOutputFingerprint {
  private ProductionOutputFingerprint() {
    throw new AssertionError("No instances");
  }

  /** Hashes the exact class files used by production bytecode scanning. */
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  static String fingerprint(final Path output) throws IOException {
    final Path scope = output.toAbsolutePath().normalize();
    if (!Files.isDirectory(scope)) {
      throw new IOException("Production class output directory is missing: " + scope);
    }
    final List<Path> classes;
    try (Stream<Path> paths = Files.walk(scope)) {
      classes =
          paths
              .filter(Files::isRegularFile)
              .filter(ProductionOutputFingerprint::isClassFile)
              .sorted()
              .toList();
    }
    final MessageDigest digest = sha256();
    digest.update("production-output-v2".getBytes(StandardCharsets.UTF_8));
    for (final Path classFile : classes) {
      final byte[] relativePath =
          scope
              .relativize(classFile)
              .toString()
              .replace('\\', '/')
              .getBytes(StandardCharsets.UTF_8);
      final byte[] content = Files.readAllBytes(classFile);
      updateLength(digest, relativePath.length);
      digest.update(relativePath);
      updateLength(digest, content.length);
      digest.update(content);
    }
    return HexFormat.of().formatHex(digest.digest());
  }

  private static void updateLength(final MessageDigest digest, final int length) {
    digest.update(ByteBuffer.allocate(Integer.BYTES).putInt(length).array());
  }

  private static MessageDigest sha256() {
    try {
      return MessageDigest.getInstance("SHA-256");
    } catch (final NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is unavailable", exception);
    }
  }

  private static boolean isClassFile(final Path path) {
    final Path fileName = path.getFileName();
    return fileName != null && fileName.toString().endsWith(".class");
  }
}
