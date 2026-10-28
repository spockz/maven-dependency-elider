// WHY: Centralizes filesystem primitives shared by generation publication and rollback ownership.

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Comparator;
import java.util.UUID;
import java.util.stream.Stream;

/** Filesystem primitives for atomically publishing trim generations. */
@SuppressWarnings(
    "PMD.CommentDefaultAccessModifier") // Only the generation publisher uses these operations.
final class TrimOutputGenerationFileOps {
  private TrimOutputGenerationFileOps() {
    throw new AssertionError("No instances");
  }

  static Path backupFilePath(final Path file) throws IOException {
    final Path parent = file.getParent();
    if (parent == null) {
      throw new IOException("Trim manifest has no parent directory: " + file);
    }
    Files.createDirectories(parent);
    return parent.resolve("." + file.getFileName() + ".backup-" + UUID.randomUUID());
  }

  static Path backupPath(final Path generation) throws IOException {
    final Path parent = generation.getParent();
    if (parent == null) {
      throw new IOException("Trim generation has no parent directory: " + generation);
    }
    Files.createDirectories(parent);
    final Path backup = Files.createTempDirectory(parent, ".previous-generation-");
    Files.delete(backup);
    return backup;
  }

  static void atomicMove(final Path source, final Path target, final boolean replace)
      throws IOException {
    try {
      if (replace) {
        Files.move(
            source, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
      } else {
        Files.move(source, target, StandardCopyOption.ATOMIC_MOVE);
      }
    } catch (final AtomicMoveNotSupportedException exception) {
      throw new IOException("Filesystem cannot atomically publish trim generation", exception);
    }
  }

  static void deleteTree(final Path root) throws IOException {
    if (Files.exists(root)) {
      deleteEntries(root);
    }
  }

  static IOException append(final IOException first, final IOException next) {
    if (first == null) {
      return next;
    }
    first.addSuppressed(next);
    return first;
  }

  private static void deleteEntries(final Path root) throws IOException {
    try (Stream<Path> paths = Files.walk(root)) {
      for (final Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
        Files.delete(path);
      }
    }
  }
}
