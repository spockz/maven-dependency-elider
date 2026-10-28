// WHY: Gives report publication one atomic move implementation with a stable failure contract.

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

/** Performs an atomic report-output move. */
@SuppressWarnings(
    "PMD.CommentDefaultAccessModifier") // This filesystem seam is package-internal only.
final class MavenOutputFileMover {
  private MavenOutputFileMover() {
    throw new AssertionError("No instances");
  }

  static void move(final Path source, final Path target) throws IOException {
    try {
      Files.move(
          source, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    } catch (final AtomicMoveNotSupportedException exception) {
      throw new IOException("Filesystem cannot atomically publish output: " + target, exception);
    }
  }
}
