// WHY: Preserves all rollback cleanup errors without replacing the primary publication failure.

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/** Collects failures while deleting staged or committed output paths. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier") // This collaborator is package-internal only.
final class MavenOutputFileCleanup {
  private MavenOutputFileCleanup() {
    throw new AssertionError("No instances");
  }

  static IOException delete(final Iterable<Path> paths, final IOException initialFailure) {
    IOException failure = initialFailure;
    for (final Path path : paths) {
      try {
        Files.deleteIfExists(path);
      } catch (final IOException exception) {
        failure = append(failure, exception);
      }
    }
    return failure;
  }

  static IOException append(final IOException first, final IOException next) {
    if (first == null) {
      return next;
    }
    first.addSuppressed(next);
    return first;
  }
}
