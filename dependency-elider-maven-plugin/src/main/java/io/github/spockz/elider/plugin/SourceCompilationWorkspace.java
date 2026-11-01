// WHY: Gives each correspondence attempt isolated compiler directories and deterministic cleanup.

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.stream.Stream;

/** Owns the temporary files used by one source correspondence compilation. */
final class SourceCompilationWorkspace implements AutoCloseable {
  /** Temporary root deleted when this compilation attempt closes. */
  private final Path root;

  private SourceCompilationWorkspace(final Path root) {
    this.root = root;
  }

  /* default */ static SourceCompilationWorkspace create() throws IOException {
    return new SourceCompilationWorkspace(
        Files.createTempDirectory("elider-source-correspondence-"));
  }

  /* default */ Path directory(final String name) throws IOException {
    return Files.createDirectory(root.resolve(name));
  }

  @Override
  public void close() throws IOException {
    if (!Files.exists(root)) {
      return;
    }
    try (Stream<Path> paths = Files.walk(root)) {
      for (final Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
        Files.delete(path);
      }
    }
  }
}
