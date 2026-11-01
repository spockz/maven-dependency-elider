// WHY: Gives Analyze MRJAR projections an isolated temporary location that is always removed.

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.Objects;
import java.util.stream.Stream;

/** Owns temporary archive projections for one prediction operation. */
final class AnalysisProjectionWorkspace implements AutoCloseable {
  private final Path directory;

  private AnalysisProjectionWorkspace(final Path directory) {
    this.directory = Objects.requireNonNull(directory, "directory");
  }

  static AnalysisProjectionWorkspace create() throws IOException {
    return new AnalysisProjectionWorkspace(
        Files.createTempDirectory("dependency-elider-analysis-projections-"));
  }

  Path directory() {
    return directory;
  }

  @Override
  public void close() throws IOException {
    try (Stream<Path> paths = Files.walk(directory)) {
      for (final Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
        Files.deleteIfExists(path);
      }
    }
  }
}
