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
  /** Temporary root that scopes all projections for one prediction. */
  private final Path rootDirectory;

  private AnalysisProjectionWorkspace(final Path directory) {
    this.rootDirectory = Objects.requireNonNull(directory, "directory");
  }

  /* default */ static AnalysisProjectionWorkspace create() throws IOException {
    return new AnalysisProjectionWorkspace(
        Files.createTempDirectory("dependency-elider-analysis-projections-"));
  }

  /* default */ Path directory() {
    return rootDirectory;
  }

  @Override
  public void close() throws IOException {
    try (Stream<Path> paths = Files.walk(rootDirectory)) {
      for (final Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
        Files.deleteIfExists(path);
      }
    }
  }
}
