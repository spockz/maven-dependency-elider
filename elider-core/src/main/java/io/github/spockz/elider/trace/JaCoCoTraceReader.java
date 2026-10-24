/* WHY: Converts JaCoCo execution data into the shared class reachability model. */

package io.github.spockz.elider.trace;

import io.github.spockz.elider.model.TraceData;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import org.jacoco.core.data.ExecutionDataReader;

/** Reads class names recorded in JaCoCo {@code .exec} files. */
public final class JaCoCoTraceReader implements RuntimeTraceReader {
  /** Creates a reader for JaCoCo execution data files. */
  @SuppressWarnings("PMD.UncommentedEmptyConstructor")
  public JaCoCoTraceReader() {}

  /** Recognizes files by their conventional {@code .exec} suffix. */
  @Override
  public boolean supports(final Path path) {
    if (path == null) {
      return false;
    }
    final Path fileName = path.getFileName();
    return fileName != null && fileName.toString().toLowerCase(Locale.ROOT).endsWith(".exec");
  }

  /** Includes every class record, whether or not its execution probes were hit. */
  @Override
  @SuppressWarnings("PMD.UseConcurrentHashMap")
  public TraceData read(final Path path) throws IOException {
    if (!supports(path)) {
      throw new IOException("Unsupported JaCoCo execution data file: " + path);
    }
    if (Files.size(path) == 0) {
      throw new IOException("JaCoCo execution data file is empty: " + path);
    }
    final Set<String> classes = new HashSet<>();
    final Map<Long, String> classNamesById = new HashMap<>();
    final Set<Long> conflicts = new HashSet<>();
    try {
      try (InputStream input = Files.newInputStream(path)) {
        final ExecutionDataReader reader = new ExecutionDataReader(input);
        reader.setSessionInfoVisitor(sessionInfo -> {});
        reader.setExecutionDataVisitor(
            data -> {
              final String priorName = classNamesById.putIfAbsent(data.getId(), data.getName());
              if (priorName != null && !priorName.equals(data.getName())) {
                conflicts.add(data.getId());
              }
              classes.add(data.getName());
            });
        readToEnd(reader);
      }
    } catch (final IOException exception) {
      throw new IOException("Unable to read JaCoCo execution data file " + path, exception);
    }
    if (!conflicts.isEmpty()) {
      final IllegalStateException cause =
          new IllegalStateException("Conflicting class IDs: " + conflicts);
      throw new IOException("Unable to read JaCoCo execution data file " + path, cause);
    }
    return TraceData.of(classes);
  }

  @SuppressWarnings("PMD.EmptyControlStatement")
  private static void readToEnd(final ExecutionDataReader reader) throws IOException {
    while (reader.read()) {
      // WHY: Reading to EOF validates trailing records after each visitor callback.
    }
  }
}
