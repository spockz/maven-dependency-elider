/* WHY: Converts JaCoCo execution data into the shared class reachability model. */

package io.github.spockz.elider.trace;

import io.github.spockz.elider.model.TraceData;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collection;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import org.jacoco.core.data.ExecutionData;
import org.jacoco.core.data.ExecutionDataReader;
import org.jacoco.core.data.ExecutionDataStore;

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
  public TraceData read(final Path path) throws IOException {
    if (!supports(path)) {
      throw new IOException("Unsupported JaCoCo execution data file: " + path);
    }
    if (Files.size(path) == 0) {
      throw new IOException("JaCoCo execution data file is empty: " + path);
    }
    try {
      try (InputStream input = Files.newInputStream(path)) {
        final ExecutionDataReader reader = new ExecutionDataReader(input);
        reader.setSessionInfoVisitor(sessionInfo -> {});
        final ExecutionDataStore store = new ExecutionDataStore();
        reader.setExecutionDataVisitor(store);
        reader.read();
        return readClassNames(path, store.getContents());
      }
    } catch (final IOException | IllegalArgumentException | IllegalStateException exception) {
      throw new IOException("Unable to read JaCoCo execution data file " + path, exception);
    }
  }

  private static TraceData readClassNames(final Path path, final Collection<ExecutionData> records)
      throws IOException {
    final Set<String> classes = new HashSet<>();
    for (final ExecutionData record : records) {
      final String className = record.getName();
      if (!TraceClassName.isValid(className)) {
        throw new IOException("Invalid class name in JaCoCo execution data file " + path);
      }
      classes.add(className);
    }
    return TraceData.of(classes);
  }
}
