/* WHY: Merges explicit telemetry files and rejects unsupported paths. */

package io.github.spockz.elider.trace;

import io.github.spockz.elider.model.TraceData;
import java.io.IOException;
import java.nio.file.Path;
import java.util.Collection;
import java.util.List;

/** Reads one supported file or merges multiple explicitly supplied trace files. */
public final class CompositeTraceReader implements RuntimeTraceReader {
  /** Holds all built-in readers used for path dispatch. */
  private final List<RuntimeTraceReader> readers;

  /** Creates a composite over the built-in text, CDS, GraalVM, and JFR readers. */
  public CompositeTraceReader() {
    readers =
        List.of(
            new ClassLoaderLogReader(),
            new CdsClassListReader(),
            new GraalVmConfigReader(),
            new JfrTraceReader());
  }

  /** Returns whether at least one built-in reader recognizes the path. */
  @Override
  public boolean supports(final Path path) {
    return readers.stream().anyMatch(reader -> reader.supports(path));
  }

  /** Reads one file using its matching reader, rejecting unsupported formats. */
  @Override
  public TraceData read(final Path path) throws IOException {
    for (final RuntimeTraceReader reader : readers) {
      if (reader.supports(path)) {
        return reader.read(path);
      }
    }
    throw new IOException("No trace reader supports file: " + path);
  }

  /** Merges observations from explicit paths and requires a supported input. */
  public TraceData readAll(final Collection<Path> paths) throws IOException {
    if (paths == null || paths.isEmpty()) {
      throw new IOException("At least one supported trace input is required");
    }
    TraceData result = TraceData.empty();
    for (final Path path : paths) {
      if (!supports(path)) {
        throw new IOException("No trace reader supports file: " + path);
      }
      result = result.merge(read(path));
    }
    if (result.size() == 0) {
      throw new IOException("Supported trace inputs contained no class observations");
    }
    return result;
  }
}
