/* WHY: Merges explicit telemetry files and rejects unsupported paths. */

package io.github.spockz.elider.trace;

import io.github.spockz.elider.model.TraceData;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/** Reads one supported file or merges multiple explicitly supplied trace files. */
public final class CompositeTraceReader implements RuntimeTraceReader {
  /** Holds all built-in readers used for path dispatch. */
  private final List<RuntimeTraceReader> readers;

  /** Creates a composite over every built-in telemetry reader. */
  public CompositeTraceReader() {
    readers =
        List.of(
            new ClassLoaderLogReader(),
            new CdsClassListReader(),
            new GraalVmConfigReader(),
            new JfrTraceReader(),
            new JaCoCoTraceReader());
  }

  /** Returns whether at least one built-in reader recognizes the path. */
  @Override
  public boolean supports(final Path path) {
    return readers.stream().anyMatch(reader -> reader.supports(path));
  }

  /** Reads one file using its matching reader, rejecting unsupported formats. */
  @Override
  public TraceData read(final Path path) throws IOException {
    return readerFor(path).read(path);
  }

  /** Merges observations from explicit paths and requires a supported input. */
  public TraceData readAll(final Collection<Path> paths) throws IOException {
    return readAllEvidence(paths).observations();
  }

  /** Reads and validates each explicit file while preserving its evidence kind. */
  public CompositeTraceEvidence readAllEvidence(final Collection<Path> paths) throws IOException {
    if (paths == null || paths.isEmpty()) {
      throw new IOException("At least one supported trace input is required");
    }
    TraceData result = TraceData.empty();
    final List<CompositeTraceEvidence.Input> inputs = new ArrayList<>();
    for (final Path path : paths) {
      final RuntimeTraceReader reader = readerFor(path);
      final TraceData input = reader.read(path);
      if (input.size() == 0) {
        throw new IOException("Supported trace input contained no class observations: " + path);
      }
      if (reader.evidenceKind() == TraceEvidenceKind.UNCLASSIFIED) {
        throw new IOException("Trace evidence kind is not recognized for input: " + path);
      }
      inputs.add(new CompositeTraceEvidence.Input(path, reader.evidenceKind(), input));
      result = result.merge(input);
    }
    return new CompositeTraceEvidence(result, inputs);
  }

  private RuntimeTraceReader readerFor(final Path path) throws IOException {
    for (final RuntimeTraceReader reader : readers) {
      if (reader.supports(path)) {
        return reader;
      }
    }
    throw new IOException("No trace reader supports file: " + path);
  }
}
