/* WHY: Defines the shared file-based contract so telemetry formats can feed the same normalized
 * trace model. */

package io.github.spockz.elider.trace;

import io.github.spockz.elider.model.TraceData;
import java.io.IOException;
import java.nio.file.Path;

/** Reads one supported runtime telemetry file into normalized class observations. */
public interface RuntimeTraceReader {
  /** Returns whether this reader recognizes the file path's format. */
  boolean supports(Path path);

  /**
   * Reads a supported file.
   *
   * @throws IOException if input cannot be read or is malformed
   */
  TraceData read(Path path) throws IOException;
}
