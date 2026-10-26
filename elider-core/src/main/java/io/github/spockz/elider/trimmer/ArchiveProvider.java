/* WHY: Supplies an invocation's immutable archive snapshots to isolated class-pool analyses. */

package io.github.spockz.elider.trimmer;

import java.io.IOException;
import java.nio.file.Path;

/** Supplies the archive snapshots used by one candidate analysis. */
@FunctionalInterface
interface ArchiveProvider {
  /** Returns a validated snapshot with candidate rules applied when requested. */
  ArchiveSnapshot read(Path path, boolean candidate) throws IOException;
}
