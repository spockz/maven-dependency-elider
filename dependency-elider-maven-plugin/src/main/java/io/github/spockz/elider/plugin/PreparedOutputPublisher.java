/* WHY: Exposes the ordered publication boundary so prepared archives are
 * installed only after preparation succeeds. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.trimmer.ArchiveSanitizer;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.IOException;

/** Publishes an archive after the complete preparation batch succeeds. */
@FunctionalInterface
interface PreparedOutputPublisher {
  /** Installs one archive after all candidate preparation has succeeded. */
  ArtifactTrimRecord publish(ArchiveSanitizer.PreparedOutput prepared) throws IOException;
}
