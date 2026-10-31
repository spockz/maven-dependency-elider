/* WHY: Binds discovered roots to a coordinate, normalized path, and digest
 * so stale archive roots are rejected. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.nio.file.Path;

/** Identifies roots by artifact coordinate, normalized path, and digest. */
record TrimArtifactRootKey(ArtifactCoordinate coordinate, Path path, String sha256) {
  TrimArtifactRootKey {
    path = path.toAbsolutePath().normalize();
  }
}
