/* WHY: Keeps one MRJAR operation's bounds and policy together so extracted
 * phases cannot mix analysis contexts. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.util.Map;
import java.util.Set;

/** Operation bounds shared by tier inventory, roots, preparation, and closure. */
record MultiReleaseTrimContext(
    TrimRequest request,
    Map<TrimArtifactRootKey, Set<String>> discoveredRoots,
    Set<ArtifactCoordinate> forcedUnchanged,
    int targetRelease,
    int runtimeRelease) {
  /** Preserves the default constructor's initial map capacity. */
  /* package */ static final int DEFAULT_EXPECTED_MAP_SIZE = 12;
}
