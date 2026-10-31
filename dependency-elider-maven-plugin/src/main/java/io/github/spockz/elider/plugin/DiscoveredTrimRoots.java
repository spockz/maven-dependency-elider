// WHY: Binds discovered roots to exact archive digests before the next graph
// iteration.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.ArtifactSnapshot;
import io.github.spockz.elider.trimmer.ArtifactDigests;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Fingerprints the archive owning each newly discovered class root. */
final class DiscoveredTrimRoots {
  private DiscoveredTrimRoots() {}

  /** These maps are local to one analysis invocation and not shared. */
  /* package */ static Map<TrimArtifactRootKey, Set<String>> from(
      final List<ArtifactSnapshot> snapshots, final Map<ArtifactCoordinate, Set<String>> roots)
      throws IOException {
    final Map<ArtifactCoordinate, ArtifactSnapshot> snapshotsByCoordinate =
        HashMap.newHashMap(snapshots.size());
    snapshots.forEach(snapshot -> snapshotsByCoordinate.put(snapshot.coordinate(), snapshot));
    final Map<TrimArtifactRootKey, Set<String>> result = HashMap.newHashMap(roots.size());
    for (final Map.Entry<ArtifactCoordinate, Set<String>> entry : roots.entrySet()) {
      result.put(artifactRootKey(snapshotsByCoordinate, entry.getKey()), entry.getValue());
    }
    return Map.copyOf(result);
  }

  private static TrimArtifactRootKey artifactRootKey(
      final Map<ArtifactCoordinate, ArtifactSnapshot> snapshotsByCoordinate,
      final ArtifactCoordinate coordinate)
      throws IOException {
    final ArtifactSnapshot snapshot = snapshotsByCoordinate.get(coordinate);
    if (snapshot == null || snapshot.filePath() == null) {
      throw new IOException("Discovered roots have no artifact file: " + coordinate);
    }
    return new TrimArtifactRootKey(
        snapshot.coordinate(),
        snapshot.filePath(),
        ArtifactDigests.read(snapshot.filePath()).sha256());
  }
}
