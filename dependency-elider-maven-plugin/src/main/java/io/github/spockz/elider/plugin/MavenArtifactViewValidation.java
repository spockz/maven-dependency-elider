// WHY: Preserves Maven artifact reference order while checking coordinates and
// paths for changes.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.plugin.ElisionAnalysisModel.ArtifactSnapshot;
import java.io.IOException;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.apache.maven.artifact.Artifact;

/** Checks identity and content of an ordered live Maven artifact view. */
final class MavenArtifactViewValidation {
  private MavenArtifactViewValidation() {}

  /* package */ static void validateCurrentView(
      final String viewName, final List<Artifact> current, final List<ArtifactSnapshot> snapshots)
      throws IOException {
    if (current.size() != snapshots.size()) {
      throw changed(viewName, "view size");
    }
    final Map<Artifact, List<Integer>> positions = referencePositions(current);
    for (int index = 0; index < current.size(); index++) {
      final ArtifactSnapshot snapshot = snapshots.get(index);
      final List<Integer> referencePositions = positions.get(snapshot.artifact());
      if (referencePositions == null || !referencePositions.contains(index)) {
        throw changed(viewName, "order or reference");
      }
      validateArtifact(viewName, current.get(index), snapshot);
    }
  }

  private static Map<Artifact, List<Integer>> referencePositions(final List<Artifact> artifacts) {
    return java.util.stream.IntStream.range(0, artifacts.size())
        .boxed()
        .collect(
            java.util.stream.Collectors.groupingBy(
                artifacts::get, IdentityHashMap::new, java.util.stream.Collectors.toList()));
  }

  private static void validateArtifact(
      final String viewName, final Artifact artifact, final ArtifactSnapshot snapshot)
      throws IOException {
    if (!snapshot.coordinate().equals(MavenArtifactInventory.toCoordinate(artifact))) {
      throw changed(viewName, "coordinate");
    }
    if (!Objects.equals(snapshot.filePath(), MavenArtifactInventory.normalizedPath(artifact))) {
      throw changed(viewName, "file path");
    }
  }

  private static IOException changed(final String viewName, final String detail) {
    return new IOException("Maven " + viewName + " artifact " + detail + " changed after analysis");
  }
}
