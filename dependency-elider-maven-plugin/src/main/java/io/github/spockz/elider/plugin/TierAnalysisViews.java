/* WHY: Provides canonical sibling and candidate views shared by tier
 * preparation and closure results. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.plugin.TierArchiveProjector.TierContext;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Provides canonical sibling and candidate views for tier analysis. */
final class TierAnalysisViews {
  private TierAnalysisViews() {}

  /* package */ static Set<String> classesInTargetTier(
      final ElisionAnalysisModel.ArtifactSnapshot snapshot, final List<TierContext> contexts) {
    for (final TierContext context : contexts) {
      if (context.release() == context.targetRelease()) {
        return context.classesOf(snapshot);
      }
    }
    return Set.of();
  }

  /* package */ static List<Path> tierSiblings(
      final List<ElisionAnalysisModel.ArtifactSnapshot> inventory,
      final TierContext context,
      final ElisionAnalysisModel.ArtifactSnapshot candidate) {
    final List<Path> siblings = new ArrayList<>();
    for (final ElisionAnalysisModel.ArtifactSnapshot snapshot : inventory) {
      if (MavenDependencyTrimmer.ANALYSIS_LIBRARY_SCOPES.contains(snapshot.coordinate().scope())
          && !snapshot.equals(candidate)) {
        final Path path = context.pathFor(snapshot);
        if (path != null) {
          siblings.add(path);
        }
      }
    }
    return siblings;
  }

  /* package */ static <V> List<Map.Entry<ElisionAnalysisModel.ArtifactSnapshot, V>> orderedEntries(
      final Map<ElisionAnalysisModel.ArtifactSnapshot, V> entries) {
    return entries.entrySet().stream()
        .sorted(Map.Entry.comparingByKey(TrimCandidatePlanner.artifactSnapshotOrder()))
        .toList();
  }
}
