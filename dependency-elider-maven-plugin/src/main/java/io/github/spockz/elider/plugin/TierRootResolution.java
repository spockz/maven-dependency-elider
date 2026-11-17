/* WHY: Binds trace and dynamic roots to tier-local owners while
 * distinguishing missing required roots. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.plugin.TierArchiveProjector.TierContext;
import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Resolves trace and dynamic roots onto tier-local artifact owners. */
final class TierRootResolution {
  /** Bounds and policy belong to this analysis operation. */
  private final MultiReleaseTrimContext operation;

  /* package */ TierRootResolution(final MultiReleaseTrimContext operation) {
    this.operation = operation;
  }

  /* package */ void addCommonRoots(
      final Set<String> roots,
      final List<TierContext> contexts,
      final Map<ElisionAnalysisModel.ArtifactSnapshot, Set<String>> rootsByOwner,
      final Set<ArtifactCoordinate> reachableArtifacts) {
    for (final String rawRoot : roots) {
      final String root = rawRoot.replace('/', '.');
      for (final TierContext context : contexts) {
        for (final ElisionAnalysisModel.ArtifactSnapshot owner : context.ownersOf(root)) {
          addOwnedRoot(owner, root, rootsByOwner, reachableArtifacts);
        }
      }
    }
  }

  private void addOwnedRoot(
      final ElisionAnalysisModel.ArtifactSnapshot owner,
      final String root,
      final Map<ElisionAnalysisModel.ArtifactSnapshot, Set<String>> rootsByOwner,
      final Set<ArtifactCoordinate> reachableArtifacts) {
    if (owner == null) {
      return;
    }
    if (!operation.request().retainedCoordinates().contains(owner.coordinate())) {
      reachableArtifacts.add(owner.coordinate());
    }
    final Set<String> ownedRoots = rootsByOwner.get(owner);
    if (operation.request().retainedCoordinates().contains(owner.coordinate())
        && ownedRoots != null) {
      ownedRoots.add(root);
    }
  }

  /* package */ void addRequestedRoots(
      final Map<ElisionAnalysisModel.ArtifactSnapshot, Set<String>> requested,
      final List<TierContext> contexts,
      final Map<ElisionAnalysisModel.ArtifactSnapshot, Set<String>> rootsByOwner)
      throws IOException {
    for (final Map.Entry<ElisionAnalysisModel.ArtifactSnapshot, Set<String>> entry :
        requested.entrySet()) {
      final Set<String> ownedRoots = rootsByOwner.get(entry.getKey());
      if (ownedRoots == null || entry.getValue().isEmpty()) {
        continue;
      }
      final Set<String> matching =
          rootsPresentInAnyTier(entry.getKey(), entry.getValue(), contexts);
      if (matching.isEmpty()) {
        throw new IOException(
            "Previously discovered roots are absent from every analyzed tier: "
                + entry.getKey().coordinate());
      }
      ownedRoots.addAll(matching);
    }
  }

  private static Set<String> rootsPresentInAnyTier(
      final ElisionAnalysisModel.ArtifactSnapshot snapshot,
      final Set<String> roots,
      final List<TierContext> contexts) {
    final Set<String> matching = new HashSet<>();
    for (final TierContext context : contexts) {
      matching.addAll(context.classesOf(snapshot));
    }
    matching.retainAll(roots);
    return matching;
  }

  /* package */ void addDynamicRoots(
      final List<ElisionAnalysisModel.ArtifactSnapshot> retainedLibraries,
      final List<TierContext> contexts,
      final Map<ElisionAnalysisModel.ArtifactSnapshot, Set<String>> rootsByOwner,
      final Set<ArtifactCoordinate> reachableArtifacts)
      throws IOException {
    for (final ElisionAnalysisModel.ArtifactSnapshot source : retainedLibraries) {
      for (final String root :
          TrimRootPlanner.dynamicRoots(operation.request(), source.filePath())) {
        addDynamicRoot(root, contexts, rootsByOwner, reachableArtifacts);
      }
    }
  }

  private void addDynamicRoot(
      final String root,
      final List<TierContext> contexts,
      final Map<ElisionAnalysisModel.ArtifactSnapshot, Set<String>> rootsByOwner,
      final Set<ArtifactCoordinate> reachableArtifacts) {
    for (final TierContext context : contexts) {
      for (final ElisionAnalysisModel.ArtifactSnapshot owner : context.ownersOf(root)) {
        addOwnedRoot(owner, root, rootsByOwner, reachableArtifacts);
      }
    }
  }
}
