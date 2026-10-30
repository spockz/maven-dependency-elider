/* WHY: Keeps candidate roots mutable across tiers while retaining immutable
 * candidate class inventories. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.plugin.TierArchiveProjector.TierContext;
import io.github.spockz.elider.plugin.TierInventoryReader.MultiReleaseCandidateInfo;
import io.github.spockz.elider.plugin.TierRootPlanner.RootPlan;
import java.io.IOException;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/** Builds candidates whose roots can grow across tier closure. */
final class TierCandidatePlanner {
  /** Bounds and policy belong to this analysis operation. */
  private final MultiReleaseTrimContext operation;

  /* package */ TierCandidatePlanner(final MultiReleaseTrimContext operation) {
    this.operation = operation;
  }

  /* package */ Map<ElisionAnalysisModel.ArtifactSnapshot, TierCandidate> createCandidates(
      final RootPlan rootPlan,
      final List<TierContext> projections,
      final Map<ElisionAnalysisModel.ArtifactSnapshot, MultiReleaseCandidateInfo> multiRelease)
      throws IOException {
    final Map<ElisionAnalysisModel.ArtifactSnapshot, TierCandidate> candidates =
        LinkedHashMap.newLinkedHashMap(MultiReleaseTrimContext.DEFAULT_EXPECTED_MAP_SIZE);
    final Set<Path> outputPaths = new HashSet<>();
    for (final ElisionAnalysisModel.ArtifactSnapshot snapshot : rootPlan.candidateSnapshots()) {
      addCandidate(snapshot, rootPlan.roots(), projections, multiRelease, outputPaths, candidates);
    }
    return candidates;
  }

  private void addCandidate(
      final ElisionAnalysisModel.ArtifactSnapshot snapshot,
      final Map<ElisionAnalysisModel.ArtifactSnapshot, Set<String>> candidateRoots,
      final List<TierContext> projections,
      final Map<ElisionAnalysisModel.ArtifactSnapshot, MultiReleaseCandidateInfo> multiRelease,
      final Set<Path> outputPaths,
      final Map<ElisionAnalysisModel.ArtifactSnapshot, TierCandidate> candidates)
      throws IOException {
    final Set<String> targetClasses = TierAnalysisViews.classesInTargetTier(snapshot, projections);
    final Path output = TrimPaths.outputPath(operation.request().project(), snapshot.coordinate());
    if (!outputPaths.add(output)) {
      throw new IOException("Distinct tiered candidates share output path: " + output);
    }
    final MultiReleaseCandidateInfo mrInfo = multiRelease.get(snapshot);
    final Set<String> roots = new TreeSet<>(candidateRoots.get(snapshot));
    if (roots.isEmpty() && !targetClasses.isEmpty()) {
      roots.addAll(targetClasses);
    }
    candidates.put(snapshot, new TierCandidate(targetClasses, roots, mrInfo != null));
  }

  /* package */ record TierCandidate(
      Set<String> candidateClasses, Set<String> rootNames, boolean multiReleaseCandidate) {
    /* package */ TierCandidate {
      candidateClasses = Set.copyOf(candidateClasses);
      rootNames = new TreeSet<>(rootNames);
    }

    /* package */ Set<String> localRoots(final Set<String> classesInTier) {
      final Set<String> local = new TreeSet<>(rootNames);
      local.retainAll(classesInTier);
      return local;
    }

    /* package */ Set<String> roots() {
      return rootNames;
    }

    /* package */ Set<String> classes() {
      return candidateClasses;
    }

    /* package */ boolean isMultiRelease() {
      return multiReleaseCandidate;
    }
  }
}
