/* WHY: Creates canonical candidate work plans without changing Maven
 * artifact pointers during analysis. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.trimmer.DependencyJarTrimmer;
import java.io.IOException;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Provides canonical candidate inventory and effective-analysis validation. */
final class TrimCandidatePlanner {
  private TrimCandidatePlanner() {}

  /* package */ record CandidatePlan(
      List<Path> retainedInputPaths,
      List<TrimCandidate> work,
      Map<String, List<TrimCandidate>> ownersByClass,
      Map<String, Path> ownerByClass) {}

  /* package */

  /* package */

  /* package */ static Map<Path, Set<String>> classesByPath(
      final Map<io.github.spockz.elider.model.ArtifactFileRef, Set<String>> classesByArtifact) {
    final Map<Path, Set<String>> result = TrimCollections.orderedMap();
    classesByArtifact.forEach(
        (artifact, classes) ->
            result.put(artifact.filePath().toAbsolutePath().normalize(), classes));
    return result;
  }

  /* package */ static Set<String> classesFor(
      final ElisionAnalysisModel.ArtifactSnapshot snapshot,
      final Map<io.github.spockz.elider.model.ArtifactFileRef, Set<String>> classesByArtifact)
      throws IOException {
    return classesByArtifact.entrySet().stream()
        .filter(
            entry ->
                entry
                    .getKey()
                    .filePath()
                    .toAbsolutePath()
                    .normalize()
                    .equals(snapshot.filePath().toAbsolutePath().normalize()))
        .map(Map.Entry::getValue)
        .findFirst()
        .orElseThrow(() -> new IOException("Missing indexed classes for " + snapshot.coordinate()));
  }

  /* package */ static void assignEffectiveAnalyses(
      final CandidatePlan plan, final TrimAnalysisResult analysis) throws IOException {
    if (plan.work().size() != analysis.candidateAnalyses().size()) {
      throw new IOException("Effective analysis candidate inventory changed before output trim");
    }
    for (final TrimCandidate candidate : plan.work()) {
      final DependencyJarTrimmer.TrimAnalysis candidateAnalysis =
          analysis.candidateAnalyses().get(candidate.archive().snapshot().coordinate());
      if (candidateAnalysis == null
          || !candidateAnalysis.roots().stream()
              .map(name -> name.replace('/', '.'))
              .collect(java.util.stream.Collectors.toSet())
              .equals(candidate.targetRoots())) {
        throw new IOException(
            "Output candidate roots do not match effective analysis: "
                + candidate.archive().snapshot().coordinate());
      }
      candidate.analysis(candidateAnalysis);
    }
  }

  /* package */ static List<ElisionAnalysisModel.ArtifactSnapshot> fullJarInventory(
      final List<ElisionAnalysisModel.ArtifactSnapshot> snapshots) {
    return snapshots.stream()
        .filter(snapshot -> MavenDependencyTrimmer.JAR_TYPE.equals(snapshot.coordinate().type()))
        .sorted(artifactSnapshotOrder())
        .toList();
  }

  /* package */ static Comparator<ElisionAnalysisModel.ArtifactSnapshot> artifactSnapshotOrder() {
    return Comparator.comparing(ElisionAnalysisModel.ArtifactSnapshot::coordinate)
        .thenComparing(snapshot -> snapshot.filePath().toAbsolutePath().normalize());
  }

  /* package */ static void addPresentRoots(
      final Set<String> roots, final Set<String> candidates, final Set<String> candidateClasses) {
    for (final String root : candidates) {
      final String normalized = root.replace('/', '.');
      if (candidateClasses.contains(normalized)) {
        roots.add(normalized);
      }
    }
  }
}
