/* WHY: Preserves reference identity for staged-output keys while separating
 * immutable archive facts from mutable closure and publication state. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.trimmer.DependencyJarTrimmer;
import java.nio.file.Path;
import java.util.Set;
import java.util.TreeSet;

/** Owns one candidate's root closure and planned output location. */
final class TrimCandidate {
  /** Archive facts do not change while candidate roots and output state evolve. */
  private final CandidateArchive sourceArchive;

  /** Sibling closure can add roots between isolated analysis rounds. */
  private final Set<String> rootNames;

  /** Effective publication relocates this path into the selected generation. */
  private Path plannedOutput;

  /** The last completed analysis supplies provenance and retained class evidence. */
  private DependencyJarTrimmer.TrimAnalysis closureAnalysis;

  /* package */ record CandidateArchive(
      ElisionAnalysisModel.ArtifactSnapshot snapshot,
      Set<String> classes,
      boolean multiRelease,
      int logicalClassCount,
      Set<String> upperTierClasses) {
    CandidateArchive {
      classes = Set.copyOf(classes);
      upperTierClasses = Set.copyOf(upperTierClasses);
    }
  }

  /* package */ TrimCandidate(
      final ElisionAnalysisModel.ArtifactSnapshot snapshot,
      final Set<String> classes,
      final Set<String> roots,
      final Path output) {
    this(snapshot, classes, roots, output, false, classes.size(), Set.of());
  }

  /* package */ TrimCandidate(
      final ElisionAnalysisModel.ArtifactSnapshot snapshot,
      final Set<String> classes,
      final Set<String> roots,
      final Path output,
      final boolean multiRelease,
      final int logicalClassCount) {
    this(snapshot, classes, roots, output, multiRelease, logicalClassCount, Set.of());
  }

  /* package */ TrimCandidate(
      final ElisionAnalysisModel.ArtifactSnapshot snapshot,
      final Set<String> classes,
      final Set<String> roots,
      final Path output,
      final boolean multiRelease,
      final int logicalClassCount,
      final Set<String> upperTierClasses) {
    sourceArchive =
        new CandidateArchive(snapshot, classes, multiRelease, logicalClassCount, upperTierClasses);
    rootNames = new TreeSet<>(multiRelease || !roots.isEmpty() ? roots : classes);
    plannedOutput = output;
  }

  /* package */ CandidateArchive archive() {
    return sourceArchive;
  }

  /* package */ Set<String> roots() {
    return rootNames;
  }

  /* package */ Set<String> targetRoots() {
    final Set<String> result = new TreeSet<>(rootNames);
    result.retainAll(sourceArchive.classes());
    return java.util.Collections.unmodifiableSet(result);
  }

  /* package */ boolean requiresOutput() {
    return sourceArchive.multiRelease()
        || closureAnalysis == null
        || closureAnalysis.retainedClasses().size() < closureAnalysis.totalClasses();
  }

  /* package */ Path output() {
    return plannedOutput;
  }

  /* package */ void relocateOutput(final Path generation) {
    plannedOutput = generation.resolve(plannedOutput.getFileName());
  }

  /* package */ DependencyJarTrimmer.TrimAnalysis analysis() {
    return closureAnalysis;
  }

  /* package */ void analysis(final DependencyJarTrimmer.TrimAnalysis value) {
    closureAnalysis = value;
  }
}
