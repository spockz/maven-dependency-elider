/* WHY: Binds effective roots to target projections and logical MRJAR counts
 * before outputs can be staged. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactFileRef;
import io.github.spockz.elider.plugin.TrimCandidatePlanner.CandidatePlan;
import io.github.spockz.elider.plugin.TrimGenerationPublisher.EffectiveOutputPlan;
import io.github.spockz.elider.trimmer.MultiReleaseArchivePlan;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.apache.maven.project.MavenProject;

/** Plans effective candidates from their validated per-artifact root evidence. */
final class EffectiveCandidatePlanner {
  private EffectiveCandidatePlanner() {}

  private record CandidateInputs(
      MavenProject project,
      Map<ArtifactFileRef, Set<String>> classes,
      EffectiveOutputPlan output,
      Map<ElisionAnalysisModel.ArtifactSnapshot, Set<String>> roots) {}

  private record CandidateClasses(Set<String> names, boolean multiRelease, int logicalCount) {}

  /* package */ static CandidatePlan effectiveCandidatePlan(
      final MavenProject project,
      final List<ElisionAnalysisModel.ArtifactSnapshot> libraries,
      final List<ElisionAnalysisModel.ArtifactSnapshot> retained,
      final Map<ArtifactFileRef, Set<String>> classes,
      final EffectiveOutputPlan output)
      throws IOException {
    final Map<ElisionAnalysisModel.ArtifactSnapshot, Set<String>> roots =
        TrimRootPlanner.validateDiscoveredRoots(
            output.roots(),
            TrimCandidatePlanner.fullJarInventory(libraries),
            TrimCandidatePlanner.classesByPath(classes));
    final CandidateInputs inputs = new CandidateInputs(project, classes, output, roots);
    final Set<Path> outputs = new HashSet<>();
    final List<TrimCandidate> work = new ArrayList<>();
    for (final ElisionAnalysisModel.ArtifactSnapshot snapshot :
        retained.stream().sorted(TrimCandidatePlanner.artifactSnapshotOrder()).toList()) {
      addCandidate(snapshot, inputs, outputs, work);
    }
    return new CandidatePlan(
        libraries.stream().map(ElisionAnalysisModel.ArtifactSnapshot::filePath).toList(),
        work,
        Map.of(),
        Map.of());
  }

  private static void addCandidate(
      final ElisionAnalysisModel.ArtifactSnapshot snapshot,
      final CandidateInputs inputs,
      final Set<Path> outputs,
      final List<TrimCandidate> work)
      throws IOException {
    if (inputs.output().unchangedCoordinates().contains(snapshot.coordinate())) {
      return;
    }
    final CandidateClasses classes = readClasses(snapshot, inputs);
    if (classes.names().isEmpty() && !classes.multiRelease()) {
      return;
    }
    final Set<String> discovered = inputs.roots().get(snapshot);
    if (discovered == null) {
      throw new IOException("Effective analysis has no roots for " + snapshot.coordinate());
    }
    final Set<String> roots = new TreeSet<>(discovered);
    roots.retainAll(classes.names());
    final Path output = TrimPaths.outputPath(inputs.project(), snapshot.coordinate());
    if (!outputs.add(output)) {
      throw new IOException("Distinct effective candidates share output path: " + output);
    }
    work.add(
        new TrimCandidate(
            snapshot,
            classes.names(),
            roots,
            output,
            classes.multiRelease(),
            classes.logicalCount(),
            inputs
                .output()
                .analysis()
                .upperTierClasses()
                .getOrDefault(snapshot.coordinate(), Set.of())));
  }

  private static CandidateClasses readClasses(
      final ElisionAnalysisModel.ArtifactSnapshot snapshot, final CandidateInputs inputs)
      throws IOException {
    final boolean multiRelease =
        inputs.output().analysis().upperTierClasses().containsKey(snapshot.coordinate());
    if (!multiRelease) {
      final Set<String> classes = TrimCandidatePlanner.classesFor(snapshot, inputs.classes());
      return new CandidateClasses(classes, false, classes.size());
    }
    final int release = inputs.output().analysis().compilerRelease();
    final Path projection =
        MultiReleaseLibraryProjection.create(
            snapshot.filePath(),
            snapshot.coordinate(),
            TrimPaths.analysisLibraryDirectory(inputs.project()),
            release);
    final Set<String> classes = TrimPaths.classNames(projection);
    final MultiReleaseArchivePlan initial =
        MultiReleaseArchivePlan.create(snapshot.filePath(), release, Set.of(), Set.of());
    return new CandidateClasses(classes, true, initial.pluginView().logicalClassCount());
  }
}
