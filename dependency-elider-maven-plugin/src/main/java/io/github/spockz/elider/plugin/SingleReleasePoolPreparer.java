/* WHY: Prepares isolated candidate and unchanged-program pools using one
 * archive session. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.plugin.SingleReleasePlatforms.JdkClassTables;
import io.github.spockz.elider.plugin.SingleReleaseTrimInventory.SingleReleaseInventory;
import io.github.spockz.elider.plugin.SingleReleaseTrimInventory.SingleReleaseLayout;
import io.github.spockz.elider.trimmer.DependencyJarTrimmer;
import io.github.spockz.elider.trimmer.TrimAnalysisSession;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

/** Prepares isolated candidate and unchanged-program pools. */
final class SingleReleasePoolPreparer {
  private SingleReleasePoolPreparer() {}

  /* package */ static Map<
          ElisionAnalysisModel.ArtifactSnapshot, DependencyJarTrimmer.PreparedAnalysis>
      prepareCandidates(
          final SingleReleaseLayout layout,
          final List<Path> fullClasspath,
          final JdkClassTables tables,
          final TrimAnalysisSession analysisSession,
          final int trimWorkers,
          final boolean allowModularCandidate)
          throws IOException {
    final List<DependencyJarTrimmer.PreparedAnalysis> results =
        ParallelTrimExecutor.mapParallel(
            layout.candidates(),
            trimWorkers,
            candidate -> {
              final Path path = candidate.filePath().toAbsolutePath().normalize();
              final List<Path> siblings =
                  fullClasspath.stream().filter(value -> !value.equals(path)).toList();
              return analysisSession.prepareWithUnchangedPassThroughLibraries(
                  path,
                  siblings,
                  tables.candidate(),
                  layout.unchangedPassThroughClasses(),
                  allowModularCandidate);
            });
    final Map<ElisionAnalysisModel.ArtifactSnapshot, DependencyJarTrimmer.PreparedAnalysis>
        preparedCandidates = TrimCollections.orderedMap();
    for (int index = 0; index < layout.candidates().size(); index++) {
      preparedCandidates.put(layout.candidates().get(index), results.get(index));
    }
    return preparedCandidates;
  }

  /* package */ static Map<
          ElisionAnalysisModel.ArtifactSnapshot, DependencyJarTrimmer.PreparedAnalysis>
      preparePrograms(
          final SingleReleaseInventory inventory,
          final SingleReleaseLayout layout,
          final List<Path> fullClasspath,
          final JdkClassTables tables,
          final TrimAnalysisSession analysisSession,
          final int trimWorkers)
          throws IOException {
    final List<DependencyJarTrimmer.PreparedAnalysis> results =
        ParallelTrimExecutor.mapParallel(
            layout.unchangedPrograms(),
            trimWorkers,
            program -> {
              final Path path =
                  inventory
                      .analysisPaths()
                      .getOrDefault(program, program.filePath().toAbsolutePath().normalize());
              final List<Path> siblings =
                  fullClasspath.stream().filter(value -> !value.equals(path)).toList();
              return layout.skippedProgramCoordinates().contains(program.coordinate())
                  ? analysisSession.prepareUnchangedPassThrough(
                      path, siblings, tables.passThrough(), layout.unchangedPassThroughClasses())
                  : analysisSession.prepareWithUnchangedPassThroughLibraries(
                      path, siblings, tables.passThrough(), layout.unchangedPassThroughClasses());
            });
    final Map<ElisionAnalysisModel.ArtifactSnapshot, DependencyJarTrimmer.PreparedAnalysis>
        preparedPrograms = TrimCollections.orderedMap();
    for (int index = 0; index < layout.unchangedPrograms().size(); index++) {
      preparedPrograms.put(layout.unchangedPrograms().get(index), results.get(index));
    }
    return preparedPrograms;
  }

  /* package */ record PreparedPools(
      Map<ElisionAnalysisModel.ArtifactSnapshot, DependencyJarTrimmer.PreparedAnalysis> candidates,
      Map<ElisionAnalysisModel.ArtifactSnapshot, DependencyJarTrimmer.PreparedAnalysis> programs) {}

  /* package */ static PreparedPools prepare(
      final SingleReleaseInventory inventory,
      final SingleReleaseLayout layout,
      final List<Path> classpath,
      final JdkClassTables tables,
      final int workers,
      final boolean allowModularCandidate)
      throws IOException {
    final TrimAnalysisSession session = new TrimAnalysisSession(new DependencyJarTrimmer());
    return new PreparedPools(
        prepareCandidates(layout, classpath, tables, session, workers, allowModularCandidate),
        preparePrograms(inventory, layout, classpath, tables, session, workers));
  }
}
