/* WHY: Feeds candidate and unchanged-program closure back to sibling
 * analysis until retained roots stop changing. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.plugin.PassThroughAnalysisLibraries.AnalysisLibraries;
import io.github.spockz.elider.plugin.PassThroughAnalysisLibraries.SkippedProgram;
import io.github.spockz.elider.plugin.SingleReleasePlatforms.PlatformPools;
import io.github.spockz.elider.plugin.TrimCandidatePlanner.CandidatePlan;
import io.github.spockz.elider.trimmer.DependencyJarTrimmer;
import io.github.spockz.elider.trimmer.TrimAnalysisSession;
import java.io.IOException;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import proguard.classfile.ClassPool;

/** Computes direct candidate and unchanged-program closure. */
final class ProGuardTrimEngine {
  private ProGuardTrimEngine() {}

  /* package */

  /* package */ static int analyze(
      final CandidatePlan candidatePlan,
      final TrimPassThroughPlan passThroughPlan,
      final Path analysisLibraryDirectory,
      final int runtimeRelease,
      final PlatformPools platformPools,
      final int trimWorkers)
      throws IOException {
    final AnalysisLibraries libraries =
        PassThroughAnalysisLibraries.analysisLibraries(
            passThroughPlan, analysisLibraryDirectory, runtimeRelease);
    final DependencyJarTrimmer trimmer = new DependencyJarTrimmer();
    final TrimAnalysisSession session = new TrimAnalysisSession(trimmer);
    validateUniqueAnalysisClasses(candidatePlan, libraries.skippedPrograms());
    final int passThroughRuns =
        analyzePassThroughPrograms(
            candidatePlan, libraries, session, platformPools.runtime(), trimWorkers);
    return passThroughRuns
        + analyzeCandidateFixedPoint(
            candidatePlan, libraries, session, platformPools.compiler(), trimWorkers);
  }

  private static void validateUniqueAnalysisClasses(
      final CandidatePlan candidatePlan, final List<SkippedProgram> skippedPrograms)
      throws IOException {
    final Set<String> allCandidateClasses = new HashSet<>(candidatePlan.ownerByClass().keySet());
    for (final SkippedProgram skippedProgram : skippedPrograms) {
      for (final String className : skippedProgram.classNames()) {
        if (!allCandidateClasses.add(className)) {
          throw new IOException(
              "Duplicate class across retained dependency JARs makes library order ambiguous: "
                  + className);
        }
      }
    }
  }

  private static int analyzePassThroughPrograms(
      final CandidatePlan candidatePlan,
      final AnalysisLibraries libraries,
      final TrimAnalysisSession analysisSession,
      final ClassPool runtimePlatform,
      final int trimWorkers)
      throws IOException {
    final List<SkippedProgram> skipped = libraries.skippedPrograms();
    if (skipped.isEmpty()) {
      return 0;
    }
    final List<DependencyJarTrimmer.TrimAnalysis> analyses =
        ParallelTrimExecutor.mapParallel(
            skipped,
            trimWorkers,
            skippedProgram -> {
              final List<Path> siblings =
                  libraries.paths().stream()
                      .filter(path -> !path.equals(skippedProgram.path()))
                      .toList();
              final DependencyJarTrimmer.PreparedAnalysis prepared =
                  analysisSession.prepareUnchangedPassThrough(
                      skippedProgram.path(),
                      siblings,
                      runtimePlatform,
                      libraries.passThroughClassNames());
              return prepared.analyze(skippedProgram.classNames());
            });
    int analysisRuns = 0;
    for (final DependencyJarTrimmer.TrimAnalysis analysis : analyses) {
      analysisRuns++;
      for (final String linkedName : analysis.reachableLibraryClasses()) {
        final String dottedName = linkedName.replace('/', '.');
        for (final TrimCandidate owner :
            candidatePlan.ownersByClass().getOrDefault(dottedName, List.of())) {
          owner.roots().add(dottedName);
        }
      }
    }
    return analysisRuns;
  }

  private static int analyzeCandidateFixedPoint(
      final CandidatePlan candidatePlan,
      final AnalysisLibraries libraries,
      final TrimAnalysisSession analysisSession,
      final ClassPool platform,
      final int trimWorkers)
      throws IOException {
    int analysisRuns = 0;
    final List<TrimCandidate> work = candidatePlan.work();
    final List<DependencyJarTrimmer.PreparedAnalysis> preparedList =
        ParallelTrimExecutor.mapParallel(
            work,
            trimWorkers,
            candidate -> {
              final List<Path> siblings =
                  libraries.paths().stream()
                      .filter(path -> !path.equals(candidate.archive().snapshot().filePath()))
                      .toList();
              return analysisSession.prepareWithUnchangedPassThroughLibraries(
                  candidate.archive().snapshot().filePath(),
                  siblings,
                  platform,
                  libraries.passThroughClassNames());
            });
    final Map<TrimCandidate, DependencyJarTrimmer.PreparedAnalysis> candidateAnalyses =
        TrimCollections.lookupMap();
    for (int index = 0; index < work.size(); index++) {
      candidateAnalyses.put(work.get(index), preparedList.get(index));
    }
    boolean rootsChanged;
    do {
      rootsChanged = false;
      final List<DependencyJarTrimmer.TrimAnalysis> roundAnalyses =
          ParallelTrimExecutor.mapParallel(
              work,
              trimWorkers,
              candidate -> candidateAnalyses.get(candidate).analyze(candidate.roots()));
      for (int index = 0; index < work.size(); index++) {
        final TrimCandidate candidate = work.get(index);
        final DependencyJarTrimmer.TrimAnalysis analysis = roundAnalyses.get(index);
        analysisRuns++;
        candidate.analysis(analysis);
        rootsChanged |= propagateCandidateRoots(candidate, analysis, candidatePlan.ownersByClass());
      }
    } while (rootsChanged);
    return analysisRuns;
  }

  /* package */

  private static boolean propagateCandidateRoots(
      final TrimCandidate candidate,
      final DependencyJarTrimmer.TrimAnalysis analysis,
      final Map<String, List<TrimCandidate>> owners) {
    boolean changed = false;
    for (final String linked : analysis.reachableLibraryClasses()) {
      final String name = linked.replace('/', '.');
      for (final TrimCandidate owner : owners.getOrDefault(name, List.of())) {
        if (!owner.equals(candidate) && owner.roots().add(name)) {
          changed = true;
        }
      }
    }
    return changed;
  }
}
