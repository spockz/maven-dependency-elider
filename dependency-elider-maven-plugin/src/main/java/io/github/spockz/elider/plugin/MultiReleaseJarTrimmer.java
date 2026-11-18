/* WHY: Selects tier-aware analysis when versioned implementations can affect
 * the dependency closure. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.MultiReleaseClassInventory;
import java.io.IOException;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.maven.plugin.MojoFailureException;

/** Selects tier-aware analysis when versioned implementations can affect closure. */
final class MultiReleaseJarTrimmer {
  private MultiReleaseJarTrimmer() {}

  /* package */ record TieringDecision(boolean required, boolean hasVerticalShadingCandidate) {}

  /* package */ static TrimAnalysisResult analyzeInMemory(
      final TrimRequest request,
      final Map<TrimArtifactRootKey, Set<String>> discoveredRoots,
      final Set<ArtifactCoordinate> forcedUnchanged)
      throws IOException, MojoFailureException {
    if (!request.policy().trimPassThroughOnUnresolved()) {
      return analyzeInMemoryPass(request, discoveredRoots, forcedUnchanged);
    }
    final Set<ArtifactCoordinate> effectiveForcedUnchanged =
        new java.util.LinkedHashSet<>(forcedUnchanged);
    while (true) {
      try {
        return analyzeInMemoryPass(request, discoveredRoots, Set.copyOf(effectiveForcedUnchanged));
      } catch (final IOException exception) {
        final java.util.Optional<ArtifactCoordinate> failed = unresolvedCandidate(exception);
        if (failed.isEmpty() || !effectiveForcedUnchanged.add(failed.orElseThrow())) {
          throw exception;
        }
      }
    }
  }

  private static java.util.Optional<ArtifactCoordinate> unresolvedCandidate(final Throwable error) {
    Throwable cursor = error;
    while (cursor != null) {
      if (cursor instanceof TierClosureAnalyzer.CandidateUnresolvedReferenceException candidate) {
        return java.util.Optional.of(candidate.coordinate());
      }
      cursor = cursor.getCause();
    }
    return java.util.Optional.empty();
  }

  private static TrimAnalysisResult analyzeInMemoryPass(
      final TrimRequest request,
      final Map<TrimArtifactRootKey, Set<String>> discoveredRoots,
      final Set<ArtifactCoordinate> forcedUnchanged)
      throws IOException, MojoFailureException {
    final TrimPassThroughPlan passThrough = TrimPassThroughPlanner.passThroughPlan(request);
    final TieringDecision decision = tieringDecision(request, passThrough, forcedUnchanged);
    final TrimExecutionEnvironment executionEnvironment =
        MavenDependencyTrimmer.executionEnvironment(request);
    final int release = executionEnvironment.targetRelease();
    final int runtimeRelease = executionEnvironment.runtimeRelease();
    if (decision.required() && release > runtimeRelease && decision.hasVerticalShadingCandidate()) {
      throw new IOException(
          "Compiler release " + release + " exceeds Maven runtime release " + runtimeRelease);
    }
    final MultiReleaseTrimContext operation =
        new MultiReleaseTrimContext(
            request, discoveredRoots, forcedUnchanged, release, runtimeRelease);
    final TierInventoryReader.PreparedInventory prepared =
        TierInventoryReader.prepare(operation, passThrough);
    final TierRootPlanner.RootPlan roots =
        new TierRootPlanner(operation)
            .findRoots(
                prepared.inventory(), prepared.projections(), prepared.classTables().byRelease());
    final Map<ElisionAnalysisModel.ArtifactSnapshot, TierCandidatePlanner.TierCandidate>
        candidates =
            new TierCandidatePlanner(operation)
                .createCandidates(
                    roots, prepared.projections(), prepared.inventory().multiReleaseCandidates());
    final List<TierArchiveProjector.TierContext> contexts =
        new TierAnalysisPreparer(operation)
            .prepareContexts(prepared.inventory(), prepared.projections(), roots, candidates);
    final TierClosureAnalyzer.ClosureResult closure =
        new TierClosureAnalyzer(operation).analyzeToFixedPoint(contexts, roots, candidates);
    return new TierAnalysisResultBuilder(operation)
        .createResult(
            prepared.inventory(),
            roots,
            candidates,
            closure,
            passThrough.skippedArtifactIdentities());
  }

  @SuppressWarnings("PMD.UseConcurrentHashMap")
  private static TieringDecision tieringDecision(
      final TrimRequest request,
      final TrimPassThroughPlan passThrough,
      final Set<ArtifactCoordinate> forcedUnchanged)
      throws IOException {
    if (!request.policy().trimEnabled()) {
      return new TieringDecision(false, false);
    }
    final Map<Path, Boolean> mrjarCache = new HashMap<>();
    final boolean otherTrimCandidate =
        hasOtherTrimCandidate(passThrough, forcedUnchanged, mrjarCache);
    final boolean unchangedMrjarProgram =
        hasUnchangedMultiReleaseProgram(request, passThrough, forcedUnchanged, mrjarCache);
    final boolean verticalCandidate =
        hasVerticalShadingCandidate(request, passThrough, forcedUnchanged, mrjarCache);
    return new TieringDecision(
        verticalCandidate || (otherTrimCandidate && unchangedMrjarProgram), verticalCandidate);
  }

  private static boolean hasOtherTrimCandidate(
      final TrimPassThroughPlan passThrough,
      final Set<ArtifactCoordinate> forcedUnchanged,
      final Map<Path, Boolean> mrjarCache)
      throws IOException {
    for (final ElisionAnalysisModel.ArtifactSnapshot snapshot : passThrough.retained()) {
      if (!forcedUnchanged.contains(snapshot.coordinate())
          && !isMultiReleaseArchive(snapshot.filePath(), mrjarCache)) {
        return true;
      }
    }
    return false;
  }

  private static boolean hasUnchangedMultiReleaseProgram(
      final TrimRequest request,
      final TrimPassThroughPlan passThrough,
      final Set<ArtifactCoordinate> forcedUnchanged,
      final Map<Path, Boolean> mrjarCache)
      throws IOException {
    for (final ElisionAnalysisModel.ArtifactSnapshot snapshot :
        TrimPassThroughPlanner.retainedAnalysisLibraries(request)) {
      if (!isMultiReleaseArchive(snapshot.filePath(), mrjarCache)) {
        continue;
      }
      final boolean forced = forcedUnchanged.contains(snapshot.coordinate());
      final boolean skipped =
          passThrough
              .skippedArtifactIdentities()
              .contains(TrimPassThroughPlanner.artifactIdentity(snapshot.coordinate()));
      if (forced
          || TrimPassThroughPlanner.unchangedScope(snapshot.coordinate())
          || skipped
          || MavenDependencyTrimmer.MRJAR_PASS_THROUGH.equals(request.policy().mrjarStrategy())) {
        return true;
      }
    }
    return false;
  }

  private static boolean hasVerticalShadingCandidate(
      final TrimRequest request,
      final TrimPassThroughPlan passThrough,
      final Set<ArtifactCoordinate> forcedUnchanged,
      final Map<Path, Boolean> mrjarCache)
      throws IOException {
    if (!MavenDependencyTrimmer.MRJAR_VERTICAL_SHADING.equals(request.policy().mrjarStrategy())) {
      return false;
    }
    for (final ElisionAnalysisModel.ArtifactSnapshot snapshot : passThrough.retained()) {
      if (!forcedUnchanged.contains(snapshot.coordinate())
          && isMultiReleaseArchive(snapshot.filePath(), mrjarCache)) {
        return true;
      }
    }
    return false;
  }

  private static boolean isMultiReleaseArchive(final Path path, final Map<Path, Boolean> mrjarCache)
      throws IOException {
    final Boolean cached = mrjarCache.get(path);
    if (cached != null) {
      return cached;
    }
    final boolean mrjar = MultiReleaseClassInventory.hasUnsupportedVersionedClasses(path);
    mrjarCache.put(path, mrjar);
    return mrjar;
  }
}
