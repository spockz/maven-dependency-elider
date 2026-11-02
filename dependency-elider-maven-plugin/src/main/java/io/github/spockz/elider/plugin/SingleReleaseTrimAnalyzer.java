/* WHY: Computes candidate closure against isolated JDK class tables while
 * keeping each candidate analysis independent. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.plugin.SingleReleaseTrimInventory.SingleReleaseInventory;
import io.github.spockz.elider.plugin.SingleReleaseTrimInventory.SingleReleaseLayout;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.maven.plugin.MojoFailureException;

/** Coordinates single-release candidate and sibling closure. */
final class SingleReleaseTrimAnalyzer {
  private SingleReleaseTrimAnalyzer() {}

  /* package */

  /* package */

  /* package */

  /* package */ static TrimAnalysisResult analyzeInMemorySingleRelease(
      final TrimRequest request,
      final Map<TrimArtifactRootKey, Set<String>> discoveredRoots,
      final Set<ArtifactCoordinate> forcedUnchanged)
      throws IOException, MojoFailureException {
    final SingleReleaseInventory inventory =
        SingleReleaseTrimInventory.readSingleReleaseInventory(request, discoveredRoots);
    final SingleReleaseLayout layout =
        SingleReleaseTrimInventory.singleReleaseLayout(request, inventory, forcedUnchanged);
    final SingleReleasePlatforms.AnalysisPlatform platform =
        SingleReleasePlatforms.prepare(request);
    final SingleReleaseRootPlanner.SingleReleaseRootPlan roots =
        SingleReleaseRootPlanner.singleReleaseRootPlan(request, inventory, layout, platform);
    final SingleReleaseClosureAnalyzer.SingleReleaseClosure closure =
        SingleReleaseClosureAnalyzer.analyzeSingleReleaseClosure(
            inventory, layout, roots, request.policy().trimWorkers());
    return TrimRootPlanner.inMemoryResult(
        closure.analyses(),
        roots.candidateRoots(),
        closure.reachableArtifacts(),
        closure.analysisRuns(),
        platform.targetRelease(),
        platform.runtimeRelease(),
        List.of(platform.targetRelease(), platform.runtimeRelease()),
        platform.snapshots(),
        Map.of());
  }

  /* package */
}
