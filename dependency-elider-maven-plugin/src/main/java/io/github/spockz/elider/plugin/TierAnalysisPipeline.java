/* WHY: Orders tier phases so closure always uses the inventory and root
 * evidence from one completed preparation. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.plugin.TierArchiveProjector.TierContext;
import io.github.spockz.elider.plugin.TierCandidatePlanner.TierCandidate;
import io.github.spockz.elider.plugin.TierClosureAnalyzer.ClosureResult;
import io.github.spockz.elider.plugin.TierInventoryPreparer.PreparedInventory;
import io.github.spockz.elider.plugin.TierRootPlanner.RootPlan;
import java.io.IOException;
import java.util.List;
import java.util.Map;

/** Runs inventory, root, preparation, and closure phases in order. */
final class TierAnalysisPipeline {
  private TierAnalysisPipeline() {}

  /* package */ static TrimAnalysisResult analyze(final MultiReleaseTrimContext operation)
      throws IOException {
    final PreparedInventory prepared = TierInventoryPreparer.prepare(operation);
    final RootPlan roots =
        new TierRootPlanner(operation)
            .findRoots(
                prepared.inventory(), prepared.projections(), prepared.platforms().byRelease());
    final Map<ElisionAnalysisModel.ArtifactSnapshot, TierCandidate> candidates =
        new TierCandidatePlanner(operation)
            .createCandidates(
                roots, prepared.projections(), prepared.inventory().multiReleaseCandidates());
    final List<TierContext> contexts =
        new TierAnalysisPreparer(operation)
            .prepareContexts(prepared.inventory(), prepared.projections(), roots, candidates);
    final ClosureResult closure =
        new TierClosureAnalyzer(operation).analyzeToFixedPoint(contexts, roots, candidates);
    return new TierAnalysisResultBuilder(operation)
        .createResult(prepared.inventory(), roots, candidates, closure);
  }
}
