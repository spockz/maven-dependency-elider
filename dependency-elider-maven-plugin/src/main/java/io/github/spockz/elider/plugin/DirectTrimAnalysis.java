/* WHY: Defers frozen platform loading and ProGuard work until a direct trim
 * cache miss requires fresh closure analysis. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.plugin.DirectTrimPreparation.PreparedDirectTrim;
import io.github.spockz.elider.plugin.SingleReleasePlatforms.PlatformPools;
import java.io.IOException;

/** Runs direct candidate closure only after cache validation misses. */
final class DirectTrimAnalysis {
  private DirectTrimAnalysis() {}

  /* package */ static int analyze(final PreparedDirectTrim plan) throws IOException {
    final PlatformPools pools =
        SingleReleasePlatforms.readPlatformPools(
            plan.fingerprint().platformSnapshots(), plan.compilerRelease(), plan.runtimeRelease());
    return ProGuardTrimEngine.analyze(
        plan.candidatePlan(),
        plan.passThrough(),
        TrimPaths.analysisLibraryDirectory(plan.request().project()),
        plan.runtimeRelease(),
        pools,
        plan.request().policy().trimWorkers());
  }
}
