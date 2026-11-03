/* WHY: Defers frozen platform loading and ProGuard work until a direct trim
 * cache miss requires fresh closure analysis. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.plugin.DirectTrimPreparation.PreparedDirectTrim;
import io.github.spockz.elider.plugin.SingleReleasePlatforms.JdkClassTables;
import java.io.IOException;

/** Runs direct candidate closure only after cache validation misses. */
final class DirectTrimAnalysis {
  private DirectTrimAnalysis() {}

  /* package */ static int analyze(final PreparedDirectTrim plan) throws IOException {
    final JdkClassTables tables =
        SingleReleasePlatforms.readJdkClassTables(plan.fingerprint().platformSnapshots());
    final boolean allowModularCandidate =
        MavenDependencyTrimmer.MRJAR_CLASSPATH_ONLY.equals(
            plan.request().policy().mrjarStrategy());
    return ProGuardTrimEngine.analyze(
        plan.candidatePlan(),
        plan.passThrough(),
        TrimPaths.analysisLibraryDirectory(plan.request().project()),
        plan.runtimeRelease(),
        tables,
        plan.request().policy().trimWorkers(),
        allowModularCandidate);
  }
}
