/* WHY: Orders direct trim planning, cache validation, analysis, and
 * complete-batch publication before recording a new cache manifest. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.plugin.DirectArchiveStaging.PublishedArchives;
import io.github.spockz.elider.plugin.DirectTrimPreparation.PreparedDirectTrim;
import io.github.spockz.elider.trimmer.JdkPlatformContext;
import java.io.IOException;
import org.apache.maven.plugin.MojoFailureException;

/** Coordinates direct trim analysis and publication. */
final class DirectTrimOutput {
  private DirectTrimOutput() {}

  /* package */ static TrimResult trimDirectPrepared(
      final TrimRequest request,
      final int release,
      final int runtimeRelease,
      final JdkPlatformContext platform)
      throws IOException, MojoFailureException {
    final PreparedDirectTrim plan =
        DirectTrimPreparation.prepare(request, release, runtimeRelease, platform);
    final TrimResult cached = DirectTrimCache.load(plan);
    if (cached != null) {
      return cached;
    }
    final int analysisRuns = DirectTrimAnalysis.analyze(plan);
    final PublishedArchives published = DirectArchiveStaging.publish(plan);
    DirectTrimCache.store(plan, published.entries());
    return new TrimResult(
        published.records(),
        plan.passThrough().multiReleaseCoordinates(),
        plan.passThrough().moduleInfoCoordinates(),
        plan.passThrough().configuredCoordinates(),
        0,
        0L,
        analysisRuns);
  }
}
