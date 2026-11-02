/* WHY: Runs MRJAR analysis as ordered phases bound to one request and the
 * same compiler/runtime release interval. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.io.IOException;
import java.util.Map;
import java.util.Set;

/** Entry point for release-specific candidate and sibling closure analysis. */
final class MultiReleaseTierAnalyzer {
  private MultiReleaseTierAnalyzer() {}

  /* package */ static TrimAnalysisResult analyze(
      final TrimRequest request,
      final Map<TrimArtifactRootKey, Set<String>> discoveredRoots,
      final Set<ArtifactCoordinate> forcedUnchanged,
      final int targetRelease,
      final int runtimeRelease)
      throws IOException {
    return TierAnalysisPipeline.analyze(
        new MultiReleaseTrimContext(
            request, discoveredRoots, forcedUnchanged, targetRelease, runtimeRelease));
  }
}
