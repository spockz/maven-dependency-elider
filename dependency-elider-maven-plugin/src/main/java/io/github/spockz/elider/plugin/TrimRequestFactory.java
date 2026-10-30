/* WHY: Builds trimming requests consistently from prepared Maven analysis
 * evidence. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.AnalysisOptions;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.PreparedAnalysis;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.TrimOptions;
import io.github.spockz.elider.scanner.BytecodeReferenceScan;
import java.util.Set;

/** Constructs the immutable request shared by both trimming paths. */
final class TrimRequestFactory {
  private TrimRequestFactory() {}

  /* default */ static TrimRequest fromPreparedAnalysis(
      final PreparedAnalysis prepared,
      final Set<ArtifactCoordinate> retainedArtifacts,
      final Set<String> rootClasses) {
    final AnalysisOptions options = prepared.options();
    final TrimOptions trim = options.trim();
    return new TrimRequest(
        prepared.project(),
        options.session(),
        prepared.resolvedSnapshots(),
        new TrimScanInputs(prepared.index(), prepared.dynamicRootInputs().scansByPath()),
        retainedArtifacts,
        new TrimEvidence(
            prepared.trace(),
            rootClasses,
            prepared.bytecodeScan().map(BytecodeReferenceScan::referencedClasses).orElse(Set.of()),
            prepared.projectOutputClasses(),
            prepared.dynamicRootInputs().provenServiceInterfaces()),
        new TrimPolicy(
            trim.explicitRoots(),
            trim.failOnUnsupportedMultiRelease(),
            trim.passThroughArtifacts(),
            trim.failOnUnsupportedModuleInfo(),
            trim.mrjarStrategy(),
            trim.enabled(),
            options.dynamicRoots().conservativeServiceLoaderRoots(),
            trim.workers()));
  }
}
