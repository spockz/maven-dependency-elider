// WHY: Keeps unverified advisory mappings separate from prediction results and trim proofs.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.VulnerabilitySymbolMapping;
import java.util.List;
import java.util.Set;

/** Builds review findings for mappings that Analyze cannot prove from unpublished trim output. */
final class MavenPredictionMappingReview {
  private MavenPredictionMappingReview() {
    throw new AssertionError("No instances");
  }

  /* default */ static List<MavenVulnerabilityAssessment.ConservativeFinding> findings(
      final List<VulnerabilitySymbolMapping> mappings, final AnalyzePrediction prediction) {
    final Set<ArtifactCoordinate> plannedElisions = Set.copyOf(prediction.wouldElideArtifacts());
    return mappings.stream()
        .flatMap(
            mapping ->
                prediction.inputArtifacts().stream()
                    .map(ElisionAnalysisModel.ArtifactSnapshot::coordinate)
                    .filter(candidate -> MavenMappingApplicability.appliesTo(mapping, candidate))
                    .map(
                        candidate ->
                            new MavenVulnerabilityAssessment.ConservativeFinding(
                                mapping.cveId(),
                                candidate,
                                plannedElisions.contains(candidate)
                                    ? "Analyze predicts this component would be elided, but no "
                                        + "archive was published; the whole-component finding is "
                                        + "conditional and no omitted-code proof is claimed."
                                    : "Analyze did not publish a trimmed archive, so this "
                                        + "vulnerability mapping remains unresolved and no "
                                        + "omitted-code proof is claimed.",
                                MavenVulnerabilityAssessment.formatPomOverrideSnippet(
                                    mapping, candidate, mapping.vulnerableClasses()))))
        .distinct()
        .toList();
  }
}
