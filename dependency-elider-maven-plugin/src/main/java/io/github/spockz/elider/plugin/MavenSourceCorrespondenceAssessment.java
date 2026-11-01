// WHY: Keeps source reproduction results separate from proof admission and classification.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.OsvAdvisoryRecord;
import io.github.spockz.elider.model.StructuredSourceClassEvidence;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.project.MavenProject;

/** Collects exact, raw-applicable structured claim correspondence results. */
final class MavenSourceCorrespondenceAssessment {
  private MavenSourceCorrespondenceAssessment() {}

  /* default */ static List<SourceBuildCorrespondence> evaluate(
      final ArtifactCoordinate candidate,
      final List<OsvAdvisoryRecord> records,
      final List<MavenVulnerabilityAssessment.MatchedAdvisoryEvidence> matched,
      final List<ElisionAnalysisModel.ArtifactSnapshot> artifacts,
      final MavenProject project,
      final MavenSession session,
      final Optional<MavenSourceClassifierResolver> resolver,
      final boolean conventionalLayoutAssumed,
      final SourceJdkIdentity.Resolution sourceJdkIdentity) {
    final MavenSourceCorrespondenceClaimEvaluator evaluator =
        new MavenSourceCorrespondenceClaimEvaluator(
            candidate,
            records,
            artifacts,
            project,
            session,
            resolver,
            conventionalLayoutAssumed,
            sourceJdkIdentity);
    final List<SourceBuildCorrespondence> results = new ArrayList<>();
    for (final MavenVulnerabilityAssessment.MatchedAdvisoryEvidence item : matched) {
      if (item.evidence() instanceof StructuredSourceClassEvidence evidence) {
        evaluator.evaluate(item, evidence).ifPresent(results::add);
      }
    }
    return List.copyOf(results);
  }
}
