// WHY: Builds the report that accompanies completed effective trim outputs.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.plugin.ElisionAnalysisModel.Analysis;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.EffectiveAnalysis;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.PreparedAnalysis;
import java.io.IOException;
import org.apache.maven.project.MavenProject;

/** Constructs effective analysis reports. */
final class MavenEffectiveAnalysisReport {
  private MavenEffectiveAnalysisReport() {}

  /* package */ static Analysis create(
      final EffectiveAnalysis effective, final TrimResult trimResult) throws IOException {
    final PreparedAnalysis prepared = effective.prepared();
    final MediatedGraphReport mediatedGraph =
        MediatedGraphReport.create(
            prepared.graphBinding().pair(),
            effective.graphEvaluation(),
            effective.effectiveDecision().elidedArtifacts(),
            trimResult.records(),
            projectKey(prepared.project()));
    return new Analysis(
        ElisionAnalysisModel.artifactViews(prepared),
        effective.rawDecision(),
        effective.effectiveDecision(),
        ElisionAnalysisModel.evidence(prepared),
        trimResult,
        effective.graphProjection(),
        mediatedGraph,
        effective
            .prepared()
            .policyOptions()
            .withOperationFingerprint(effective.operationFingerprint()),
        effective.prepared().traceDecision(),
        effective.banPlan());
  }

  private static String projectKey(final MavenProject project) {
    return project.getGroupId() + ":" + project.getArtifactId() + ":" + project.getVersion();
  }
}
