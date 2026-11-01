// WHY: Rolls back staged output if report construction fails before analysis
// owns the generation.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.plugin.ElisionAnalysisModel.Analysis;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.EffectiveAnalysis;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.PreparedAnalysis;
import java.io.IOException;
import org.apache.maven.project.MavenProject;

/** Constructs effective analysis reports while guarding staged output ownership. */
final class MavenEffectiveAnalysisReport {
  private MavenEffectiveAnalysisReport() {}

  /* package */ static Analysis create(
      final EffectiveAnalysis effective, final TrimResult trimResult) throws IOException {
    try (ReportCleanup cleanup = new ReportCleanup(trimResult.generationCommit())) {
      final PreparedAnalysis prepared = effective.prepared();
      final MediatedGraphReport mediatedGraph =
          MediatedGraphReport.create(
              prepared.graphBinding().pair(),
              effective.graphEvaluation(),
              effective.effectiveDecision().elidedArtifacts(),
              trimResult.records(),
              projectKey(prepared.project()));
      final Analysis analysis =
          new Analysis(
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
                  .withOperationFingerprint(effective.operationFingerprint()));
      cleanup.transferOwnership();
      return analysis;
    }
  }

  private static String projectKey(final MavenProject project) {
    return project.getGroupId() + ":" + project.getArtifactId() + ":" + project.getVersion();
  }

  /** Keeps failure cleanup active until a complete analysis owns the generation. */
  private static final class ReportCleanup implements AutoCloseable {
    /** Staged output remains guarded until a completed analysis takes ownership. */
    private final TrimOutputGenerationCommitHandle generation;

    /** A completed result owns cleanup of the staged generation. */
    private boolean transferred;

    private ReportCleanup(final TrimOutputGenerationCommitHandle generation) {
      this.generation = generation;
    }

    private void transferOwnership() {
      transferred = true;
    }

    @Override
    public void close() throws IOException {
      if (!transferred && generation != null) {
        generation.close();
      }
    }
  }
}
