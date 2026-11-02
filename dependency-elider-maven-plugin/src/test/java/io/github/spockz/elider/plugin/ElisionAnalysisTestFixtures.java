// WHY: Provides immutable empty evidence and trim defaults for tests constructing artifact-view
// analyses.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.engine.ClassUsageReport;
import io.github.spockz.elider.model.ElisionDecision;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.Analysis;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.AnalysisEvidence;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.ArtifactViews;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** Builds analysis fixtures from the artifact views relevant to each test. */
final class ElisionAnalysisTestFixtures {
  /** Evidence absent from tests concerned only with Maven artifact views. */
  private static final AnalysisEvidence EMPTY_EVIDENCE =
      new AnalysisEvidence(
          new ClassUsageReport(List.of()), Optional.empty(), Map.of(), false, false, null);

  /** No trimming or staged generation is needed for artifact-view fixtures. */
  private static final TrimResult EMPTY_TRIM =
      new TrimResult(
          List.of(),
          List.of(),
          List.of(),
          List.of(),
          0,
          0L,
          0,
          new TrimExecutionEnvironment(21, Runtime.version().feature()),
          null);

  private ElisionAnalysisTestFixtures() {}

  /* package */ static Analysis analysis(
      final ArtifactViews artifacts, final ElisionDecision decision) {
    return analysis(artifacts, decision, EMPTY_EVIDENCE);
  }

  /* package */ static Analysis analysis(
      final ArtifactViews artifacts,
      final ElisionDecision decision,
      final AnalysisEvidence evidence) {
    return new Analysis(
        artifacts,
        decision,
        decision,
        evidence,
        EMPTY_TRIM,
        null,
        null,
        MavenElisionPolicyIdentityTestSupport.emptyPolicy());
  }
}
