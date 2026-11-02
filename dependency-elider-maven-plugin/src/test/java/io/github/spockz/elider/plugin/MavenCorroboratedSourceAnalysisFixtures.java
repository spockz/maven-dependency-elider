// WHY: Builds minimal analysis snapshots shared by source-review integration scenarios.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.engine.ClassUsageReport;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ElisionDecision;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/** Creates analysis inputs without duplicating test execution setup. */
final class MavenCorroboratedSourceAnalysisFixtures {
  private MavenCorroboratedSourceAnalysisFixtures() {}

  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  static ElisionAnalysisModel.Analysis analysis(
      final ArtifactCoordinate coordinate,
      final Path originalJar,
      final List<ArtifactTrimRecord> trimRecords,
      final boolean removed,
      final boolean duplicateExactSnapshots) {
    final ElisionDecision decision =
        new ElisionDecision(
            removed ? Set.of() : Set.of(coordinate),
            removed ? Set.of(coordinate) : Set.of(),
            Map.of(),
            Map.of(),
            0L);
    return new ElisionAnalysisModel.Analysis(
        new ElisionAnalysisModel.ArtifactViews(
            snapshots(coordinate, originalJar, duplicateExactSnapshots), true, List.of()),
        decision,
        decision,
        new ElisionAnalysisModel.AnalysisEvidence(
            new ClassUsageReport(List.of()), Optional.empty(), Map.of(), false, false, null),
        new TrimResult(
            trimRecords,
            List.of(),
            List.of(),
            List.of(),
            0,
            0L,
            0,
            new TrimExecutionEnvironment(21, Runtime.version().feature()),
            null),
        null,
        null,
        MavenElisionPolicyIdentityTestSupport.emptyPolicy());
  }

  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  static ElisionAnalysisModel.Analysis analysisWithSnapshots(
      final List<ElisionAnalysisModel.ArtifactSnapshot> snapshots,
      final List<ArtifactTrimRecord> trimRecords) {
    final Set<ArtifactCoordinate> retained =
        snapshots.stream()
            .map(ElisionAnalysisModel.ArtifactSnapshot::coordinate)
            .collect(Collectors.toSet());
    final ElisionDecision decision =
        new ElisionDecision(retained, Set.of(), Map.of(), Map.of(), 0L);
    return new ElisionAnalysisModel.Analysis(
        new ElisionAnalysisModel.ArtifactViews(snapshots, true, List.of()),
        decision,
        decision,
        new ElisionAnalysisModel.AnalysisEvidence(
            new ClassUsageReport(List.of()), Optional.empty(), Map.of(), false, false, null),
        new TrimResult(
            trimRecords,
            List.of(),
            List.of(),
            List.of(),
            0,
            0L,
            0,
            new TrimExecutionEnvironment(21, Runtime.version().feature()),
            null),
        null,
        null,
        MavenElisionPolicyIdentityTestSupport.emptyPolicy());
  }

  private static List<ElisionAnalysisModel.ArtifactSnapshot> snapshots(
      final ArtifactCoordinate coordinate,
      final Path originalJar,
      final boolean duplicateExactSnapshots) {
    final ElisionAnalysisModel.ArtifactSnapshot snapshot =
        new ElisionAnalysisModel.ArtifactSnapshot(null, coordinate, originalJar);
    return duplicateExactSnapshots ? List.of(snapshot, snapshot) : List.of(snapshot);
  }
}
