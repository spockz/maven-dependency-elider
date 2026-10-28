/* WHY: Proves service analysis carries graph paths into the persisted report model. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Verifies graph-bound output analysis produces a path-aware report input. */
@SuppressWarnings("PMD.AtLeastOneConstructor") // JUnit owns test-instance creation.
final class MavenElisionServiceEffectiveReportTest
    extends MavenElisionServiceEffectiveOutputSupport {
  /** Path kind asserted for each retained artifact with class-level trimming. */
  private static final String CLASS_TRIMMED = "CLASS_TRIMMED";

  @Test
  void effectiveOutputAnalysisCarriesTrimmedArtifactPath() throws Exception {
    final Fixture fixture = fixture(false);
    final ServiceOperation operation =
        operation(fixture, trace(temporaryDirectory, "closure/a/Entry"), null);
    final MavenElisionService.EffectiveAnalysis effective =
        operation.service().finishAnalysis(operation.prepared());
    final MavenElisionService.Analysis analysis =
        operation.service().finishEffectiveOutputs(effective);

    try (TrimOutputGenerationCommitHandle ignored = analysis.generationCommit()) {
      assertThat(
              List.of(
                  analysis.mediatedGraph() != null,
                  analysis.mediatedGraph().available(),
                  analysis.mediatedGraph().snapshot().graphFingerprint(),
                  analysis.mediatedGraph().artifactPaths().stream()
                      .filter(path -> CLASS_TRIMMED.equals(path.kind()))
                      .map(MediatedGraphReport.ArtifactPath::coordinate)
                      .toList(),
                  analysis.trimRecords().stream().map(ArtifactTrimRecord::coordinate).toList()))
          .containsExactly(
              true,
              true,
              effective.graphEvaluation().afterFingerprint(),
              List.of(fixture.coordinate("a")),
              List.of(fixture.coordinate("a")));
    }
  }

  @Test
  @SuppressWarnings(
      "PMD.UnitTestContainsTooManyAsserts") // Prior manifest, files, and generation form one
  // rollback invariant.
  void reportConstructionFailureRestoresThePreviouslyCommittedGeneration() throws Exception {
    final Fixture fixture = fixture(false);
    final Path traceFile = trace(temporaryDirectory, "closure/a/Entry");
    final ServiceOperation firstOperation = operation(fixture, traceFile, null);
    final MavenElisionService.Analysis first =
        firstOperation
            .service()
            .finishEffectiveOutputs(
                firstOperation.service().finishAnalysis(firstOperation.prepared()));
    try (TrimOutputGenerationCommitHandle generationCommit = first.generationCommit()) {
      generationCommit.commit();
      generationCommit.cleanupCommitted();
    }
    final Path manifest = EffectiveOutputCacheTestFiles.cacheManifest(fixture.mavenProject());
    final byte[] priorManifest = Files.readAllBytes(manifest);
    final List<Path> priorOutputs =
        first.trimRecords().stream().map(ArtifactTrimRecord::trimmedPath).toList();

    Files.writeString(traceFile, "closure/a/Extra\n");
    final ServiceOperation secondOperation = operation(fixture, traceFile, null);
    final MavenElisionService.EffectiveAnalysis valid =
        secondOperation.service().finishAnalysis(secondOperation.prepared());
    final MavenElisionService.EffectiveAnalysis invalidReport =
        new MavenElisionService.EffectiveAnalysis(
            valid.prepared(),
            EffectiveGraphPolicy.failClosed(
                valid.graphEvaluation().projectKey(),
                valid.rawDecision(),
                "injected report construction failure"),
            valid.rawDecision(),
            valid.effectiveDecision(),
            valid.forcedUnchangedCoordinates(),
            valid.trimAnalysis(),
            valid.inventoryFingerprint(),
            valid.operationFingerprint(),
            valid.graphProjection());

    assertThatThrownBy(() -> secondOperation.service().finishEffectiveOutputs(invalidReport))
        .isInstanceOf(java.io.IOException.class)
        .hasMessageContaining("missing a successful policy evaluation");

    assertThat(Files.readAllBytes(manifest)).isEqualTo(priorManifest);
    priorOutputs.forEach(
        path -> assertTrue(Files.isRegularFile(path), "Prior generation file was not restored"));
    assertThat(EffectiveOutputCacheTestFiles.generationCount(fixture.mavenProject())).isEqualTo(1);
  }
}
