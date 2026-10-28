// WHY: Verifies whole-drop metrics remain visible when retained-JAR trimming is disabled.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ElisionDecision;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** Tests dropped-JAR summary metrics without a retained-JAR trim stage. */
final class ElisionSummaryMetricTest {
  /** Group used for synthetic artifact identities. */
  private static final String GROUP_ID = "org.example";

  /** Project artifact used by graph-backed report fixtures. */
  private static final String PROJECT_ARTIFACT_ID = "consumer";

  /** Version shared by the synthetic artifacts. */
  private static final String VERSION = "1.0";

  /** Artifact removed in dropped-JAR metric cases. */
  private static final String DROPPED_ARTIFACT_ID = "removed";

  /** Project identity shared by the graph-backed report fixtures. */
  private static final String PROJECT_GAV = GROUP_ID + ":" + PROJECT_ARTIFACT_ID + ":" + VERSION;

  /** Coordinate used by dropped-JAR summary cases. */
  private static final String DROPPED_COORDINATE =
      GROUP_ID + ":" + DROPPED_ARTIFACT_ID + ":jar:" + VERSION + " (compile)";

  /** Creates the package-visible test instance required by JUnit. */
  @SuppressWarnings({"PMD.UncommentedEmptyConstructor", "PMD.CommentDefaultAccessModifier"})
  ElisionSummaryMetricTest() {}

  @Test
  @SuppressWarnings(
      "PMD.UnitTestContainsTooManyAsserts") // Checks separate totals and emitted output.
  void reportsDroppedJarClassesWhenRetainedTrimmingIsDisabled() throws IOException {
    final ArtifactCoordinate coordinate =
        ArtifactCoordinate.of(GROUP_ID, DROPPED_ARTIFACT_ID, VERSION);
    final MavenElisionReportSnapshot snapshot =
        new MavenElisionReportSnapshot(
            MavenElisionReportSnapshot.SCHEMA_VERSION,
            GROUP_ID,
            PROJECT_ARTIFACT_ID,
            VERSION,
            Path.of(".").toAbsolutePath().normalize().toString(),
            "2026-10-28T00:00:00Z",
            1,
            2048,
            List.of(
                new MavenElisionReportSnapshot.DroppedArtifact(DROPPED_COORDINATE, 2048, 2, 18)),
            List.of(DROPPED_COORDINATE),
            0,
            0,
            List.of(),
            MediatedGraphReportTestSupport.reportForDroppedOutput(coordinate, PROJECT_GAV));
    final RecordingMavenLog log = new RecordingMavenLog();
    final ElisionDecision decision =
        new ElisionDecision(Set.of(), Set.of(coordinate), Map.of(), Map.of(), 0L);

    assertThat(snapshot.droppedProgramClassEntries()).isEqualTo(2);
    assertThat(snapshot.droppedProgramClassBytes()).isEqualTo(18);
    assertThat(snapshot.programClassesPruned()).isZero();
    assertThat(snapshot.uncompressedProgramClassBytesPruned()).isZero();

    ElisionSummary.report(log, decision, 1, snapshot);

    assertThat(log.messages())
        .contains(
            "  Program classes removed with dropped JARs: 2 (uncompressed .class entry payload"
                + " bytes: 18 B; excludes module descriptors and archive sanitation metadata)",
            "  Classes removed: 0 / N/A (N/A; stage not run)");
    assertThat(log.messages()).doesNotContain("  Program classes removed:");
  }

  @Test
  void rejectsAnArtifactCountedAsBothDroppedAndTrimmed() throws IOException {
    final ArtifactCoordinate coordinate =
        ArtifactCoordinate.of(GROUP_ID, DROPPED_ARTIFACT_ID, VERSION);
    final String projectDirectory = Path.of(".").toAbsolutePath().normalize().toString();

    assertThatThrownBy(
            () ->
                new MavenElisionReportSnapshot(
                    MavenElisionReportSnapshot.SCHEMA_VERSION,
                    GROUP_ID,
                    PROJECT_ARTIFACT_ID,
                    VERSION,
                    projectDirectory,
                    "2026-10-28T00:00:00Z",
                    1,
                    2048,
                    List.of(
                        new MavenElisionReportSnapshot.DroppedArtifact(
                            DROPPED_COORDINATE, 2048, 2, 18)),
                    List.of(DROPPED_COORDINATE),
                    1,
                    16,
                    List.of(
                        new MavenElisionReportSnapshot.TrimmedArtifact(DROPPED_COORDINATE, 1, 16)),
                    MediatedGraphReportTestSupport.reportForDroppedOutput(coordinate, PROJECT_GAV)))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("An artifact cannot be both dropped and class-trimmed");
  }
}
