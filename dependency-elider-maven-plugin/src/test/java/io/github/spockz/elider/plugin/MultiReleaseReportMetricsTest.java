/* WHY: Verifies the report's zero-prune exception is limited to vertical-shaded MRJARs. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

/** Verifies report conversion for elevation-only records. */
final class MultiReleaseReportMetricsTest {
  /** Creates this focused report-conversion test group. */
  @SuppressWarnings({"PMD.CommentDefaultAccessModifier", "PMD.UncommentedEmptyConstructor"})
  MultiReleaseReportMetricsTest() {}

  @Test
  @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
  void zeroPrunedClassesAreAllowedOnlyForElevatedMultiReleaseRecords() {
    final ArtifactCoordinate coordinate = ArtifactCoordinate.of("org.example", "elevated", "1.0");
    final ArtifactTrimRecord singleRelease =
        new ArtifactTrimRecord(
            coordinate,
            Path.of("original.jar"),
            "a".repeat(64),
            "b".repeat(40),
            Path.of("trimmed.jar"),
            "c".repeat(64),
            "d".repeat(40),
            3,
            3,
            0L);
    final ArtifactTrimRecord elevated =
        new ArtifactTrimRecord(
            coordinate,
            Path.of("original.jar"),
            "a".repeat(64),
            "b".repeat(40),
            Path.of("trimmed.jar"),
            "c".repeat(64),
            "d".repeat(40),
            3,
            3,
            0L,
            6,
            5,
            "elevated_and_trimmed");

    assertThatThrownBy(() -> MavenElisionReportSnapshot.trimmedArtifact(singleRelease))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("must prune at least one class");
    assertThat(MavenElisionReportSnapshot.trimmedArtifact(elevated).programClassesPruned())
        .isZero();
  }
}
