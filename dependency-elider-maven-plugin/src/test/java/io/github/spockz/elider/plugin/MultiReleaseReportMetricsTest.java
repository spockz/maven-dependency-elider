/* WHY: Verifies zero-class outputs are backed by MRJAR elevation or descriptor changes. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Verifies report conversion for elevation-only records. */
final class MultiReleaseReportMetricsTest {
  /** Creates this focused report-conversion test group. */
  @SuppressWarnings({"PMD.CommentDefaultAccessModifier", "PMD.UncommentedEmptyConstructor"})
  MultiReleaseReportMetricsTest() {}

  @Test
  @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
  void zeroPrunedClassesRequireElevationOrChangedServiceDescriptorMetadata() {
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
    final ArtifactTrimRecord classpathOnly =
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
            0,
            0,
            "classpath-only");

    assertThatThrownBy(() -> MavenElisionReportSnapshot.trimmedArtifact(singleRelease))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("change a service descriptor");
    final MavenElisionReportSnapshot.TrimmedArtifact elevatedRow =
        MavenElisionReportSnapshot.trimmedArtifact(elevated);
    final MavenElisionReportSnapshot.TrimmedArtifact classpathOnlyRow =
        MavenElisionReportSnapshot.trimmedArtifact(classpathOnly);
    final ServiceDescriptorChange omitted =
        new ServiceDescriptorChange(
            "META-INF/services/example.Service", ServiceDescriptorChange.Outcome.OMIT);
    final MavenElisionReportSnapshot.TrimmedArtifact singleDescriptorChange =
        MavenElisionReportSnapshot.trimmedArtifact(singleRelease, List.of(omitted));
    final MavenElisionReportSnapshot.TrimmedArtifact elevatedDescriptorChange =
        MavenElisionReportSnapshot.trimmedArtifact(elevated, List.of(omitted));
    final int singleClassCount = singleDescriptorChange.programClassesPruned();
    final int elevatedClassCount = elevatedDescriptorChange.programClassesPruned();
    assertAll(
        "zero-class archive rows preserve elevation or identify a changed root descriptor",
        () -> assertThat(elevatedRow.mrjarStatus()).isEqualTo("elevated_and_trimmed"),
        () -> assertThat(classpathOnlyRow.mrjarStatus()).isEqualTo("classpath-only"),
        () -> assertThat(elevatedRow.serviceDescriptorChanges()).isEmpty(),
        () -> assertEquals(0, singleClassCount, "A changed descriptor can justify an output row"),
        () -> assertEquals(0, elevatedClassCount, "Elevation can occur without class pruning"));
  }
}
