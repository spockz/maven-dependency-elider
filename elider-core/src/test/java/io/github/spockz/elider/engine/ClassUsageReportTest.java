// WHY: Verifies report classifications and immutable evidence joining without invoking pruning.

package io.github.spockz.elider.engine;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ArtifactFileRef;
import io.github.spockz.elider.model.OriginEvidence;
import io.github.spockz.elider.model.TraceData;
import io.github.spockz.elider.scanner.ArtifactClassIndex;
import io.github.spockz.elider.scanner.BytecodeReferenceScan;
import java.nio.file.Path;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** Tests report output ordering, categories, and source attribution. */
@SuppressWarnings({
  "PMD.AtLeastOneConstructor",
  "PMD.UnitTestContainsTooManyAsserts",
  "PMD.AvoidDuplicateLiterals"
})
class ClassUsageReportTest {
  /** First synthetic artifact used by report inputs. */
  private final ArtifactFileRef first = artifact("first", "classes.jar");

  /** Second synthetic artifact used to verify duplicate ownership. */
  private final ArtifactFileRef second = artifact("second", "other.jar");

  @Test
  void classifiesAllReferenceAndObservationCombinations() {
    final ClassUsageReport report =
        ClassUsageReport.classify(
            new ArtifactClassIndex(
                Map.of(
                    first,
                    Set.of("sample.Both", "sample.Static"),
                    second,
                    Set.of("sample.Runtime", "sample.Neither"))),
            TraceData.of(Set.of("sample.Both", "sample.Runtime")),
            Optional.of(scan(Set.of("sample.Both", "sample.Static"), true)));

    assertThat(byName(report, "sample.Both").category())
        .isEqualTo(ClassUsageReport.Category.APPLICATION_REFERENCED_AND_RUNTIME_OBSERVED);
    assertThat(byName(report, "sample.Static").category())
        .isEqualTo(ClassUsageReport.Category.APPLICATION_REFERENCED_NOT_RUNTIME_OBSERVED);
    assertThat(byName(report, "sample.Runtime").category())
        .isEqualTo(ClassUsageReport.Category.RUNTIME_OBSERVED_WITHOUT_APPLICATION_REFERENCE);
    assertThat(byName(report, "sample.Neither").category())
        .isEqualTo(ClassUsageReport.Category.NEITHER_REFERENCED_NOR_OBSERVED);
    assertThat(byName(report, "sample.Runtime").applicationBytecodeReferenced()).isFalse();
    assertThat(byName(report, "sample.Runtime").runtimeObserved()).isTrue();
    assertThat(report.applicationBytecodeReferenced())
        .extracting(ClassUsageReport.ClassUsage::className)
        .containsExactly("sample.Both", "sample.Static");
    assertThat(report.runtimeObservedWithoutApplicationReference())
        .extracting(ClassUsageReport.ClassUsage::className)
        .containsExactly("sample.Runtime");
    assertThat(report.neitherReferencedNorObserved())
        .extracting(ClassUsageReport.ClassUsage::className)
        .containsExactly("sample.Neither");
  }

  @Test
  void marksObservedClassesUnknownWhenStaticEvidenceIsUnavailable() {
    final ClassUsageReport report =
        ClassUsageReport.classify(
            new ArtifactClassIndex(Map.of(first, Set.of("sample.Runtime"))),
            TraceData.of(Set.of("sample.Runtime")),
            Optional.empty());

    final ClassUsageReport.ClassUsage usage = byName(report, "sample.Runtime");
    assertThat(usage.category())
        .isEqualTo(ClassUsageReport.Category.RUNTIME_OBSERVED_WITH_UNKNOWN_STATIC_EVIDENCE);
    assertThat(usage.staticEvidenceAvailable()).isFalse();
    assertThat(usage.applicationBytecodeReferenced()).isFalse();
    assertThat(report.runtimeObservedWithUnknownStaticEvidence()).containsExactly(usage);
  }

  @Test
  void leavesUnobservedClassesUngroupedWhenStaticScanIsIncomplete() {
    final ClassUsageReport report =
        ClassUsageReport.classify(
            new ArtifactClassIndex(Map.of(first, Set.of("sample.Unobserved"))),
            TraceData.empty(),
            Optional.of(scan(Set.of(), false)));

    assertThat(byName(report, "sample.Unobserved").category())
        .isEqualTo(ClassUsageReport.Category.UNKNOWN_STATIC_EVIDENCE);
    assertThat(report.applicationBytecodeReferenced()).isEmpty();
    assertThat(report.runtimeObservedWithoutApplicationReference()).isEmpty();
    assertThat(report.neitherReferencedNorObserved()).isEmpty();
  }

  @Test
  void retainsEveryDuplicateOwnerAndTraceOriginEvidence() {
    final Path origin = Path.of("first.jar").toAbsolutePath();
    final ArtifactFileRef sameIdentityDifferentMetadata =
        new ArtifactFileRef(first.coordinate(), first.filePath(), first.lastModified(), 2);
    final ClassUsageReport report =
        ClassUsageReport.classify(
            new ArtifactClassIndex(
                Map.of(
                    first,
                    Set.of("sample.Duplicate"),
                    sameIdentityDifferentMetadata,
                    Set.of("sample.Duplicate"),
                    second,
                    Set.of("sample.Duplicate"))),
            TraceData.fromClassOrigins(
                Map.of("sample.Duplicate", new OriginEvidence(Set.of(origin), false))),
            Optional.of(scan(Set.of(), true)));

    final ClassUsageReport.ClassUsage usage = byName(report, "sample.Duplicate");
    assertThat(usage.owners())
        .containsExactlyInAnyOrder(first, sameIdentityDifferentMetadata, second);
    assertThat(usage.originEvidence()).contains(new OriginEvidence(Set.of(origin), false));
  }

  @Test
  void handlesEmptyClassInventoriesAndResourceOnlyArtifacts() {
    final ClassUsageReport report =
        ClassUsageReport.classify(
            new ArtifactClassIndex(Map.of(first, Set.of())),
            TraceData.empty(),
            Optional.of(scan(Set.of(), true)));
    assertThat(report.classes()).isEmpty();
  }

  @Test
  void sortsRowsAndSnapshotsCallerCollections() {
    final Set<String> classes = new java.util.HashSet<>(Set.of("sample.Z", "sample.A"));
    final ClassUsageReport report =
        ClassUsageReport.classify(
            new ArtifactClassIndex(Map.of(first, classes)),
            TraceData.empty(),
            Optional.of(scan(Set.of(), true)));
    classes.clear();

    assertThat(report.classes())
        .extracting(ClassUsageReport.ClassUsage::className)
        .containsExactly("sample.A", "sample.Z");
    assertThatThrownBy(() -> report.classes().clear())
        .isInstanceOf(UnsupportedOperationException.class);
    assertThatThrownBy(() -> byName(report, "sample.A").owners().clear())
        .isInstanceOf(UnsupportedOperationException.class);
  }

  private static ClassUsageReport.ClassUsage byName(
      final ClassUsageReport report, final String name) {
    return report.classes().stream()
        .filter(usage -> usage.className().equals(name))
        .findFirst()
        .orElseThrow();
  }

  private static BytecodeReferenceScan scan(final Set<String> names, final boolean complete) {
    return new BytecodeReferenceScan(Path.of("target/classes"), names, 1, complete);
  }

  private static ArtifactFileRef artifact(final String artifactId, final String path) {
    return new ArtifactFileRef(
        ArtifactCoordinate.of("sample", artifactId, "1.0"), Path.of(path), 1, 1);
  }
}
