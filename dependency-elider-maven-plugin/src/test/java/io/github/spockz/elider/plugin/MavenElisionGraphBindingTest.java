/* WHY: Verifies unique planless graph-pair selection and TEST context. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.spockz.elider.model.ElisionDecision;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** Verifies graph-pair selection and TEST context. */
@SuppressWarnings({"PMD.UnitTestContainsTooManyAsserts"})
final class MavenElisionGraphBindingTest extends MavenElisionGraphBindingTestSupport {
  /** Fixture content used to fingerprint the single resolved JAR. */
  private static final String JAR_BYTES = "jar bytes";

  /** Creates this focused behavior test group. */
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  MavenElisionGraphBindingTest() {
    super();
  }

  @Test
  void bindsUniquePlanlessPairAndHashesActualJar() throws Exception {
    final Fixture fixture = fixture(true, JAR_BYTES);
    final MavenElisionGraphBinding.Result result = fixture.bind(List.of(fixture.snapshot()));

    assertThat(result.evaluation().failClosed()).isFalse();
    assertThat(result.evaluation().captureToken()).isEqualTo("capture-1");
    assertThat(result.inventoryFingerprint()).matches("[0-9a-f]{64}");
    assertThat(result.operationFingerprint()).matches("[0-9a-f]{64}");
    assertThat(fixture.sessionValue("untouched")).isNull();
  }

  @Test
  void operationFingerprintIncludesCompilerReleaseAndMultiReleaseStrategy() throws Exception {
    final Fixture fixture = fixture(true, JAR_BYTES);
    final List<MavenElisionService.ArtifactSnapshot> inventory = List.of(fixture.snapshot());
    final MavenElisionGraphBinding.Result baseline = fixture.bind(inventory);

    fixture.project().getProperties().setProperty("maven.compiler.release", "17");
    final MavenElisionGraphBinding.Result changedTarget =
        fixture.bind(
            fixture.options(),
            inventory,
            new ElisionDecision(Set.of(coordinate(VERSION)), Set.of(), Map.of(), Map.of(), 0L));
    final MavenElisionService.AnalysisOptions options = fixture.options();
    final MavenElisionService.AnalysisOptions passThrough =
        new MavenElisionService.AnalysisOptions(
            options.traceFiles(),
            options.excludedArtifacts(),
            options.productionOutput(),
            options.session(),
            options.sourceRootsComplete(),
            options.trimJars(),
            options.explicitTrimRoots(),
            options.failOnUnsupportedMultiRelease(),
            options.explicitPassThroughArtifacts(),
            options.failOnUnsupportedModuleInfo(),
            options.testResolutionContext(),
            options.conservativeServiceLoaderRoots(),
            "pass-through");
    final MavenElisionGraphBinding.Result changedStrategy =
        fixture.bind(
            passThrough,
            inventory,
            new ElisionDecision(Set.of(coordinate(VERSION)), Set.of(), Map.of(), Map.of(), 0L));

    assertThat(changedTarget.operationFingerprint()).isNotEqualTo(baseline.operationFingerprint());
    assertThat(changedStrategy.operationFingerprint())
        .isNotEqualTo(changedTarget.operationFingerprint());
  }

  @Test
  void rejectsPairWithoutExplicitTestResolutionContext() throws Exception {
    final Fixture fixture = fixture(false, JAR_BYTES);
    final MavenElisionGraphBinding.Result result = fixture.bind(List.of(fixture.snapshot()));

    assertThat(result.evaluation().failClosed()).isTrue();
    assertThat(result.evaluation().elidedArtifacts()).isEmpty();
    assertThat(result.evaluation().failClosedReason())
        .contains("does not establish TEST resolution context");
  }

  @Test
  void rejectsMissingPairWithoutReturningRawDrops() throws Exception {
    final Fixture fixture = fixture(true, JAR_BYTES);
    fixture.clearCapturePairs();
    final MavenElisionGraphBinding.Result result = fixture.bind(List.of(fixture.snapshot()));

    assertThat(result.evaluation().failClosed()).isTrue();
    assertThat(result.evaluation().elidedArtifacts()).isEmpty();
    assertThat(result.evaluation().failClosedReason())
        .contains("No plan-absent graph pair matches");
  }

  @Test
  void rejectsMultipleMatchingPairs() throws Exception {
    final Fixture fixture = fixture(true, JAR_BYTES);
    appendPair(fixture.repositorySession(), projectKey(fixture.project()), "capture-2");
    final MavenElisionGraphBinding.Result result = fixture.bind(List.of(fixture.snapshot()));

    assertThat(result.evaluation().failClosed()).isTrue();
    assertThat(result.evaluation().elidedArtifacts()).isEmpty();
    assertThat(result.evaluation().failClosedReason()).contains("Multiple plan-absent");
  }
}
