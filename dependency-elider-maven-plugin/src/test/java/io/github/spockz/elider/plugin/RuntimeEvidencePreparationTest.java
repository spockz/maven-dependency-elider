/* WHY: Confirms the admitted policy reaches prepared Maven analysis before publication. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.trace.TraceEvidenceKind;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** Exercises evidence admission at the Maven preparation boundary. */
@SuppressWarnings("PMD.AtLeastOneConstructor")
final class RuntimeEvidencePreparationTest extends MavenDependencyTrimmerInMemoryClosureSupport {
  /** WHY: This known root affects allowed classes, not observations. */
  private static final String DYNAMIC_SERVICE_ROOT = "closure.b.Middle";

  @Test
  void preparationCarriesClosedWorldObservedAndExplicitRootsIntoOperationIdentity()
      throws Exception {
    final Fixture fixture = fixture(false, true);
    final Path trace = temporaryDirectory.resolve("closed-world.lst");
    Files.writeString(trace, "closure/a/Entry\n");

    final ElisionAnalysisModel.PreparedAnalysis prepared =
        new MavenElisionService().prepare(fixture.mavenProject(), options(trace, true));
    final RuntimeEvidencePolicy policy = prepared.policyOptions().runtimePolicy();

    assertAll(
        () -> assertPolicy(policy),
        () -> assertThat(prepared.graphBinding().operationFingerprint()).hasSize(64));
  }

  @Test
  void irrelevantInputFailsPreparationEvenBesideRelevantEvidence() throws Exception {
    final Fixture fixture = fixture(false, true);
    final Path relevant = temporaryDirectory.resolve("relevant.lst");
    final Path irrelevant = temporaryDirectory.resolve("irrelevant.lst");
    Files.writeString(relevant, "closure/a/Entry\n");
    Files.writeString(irrelevant, "java.lang.String\n");
    final Path report = temporaryDirectory.resolve("must-not-publish.json");

    assertAll(
        () ->
            assertThatThrownBy(
                    () ->
                        new MavenElisionService()
                            .prepare(
                                fixture.mavenProject(),
                                options(List.of(relevant, irrelevant), true)))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("irrelevant.lst")
                .hasMessageContaining("irrelevant"),
        () -> assertThat(report).doesNotExist());
  }

  @Test
  void activeDynamicRootsChangeClosedWorldIdentityWithoutChangingObservedEvidence()
      throws Exception {
    final Fixture fixture = fixture(false);
    final Path trace = temporaryDirectory.resolve("dynamic-root-identity.lst");
    Files.writeString(trace, "closure/a/Entry\n");
    final MavenElisionService service = new MavenElisionService();
    final ElisionAnalysisModel.AnalysisOptions options = options(trace, true);
    final ElisionAnalysisModel.PreparedAnalysis withoutDynamicRoot =
        service.prepare(
            fixture.mavenProject(),
            options,
            (path, context) -> new DependencyDynamicRoots.RootScan(Set.of(), false));
    final ElisionAnalysisModel.PreparedAnalysis withDynamicRoot =
        service.prepare(
            fixture.mavenProject(),
            options,
            (path, context) ->
                new DependencyDynamicRoots.RootScan(Set.of(DYNAMIC_SERVICE_ROOT), true));

    assertAll(
        () ->
            assertThat(withDynamicRoot.policyOptions().runtimePolicy().observedClasses())
                .isEqualTo(withoutDynamicRoot.policyOptions().runtimePolicy().observedClasses()),
        () ->
            assertThat(withDynamicRoot.policyOptions().runtimePolicy().allowedClasses())
                .contains(DYNAMIC_SERVICE_ROOT),
        () ->
            assertThat(withDynamicRoot.graphBinding().operationFingerprint())
                .isNotEqualTo(withoutDynamicRoot.graphBinding().operationFingerprint()));
  }

  private static void assertPolicy(final RuntimeEvidencePolicy policy) {
    assertThat(policy.closedWorld()).isTrue();
    assertThat(policy.observedClasses()).contains("closure.a.Entry");
    assertThat(policy.observedClasses()).doesNotContain(DYNAMIC_SERVICE_ROOT);
    assertThat(policy.allowedClasses())
        .contains("closure.a.Entry", "closure.a.Explicit", DYNAMIC_SERVICE_ROOT);
    assertThat(policy.evidenceKinds()).containsExactly(TraceEvidenceKind.CDS_CLASS_LIST);
  }

  private static ElisionAnalysisModel.AnalysisOptions options(
      final Path trace, final boolean closedWorld) {
    return options(List.of(trace), closedWorld);
  }

  private static ElisionAnalysisModel.AnalysisOptions options(
      final List<Path> traces, final boolean closedWorld) {
    return new ElisionAnalysisModel.AnalysisOptions(
        traces.stream().map(Path::toFile).toList(),
        List.of(),
        List.of(),
        null,
        null,
        new ElisionAnalysisModel.CompletenessOptions(false, false, false, true),
        new ElisionAnalysisModel.TrimOptions(
            false,
            List.of("closure.a.Explicit"),
            false,
            List.of(),
            false,
            MavenDependencyTrimmer.DEFAULT_TRIM_WORKERS,
            MavenDependencyTrimmer.MRJAR_VERTICAL_SHADING),
        new ElisionAnalysisModel.DynamicRootOptions(true),
        null,
        closedWorld);
  }
}
