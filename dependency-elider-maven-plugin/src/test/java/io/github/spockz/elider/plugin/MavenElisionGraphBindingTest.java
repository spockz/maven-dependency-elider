/* WHY: Verifies unique planless graph-pair selection and TEST context. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.model.ElisionDecision;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** Verifies graph-pair selection and TEST context. */
@SuppressWarnings({"PMD.UnitTestContainsTooManyAsserts", "PMD.TooManyMethods"})
final class MavenElisionGraphBindingTest extends MavenElisionGraphBindingTestSupport {
  /** Fixture content used to fingerprint the single resolved JAR. */
  private static final String JAR_BYTES = "jar bytes";

  /** Canonical retention or ban identity used by fingerprint comparisons. */
  private static final String LIBRARY_IDENTITY = "fixture:library";

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
    final List<ElisionAnalysisModel.ArtifactSnapshot> inventory = List.of(fixture.snapshot());
    final MavenElisionGraphBinding.Result baseline = fixture.bind(inventory);

    fixture.project().getProperties().setProperty("maven.compiler.release", "17");
    final MavenElisionGraphBinding.Result changedTarget =
        fixture.bind(
            fixture.options(),
            inventory,
            new ElisionDecision(Set.of(coordinate(VERSION)), Set.of(), Map.of(), Map.of(), 0L));
    final ElisionAnalysisModel.AnalysisOptions options = fixture.options();
    final ElisionAnalysisModel.AnalysisOptions passThrough =
        new ElisionAnalysisModel.AnalysisOptions(
            options.traceFiles(),
            options.retainedArtifacts(),
            options.productionOutput(),
            options.session(),
            new ElisionAnalysisModel.CompletenessOptions(
                options.completeness().sourceRootsComplete(),
                false,
                false,
                options.completeness().testResolutionContext()),
            new ElisionAnalysisModel.TrimOptions(
                options.trim().enabled(),
                options.trim().explicitRoots(),
                options.trim().failOnUnsupportedMultiRelease(),
                options.trim().passThroughArtifacts(),
                options.trim().failOnUnsupportedModuleInfo(),
                MavenDependencyTrimmer.DEFAULT_TRIM_WORKERS,
                "pass-through"),
            new ElisionAnalysisModel.DynamicRootOptions(
                options.dynamicRoots().conservativeServiceLoaderRoots()));
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
  void operationFingerprintIncludesNormalizedBanRequests() throws Exception {
    final Fixture fixture = fixture(true, JAR_BYTES);
    final List<ElisionAnalysisModel.ArtifactSnapshot> inventory = List.of(fixture.snapshot());
    final ElisionAnalysisModel.AnalysisOptions options = fixture.options();
    final ElisionDecision decision =
        new ElisionDecision(Set.of(coordinate(VERSION)), Set.of(), Map.of(), Map.of(), 0L);
    final MavenElisionGraphBinding.Result normalized =
        fixture.bind(
            withBans(options, List.of(" fixture : library ", LIBRARY_IDENTITY)),
            inventory,
            decision);
    final MavenElisionGraphBinding.Result canonical =
        fixture.bind(withBans(options, List.of(LIBRARY_IDENTITY)), inventory, decision);
    final MavenElisionGraphBinding.Result changed =
        fixture.bind(withBans(options, List.of("fixture:other")), inventory, decision);

    assertAll(
        "operation identity uses normalized exact ban requests",
        () ->
            assertThat(normalized.operationFingerprint())
                .isEqualTo(canonical.operationFingerprint()),
        () ->
            assertThat(changed.operationFingerprint())
                .isNotEqualTo(canonical.operationFingerprint()));
  }

  @Test
  void operationFingerprintNormalizesRetentionDefaults() throws Exception {
    final Fixture fixture = fixture(true, JAR_BYTES);
    final List<ElisionAnalysisModel.ArtifactSnapshot> inventory = List.of(fixture.snapshot());
    final ElisionAnalysisModel.AnalysisOptions options = fixture.options();
    final ElisionDecision decision =
        new ElisionDecision(Set.of(coordinate(VERSION)), Set.of(), Map.of(), Map.of(), 0L);

    final MavenElisionGraphBinding.Result shorthand =
        fixture.bind(withRetention(options, List.of(LIBRARY_IDENTITY)), inventory, decision);
    final MavenElisionGraphBinding.Result explicitDefaults =
        fixture.bind(withRetention(options, List.of("fixture:library::jar:")), inventory, decision);

    assertAll(
        "retention shorthand and explicit defaults have the same operation identity",
        () ->
            assertThat(shorthand.operationFingerprint())
                .isEqualTo(explicitDefaults.operationFingerprint()));
  }

  @Test
  void operationFingerprintLabelsRetainedAndElidedActions() throws Exception {
    final Fixture fixture = fixture(true, JAR_BYTES);
    final List<ElisionAnalysisModel.ArtifactSnapshot> inventory = List.of(fixture.snapshot());
    final ElisionAnalysisModel.AnalysisOptions options = fixture.options();
    final MavenElisionGraphBinding.Result retained =
        fixture.bind(
            options,
            inventory,
            new ElisionDecision(Set.of(coordinate(VERSION)), Set.of(), Map.of(), Map.of(), 0L));
    final MavenElisionGraphBinding.Result elided =
        fixture.bind(
            options,
            inventory,
            new ElisionDecision(Set.of(), Set.of(coordinate(VERSION)), Map.of(), Map.of(), 0L));

    assertAll(
        "operation identity records the action for unchanged inventory",
        () -> assertThat(retained.inventoryFingerprint()).isEqualTo(elided.inventoryFingerprint()),
        () ->
            assertThat(retained.operationFingerprint())
                .isNotEqualTo(elided.operationFingerprint()));
  }

  @Test
  void analysisOptionsFreezeConfiguredPolicyLists() throws Exception {
    final Fixture fixture = fixture(true, JAR_BYTES);
    final ElisionAnalysisModel.AnalysisOptions base = fixture.options();
    final List<String> retained = new ArrayList<>(List.of(LIBRARY_IDENTITY));
    final List<String> banished = new ArrayList<>(List.of(" fixture : other "));
    final ElisionAnalysisModel.AnalysisOptions options =
        new ElisionAnalysisModel.AnalysisOptions(
            base.traceFiles(),
            retained,
            banished,
            base.productionOutput(),
            base.session(),
            base.completeness(),
            base.trim(),
            base.dynamicRoots());
    retained.add("fixture:later");
    banished.add("fixture:later");

    assertAll(
        "prepared policy options are immutable and normalize to canonical identities",
        () -> assertThat(options.retainedArtifacts()).containsExactly(LIBRARY_IDENTITY),
        () -> assertThat(options.banishedDependencies()).containsExactly(" fixture : other "),
        () -> {
          final MavenElisionPolicyIdentity.Options normalized =
              MavenElisionPolicyIdentity.normalize(options);
          assertAll(
              "normalization produces canonical policy values",
              () ->
                  assertThat(normalized.retainedArtifacts())
                      .containsExactly("fixture:library::jar:"),
              () -> assertThat(normalized.banishedDependencies()).containsExactly("fixture:other"));
        });
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

  private static ElisionAnalysisModel.AnalysisOptions withBans(
      final ElisionAnalysisModel.AnalysisOptions options, final List<String> bans) {
    return new ElisionAnalysisModel.AnalysisOptions(
        options.traceFiles(),
        options.retainedArtifacts(),
        bans,
        options.productionOutput(),
        options.session(),
        options.completeness(),
        options.trim(),
        options.dynamicRoots());
  }

  private static ElisionAnalysisModel.AnalysisOptions withRetention(
      final ElisionAnalysisModel.AnalysisOptions options, final List<String> retainedArtifacts) {
    return new ElisionAnalysisModel.AnalysisOptions(
        options.traceFiles(),
        retainedArtifacts,
        options.banishedDependencies(),
        options.productionOutput(),
        options.session(),
        options.completeness(),
        options.trim(),
        options.dynamicRoots());
  }
}
