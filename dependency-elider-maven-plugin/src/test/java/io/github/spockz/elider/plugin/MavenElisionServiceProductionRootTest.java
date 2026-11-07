/* WHY: Isolates production-bytecode owner promotion from resolver graph ancestry. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import org.junit.jupiter.api.Test;

/** Verifies graph-independent production-bytecode owner promotion. */
final class MavenElisionServiceProductionRootTest
    extends MavenDependencyTrimmerInMemoryClosureSupport {
  /** WHY: The recognized dynamic root is owned by a known candidate archive. */
  private static final String KNOWN_DYNAMIC_ROOT = "closure.b.Middle";

  /** WHY: This external root affects identity, not archive retention. */
  private static final String UNKNOWN_DYNAMIC_ROOT = "external.Optional";

  /** Creates this focused behavior test group. */
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  MavenElisionServiceProductionRootTest() {
    super();
  }

  @Test
  @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
  void productionBytecodeRootPromotesItsRawDroppedArtifactOwner() throws Exception {
    final Fixture fixture = fixture(false);
    final Path trace = temporaryDirectory.resolve("production-root.lst");
    Files.writeString(trace, "closure/a/Entry\n");
    final MavenElisionService service = new MavenElisionService();
    final ResolverArtifactGraphCapturePair pair =
        MavenElisionServiceEffectiveAnalysisFixtures.graphPairWithAncestorEdges(fixture, false);
    final ElisionAnalysisModel.PreparedAnalysis withoutProductionOutput =
        service.prepare(
            fixture.mavenProject(),
            MavenElisionServiceEffectiveAnalysisFixtures.options(
                List.of(trace.toFile()), null, true));
    assertThat(
            MavenElisionGraphInventory.matchesGraph(
                pair.after(), withoutProductionOutput.resolvedSnapshots()))
        .isTrue();
    final EffectiveGraphPolicy.Evaluation withoutProductionPolicy =
        EffectiveGraphPolicy.evaluatePair(pair, withoutProductionOutput.rawDecision());
    assertThat(
            withoutProductionPolicy
                .effectiveDecision(withoutProductionOutput.rawDecision())
                .elidedArtifacts())
        .contains(fixture.coordinate("e"));
    final MavenElisionGraphBinding.Result withoutProductionBinding =
        new MavenElisionGraphBinding.Result(
            withoutProductionPolicy,
            withoutProductionOutput.graphBinding().inventoryFingerprint(),
            withoutProductionOutput.graphBinding().operationFingerprint(),
            pair);
    final ElisionAnalysisModel.EffectiveAnalysis withoutProductionResult =
        service.finishAnalysis(
            MavenElisionServiceEffectiveAnalysisFixtures.withBinding(
                withoutProductionOutput, withoutProductionBinding));
    assertThat(withoutProductionResult.effectiveDecision().elidedArtifacts())
        .contains(fixture.coordinate("e"));

    final Path productionOutput = Files.createDirectories(temporaryDirectory.resolve("production"));
    final Path productionPackage = Files.createDirectories(productionOutput.resolve("closure/d"));
    try (JarFile archive = new JarFile(fixture.snapshot("d").filePath().toFile())) {
      final JarEntry entry = archive.getJarEntry("closure/d/Ancestor.class");
      try (java.io.InputStream input = archive.getInputStream(entry)) {
        Files.copy(input, productionPackage.resolve("Ancestor.class"));
      }
    }
    final ElisionAnalysisModel.PreparedAnalysis raw =
        service.prepare(
            fixture.mavenProject(),
            MavenElisionServiceEffectiveAnalysisFixtures.options(
                List.of(trace.toFile()), productionOutput.toFile(), true));
    assertThat(raw.rawDecision().elidedArtifacts()).contains(fixture.coordinate("e"));
    final EffectiveGraphPolicy.Evaluation initialPolicy =
        EffectiveGraphPolicy.evaluatePair(pair, raw.rawDecision());
    assertThat(initialPolicy.effectiveDecision(raw.rawDecision()).elidedArtifacts())
        .contains(fixture.coordinate("e"));
    final MavenElisionGraphBinding.Result binding =
        new MavenElisionGraphBinding.Result(
            initialPolicy,
            raw.graphBinding().inventoryFingerprint(),
            raw.graphBinding().operationFingerprint(),
            pair);

    final ElisionAnalysisModel.EffectiveAnalysis result =
        service.finishAnalysis(
            MavenElisionServiceEffectiveAnalysisFixtures.withBinding(raw, binding));

    assertThat(result.effectiveDecision().retainedArtifacts()).contains(fixture.coordinate("e"));
    assertThat(result.effectiveDecision().elidedArtifacts())
        .doesNotContain(fixture.coordinate("e"));
    assertThat(result.trimAnalysis().reachableArtifacts()).isEmpty();
  }

  @Test
  void knownDynamicRootDoesNotKeepUnrelatedArchivesForUnknownExternalRoot() throws Exception {
    final Fixture fixture = fixtureWithRuntimeA();
    final Path trace = temporaryDirectory.resolve("dynamic-external-root.lst");
    Files.writeString(trace, "closure/a/Entry\n");
    final Path declaringArchive = fixture.snapshot("a").filePath();
    final MavenElisionService service = new MavenElisionService();
    final ElisionAnalysisModel.AnalysisOptions baseOptions =
        MavenElisionServiceEffectiveAnalysisFixtures.options(List.of(trace.toFile()), null, true);
    final ElisionAnalysisModel.AnalysisOptions options =
        new ElisionAnalysisModel.AnalysisOptions(
            baseOptions.traceFiles(),
            baseOptions.retainedArtifacts(),
            baseOptions.banishedDependencies(),
            baseOptions.productionOutput(),
            baseOptions.session(),
            baseOptions.completeness(),
            baseOptions.trim(),
            baseOptions.dynamicRoots(),
            baseOptions.environment(),
            true);
    final ElisionAnalysisModel.PreparedAnalysis prepared =
        service.prepare(
            fixture.mavenProject(),
            options,
            (path, context) ->
                path.equals(declaringArchive)
                    ? new DependencyDynamicRoots.RootScan(
                        Set.of(KNOWN_DYNAMIC_ROOT, UNKNOWN_DYNAMIC_ROOT), true)
                    : new DependencyDynamicRoots.RootScan(Set.of(), false));
    final ResolverArtifactGraphCapturePair pair =
        MavenElisionServiceEffectiveAnalysisFixtures.graphPairWithAncestorEdges(fixture, false);
    final EffectiveGraphPolicy.Evaluation policy =
        EffectiveGraphPolicy.evaluatePair(pair, prepared.rawDecision());
    final ElisionAnalysisModel.EffectiveAnalysis effective =
        service.finishAnalysis(
            MavenElisionServiceEffectiveAnalysisFixtures.withBinding(
                prepared,
                new MavenElisionGraphBinding.Result(
                    policy,
                    prepared.graphBinding().inventoryFingerprint(),
                    prepared.graphBinding().operationFingerprint(),
                    pair)));
    final ElisionAnalysisModel.PreparedAnalysis knownOnlyPrepared =
        service.prepare(
            fixture.mavenProject(),
            options,
            (path, context) ->
                path.equals(declaringArchive)
                    ? new DependencyDynamicRoots.RootScan(Set.of(KNOWN_DYNAMIC_ROOT), true)
                    : new DependencyDynamicRoots.RootScan(Set.of(), false));
    final EffectiveGraphPolicy.Evaluation knownOnlyPolicy =
        EffectiveGraphPolicy.evaluatePair(pair, knownOnlyPrepared.rawDecision());
    final ElisionAnalysisModel.EffectiveAnalysis knownOnlyEffective =
        service.finishAnalysis(
            MavenElisionServiceEffectiveAnalysisFixtures.withBinding(
                knownOnlyPrepared,
                new MavenElisionGraphBinding.Result(
                    knownOnlyPolicy,
                    knownOnlyPrepared.graphBinding().inventoryFingerprint(),
                    knownOnlyPrepared.graphBinding().operationFingerprint(),
                    pair)));

    assertAll(
        () ->
            assertThat(prepared.policyOptions().runtimePolicy().allowedClasses())
                .contains(KNOWN_DYNAMIC_ROOT, UNKNOWN_DYNAMIC_ROOT),
        () ->
            assertThat(prepared.policyOptions().runtimePolicy().observedClasses())
                .doesNotContain(UNKNOWN_DYNAMIC_ROOT),
        () ->
            assertThat(prepared.graphBinding().operationFingerprint())
                .isNotEqualTo(knownOnlyPrepared.graphBinding().operationFingerprint()),
        () ->
            assertThat(prepared.dynamicRootInputs().classNames())
                .contains(KNOWN_DYNAMIC_ROOT, UNKNOWN_DYNAMIC_ROOT),
        () ->
            assertThat(prepared.rawDecision().retainedArtifacts())
                .contains(fixture.coordinate("a"), fixture.coordinate("b")),
        () ->
            assertThat(prepared.rawDecision().elidedArtifacts())
                .contains(
                    fixture.coordinate("c"), fixture.coordinate("d"), fixture.coordinate("e")),
        () ->
            assertThat(effective.effectiveDecision().elidedArtifacts())
                .contains(
                    fixture.coordinate("c"), fixture.coordinate("d"), fixture.coordinate("e")),
        () ->
            assertThat(effective.effectiveDecision().retainedArtifacts())
                .isEqualTo(knownOnlyEffective.effectiveDecision().retainedArtifacts()),
        () ->
            assertThat(effective.trimAnalysis().candidateRoots())
                .isEqualTo(knownOnlyEffective.trimAnalysis().candidateRoots()));
  }
}
