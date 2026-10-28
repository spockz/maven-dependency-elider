/* WHY: Isolates production-bytecode owner promotion from resolver graph ancestry. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import org.junit.jupiter.api.Test;

/** Verifies graph-independent production-bytecode owner promotion. */
final class MavenElisionServiceProductionRootTest
    extends MavenDependencyTrimmerInMemoryClosureSupport {
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
    final MavenElisionService.PreparedAnalysis withoutProductionOutput =
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
    final MavenElisionService.EffectiveAnalysis withoutProductionResult =
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
    final MavenElisionService.PreparedAnalysis raw =
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

    final MavenElisionService.EffectiveAnalysis result =
        service.finishAnalysis(
            MavenElisionServiceEffectiveAnalysisFixtures.withBinding(raw, binding));

    assertThat(result.effectiveDecision().retainedArtifacts()).contains(fixture.coordinate("e"));
    assertThat(result.effectiveDecision().elidedArtifacts())
        .doesNotContain(fixture.coordinate("e"));
    assertThat(result.trimAnalysis().reachableArtifacts()).isEmpty();
  }
}
