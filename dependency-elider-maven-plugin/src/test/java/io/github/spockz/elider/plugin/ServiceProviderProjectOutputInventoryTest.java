/* WHY: Proves retained application classes participate in descriptor provider ownership. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ArtifactFileRef;
import io.github.spockz.elider.plugin.ServiceProviderTrimInventory.ServiceProviderInventory;
import io.github.spockz.elider.plugin.TrimGenerationPublisher.EffectiveOutputPlan;
import io.github.spockz.elider.scanner.ArtifactClassIndex;
import io.github.spockz.elider.trimmer.DependencyJarTrimmer.TrimAnalysis;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** Checks provider ownership against compiled application output. */
final class ServiceProviderProjectOutputInventoryTest
    extends MavenDependencyTrimmerInMemoryClosureSupport {
  /** Entry class retained from the candidate artifact. */
  private static final String ENTRY_CLASS = "closure.a.Entry";

  /** Provider duplicated by application output and a dependency. */
  private static final String DUPLICATE_PROVIDER = "closure.a.Extra";

  @SuppressWarnings("PMD.UnnecessaryConstructor")
  /* default */ ServiceProviderProjectOutputInventoryTest() {
    super();
  }

  @Test
  void projectOutputProviderKeepsDescriptorDeclarationWhenDependencyCopyIsPruned()
      throws Exception {
    final Fixture fixture = fixtureWithDuplicateAndUnusedSecond();
    final Path trace = temporaryDirectory.resolve("project-output-provider.lst");
    Files.writeString(trace, "closure/a/Entry\n");
    final Path classes = temporaryDirectory.resolve("classes");
    final ElisionAnalysisModel.PreparedAnalysis prepared =
        new MavenElisionService()
            .prepare(
                fixture.projectValue(),
                MavenElisionServiceEffectiveAnalysisFixtures.options(
                    List.of(trace.toFile()), classes.toFile(), true));
    final ArtifactClassIndex index = prepared.index();
    final Map<ArtifactFileRef, Set<String>> classesByArtifact = index.classesByArtifact();
    final ElisionAnalysisModel.ArtifactSnapshot candidateSnapshot =
        prepared.resolvedSnapshots().stream()
            .filter(snapshot -> "a".equals(snapshot.coordinate().artifactId()))
            .findFirst()
            .orElseThrow();
    final Set<ArtifactCoordinate> retained = Set.of(candidateSnapshot.coordinate());
    final Set<String> candidateClasses =
        classesByArtifact.entrySet().stream()
            .filter(entry -> entry.getKey().coordinate().equals(candidateSnapshot.coordinate()))
            .map(Map.Entry::getValue)
            .findFirst()
            .orElseThrow();
    final TrimCandidate candidate =
        new TrimCandidate(
            candidateSnapshot,
            candidateClasses,
            Set.of(ENTRY_CLASS),
            Path.of("candidate-trimmed.jar"),
            false,
            candidateClasses.size(),
            Set.of());
    candidate.analysis(
        new TrimAnalysis(candidateClasses.size(), Set.of(ENTRY_CLASS), Set.of(ENTRY_CLASS)));
    final ServiceProviderInventory inventory =
        ServiceProviderTrimInventory.serviceProviderInventory(
            new EffectiveOutputPlan(
                prepared,
                new TrimAnalysisResult(
                    Map.of(), Map.of(), Set.of(), 0, 11, 25, List.of(), List.of(11, 17), Map.of()),
                Map.of(),
                Set.of(),
                retained,
                "inventory",
                "direct",
                "operation",
                "production",
                Set.of(),
                List.of(),
                List.of(),
                false,
                false,
                MavenDependencyTrimmer.MRJAR_VERTICAL_SHADING,
                false),
            List.of(candidate));

    assertAll(
        "application output keeps a provider declaration even when its dependency copy is pruned",
        () -> assertThat(prepared.projectOutputClasses()).contains(DUPLICATE_PROVIDER),
        () -> assertThat(inventory.ownedClasses()).contains(DUPLICATE_PROVIDER),
        () -> assertThat(inventory.retainedClasses()).contains(DUPLICATE_PROVIDER));
  }
}
