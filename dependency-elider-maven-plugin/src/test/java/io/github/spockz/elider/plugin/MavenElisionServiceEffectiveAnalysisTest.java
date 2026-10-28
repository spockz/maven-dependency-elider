/* WHY: Verifies service graph/bytecode fixed points without publishing artifacts. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.TraceData;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.plugin.MojoFailureException;
import org.junit.jupiter.api.Test;

/** Verifies service-level analysis preparation and fixed-point closure. */
@SuppressWarnings({"PMD.UnitTestContainsTooManyAsserts"})
final class MavenElisionServiceEffectiveAnalysisTest
    extends MavenDependencyTrimmerInMemoryClosureSupport {
  /** Entry root shared by traced fixed-point scenarios. */
  private static final String ENTRY_CLASS = "closure.a.Entry";

  /** Rule key for shared package-visible test helpers. */
  private static final String ACCESS_MODIFIER_SUPPRESSION = "PMD.CommentDefaultAccessModifier";

  /** Creates this focused behavior test group. */
  @SuppressWarnings(ACCESS_MODIFIER_SUPPRESSION)
  MavenElisionServiceEffectiveAnalysisTest() {
    super();
  }

  @Test
  void metadataRootsRetainDeclaringAndProviderArtifactsWithoutJarTrimming() throws Exception {
    final Fixture fixture = fixture(false, true);
    fixture.artifacts().getFirst().setScope("runtime");
    final Path trace = temporaryDirectory.resolve("metadata-without-trim.lst");
    Files.writeString(trace, "closure/c/Leaf\n");
    final MavenElisionService service = new MavenElisionService();
    final MavenElisionService.PreparedAnalysis prepared =
        service.prepare(
            fixture.mavenProject(),
            MavenElisionServiceEffectiveAnalysisFixtures.options(
                List.of(trace.toFile()), null, false));
    assertThat(prepared.dynamicRootInputs().classNames()).contains(ENTRY_CLASS, "closure.b.Middle");
    assertThat(prepared.pruningRequiredClasses()).contains("closure.b.Middle");
    final MavenElisionService.Analysis analysis = service.finish(prepared);
    final ArtifactCoordinate artifactA =
        MavenElisionServiceEffectiveAnalysisFixtures.coordinate(analysis.resolvedSnapshots(), "a");
    final ArtifactCoordinate artifactB =
        MavenElisionServiceEffectiveAnalysisFixtures.coordinate(analysis.resolvedSnapshots(), "b");
    final ArtifactCoordinate artifactC =
        MavenElisionServiceEffectiveAnalysisFixtures.coordinate(analysis.resolvedSnapshots(), "c");

    assertThat(analysis.decision().retainedArtifacts()).contains(artifactA, artifactB, artifactC);
    assertThat(analysis.decision().elidedArtifacts()).doesNotContain(artifactA, artifactB);
  }

  @Test
  void serviceAlternatesBytecodePromotionWithGraphAncestorClosure() throws Exception {
    final Fixture fixture = fixture(false);
    final Path trace = temporaryDirectory.resolve("runtime.lst");
    Files.writeString(trace, ENTRY_CLASS.replace('.', '/') + "\n");
    final MavenElisionService service = new MavenElisionService();
    final MavenElisionService.AnalysisOptions options =
        new MavenElisionService.AnalysisOptions(
            List.of(trace.toFile()),
            List.of(),
            null,
            null,
            false,
            true,
            List.of(),
            false,
            List.of(),
            false,
            true);
    final MavenElisionService.PreparedAnalysis raw =
        service.prepare(fixture.mavenProject(), options);
    assertThat(raw.rawDecision().elidedArtifacts())
        .contains(
            fixture.coordinate("b"),
            fixture.coordinate("c"),
            fixture.coordinate("d"),
            fixture.coordinate("e"));
    final ResolverArtifactGraphCapturePair pair =
        MavenElisionServiceEffectiveAnalysisFixtures.graphPair(fixture);
    final EffectiveGraphPolicy.Evaluation initialPolicy =
        EffectiveGraphPolicy.evaluatePair(pair, raw.rawDecision());
    final MavenElisionGraphBinding.Result binding =
        new MavenElisionGraphBinding.Result(
            initialPolicy,
            raw.graphBinding().inventoryFingerprint(),
            raw.graphBinding().operationFingerprint(),
            pair);
    final MavenElisionService.PreparedAnalysis prepared =
        MavenElisionServiceEffectiveAnalysisFixtures.withBinding(raw, binding);
    final Set<Artifact> beforeArtifacts =
        new LinkedHashSet<>(fixture.mavenProject().getArtifacts());
    final MavenElisionService.EffectiveAnalysis result = service.finishAnalysis(prepared);

    assertThat(result.rawDecision().elidedArtifacts())
        .contains(
            fixture.coordinate("b"),
            fixture.coordinate("c"),
            fixture.coordinate("d"),
            fixture.coordinate("e"));
    assertThat(result.effectiveDecision().elidedArtifacts()).isEmpty();
    assertThat(result.effectiveDecision().retainedArtifacts())
        .containsExactlyInAnyOrderElementsOf(
            fixture.allSnapshots().stream()
                .map(MavenElisionService.ArtifactSnapshot::coordinate)
                .toList());
    assertThat(result.graphEvaluation().ancestorPromotedArtifacts())
        .contains(fixture.coordinate("d"));
    assertThat(result.trimAnalysis().reachableArtifacts()).isEmpty();
    assertThat(result.trimAnalysis().candidateRoots().get(fixture.coordinate("a")))
        .contains(ENTRY_CLASS);
    assertThat(result.trimAnalysis().candidateAnalyses().get(fixture.coordinate("a")).roots())
        .contains(ENTRY_CLASS.replace('.', '/'));
    assertThat(fixture.mavenProject().getArtifacts())
        .containsExactlyInAnyOrderElementsOf(beforeArtifacts);
    assertThat(temporaryDirectory.resolve("build/elided-artifacts")).doesNotExist();
  }

  @Test
  void retainedServiceRootPreservesItsProviderWithoutJarTrimming() throws Exception {
    final Fixture fixture = fixture(false, true);
    final Path trace = temporaryDirectory.resolve("service-runtime.lst");
    Files.writeString(trace, ENTRY_CLASS.replace('.', '/') + "\n");
    final MavenElisionService service = new MavenElisionService();
    final MavenElisionService.AnalysisOptions options =
        new MavenElisionService.AnalysisOptions(
            List.of(trace.toFile()),
            List.of(),
            null,
            null,
            false,
            false,
            List.of(),
            false,
            List.of(),
            false,
            true);
    final MavenElisionService.PreparedAnalysis raw =
        service.prepare(fixture.mavenProject(), options);
    assertThat(raw.dynamicRootInputs().classNames()).contains(ENTRY_CLASS, "closure.b.Middle");
    assertThat(raw.rawDecision().retainedArtifacts()).contains(fixture.coordinate("a"));
    assertThat(raw.rawDecision().retainedArtifacts()).contains(fixture.coordinate("b"));
    final ResolverArtifactGraphCapturePair pair =
        MavenElisionServiceEffectiveAnalysisFixtures.graphPair(fixture);
    assertThat(MavenElisionGraphInventory.matchesGraph(pair.after(), raw.resolvedSnapshots()))
        .isTrue();
    final EffectiveGraphPolicy.Evaluation initialPolicy =
        EffectiveGraphPolicy.evaluatePair(pair, raw.rawDecision());
    final MavenElisionGraphBinding.Result binding =
        new MavenElisionGraphBinding.Result(
            initialPolicy,
            raw.graphBinding().inventoryFingerprint(),
            raw.graphBinding().operationFingerprint(),
            pair);

    final MavenElisionService.EffectiveAnalysis result =
        service.finishAnalysis(
            MavenElisionServiceEffectiveAnalysisFixtures.withBinding(raw, binding));

    assertThat(raw.rawDecision().elidedArtifacts()).doesNotContain(fixture.coordinate("b"));
    assertThat(result.effectiveDecision().retainedArtifacts()).contains(fixture.coordinate("b"));
    assertThat(result.effectiveDecision().elidedArtifacts()).isEmpty();
    assertThat(temporaryDirectory.resolve("build/elided-artifacts")).doesNotExist();
  }

  @Test
  void unknownSourceRootFailsClosedWhileTraceOnlyApplicationRootsAreTolerated() throws Exception {
    final Fixture fixture = fixture(false);
    final Set<ArtifactCoordinate> retained =
        fixture.allSnapshots().stream()
            .map(MavenElisionService.ArtifactSnapshot::coordinate)
            .collect(java.util.stream.Collectors.toSet());
    final MavenDependencyTrimmer.TrimRequest request =
        new MavenDependencyTrimmer.TrimRequest(
            fixture.mavenProject(),
            null,
            fixture.allSnapshots(),
            fixture.scanInputs,
            retained,
            TraceData.of(Set.of("sample.App")),
            Set.of("missing.RequiredApi"),
            Set.of(),
            Set.of(),
            List.of(),
            false,
            List.of(),
            false);

    assertThatThrownBy(
            () -> MavenDependencyTrimmer.analyzeInMemory(request, java.util.Map.of(), Set.of()))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Required class root has no recognized owner: missing.RequiredApi");
  }

  @Test
  void sourceDefinedTypesAreRecognizedWithoutProductionOutput() throws Exception {
    final Fixture fixture = fixture(false);
    final Path sourceRoot =
        Files.createDirectories(temporaryDirectory.resolve("source-provenance"));
    Files.writeString(
        sourceRoot.resolve("App.java"),
        "package sample; public class App { private Helper helper; }\n");
    Files.writeString(
        sourceRoot.resolve("Helper.java"), "package sample; public class Helper {}\n");
    fixture.mavenProject().addCompileSourceRoot(sourceRoot.toString());
    final Path trace = temporaryDirectory.resolve("source-provenance.lst");
    Files.writeString(trace, "sample.App\n" + ENTRY_CLASS.replace('.', '/') + "\n");
    final MavenElisionService service = new MavenElisionService();
    final MavenElisionService.AnalysisOptions options =
        new MavenElisionService.AnalysisOptions(
            List.of(trace.toFile()),
            List.of(),
            null,
            null,
            true,
            false,
            List.of(),
            false,
            List.of(),
            false,
            true);

    final MavenElisionService.PreparedAnalysis prepared =
        service.prepare(fixture.mavenProject(), options);
    final MavenElisionService.EffectiveAnalysis effective = service.finishAnalysis(prepared);

    assertThat(prepared.projectOutputClasses()).contains("sample.App", "sample.Helper");
    assertThat(effective.effectiveDecision().elidedArtifacts()).isEmpty();
  }

  @Test
  void unknownDynamicOwnerUsesConservativeWholeInventoryRetention() throws Exception {
    final Fixture fixture = fixture(false);
    final Path trace = temporaryDirectory.resolve("unknown-dynamic-root.lst");
    Files.writeString(trace, ENTRY_CLASS.replace('.', '/') + "\n");
    final Path declaringJar = fixture.snapshot("a").filePath();
    final MavenElisionService service = new MavenElisionService();
    final MavenElisionService.PreparedAnalysis prepared =
        service.prepare(
            fixture.mavenProject(),
            MavenElisionServiceEffectiveAnalysisFixtures.options(
                List.of(trace.toFile()), null, false),
            path ->
                new DependencyDynamicRoots.RootScan(
                    path.equals(declaringJar) ? Set.of("optional.unresolved.Api") : Set.of(),
                    true));

    final MavenElisionService.EffectiveAnalysis effective = service.finishAnalysis(prepared);

    assertThat(prepared.rawDecision().retainedArtifacts())
        .containsExactlyInAnyOrderElementsOf(
            fixture.allSnapshots().stream()
                .map(MavenElisionService.ArtifactSnapshot::coordinate)
                .toList());
    assertThat(effective.effectiveDecision().elidedArtifacts()).isEmpty();
  }

  @Test
  void providedAndSystemScopeJarsRemainUnchangedAnalysisLibraries() throws Exception {
    final Fixture fixture = fixture(false);
    final Artifact providedArtifact =
        fixture.artifacts().stream()
            .filter(artifact -> "b".equals(artifact.getArtifactId()))
            .findFirst()
            .orElseThrow();
    assertScopeRemainsUnchangedLibrary(fixture, providedArtifact, "provided");
    assertScopeRemainsUnchangedLibrary(fixture, providedArtifact, "system");
  }

  private void assertScopeRemainsUnchangedLibrary(
      final Fixture fixture, final Artifact providedArtifact, final String scope)
      throws IOException, MojoFailureException {
    providedArtifact.setScope(scope);
    final ArtifactCoordinate unchangedCoordinate =
        new ArtifactCoordinate("fixture", "b", "1.0", "jar", "", scope);
    final List<MavenElisionService.ArtifactSnapshot> inventory =
        fixture.allSnapshots().stream()
            .map(
                snapshot ->
                    "b".equals(snapshot.coordinate().artifactId())
                        ? new MavenElisionService.ArtifactSnapshot(
                            providedArtifact, unchangedCoordinate, snapshot.filePath())
                        : snapshot)
            .toList();
    final Set<ArtifactCoordinate> retained =
        inventory.stream()
            .map(MavenElisionService.ArtifactSnapshot::coordinate)
            .collect(java.util.stream.Collectors.toSet());
    final MavenDependencyTrimmer.TrimRequest request =
        new MavenDependencyTrimmer.TrimRequest(
            fixture.mavenProject(),
            null,
            inventory,
            fixture.scanInputs,
            retained,
            TraceData.of(Set.of(ENTRY_CLASS)),
            Set.of(),
            Set.of(),
            Set.of(),
            List.of(),
            false,
            List.of(),
            false);

    final MavenDependencyTrimmer.InMemoryAnalysis analysis =
        MavenDependencyTrimmer.analyzeInMemory(request, java.util.Map.of(), Set.of());

    assertThat(analysis.candidateAnalyses()).doesNotContainKey(unchangedCoordinate);
    assertThat(analysis.candidateRoots().get(fixture.coordinate("c"))).contains("closure.c.Leaf");
  }
}
