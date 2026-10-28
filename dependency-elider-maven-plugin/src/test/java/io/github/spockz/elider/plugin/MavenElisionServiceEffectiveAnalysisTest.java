/* WHY: Verifies service graph/bytecode fixed points without publishing artifacts. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.project.MavenProject;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.eclipse.aether.graph.DefaultDependencyNode;
import org.eclipse.aether.graph.Dependency;
import org.eclipse.aether.graph.DependencyNode;
import org.junit.jupiter.api.Test;

/** Verifies service-level analysis preparation and fixed-point closure. */
@SuppressWarnings({"PMD.UnitTestContainsTooManyAsserts"})
final class MavenElisionServiceEffectiveAnalysisTest
    extends MavenDependencyTrimmerInMemoryClosureSupport {
  /** Rule key for shared package-visible test helpers. */
  private static final String ACCESS_MODIFIER_SUPPRESSION = "PMD.CommentDefaultAccessModifier";

  /** Scope used for transitive graph fixture nodes. */
  private static final String RUNTIME_SCOPE = "runtime";

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
        service.prepare(fixture.mavenProject(), options(List.of(trace.toFile()), null, false));
    assertThat(prepared.dynamicRootInputs().classNames())
        .contains("closure.a.Entry", "closure.b.Middle");
    assertThat(prepared.pruningRequiredClasses()).contains("closure.b.Middle");
    final MavenElisionService.Analysis analysis = service.finish(prepared);
    final ArtifactCoordinate artifactA = coordinate(analysis.resolvedSnapshots(), "a");
    final ArtifactCoordinate artifactB = coordinate(analysis.resolvedSnapshots(), "b");
    final ArtifactCoordinate artifactC = coordinate(analysis.resolvedSnapshots(), "c");

    assertThat(analysis.decision().retainedArtifacts()).contains(artifactA, artifactB, artifactC);
    assertThat(analysis.decision().elidedArtifacts()).doesNotContain(artifactA, artifactB);
  }

  /** Shared option builder for service behavior tests. */
  @SuppressWarnings(ACCESS_MODIFIER_SUPPRESSION)
  static MavenElisionService.AnalysisOptions options(
      final List<java.io.File> traceFiles,
      final java.io.File productionOutput,
      final boolean trimJars) {
    return new MavenElisionService.AnalysisOptions(
        traceFiles,
        List.of(),
        productionOutput,
        null,
        false,
        trimJars,
        List.of(),
        false,
        List.of(),
        false,
        true);
  }

  @Test
  void serviceAlternatesBytecodePromotionWithGraphAncestorClosure() throws Exception {
    final Fixture fixture = fixture(false);
    final Path trace = temporaryDirectory.resolve("runtime.lst");
    Files.writeString(trace, "closure/a/Entry\n");
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
    final ResolverArtifactGraphCapturePair pair = graphPair(fixture);
    final EffectiveGraphPolicy.Evaluation initialPolicy =
        EffectiveGraphPolicy.evaluatePair(pair, raw.rawDecision());
    final MavenElisionGraphBinding.Result binding =
        new MavenElisionGraphBinding.Result(
            initialPolicy,
            raw.graphBinding().inventoryFingerprint(),
            raw.graphBinding().operationFingerprint(),
            pair);
    final MavenElisionService.PreparedAnalysis prepared = withBinding(raw, binding);
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
        .contains("closure.a.Entry");
    assertThat(result.trimAnalysis().candidateAnalyses().get(fixture.coordinate("a")).roots())
        .contains("closure/a/Entry");
    assertThat(fixture.mavenProject().getArtifacts())
        .containsExactlyInAnyOrderElementsOf(beforeArtifacts);
    assertThat(temporaryDirectory.resolve("build/elided-artifacts")).doesNotExist();
  }

  @Test
  void retainedServiceRootPreservesItsProviderWithoutJarTrimming() throws Exception {
    final Fixture fixture = fixture(false, true);
    final Path trace = temporaryDirectory.resolve("service-runtime.lst");
    Files.writeString(trace, "closure/a/Entry\n");
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
    assertThat(raw.dynamicRootInputs().classNames())
        .contains("closure.a.Entry", "closure.b.Middle");
    assertThat(raw.rawDecision().retainedArtifacts()).contains(fixture.coordinate("a"));
    assertThat(raw.rawDecision().retainedArtifacts()).contains(fixture.coordinate("b"));
    final ResolverArtifactGraphCapturePair pair = graphPair(fixture);
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
        service.finishAnalysis(withBinding(raw, binding));

    assertThat(raw.rawDecision().elidedArtifacts()).doesNotContain(fixture.coordinate("b"));
    assertThat(result.effectiveDecision().retainedArtifacts()).contains(fixture.coordinate("b"));
    assertThat(result.effectiveDecision().elidedArtifacts()).isEmpty();
    assertThat(temporaryDirectory.resolve("build/elided-artifacts")).doesNotExist();
  }

  /** Copies prepared inputs with a fixture graph binding. */
  @SuppressWarnings(ACCESS_MODIFIER_SUPPRESSION)
  static MavenElisionService.PreparedAnalysis withBinding(
      final MavenElisionService.PreparedAnalysis prepared,
      final MavenElisionGraphBinding.Result binding) {
    return new MavenElisionService.PreparedAnalysis(
        prepared.project(),
        prepared.options(),
        prepared.resolvedSnapshots(),
        prepared.directArtifactsPresent(),
        prepared.directSnapshots(),
        prepared.rawDecision(),
        prepared.classUsageReport(),
        prepared.bytecodeScan(),
        prepared.scanCandidates(),
        prepared.trace(),
        prepared.index(),
        prepared.dynamicRootInputs(),
        prepared.projectOutputClasses(),
        prepared.pruningRequiredClasses(),
        prepared.inputFingerprint(),
        prepared.directInputFingerprint(),
        binding);
  }

  private static ArtifactCoordinate coordinate(
      final List<MavenElisionService.ArtifactSnapshot> snapshots, final String artifactId) {
    return snapshots.stream()
        .map(MavenElisionService.ArtifactSnapshot::coordinate)
        .filter(coordinate -> coordinate.artifactId().equals(artifactId))
        .findFirst()
        .orElseThrow();
  }

  private static ResolverArtifactGraphCapturePair graphPair(final Fixture fixture) {
    return graphPairWithAncestorEdges(fixture, true);
  }

  /** Builds a matching graph with optional ancestor paths for policy tests. */
  @SuppressWarnings(ACCESS_MODIFIER_SUPPRESSION)
  static ResolverArtifactGraphCapturePair graphPairWithAncestorEdges(
      final Fixture fixture, final boolean includeAncestorEdges) {
    final MavenProject project = fixture.mavenProject();
    final String projectKey = MavenElisionGraphBindingTestSupport.projectKey(project);
    final DependencyNode root =
        new DefaultDependencyNode(
            new Dependency(
                new DefaultArtifact("fixture", "consumer", "", "pom", "1.0"), "", false));
    final DependencyNode artifactA = graphNode("a", "compile");
    final DependencyNode artifactC = graphNode("c", RUNTIME_SCOPE);
    final DependencyNode artifactD = graphNode("d", RUNTIME_SCOPE);
    final DependencyNode artifactE = graphNode("e", RUNTIME_SCOPE);
    artifactA.setChildren(includeAncestorEdges ? List.of(node("b")) : List.of());
    artifactD.setChildren(includeAncestorEdges ? List.of(node("b")) : List.of());
    root.setChildren(
        includeAncestorEdges
            ? List.of(artifactA, artifactC, artifactD, artifactE)
            : List.of(artifactA, graphNode("b", RUNTIME_SCOPE), artifactC, artifactD, artifactE));
    return new ResolverArtifactGraphCapturePair(
        projectKey,
        "service-closure-capture",
        1L,
        false,
        null,
        0L,
        ResolverArtifactGraphSnapshot.capture(root, projectKey, false, null, 0L, 1L),
        ResolverArtifactGraphSnapshot.capture(root, projectKey, false, null, 0L, 1L));
  }

  private static DependencyNode node(final String artifactId) {
    final DependencyNode node =
        new DefaultDependencyNode(
            new Dependency(
                new DefaultArtifact("fixture", artifactId, "", "jar", "1.0"),
                RUNTIME_SCOPE,
                false));
    node.setChildren(List.of());
    return node;
  }

  private static DependencyNode graphNode(final String artifactId, final String scope) {
    final DependencyNode node =
        new DefaultDependencyNode(
            new Dependency(
                new DefaultArtifact("fixture", artifactId, "", "jar", "1.0"), scope, false));
    node.setChildren(List.of());
    return node;
  }
}
