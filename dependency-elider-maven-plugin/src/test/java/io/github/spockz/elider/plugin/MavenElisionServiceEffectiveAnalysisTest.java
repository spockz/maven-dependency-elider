/* WHY: Verifies service graph/bytecode fixed points without publishing artifacts. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
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
  /** Scope used for transitive graph fixture nodes. */
  private static final String RUNTIME_SCOPE = "runtime";

  /** Creates this focused behavior test group. */
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  MavenElisionServiceEffectiveAnalysisTest() {
    super();
  }

  @Test
  void rejectsJarMutationDuringDynamicRootScanning() throws Exception {
    final Fixture fixture = fixture(false);
    final Path trace = temporaryDirectory.resolve("scan-mutation.lst");
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

    assertThatThrownBy(
            () ->
                service.prepare(
                    fixture.mavenProject(),
                    options,
                    path -> {
                      if (path.equals(fixture.snapshot("a").filePath())) {
                        Files.writeString(path, "changed while scanning");
                      }
                      return new DependencyDynamicRoots.RootScan(Set.of(), true);
                    }))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("changed after fingerprinting");
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
  void retainedServiceRootPromotesRawDropEvenWhenJarTrimmingIsDisabled() throws Exception {
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
    final ResolverArtifactGraphCapturePair pair = graphPair(fixture);
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

    assertThat(raw.rawDecision().elidedArtifacts()).contains(fixture.coordinate("b"));
    assertThat(result.effectiveDecision().retainedArtifacts()).contains(fixture.coordinate("b"));
    assertThat(result.effectiveDecision().elidedArtifacts()).isEmpty();
    assertThat(temporaryDirectory.resolve("build/elided-artifacts")).doesNotExist();
  }

  private static MavenElisionService.PreparedAnalysis withBinding(
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
        prepared.pruningRequiredClasses(),
        prepared.inputFingerprint(),
        binding);
  }

  private static ResolverArtifactGraphCapturePair graphPair(final Fixture fixture) {
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
    artifactA.setChildren(List.of(node("b")));
    artifactD.setChildren(List.of(node("b")));
    root.setChildren(List.of(artifactA, artifactC, artifactD, artifactE));
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
