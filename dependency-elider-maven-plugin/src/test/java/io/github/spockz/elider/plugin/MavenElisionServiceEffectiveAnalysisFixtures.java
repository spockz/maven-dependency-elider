/* WHY: Shares deterministic graph and prepared-analysis builders across service behavior tests. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.io.File;
import java.util.List;
import org.apache.maven.project.MavenProject;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.eclipse.aether.graph.DefaultDependencyNode;
import org.eclipse.aether.graph.Dependency;
import org.eclipse.aether.graph.DependencyNode;

/** Shared fixture construction for effective graph analysis tests. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class MavenElisionServiceEffectiveAnalysisFixtures {
  /** Scope for fixture edges used to test transitive ancestor closure. */
  private static final String RUNTIME_SCOPE = "runtime";

  private MavenElisionServiceEffectiveAnalysisFixtures() {}

  static MavenElisionService.AnalysisOptions options(
      final List<File> traceFiles, final File productionOutput, final boolean trimJars) {
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
        prepared.sourceRequiredClasses(),
        prepared.pruningRequiredClasses(),
        prepared.productionOutputFingerprint(),
        prepared.inputFingerprint(),
        prepared.directInputFingerprint(),
        binding);
  }

  static ArtifactCoordinate coordinate(
      final List<MavenElisionService.ArtifactSnapshot> snapshots, final String artifactId) {
    return snapshots.stream()
        .map(MavenElisionService.ArtifactSnapshot::coordinate)
        .filter(coordinate -> coordinate.artifactId().equals(artifactId))
        .findFirst()
        .orElseThrow();
  }

  static ResolverArtifactGraphCapturePair graphPair(
      final MavenDependencyTrimmerInMemoryClosureSupport.Fixture fixture) {
    return graphPairWithAncestorEdges(fixture, true);
  }

  static ResolverArtifactGraphCapturePair graphPairWithAncestorEdges(
      final MavenDependencyTrimmerInMemoryClosureSupport.Fixture fixture,
      final boolean includeAncestorEdges) {
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
