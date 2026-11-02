// WHY: Binds Analyze identity to both request-local Resolver graph topologies.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.spockz.elider.model.ElisionDecision;
import io.github.spockz.elider.model.TraceData;
import io.github.spockz.elider.plugin.AnalyzePrediction.Provenance;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.ArtifactSnapshot;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.ArtifactViews;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.maven.plugin.MojoFailureException;
import org.junit.jupiter.api.Test;

/** Tests graph fingerprints. JUnit uses its implicit constructor. */
@SuppressWarnings("PMD.AtLeastOneConstructor")
final class MavenAnalysisGraphPairFingerprintTest extends MavenElisionGraphBindingTestSupport {
  @Test
  void edgeTopologyChangesRequestLocalPairFingerprint() {
    final ResolverArtifactGraphCapturePair noEdge = pair(List.of());
    final ResolverArtifactGraphCapturePair withEdge =
        pair(List.of(Map.of("parentNodeId", "n0", "childNodeId", "n1")));

    assertThat(MavenAnalysisResolutionContext.graphPairFingerprint(noEdge))
        .isNotEqualTo(MavenAnalysisResolutionContext.graphPairFingerprint(withEdge));
  }

  @Test
  void edgeTopologyChangesBoundOperationFingerprint() throws IOException, MojoFailureException {
    final Fixture fixture = fixture(true, "artifact bytes");
    final Object payload =
        fixture.sessionValue(EliderMediatedGraphCaptureDecorator.SESSION_DATA_KEY);
    final String key = projectKey(fixture.project());
    final ResolverArtifactGraphCapturePair original =
        ResolverArtifactGraphCapturePair.fromPayload(
            ResolverArtifactGraphSnapshotStore.fromPayload(payload)
                .capturePairs()
                .get(key)
                .getFirst());
    final List<Map<String, Object>> duplicateEdges =
        new java.util.ArrayList<>(original.after().edges());
    duplicateEdges.add(original.after().edges().getFirst());
    final ResolverArtifactGraphCapturePair changedTopology =
        new ResolverArtifactGraphCapturePair(
            original.projectKey(),
            "different-topology-token",
            original.captureGeneration(),
            original.planPresent(),
            original.planFingerprint(),
            original.planGeneration(),
            original.before(),
            snapshotWithEdges(original.after(), duplicateEdges));

    final MavenElisionGraphBinding.Result baseline = bind(fixture, original);
    final MavenElisionGraphBinding.Result changed = bind(fixture, changedTopology);

    assertThat(changed.operationFingerprint()).isNotEqualTo(baseline.operationFingerprint());
  }

  private MavenElisionGraphBinding.Result bind(
      final Fixture fixture, final ResolverArtifactGraphCapturePair pair)
      throws IOException, MojoFailureException {
    final ArtifactSnapshot snapshot = fixture.snapshot();
    final MavenAnalysisResolutionContext context =
        new MavenAnalysisResolutionContext(
            fixture.project(),
            new org.apache.maven.project.MavenProject(fixture.project()),
            Provenance.CAPTURED_EFFECTIVE_RESOLVER,
            new AnalysisEnvironment(
                Map.of(),
                Map.of(),
                temporaryDirectory,
                AnalysisEnvironment.JdkToolchainState.UNSELECTED,
                null),
            new ArtifactViews(List.of(snapshot), true, List.of(snapshot)),
            ResolvedArtifactInventoryFingerprint.fingerprint(List.of(snapshot)),
            ResolvedArtifactInventoryFingerprint.fingerprint(List.of(snapshot)),
            pair);
    final ElisionDecision decision =
        new ElisionDecision(Set.of(snapshot.coordinate()), Set.of(), Map.of(), Map.of(), 0L);
    return MavenElisionGraphBinding.bind(
        fixture.project(),
        fixture.options(),
        context,
        decision,
        TraceData.of(Set.of("fixture.Keep")),
        Set.of("fixture.Keep"),
        List.of(),
        MavenElisionPolicyIdentity.normalize(fixture.options()));
  }

  private static ResolverArtifactGraphSnapshot snapshotWithEdges(
      final ResolverArtifactGraphSnapshot source, final List<Map<String, Object>> edges) {
    return new ResolverArtifactGraphSnapshot(
        ResolverArtifactGraphSnapshot.structuralFingerprint(
            source.rootNodeId(), source.nodes(), edges),
        source.projectKey(),
        source.planPresent(),
        source.planFingerprint(),
        source.planGeneration(),
        source.captureGeneration(),
        source.rootNodeId(),
        source.nodes(),
        edges);
  }

  private static ResolverArtifactGraphCapturePair pair(final List<Map<String, Object>> edges) {
    final String projectKey = "org.example:consumer:1:/tmp/consumer";
    final List<Map<String, Object>> nodes =
        List.of(
            Map.of("nodeId", "n0", "coordinate", "root", "scope", "compile"),
            Map.of("nodeId", "n1", "coordinate", "org.example:lib:1", "scope", "compile"));
    final ResolverArtifactGraphSnapshot before = snapshot(projectKey, nodes, List.of());
    final ResolverArtifactGraphSnapshot after = snapshot(projectKey, nodes, edges);
    return new ResolverArtifactGraphCapturePair(
        projectKey, "capture-token", 1L, false, null, 0L, before, after);
  }

  private static ResolverArtifactGraphSnapshot snapshot(
      final String projectKey,
      final List<Map<String, Object>> nodes,
      final List<Map<String, Object>> edges) {
    return new ResolverArtifactGraphSnapshot(
        ResolverArtifactGraphSnapshot.structuralFingerprint("n0", nodes, edges),
        projectKey,
        false,
        null,
        0L,
        1L,
        "n0",
        nodes,
        edges);
  }
}
