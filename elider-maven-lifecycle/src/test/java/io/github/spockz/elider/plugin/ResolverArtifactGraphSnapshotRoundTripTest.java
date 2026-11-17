/* WHY: Verifies nullable graph values survive the detached session store round trip. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import org.eclipse.aether.graph.DependencyNode;
import org.junit.jupiter.api.Test;

/** Covers supported null root and dependency optionality values through the store. */
final class ResolverArtifactGraphSnapshotRoundTripTest {
  /** Creates the round-trip test fixture. */
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  ResolverArtifactGraphSnapshotRoundTripTest() {
    super();
  }

  @Test
  void roundTripsNullRoot() {
    final ResolverArtifactGraphSnapshot snapshot =
        ResolverArtifactGraphSnapshot.capture(
            null, ResolverArtifactGraphSnapshotStoreTestSupport.PROJECT_KEY, false, null, 0, 1);
    final ResolverArtifactGraphSnapshotStore store =
        ResolverArtifactGraphSnapshotStore.empty().append(snapshot);
    final Map<String, Object> restored =
        ResolverArtifactGraphSnapshotStore.fromPayload(store.toPayload())
            .snapshots()
            .get(ResolverArtifactGraphSnapshotStoreTestSupport.PROJECT_KEY)
            .getFirst();

    assertThat(restored)
        .containsEntry(ResolverArtifactGraphSnapshotSchema.ROOT_NODE_ID, null)
        .containsEntry(ResolverArtifactGraphSnapshotSchema.NODES, List.of())
        .containsEntry(ResolverArtifactGraphSnapshotSchema.EDGES, List.of());
  }

  @Test
  void roundTripsNullableDependencyOptionality() {
    final DependencyNode root = ResolverArtifactGraphSnapshotStoreTestSupport.node("root");
    root.setChildren(
        List.of(
            ResolverArtifactGraphSnapshotStoreTestSupport.dependencyNode("nullable", null),
            ResolverArtifactGraphSnapshotStoreTestSupport.dependencyNode("false", false),
            ResolverArtifactGraphSnapshotStoreTestSupport.dependencyNode("true", true)));
    final ResolverArtifactGraphSnapshot snapshot =
        ResolverArtifactGraphSnapshot.capture(
            root, ResolverArtifactGraphSnapshotStoreTestSupport.PROJECT_KEY, false, null, 0, 1);
    final ResolverArtifactGraphSnapshotStore store =
        ResolverArtifactGraphSnapshotStore.empty().append(snapshot);
    final List<?> nodes =
        (List<?>)
            ResolverArtifactGraphSnapshotStore.fromPayload(store.toPayload())
                .snapshots()
                .get(ResolverArtifactGraphSnapshotStoreTestSupport.PROJECT_KEY)
                .getFirst()
                .get(ResolverArtifactGraphSnapshotSchema.NODES);
    final List<Boolean> optionalities =
        nodes.stream()
            .skip(1)
            .map(ResolverArtifactGraphSnapshotRoundTripTest::optionality)
            .toList();

    assertThat(optionalities).containsExactly((Boolean) null, false, true);
  }

  private static Boolean optionality(final Object nodeValue) {
    final Map<?, ?> node = (Map<?, ?>) nodeValue;
    final Map<?, ?> dependency =
        (Map<?, ?>) node.get(ResolverArtifactGraphSnapshotSchema.DEPENDENCY);
    return (Boolean) dependency.get(ResolverArtifactGraphSnapshotSchema.OPTIONAL);
  }
}
