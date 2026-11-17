// WHY: Proves resolver projection follows exact node identities, shared edges, and winner refs.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.eclipse.aether.graph.DefaultDependencyNode;
import org.eclipse.aether.graph.DependencyNode;
import org.eclipse.aether.util.graph.transformer.ConflictResolver;
import org.junit.jupiter.api.Test;

/** Verifies projection output for occurrence-sensitive graph shapes. */
final class ResolverArtifactGraphProjectionBehaviorTest {
  /** Stable project identity for detached graph fingerprints. */
  private static final String PROJECT_KEY = "fixture:consumer:1.0:/tmp/fixture";

  /** Creates the resolver graph fixture. */
  @SuppressWarnings({"PMD.UncommentedEmptyConstructor", "PMD.CommentDefaultAccessModifier"})
  ResolverArtifactGraphProjectionBehaviorTest() {}

  @Test
  @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
  // Both assertions prove the chosen occurrence alone was removed.
  void equalCoordinateOccurrencesRemoveOnlyTheSelectedNodeIdentity() {
    final DependencyNode root = node("consumer");
    final DependencyNode firstDrop = node("duplicate");
    final DependencyNode secondOccurrence = node("duplicate");
    final DependencyNode keep = node("keep");
    root.setChildren(List.of(firstDrop, secondOccurrence, keep));
    final ResolverArtifactGraphProjection projection = projection(root, "n1");

    ResolverArtifactGraphProjection.apply(root, projection);

    assertThat(root.getChildren()).containsExactly(secondOccurrence, keep);
    assertThat(root.getChildren()).doesNotContain(firstDrop);
  }

  @Test
  @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
  // Checks a shared descendant remains reachable from its other parent.
  void sharedDescendantRemainsReachableThroughItsOtherParent() {
    final DependencyNode root = node("consumer");
    final DependencyNode removedBranch = node("removed-parent");
    final DependencyNode retainedBranch = node("retained-parent");
    final DependencyNode shared = node("shared");
    removedBranch.setChildren(List.of(shared));
    retainedBranch.setChildren(List.of(shared));
    root.setChildren(List.of(removedBranch, retainedBranch));
    final ResolverArtifactGraphProjection projection = projection(root, "n1");

    ResolverArtifactGraphProjection.apply(root, projection);

    assertThat(root.getChildren()).containsExactly(retainedBranch);
    assertThat(retainedBranch.getChildren()).containsExactly(shared);
  }

  @Test
  @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
  // The assertions verify winner metadata survives projection and is remapped.
  void externalConflictWinnerReferenceIsRemappedWithTheProjectedNodes() {
    final DependencyNode root = node("consumer");
    final DependencyNode drop = node("drop");
    final DependencyNode selected = node("selected");
    final DependencyNode winner = node("winner");
    selected.setData(ConflictResolver.NODE_DATA_WINNER, winner);
    root.setChildren(List.of(drop, selected));
    final ResolverArtifactGraphProjection projection = projection(root, "n1");

    ResolverArtifactGraphProjection.apply(root, projection);

    assertThat(root.getChildren()).containsExactly(selected);
    final ResolverArtifactGraphSnapshot projected =
        ResolverArtifactGraphSnapshot.capture(root, PROJECT_KEY, false, null, 0L, 1L);
    final Map<String, Object> selectedPayload =
        projected.nodes().stream()
            .filter(node -> "selected".equals(artifactId(node)))
            .findFirst()
            .orElseThrow();
    final Map<String, Object> winnerPayload =
        projected.nodes().stream()
            .filter(node -> "winner".equals(artifactId(node)))
            .findFirst()
            .orElseThrow();
    assertThat(selectedPayload.get("conflictWinnerNodeId")).isEqualTo(winnerPayload.get("id"));
    assertThat(winnerPayload.get("reachable")).isEqualTo(false);
  }

  private static ResolverArtifactGraphProjection projection(
      final DependencyNode root, final String removedNodeId) {
    final ResolverArtifactGraphSnapshot before =
        ResolverArtifactGraphSnapshot.capture(root, PROJECT_KEY, false, null, 0L, 1L);
    final ResolverArtifactGraphSnapshot after =
        ResolverArtifactGraphSnapshot.capture(root, PROJECT_KEY, false, null, 0L, 1L);
    final ResolverArtifactGraphCapturePair pair =
        new ResolverArtifactGraphCapturePair(
            PROJECT_KEY, "projection-behavior", 1L, false, null, 0L, before, after);
    return ResolverArtifactGraphProjection.create(
        pair, Map.of(removedNodeId, EffectiveGraphPolicy.NodeDisposition.SAFE_ELIDED));
  }

  private static DependencyNode node(final String artifactId) {
    return new DefaultDependencyNode(new DefaultArtifact("fixture", artifactId, "", "jar", "1.0"));
  }

  private static String artifactId(final Map<String, Object> node) {
    return (String) ((Map<?, ?>) node.get("artifact")).get("artifactId");
  }
}
