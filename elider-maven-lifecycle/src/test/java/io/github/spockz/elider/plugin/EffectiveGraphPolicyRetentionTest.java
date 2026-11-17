// WHY: Verifies one cohesive set of conservative effective-graph policy cases.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.util.List;
import java.util.Set;
import org.eclipse.aether.graph.DependencyNode;
import org.junit.jupiter.api.Test;

/** Covers conservative graph retention and whole-identity promotion behavior. */
@SuppressWarnings("PMD.AtLeastOneConstructor")
final class EffectiveGraphPolicyRetentionTest {
  /** Groups graph-policy retention behavior assertions. */
  private static final String MULTI_ASSERTS = "PMD.UnitTestContainsTooManyAsserts";

  // WHY: This scenario checks several independent outputs of one semantic case.
  @SuppressWarnings(MULTI_ASSERTS)
  @Test
  void dropsOnlyUnambiguousLeafAndReturnsDirectLeafAdvisory() {
    final DependencyNode root =
        EffectiveGraphPolicyTestSupport.node(EffectiveGraphPolicyTestSupport.ROOT_ID);
    root.setChildren(
        List.of(
            EffectiveGraphPolicyTestSupport.node(EffectiveGraphPolicyTestSupport.DROP_ID),
            EffectiveGraphPolicyTestSupport.node(EffectiveGraphPolicyTestSupport.KEEP_ID)));
    final ArtifactCoordinate drop =
        EffectiveGraphPolicyTestSupport.coordinate(
            EffectiveGraphPolicyTestSupport.DROP_ID, EffectiveGraphPolicyTestSupport.COMPILE_SCOPE);
    final ArtifactCoordinate keep =
        EffectiveGraphPolicyTestSupport.coordinate(
            EffectiveGraphPolicyTestSupport.KEEP_ID, EffectiveGraphPolicyTestSupport.COMPILE_SCOPE);
    final EffectiveGraphPolicy.Evaluation result =
        EffectiveGraphPolicyTestSupport.evaluate(
            root, root, EffectiveGraphPolicyTestSupport.decision(Set.of(keep), Set.of(drop)));

    assertThat(result.failClosed()).isFalse();
    assertThat(result.elidedArtifacts()).containsExactly(drop);
    assertThat(result.retainedArtifacts()).containsExactly(keep);
    assertThat(result.directLeafCandidatesForSeparateGate()).containsExactly(drop);
    assertThat(result.nodeDispositions())
        .containsEntry("n1", EffectiveGraphPolicy.NodeDisposition.SAFE_ELIDED)
        .containsEntry("n2", EffectiveGraphPolicy.NodeDisposition.RETAINED);
  }

  // WHY: This scenario checks several independent outputs of one semantic case.
  @SuppressWarnings(MULTI_ASSERTS)
  @Test
  void promotesRawDroppedAncestorOfRetainedChild() {
    final DependencyNode root =
        EffectiveGraphPolicyTestSupport.node(EffectiveGraphPolicyTestSupport.ROOT_ID);
    final DependencyNode ancestor =
        EffectiveGraphPolicyTestSupport.node(EffectiveGraphPolicyTestSupport.ANCESTOR_ID);
    ancestor.setChildren(
        List.of(EffectiveGraphPolicyTestSupport.node(EffectiveGraphPolicyTestSupport.RETAINED_ID)));
    root.setChildren(List.of(ancestor));
    final ArtifactCoordinate ancestorCoordinate =
        EffectiveGraphPolicyTestSupport.coordinate(
            EffectiveGraphPolicyTestSupport.ANCESTOR_ID,
            EffectiveGraphPolicyTestSupport.COMPILE_SCOPE);
    final ArtifactCoordinate childCoordinate =
        EffectiveGraphPolicyTestSupport.coordinate(
            EffectiveGraphPolicyTestSupport.RETAINED_ID,
            EffectiveGraphPolicyTestSupport.COMPILE_SCOPE);
    final EffectiveGraphPolicy.Evaluation result =
        EffectiveGraphPolicyTestSupport.evaluate(
            root,
            root,
            EffectiveGraphPolicyTestSupport.decision(
                Set.of(childCoordinate), Set.of(ancestorCoordinate)));

    assertThat(result.elidedArtifacts()).isEmpty();
    assertThat(result.ancestorPromotedArtifacts()).containsExactly(ancestorCoordinate);
    assertThat(result.retainedArtifacts()).containsExactly(ancestorCoordinate, childCoordinate);
  }

  // WHY: This scenario checks several independent outputs of one semantic case.
  @SuppressWarnings(MULTI_ASSERTS)
  @Test
  void promotesEveryRepeatedIdentityBeforeRecomputingAncestors() {
    final DependencyNode root =
        EffectiveGraphPolicyTestSupport.node(EffectiveGraphPolicyTestSupport.ROOT_ID);
    final DependencyNode firstParent =
        EffectiveGraphPolicyTestSupport.node(EffectiveGraphPolicyTestSupport.ANCESTOR_ID);
    final DependencyNode secondParent =
        EffectiveGraphPolicyTestSupport.node(EffectiveGraphPolicyTestSupport.PARENT_ID);
    firstParent.setChildren(
        List.of(EffectiveGraphPolicyTestSupport.node(EffectiveGraphPolicyTestSupport.RETAINED_ID)));
    secondParent.setChildren(
        List.of(EffectiveGraphPolicyTestSupport.node(EffectiveGraphPolicyTestSupport.ANCESTOR_ID)));
    root.setChildren(List.of(firstParent, secondParent));
    final ArtifactCoordinate ancestor =
        EffectiveGraphPolicyTestSupport.coordinate(
            EffectiveGraphPolicyTestSupport.ANCESTOR_ID,
            EffectiveGraphPolicyTestSupport.COMPILE_SCOPE);
    final ArtifactCoordinate parent =
        EffectiveGraphPolicyTestSupport.coordinate(
            EffectiveGraphPolicyTestSupport.PARENT_ID,
            EffectiveGraphPolicyTestSupport.COMPILE_SCOPE);
    final ArtifactCoordinate retained =
        EffectiveGraphPolicyTestSupport.coordinate(
            EffectiveGraphPolicyTestSupport.RETAINED_ID,
            EffectiveGraphPolicyTestSupport.COMPILE_SCOPE);
    final EffectiveGraphPolicy.Evaluation result =
        EffectiveGraphPolicyTestSupport.evaluate(
            root,
            root,
            EffectiveGraphPolicyTestSupport.decision(Set.of(retained), Set.of(ancestor, parent)));

    assertThat(result.elidedArtifacts()).isEmpty();
    assertThat(result.ancestorPromotedArtifacts()).containsExactlyInAnyOrder(ancestor, parent);
    assertThat(result.nodeDispositions())
        .containsEntry("n1", EffectiveGraphPolicy.NodeDisposition.ANCESTOR_PROMOTED)
        .containsEntry("n2", EffectiveGraphPolicy.NodeDisposition.ANCESTOR_PROMOTED)
        .containsEntry("n4", EffectiveGraphPolicy.NodeDisposition.ANCESTOR_PROMOTED)
        .containsEntry("n3", EffectiveGraphPolicy.NodeDisposition.RETAINED);
  }

  // WHY: This scenario checks several independent outputs of one semantic case.
  @SuppressWarnings(MULTI_ASSERTS)
  @Test
  void preservesBothDiamondPathsButDropsUnrelatedLeaf() {
    final DependencyNode root =
        EffectiveGraphPolicyTestSupport.node(EffectiveGraphPolicyTestSupport.ROOT_ID);
    final DependencyNode left =
        EffectiveGraphPolicyTestSupport.node(EffectiveGraphPolicyTestSupport.LEFT_ID);
    final DependencyNode right =
        EffectiveGraphPolicyTestSupport.node(EffectiveGraphPolicyTestSupport.RIGHT_ID);
    final DependencyNode shared =
        EffectiveGraphPolicyTestSupport.node(EffectiveGraphPolicyTestSupport.SHARED_ID);
    left.setChildren(List.of(shared));
    right.setChildren(List.of(shared));
    root.setChildren(
        List.of(
            left,
            right,
            EffectiveGraphPolicyTestSupport.node(EffectiveGraphPolicyTestSupport.UNUSED_ID)));
    final ArtifactCoordinate leftCoordinate =
        EffectiveGraphPolicyTestSupport.coordinate(
            EffectiveGraphPolicyTestSupport.LEFT_ID, EffectiveGraphPolicyTestSupport.COMPILE_SCOPE);
    final ArtifactCoordinate rightCoordinate =
        EffectiveGraphPolicyTestSupport.coordinate(
            EffectiveGraphPolicyTestSupport.RIGHT_ID,
            EffectiveGraphPolicyTestSupport.COMPILE_SCOPE);
    final ArtifactCoordinate sharedCoordinate =
        EffectiveGraphPolicyTestSupport.coordinate(
            EffectiveGraphPolicyTestSupport.SHARED_ID,
            EffectiveGraphPolicyTestSupport.COMPILE_SCOPE);
    final ArtifactCoordinate unusedCoordinate =
        EffectiveGraphPolicyTestSupport.coordinate(
            EffectiveGraphPolicyTestSupport.UNUSED_ID,
            EffectiveGraphPolicyTestSupport.COMPILE_SCOPE);
    final EffectiveGraphPolicy.Evaluation result =
        EffectiveGraphPolicyTestSupport.evaluate(
            root,
            root,
            EffectiveGraphPolicyTestSupport.decision(
                Set.of(sharedCoordinate),
                Set.of(leftCoordinate, rightCoordinate, unusedCoordinate)));

    assertThat(result.ancestorPromotedArtifacts())
        .containsExactlyInAnyOrder(leftCoordinate, rightCoordinate);
    assertThat(result.elidedArtifacts()).containsExactly(unusedCoordinate);
  }

  // WHY: This scenario checks several independent outputs of one semantic case.
  @SuppressWarnings(MULTI_ASSERTS)
  @Test
  void repeatedEqualIdentityOccurrencesAreDroppedTogetherWhenAllAreSafeLeaves() {
    final DependencyNode root =
        EffectiveGraphPolicyTestSupport.node(EffectiveGraphPolicyTestSupport.ROOT_ID);
    root.setChildren(
        List.of(
            EffectiveGraphPolicyTestSupport.node(EffectiveGraphPolicyTestSupport.SAME_ID),
            EffectiveGraphPolicyTestSupport.node(EffectiveGraphPolicyTestSupport.SAME_ID)));
    final ArtifactCoordinate same =
        EffectiveGraphPolicyTestSupport.coordinate(
            EffectiveGraphPolicyTestSupport.SAME_ID, EffectiveGraphPolicyTestSupport.COMPILE_SCOPE);
    final EffectiveGraphPolicy.Evaluation result =
        EffectiveGraphPolicyTestSupport.evaluate(
            root, root, EffectiveGraphPolicyTestSupport.decision(Set.of(), Set.of(same)));

    assertThat(result.elidedArtifacts()).containsExactly(same);
    assertThat(result.nodeDispositions().values())
        .containsExactly(
            EffectiveGraphPolicy.NodeDisposition.RETAINED,
            EffectiveGraphPolicy.NodeDisposition.SAFE_ELIDED,
            EffectiveGraphPolicy.NodeDisposition.SAFE_ELIDED);
  }
}
