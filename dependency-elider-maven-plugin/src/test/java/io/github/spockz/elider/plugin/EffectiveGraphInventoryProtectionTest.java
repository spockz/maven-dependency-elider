// WHY: Verifies unknown child edges block every removal whose conflict visibility they affect.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.eclipse.aether.graph.DependencyNode;
import org.junit.jupiter.api.Test;

/** Guards against treating omitted null-child branches as complete graph leaves. */
final class EffectiveGraphInventoryProtectionTest {
  /** Creates the inventory protection test fixture. */
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  EffectiveGraphInventoryProtectionTest() {
    super();
  }

  // WHY: Keep all protection outcomes asserted for one graph case.
  @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
  @Test
  void nullChildInPreGraphProtectsCandidateAndDirectLeafAdvice() {
    final DependencyNode beforeRoot = rootWithNullChild();
    final DependencyNode afterRoot =
        EffectiveGraphPolicyTestSupport.node(EffectiveGraphPolicyTestSupport.ROOT_ID);
    afterRoot.setChildren(List.of(dropNode()));
    final EffectiveGraphPolicy.Evaluation result =
        evaluate(beforeRoot, afterRoot, "pre-null-child");

    assertThat(result.elidedArtifacts()).isEmpty();
    assertThat(result.protectedReasons())
        .containsEntry(dropCoordinate(), "pre-mediation graph has incomplete conflict visibility");
    assertThat(result.nodeDispositions())
        .containsEntry("n1", EffectiveGraphPolicy.NodeDisposition.PROTECTED);
    assertThat(result.directLeafCandidatesForSeparateGate()).isEmpty();
  }

  // WHY: Keep all protection outcomes asserted for one graph case.
  @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
  @Test
  void nullChildInPostGraphProtectsCandidateAndDirectLeafAdvice() {
    final DependencyNode beforeRoot =
        EffectiveGraphPolicyTestSupport.node(EffectiveGraphPolicyTestSupport.ROOT_ID);
    beforeRoot.setChildren(List.of(dropNode()));
    final EffectiveGraphPolicy.Evaluation result =
        evaluate(beforeRoot, rootWithNullChild(), "post-null-child");

    assertThat(result.elidedArtifacts()).isEmpty();
    assertThat(result.protectedReasons())
        .containsEntry(dropCoordinate(), "post-mediation graph has incomplete child inventory");
    assertThat(result.nodeDispositions())
        .containsEntry("n1", EffectiveGraphPolicy.NodeDisposition.PROTECTED);
    assertThat(result.directLeafCandidatesForSeparateGate()).isEmpty();
  }

  private static EffectiveGraphPolicy.Evaluation evaluate(
      final DependencyNode beforeRoot, final DependencyNode afterRoot, final String token) {
    final ResolverArtifactGraphCapturePair pair =
        EffectiveGraphPolicyTestSupport.pair(beforeRoot, afterRoot, token);
    return EffectiveGraphPolicy.evaluate(
        List.of(pair),
        EffectiveGraphPolicyTestSupport.PROJECT_KEY,
        EffectiveGraphPolicyTestSupport.decision(Set.of(), Set.of(dropCoordinate())));
  }

  private static DependencyNode rootWithNullChild() {
    final DependencyNode root =
        EffectiveGraphPolicyTestSupport.node(EffectiveGraphPolicyTestSupport.ROOT_ID);
    final List<DependencyNode> children = new ArrayList<>();
    children.add(dropNode());
    children.add(null);
    root.setChildren(children);
    return root;
  }

  private static DependencyNode dropNode() {
    return EffectiveGraphPolicyTestSupport.node(EffectiveGraphPolicyTestSupport.DROP_ID);
  }

  private static ArtifactCoordinate dropCoordinate() {
    return EffectiveGraphPolicyTestSupport.coordinate(
        EffectiveGraphPolicyTestSupport.DROP_ID, EffectiveGraphPolicyTestSupport.COMPILE_SCOPE);
  }
}
