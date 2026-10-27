// WHY: Verifies one cohesive set of conservative effective-graph policy cases.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ElisionDecision;
import java.util.List;
import java.util.Set;
import org.eclipse.aether.graph.DefaultDependencyNode;
import org.eclipse.aether.graph.DependencyNode;
import org.eclipse.aether.graph.Exclusion;
import org.eclipse.aether.util.graph.transformer.ConflictResolver;
import org.junit.jupiter.api.Test;

/** Covers fail-closed graph metadata and conflict safeguards. */
@SuppressWarnings("PMD.AtLeastOneConstructor")
final class EffectiveGraphPolicySafetyTest {
  /** Groups graph-policy protection behavior assertions. */
  private static final String MULTI_ASSERTS = "PMD.UnitTestContainsTooManyAsserts";

  // WHY: This scenario checks several independent outputs of one semantic case.
  @SuppressWarnings(MULTI_ASSERTS)
  @Test
  void protectsRepeatedIdentityWithDifferentOptionalPathMetadata() {
    final DependencyNode root =
        EffectiveGraphPolicyTestSupport.node(EffectiveGraphPolicyTestSupport.ROOT_ID);
    root.setChildren(
        List.of(
            EffectiveGraphPolicyTestSupport.node(
                EffectiveGraphPolicyTestSupport.SAME_ID,
                EffectiveGraphPolicyTestSupport.COMPILE_SCOPE,
                true),
            EffectiveGraphPolicyTestSupport.node(
                EffectiveGraphPolicyTestSupport.SAME_ID,
                EffectiveGraphPolicyTestSupport.COMPILE_SCOPE,
                false)));
    final ArtifactCoordinate same =
        EffectiveGraphPolicyTestSupport.coordinate(
            EffectiveGraphPolicyTestSupport.SAME_ID, EffectiveGraphPolicyTestSupport.COMPILE_SCOPE);
    final EffectiveGraphPolicy.Evaluation result =
        EffectiveGraphPolicyTestSupport.evaluate(
            root, root, EffectiveGraphPolicyTestSupport.decision(Set.of(), Set.of(same)));

    assertThat(result.elidedArtifacts()).isEmpty();
    assertThat(result.protectedReasons())
        .containsEntry(same, "repeated artifact paths have different metadata");
    assertThat(result.nodeDispositions())
        .containsEntry("n1", EffectiveGraphPolicy.NodeDisposition.PROTECTED)
        .containsEntry("n2", EffectiveGraphPolicy.NodeDisposition.PROTECTED);
  }

  // WHY: This scenario checks several independent outputs of one semantic case.
  @SuppressWarnings(MULTI_ASSERTS)
  @Test
  void protectsRepeatedIdentityWithDifferentExclusions() {
    final DependencyNode root =
        EffectiveGraphPolicyTestSupport.node(EffectiveGraphPolicyTestSupport.ROOT_ID);
    root.setChildren(
        List.of(
            EffectiveGraphPolicyTestSupport.node(
                EffectiveGraphPolicyTestSupport.SAME_ID,
                EffectiveGraphPolicyTestSupport.COMPILE_SCOPE,
                null,
                List.of()),
            EffectiveGraphPolicyTestSupport.node(
                EffectiveGraphPolicyTestSupport.SAME_ID,
                EffectiveGraphPolicyTestSupport.COMPILE_SCOPE,
                null,
                List.of(
                    new Exclusion(
                        "other", "excluded", "", EffectiveGraphPolicyTestSupport.JAR_EXTENSION)))));
    final ArtifactCoordinate same =
        EffectiveGraphPolicyTestSupport.coordinate(
            EffectiveGraphPolicyTestSupport.SAME_ID, EffectiveGraphPolicyTestSupport.COMPILE_SCOPE);
    final EffectiveGraphPolicy.Evaluation result =
        EffectiveGraphPolicyTestSupport.evaluate(
            root, root, EffectiveGraphPolicyTestSupport.decision(Set.of(), Set.of(same)));

    assertThat(result.elidedArtifacts()).isEmpty();
    assertThat(result.protectedReasons()).containsKey(same);
    assertThat(result.nodeDispositions())
        .containsEntry("n1", EffectiveGraphPolicy.NodeDisposition.PROTECTED);
  }

  // WHY: A missing child list cannot establish that an elided artifact is a leaf.
  @SuppressWarnings(MULTI_ASSERTS)
  @Test
  void protectsCandidateWithIncompleteChildInventory() {
    final DependencyNode root =
        EffectiveGraphPolicyTestSupport.node(EffectiveGraphPolicyTestSupport.ROOT_ID);
    root.setChildren(
        List.of(EffectiveGraphPolicyTestSupport.node(EffectiveGraphPolicyTestSupport.DROP_ID)));
    final ArtifactCoordinate drop =
        EffectiveGraphPolicyTestSupport.coordinate(
            EffectiveGraphPolicyTestSupport.DROP_ID, EffectiveGraphPolicyTestSupport.COMPILE_SCOPE);

    final EffectiveGraphPolicy.Evaluation result =
        EffectiveGraphPolicy.evaluate(
            List.of(
                EffectiveGraphPolicySafetyTestSupport.withModifiedAfter(
                    root,
                    "missing-children",
                    snapshot ->
                        EffectiveGraphPolicySafetyTestSupport.nodePayload(snapshot, 1)
                            .put("childrenPresent", false))),
            EffectiveGraphPolicyTestSupport.PROJECT_KEY,
            EffectiveGraphPolicyTestSupport.decision(Set.of(), Set.of(drop)));

    assertThat(result.elidedArtifacts()).isEmpty();
    assertThat(result.protectedReasons())
        .containsEntry(drop, "candidate node has incomplete child inventory");
    assertThat(result.nodeDispositions())
        .containsEntry("n1", EffectiveGraphPolicy.NodeDisposition.PROTECTED);
  }

  @SuppressWarnings(MULTI_ASSERTS)
  @Test
  void protectsCandidatesWhenPremediationInventoryIsIncomplete() {
    final DependencyNode root =
        EffectiveGraphPolicyTestSupport.node(EffectiveGraphPolicyTestSupport.ROOT_ID);
    root.setChildren(
        List.of(EffectiveGraphPolicyTestSupport.node(EffectiveGraphPolicyTestSupport.DROP_ID)));
    final ArtifactCoordinate drop =
        EffectiveGraphPolicyTestSupport.coordinate(
            EffectiveGraphPolicyTestSupport.DROP_ID, EffectiveGraphPolicyTestSupport.COMPILE_SCOPE);
    final ResolverArtifactGraphCapturePair pair =
        EffectiveGraphPolicySafetyTestSupport.withModifiedBefore(
            root,
            "incomplete-before",
            snapshot ->
                EffectiveGraphPolicySafetyTestSupport.nodePayload(snapshot, 1)
                    .put("childrenPresent", false));

    final EffectiveGraphPolicy.Evaluation result =
        EffectiveGraphPolicy.evaluate(
            List.of(pair),
            EffectiveGraphPolicyTestSupport.PROJECT_KEY,
            EffectiveGraphPolicyTestSupport.decision(Set.of(), Set.of(drop)));

    assertThat(result.elidedArtifacts()).isEmpty();
    assertThat(result.protectedReasons())
        .containsEntry(drop, "pre-mediation graph has incomplete conflict visibility");
    assertThat(result.nodeDispositions())
        .containsEntry("n1", EffectiveGraphPolicy.NodeDisposition.PROTECTED);
  }

  // WHY: This scenario checks several independent outputs of one semantic case.
  @SuppressWarnings(MULTI_ASSERTS)
  @Test
  void protectsPremediationConflictFamilyWithoutWinnerMetadata() {
    final DependencyNode beforeRoot =
        EffectiveGraphPolicyTestSupport.node(EffectiveGraphPolicyTestSupport.ROOT_ID);
    beforeRoot.setChildren(
        List.of(
            EffectiveGraphPolicyTestSupport.node(
                EffectiveGraphPolicyTestSupport.CANDIDATE_ID,
                EffectiveGraphPolicyTestSupport.TEST_VERSION),
            EffectiveGraphPolicyTestSupport.node(
                EffectiveGraphPolicyTestSupport.CANDIDATE_ID, "2.0")));
    final DependencyNode afterRoot =
        EffectiveGraphPolicyTestSupport.node(EffectiveGraphPolicyTestSupport.ROOT_ID);
    afterRoot.setChildren(
        List.of(
            EffectiveGraphPolicyTestSupport.node(
                EffectiveGraphPolicyTestSupport.CANDIDATE_ID,
                EffectiveGraphPolicyTestSupport.TEST_VERSION)));
    final ArtifactCoordinate candidate =
        EffectiveGraphPolicyTestSupport.coordinate(
            EffectiveGraphPolicyTestSupport.CANDIDATE_ID,
            EffectiveGraphPolicyTestSupport.COMPILE_SCOPE);
    final EffectiveGraphPolicy.Evaluation result =
        EffectiveGraphPolicyTestSupport.evaluate(
            beforeRoot,
            afterRoot,
            EffectiveGraphPolicyTestSupport.decision(Set.of(), Set.of(candidate)));

    assertThat(result.elidedArtifacts()).isEmpty();
    assertThat(result.protectedReasons())
        .containsEntry(candidate, "pre-mediation graph contains a competing version");
    assertThat(result.nodeDispositions())
        .containsEntry("n1", EffectiveGraphPolicy.NodeDisposition.PROTECTED);
  }

  @Test
  void preservesMappedNodeWinnerProtectionReason() {
    final DependencyNode root =
        EffectiveGraphPolicyTestSupport.node(EffectiveGraphPolicyTestSupport.ROOT_ID);
    final DependencyNode candidate =
        EffectiveGraphPolicyTestSupport.node(EffectiveGraphPolicyTestSupport.DROP_ID);
    candidate.setData(
        ConflictResolver.NODE_DATA_WINNER,
        EffectiveGraphPolicyTestSupport.node(EffectiveGraphPolicyTestSupport.KEEP_ID));
    root.setChildren(List.of(candidate));
    final ArtifactCoordinate drop =
        EffectiveGraphPolicyTestSupport.coordinate(
            EffectiveGraphPolicyTestSupport.DROP_ID, EffectiveGraphPolicyTestSupport.COMPILE_SCOPE);

    final EffectiveGraphPolicy.Evaluation result =
        EffectiveGraphPolicyTestSupport.evaluate(
            root, root, EffectiveGraphPolicyTestSupport.decision(Set.of(), Set.of(drop)));

    assertThat(result.protectedReasons())
        .containsEntry(drop, "conflict winner metadata is present");
  }

  @Test
  void preservesExternalWinnerProtectionReason() {
    final DependencyNode root =
        EffectiveGraphPolicyTestSupport.node(EffectiveGraphPolicyTestSupport.ROOT_ID);
    final DependencyNode candidate =
        EffectiveGraphPolicyTestSupport.node(EffectiveGraphPolicyTestSupport.DROP_ID);
    root.setChildren(List.of(candidate));
    final ArtifactCoordinate drop =
        EffectiveGraphPolicyTestSupport.coordinate(
            EffectiveGraphPolicyTestSupport.DROP_ID, EffectiveGraphPolicyTestSupport.COMPILE_SCOPE);

    final ResolverArtifactGraphCapturePair externalWinnerPair =
        EffectiveGraphPolicySafetyTestSupport.externalWinnerPair(root, "external-winner");
    final EffectiveGraphPolicy.Evaluation result =
        EffectiveGraphPolicy.evaluate(
            List.of(externalWinnerPair),
            EffectiveGraphPolicyTestSupport.PROJECT_KEY,
            EffectiveGraphPolicyTestSupport.decision(Set.of(), Set.of(drop)));

    assertThat(result.protectedReasons())
        .containsEntry(drop, "conflict winner metadata is present");
  }

  // WHY: This scenario checks several independent outputs of one semantic case.
  @SuppressWarnings(MULTI_ASSERTS)
  @Test
  void failsClosedOnScopeMismatchUnknownArtifactAndUnmatchedInventory() {
    final DependencyNode root =
        EffectiveGraphPolicyTestSupport.node(EffectiveGraphPolicyTestSupport.ROOT_ID);
    root.setChildren(
        List.of(
            EffectiveGraphPolicyTestSupport.node(
                EffectiveGraphPolicyTestSupport.SAME_ID, "runtime")));
    final ArtifactCoordinate compileCoordinate =
        EffectiveGraphPolicyTestSupport.coordinate(
            EffectiveGraphPolicyTestSupport.SAME_ID, EffectiveGraphPolicyTestSupport.COMPILE_SCOPE);
    final EffectiveGraphPolicy.Evaluation scopeResult =
        EffectiveGraphPolicyTestSupport.evaluate(
            root,
            root,
            EffectiveGraphPolicyTestSupport.decision(Set.of(), Set.of(compileCoordinate)));
    assertThat(scopeResult.failClosed()).isTrue();
    assertThat(scopeResult.elidedArtifacts()).isEmpty();

    final DependencyNode unknownRoot =
        EffectiveGraphPolicyTestSupport.node(EffectiveGraphPolicyTestSupport.ROOT_ID);
    unknownRoot.setChildren(
        List.of(new DefaultDependencyNode((org.eclipse.aether.artifact.Artifact) null)));
    final EffectiveGraphPolicy.Evaluation unknownResult =
        EffectiveGraphPolicyTestSupport.evaluate(
            unknownRoot,
            unknownRoot,
            EffectiveGraphPolicyTestSupport.decision(Set.of(), Set.of(compileCoordinate)));
    assertThat(unknownResult.failClosed()).isTrue();
    assertThat(unknownResult.elidedArtifacts()).isEmpty();

    final DependencyNode unmatchedRoot =
        EffectiveGraphPolicyTestSupport.node(EffectiveGraphPolicyTestSupport.ROOT_ID);
    unmatchedRoot.setChildren(
        List.of(EffectiveGraphPolicyTestSupport.node(EffectiveGraphPolicyTestSupport.DROP_ID)));
    final EffectiveGraphPolicy.Evaluation unmatched =
        EffectiveGraphPolicyTestSupport.evaluate(
            unmatchedRoot,
            unmatchedRoot,
            EffectiveGraphPolicyTestSupport.decision(Set.of(), Set.of(compileCoordinate)));
    assertThat(unmatched.failClosed()).isTrue();
    assertThat(unmatched.elidedArtifacts()).isEmpty();
  }

  // WHY: This scenario checks several independent outputs of one semantic case.
  @SuppressWarnings(MULTI_ASSERTS)
  @Test
  void cyclesTerminateAndKeepWholeRequiredComponent() {
    final DependencyNode root =
        EffectiveGraphPolicyTestSupport.node(EffectiveGraphPolicyTestSupport.ROOT_ID);
    final DependencyNode left =
        EffectiveGraphPolicyTestSupport.node(EffectiveGraphPolicyTestSupport.LEFT_ID);
    final DependencyNode right =
        EffectiveGraphPolicyTestSupport.node(EffectiveGraphPolicyTestSupport.RIGHT_ID);
    left.setChildren(List.of(right));
    right.setChildren(
        List.of(
            left, EffectiveGraphPolicyTestSupport.node(EffectiveGraphPolicyTestSupport.KEEP_ID)));
    root.setChildren(List.of(left));
    final ArtifactCoordinate leftCoordinate =
        EffectiveGraphPolicyTestSupport.coordinate(
            EffectiveGraphPolicyTestSupport.LEFT_ID, EffectiveGraphPolicyTestSupport.COMPILE_SCOPE);
    final ArtifactCoordinate rightCoordinate =
        EffectiveGraphPolicyTestSupport.coordinate(
            EffectiveGraphPolicyTestSupport.RIGHT_ID,
            EffectiveGraphPolicyTestSupport.COMPILE_SCOPE);
    final ArtifactCoordinate keepCoordinate =
        EffectiveGraphPolicyTestSupport.coordinate(
            EffectiveGraphPolicyTestSupport.KEEP_ID, EffectiveGraphPolicyTestSupport.COMPILE_SCOPE);
    final EffectiveGraphPolicy.Evaluation result =
        EffectiveGraphPolicyTestSupport.evaluate(
            root,
            root,
            EffectiveGraphPolicyTestSupport.decision(
                Set.of(keepCoordinate), Set.of(leftCoordinate, rightCoordinate)));

    assertThat(result.elidedArtifacts()).isEmpty();
    assertThat(result.ancestorPromotedArtifacts())
        .containsExactlyInAnyOrder(leftCoordinate, rightCoordinate);
  }

  // WHY: This scenario checks several independent outputs of one semantic case.
  @SuppressWarnings(MULTI_ASSERTS)
  @Test
  void refusesAmbiguousOrPlanPresentPairAndSupportsNullRootPair() {
    final DependencyNode root =
        EffectiveGraphPolicyTestSupport.node(EffectiveGraphPolicyTestSupport.ROOT_ID);
    root.setChildren(
        List.of(EffectiveGraphPolicyTestSupport.node(EffectiveGraphPolicyTestSupport.DROP_ID)));
    final ArtifactCoordinate drop =
        EffectiveGraphPolicyTestSupport.coordinate(
            EffectiveGraphPolicyTestSupport.DROP_ID, EffectiveGraphPolicyTestSupport.COMPILE_SCOPE);
    final ElisionDecision raw = EffectiveGraphPolicyTestSupport.decision(Set.of(), Set.of(drop));
    final ResolverArtifactGraphCapturePair firstPair =
        EffectiveGraphPolicyTestSupport.pair(root, root, "first");

    final EffectiveGraphPolicy.Evaluation duplicate =
        EffectiveGraphPolicy.evaluate(
            List.of(firstPair, EffectiveGraphPolicyTestSupport.pair(root, root, "second")),
            EffectiveGraphPolicyTestSupport.PROJECT_KEY,
            raw);
    final ResolverArtifactGraphSnapshot plannedSnapshot =
        ResolverArtifactGraphSnapshot.capture(
            root, EffectiveGraphPolicyTestSupport.PROJECT_KEY, true, "a".repeat(64), 1L, 1L);
    final ResolverArtifactGraphCapturePair planned =
        new ResolverArtifactGraphCapturePair(
            EffectiveGraphPolicyTestSupport.PROJECT_KEY,
            "planned",
            1L,
            true,
            "a".repeat(64),
            1L,
            plannedSnapshot,
            plannedSnapshot);
    final EffectiveGraphPolicy.Evaluation noPlanless =
        EffectiveGraphPolicy.evaluate(
            List.of(planned), EffectiveGraphPolicyTestSupport.PROJECT_KEY, raw);
    final ResolverArtifactGraphSnapshot nullRoot =
        ResolverArtifactGraphSnapshot.capture(
            null, EffectiveGraphPolicyTestSupport.PROJECT_KEY, false, null, 0L, 1L);
    final ResolverArtifactGraphCapturePair nullPair =
        new ResolverArtifactGraphCapturePair(
            EffectiveGraphPolicyTestSupport.PROJECT_KEY,
            "null-root",
            1L,
            false,
            null,
            0L,
            nullRoot,
            nullRoot);
    final EffectiveGraphPolicy.Evaluation nullResult =
        EffectiveGraphPolicy.evaluate(
            List.of(nullPair),
            EffectiveGraphPolicyTestSupport.PROJECT_KEY,
            EffectiveGraphPolicyTestSupport.decision(Set.of(), Set.of()));

    assertThat(duplicate.failClosed()).isTrue();
    assertThat(duplicate.elidedArtifacts()).isEmpty();
    assertThat(noPlanless.failClosed()).isTrue();
    assertThat(noPlanless.elidedArtifacts()).isEmpty();
    assertThat(nullResult.failClosed()).isFalse();
    assertThat(nullResult.elidedArtifacts()).isEmpty();
  }
}
