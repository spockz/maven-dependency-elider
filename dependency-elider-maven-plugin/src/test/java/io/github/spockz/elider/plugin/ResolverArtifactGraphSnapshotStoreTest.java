/* WHY: Verifies malformed detached graph payloads fail before they cross Maven realms. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import org.eclipse.aether.graph.DependencyNode;
import org.junit.jupiter.api.Test;

/** Exercises full schema validation for the session graph payload. */
final class ResolverArtifactGraphSnapshotStoreTest {
  /** Creates the test fixture. */
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  ResolverArtifactGraphSnapshotStoreTest() {
    super();
  }

  @Test
  void rejectsDanglingEdge() {
    final Map<String, Object> danglingEdge =
        ResolverArtifactGraphSnapshotStoreTestSupport.mutablePayload();
    ResolverArtifactGraphSnapshotStoreTestSupport.payloadSnapshot(danglingEdge)
        .put("edges", List.of(Map.of("parentNodeId", "n0", "childNodeId", "n99")));
    ResolverArtifactGraphSnapshotStoreTestSupport.assertInvalid(danglingEdge);
  }

  @Test
  void rejectsDanglingConflictWinner() {
    final Map<String, Object> danglingWinner =
        ResolverArtifactGraphSnapshotStoreTestSupport.mutablePayload();
    ResolverArtifactGraphSnapshotStoreTestSupport.nodePayload(danglingWinner, 1)
        .put("conflictWinnerPresent", true);
    ResolverArtifactGraphSnapshotStoreTestSupport.nodePayload(danglingWinner, 1)
        .put("conflictWinnerNodeId", "n99");
    ResolverArtifactGraphSnapshotStoreTestSupport.assertInvalid(danglingWinner);
  }

  @Test
  void rejectsReachabilityThatDisagreesWithEdges() {
    final Map<String, Object> inconsistentReachability =
        ResolverArtifactGraphSnapshotStoreTestSupport.mutablePayload();
    ResolverArtifactGraphSnapshotStoreTestSupport.nodePayload(inconsistentReachability, 1)
        .put("reachable", false);
    ResolverArtifactGraphSnapshotStoreTestSupport.assertInvalid(inconsistentReachability);
  }

  @Test
  void rejectsFingerprintMismatch() {
    final Map<String, Object> wrongFingerprint =
        ResolverArtifactGraphSnapshotStoreTestSupport.mutablePayload();
    ResolverArtifactGraphSnapshotStoreTestSupport.payloadSnapshot(wrongFingerprint)
        .put("graphFingerprint", "0".repeat(64));
    ResolverArtifactGraphSnapshotStoreTestSupport.assertInvalid(wrongFingerprint);
  }

  @Test
  void rejectsProjectKeyMismatch() {
    final Map<String, Object> wrongProject =
        ResolverArtifactGraphSnapshotStoreTestSupport.mutablePayload();
    ResolverArtifactGraphSnapshotStoreTestSupport.payloadSnapshot(wrongProject)
        .put("projectKey", "other-project");
    ResolverArtifactGraphSnapshotStoreTestSupport.assertInvalid(wrongProject);
  }

  @Test
  void rejectsNestedFieldTypeMismatch() {
    final Map<String, Object> wrongNodeType =
        ResolverArtifactGraphSnapshotStoreTestSupport.mutablePayload();
    ResolverArtifactGraphSnapshotStoreTestSupport.nodePayload(wrongNodeType, 1)
        .put("managedBits", "0");
    ResolverArtifactGraphSnapshotStoreTestSupport.assertInvalid(wrongNodeType);
  }

  @Test
  void rejectsCaptureGenerationMismatch() {
    final Map<String, Object> wrongGeneration =
        ResolverArtifactGraphSnapshotStoreTestSupport.mutablePayload();
    ResolverArtifactGraphSnapshotStoreTestSupport.putGeneration(wrongGeneration, 2L);
    ResolverArtifactGraphSnapshotStoreTestSupport.assertInvalid(wrongGeneration);
  }

  @Test
  void rejectsNonJdkNestedValue() {
    final Map<String, Object> nonJdkProperty =
        ResolverArtifactGraphSnapshotStoreTestSupport.mutablePayload();
    ResolverArtifactGraphSnapshotStoreTestSupport.putArtifactProperty(
        ResolverArtifactGraphSnapshotStoreTestSupport.nodePayload(nonJdkProperty, 0),
        "bad",
        new Object());
    ResolverArtifactGraphSnapshotStoreTestSupport.assertInvalid(nonJdkProperty);
  }

  @Test
  void acceptsDelayedTransformationsWhosePlanGenerationOrderDiffersFromCaptureOrder() {
    final DependencyNode root = ResolverArtifactGraphSnapshotStoreTestSupport.node("root");
    final ResolverArtifactGraphSnapshot first =
        ResolverArtifactGraphSnapshot.capture(
            root,
            ResolverArtifactGraphSnapshotStoreTestSupport.PROJECT_KEY,
            true,
            "a".repeat(64),
            1,
            1);
    final ResolverArtifactGraphSnapshot delayed =
        ResolverArtifactGraphSnapshot.capture(
            root, ResolverArtifactGraphSnapshotStoreTestSupport.PROJECT_KEY, false, null, 0, 2);
    final ResolverArtifactGraphSnapshotStore store =
        ResolverArtifactGraphSnapshotStore.empty().append(first).append(delayed);

    assertThat(ResolverArtifactGraphSnapshotStore.fromPayload(store.toPayload()).snapshots())
        .containsKey(ResolverArtifactGraphSnapshotStoreTestSupport.PROJECT_KEY);
  }
}
