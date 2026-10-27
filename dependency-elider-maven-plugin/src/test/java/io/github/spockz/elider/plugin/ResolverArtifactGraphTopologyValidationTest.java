/* WHY: Isolates self-consistent malformed topology cases from store envelope validation. */

package io.github.spockz.elider.plugin;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Verifies invalid graph relationships are rejected after fingerprint validation. */
final class ResolverArtifactGraphTopologyValidationTest {
  /** Creates the topology validation test fixture. */
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  ResolverArtifactGraphTopologyValidationTest() {
    super();
  }

  @Test
  void rejectsDanglingEdgeAfterFingerprintRecomputation() {
    final Map<String, Object> payload =
        ResolverArtifactGraphSnapshotStoreTestSupport.mutablePayload();
    ResolverArtifactGraphSnapshotStoreTestSupport.payloadSnapshot(payload)
        .put("edges", List.of(Map.of("parentNodeId", "n0", "childNodeId", "n99")));
    ResolverArtifactGraphSnapshotStoreTestAssertions.recomputeFingerprint(payload);

    ResolverArtifactGraphSnapshotStoreTestAssertions.assertInvalidWithMessage(
        payload, "edge child must be reachable");
  }

  @Test
  void rejectsDanglingConflictWinnerAfterFingerprintRecomputation() {
    final Map<String, Object> payload =
        ResolverArtifactGraphSnapshotStoreTestSupport.mutablePayload();
    final Map<String, Object> winner =
        ResolverArtifactGraphSnapshotStoreTestSupport.nodePayload(payload, 1);
    winner.put("conflictWinnerPresent", true);
    winner.put("conflictWinnerNodeId", "n99");
    ResolverArtifactGraphSnapshotStoreTestAssertions.recomputeFingerprint(payload);

    ResolverArtifactGraphSnapshotStoreTestAssertions.assertInvalidWithMessage(
        payload, "conflict winner references a missing node");
  }

  @Test
  void rejectsReachabilityMismatchAfterFingerprintRecomputation() {
    final Map<String, Object> payload =
        ResolverArtifactGraphSnapshotStoreTestSupport.mutablePayload();
    ResolverArtifactGraphSnapshotStoreTestSupport.payloadSnapshot(payload).put("edges", List.of());
    ResolverArtifactGraphSnapshotStoreTestSupport.nodePayload(payload, 1).put("reachable", true);
    ResolverArtifactGraphSnapshotStoreTestAssertions.recomputeFingerprint(payload);

    ResolverArtifactGraphSnapshotStoreTestAssertions.assertInvalidWithMessage(
        payload, "node reachability does not match graph edges");
  }

  @Test
  void rejectsMutuallyExclusiveWinnerEncodingsAfterFingerprintRecomputation() {
    final Map<String, Object> payload =
        ResolverArtifactGraphSnapshotStoreTestSupport.mutablePayload();
    final Map<String, Object> node =
        ResolverArtifactGraphSnapshotStoreTestSupport.nodePayload(payload, 1);
    node.put("conflictWinnerPresent", true);
    node.put("conflictWinnerNodeId", "n0");
    node.put("conflictWinnerValueType", "java.lang.String");
    ResolverArtifactGraphSnapshotStoreTestAssertions.recomputeFingerprint(payload);

    ResolverArtifactGraphSnapshotStoreTestAssertions.assertInvalidWithMessage(
        payload, "conflict winner encodings are mutually exclusive");
  }

  @Test
  void rejectsOutgoingEdgeWhenChildrenAreAbsentAfterFingerprintRecomputation() {
    final Map<String, Object> payload =
        ResolverArtifactGraphSnapshotStoreTestSupport.mutablePayload();
    ResolverArtifactGraphSnapshotStoreTestSupport.nodePayload(payload, 0)
        .put("childrenPresent", false);
    ResolverArtifactGraphSnapshotStoreTestAssertions.recomputeFingerprint(payload);

    ResolverArtifactGraphSnapshotStoreTestAssertions.assertInvalidWithMessage(
        payload, "node with outgoing edges declares no children");
  }
}
