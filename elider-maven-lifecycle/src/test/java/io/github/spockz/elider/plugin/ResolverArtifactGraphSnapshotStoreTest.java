/* WHY: Verifies malformed detached graph payloads fail before they cross Maven realms. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertSame;

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
  void rejectsFingerprintMismatch() {
    final Map<String, Object> wrongFingerprint =
        ResolverArtifactGraphSnapshotStoreTestSupport.mutablePayload();
    ResolverArtifactGraphSnapshotStoreTestSupport.payloadSnapshot(wrongFingerprint)
        .put("graphFingerprint", "0".repeat(64));
    ResolverArtifactGraphSnapshotStoreTestAssertions.assertInvalid(wrongFingerprint);
  }

  @Test
  void rejectsNonOneStoreSchema() {
    final Map<String, Object> payload =
        ResolverArtifactGraphSnapshotStoreTestSupport.mutablePayload();
    payload.put("schemaVersion", 3);

    ResolverArtifactGraphSnapshotStoreTestAssertions.assertInvalidWithMessage(
        payload, "Unsupported graph snapshot store schema");
  }

  @Test
  void rejectsSchemaOneDraftWithPreReleaseRootFields() {
    final Map<String, Object> payload =
        ResolverArtifactGraphSnapshotStoreTestSupport.mutablePayload();
    payload.remove("planObservations");
    payload.remove("capturePairs");

    ResolverArtifactGraphSnapshotStoreTestAssertions.assertInvalidWithMessage(
        payload, "Graph snapshot store fields do not match the schema");
  }

  @Test
  void rejectsProjectKeyMismatch() {
    final Map<String, Object> wrongProject =
        ResolverArtifactGraphSnapshotStoreTestSupport.mutablePayload();
    ResolverArtifactGraphSnapshotStoreTestSupport.payloadSnapshot(wrongProject)
        .put("projectKey", "other-project");
    ResolverArtifactGraphSnapshotStoreTestAssertions.assertInvalidWithMessage(
        wrongProject, "snapshot project key does not match its store key");
  }

  @Test
  void rejectsNestedFieldTypeMismatch() {
    final Map<String, Object> wrongNodeType =
        ResolverArtifactGraphSnapshotStoreTestSupport.mutablePayload();
    ResolverArtifactGraphSnapshotStoreTestSupport.nodePayload(wrongNodeType, 1)
        .put("managedBits", "0");
    ResolverArtifactGraphSnapshotStoreTestAssertions.recomputeFingerprint(wrongNodeType);
    ResolverArtifactGraphSnapshotStoreTestAssertions.assertInvalidWithMessage(
        wrongNodeType, "managed bits must be an integer");
  }

  @Test
  void rejectsCaptureGenerationMismatch() {
    final Map<String, Object> wrongGeneration =
        ResolverArtifactGraphSnapshotStoreTestSupport.mutablePayload();
    ResolverArtifactGraphSnapshotStoreTestSupport.putGeneration(wrongGeneration, 2L);
    ResolverArtifactGraphSnapshotStoreTestAssertions.assertInvalid(wrongGeneration);
  }

  @Test
  void rejectsNonJdkNestedValue() {
    final Map<String, Object> nonJdkProperty =
        ResolverArtifactGraphSnapshotStoreTestSupport.mutablePayload();
    ResolverArtifactGraphSnapshotStoreTestSupport.putArtifactProperty(
        ResolverArtifactGraphSnapshotStoreTestSupport.nodePayload(nonJdkProperty, 0),
        "bad",
        new Object());
    ResolverArtifactGraphSnapshotStoreTestAssertions.assertInvalid(nonJdkProperty);
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

  @Test
  void sharesImmutableHistoricalEntriesAcrossUpdates() {
    final DependencyNode root = ResolverArtifactGraphSnapshotStoreTestSupport.node("root");
    final String projectKey = ResolverArtifactGraphSnapshotStoreTestSupport.PROJECT_KEY;
    final ResolverArtifactGraphSnapshot first =
        ResolverArtifactGraphSnapshot.capture(root, projectKey, true, "a".repeat(64), 1, 1);
    final ResolverArtifactGraphSnapshot second =
        ResolverArtifactGraphSnapshot.capture(root, projectKey, true, "a".repeat(64), 1, 2);

    final ResolverArtifactGraphSnapshotStore store1 =
        ResolverArtifactGraphSnapshotStore.empty().append(first);
    final ResolverArtifactGraphSnapshotStore.PlanObservation observation =
        store1.observePlan(projectKey, true, "a".repeat(64));
    final ResolverArtifactGraphSnapshotStore store2 =
        store1.withObservation(projectKey, observation);
    final ResolverArtifactGraphSnapshotStore store3 = store2.append(second);

    assertAll(
        "Immutable history sharing across store updates",
        () ->
            assertSame(
                store1.snapshots(),
                store2.snapshots(),
                "withObservation should reuse snapshots map"),
        () ->
            assertSame(
                store1.capturePairs(),
                store2.capturePairs(),
                "withObservation should reuse capturePairs map"),
        () ->
            assertSame(
                store2,
                store2.withObservation(projectKey, observation),
                "unchanged observation should return the same store instance"),
        () ->
            assertSame(
                store1.snapshots().get(projectKey).get(0),
                store3.snapshots().get(projectKey).get(0),
                "append should preserve historical snapshot map identity"),
        () ->
            assertSame(
                store1.capturePairs().get(projectKey).get(0),
                store3.capturePairs().get(projectKey).get(0),
                "append should preserve historical capture pair map identity"));
  }
}
