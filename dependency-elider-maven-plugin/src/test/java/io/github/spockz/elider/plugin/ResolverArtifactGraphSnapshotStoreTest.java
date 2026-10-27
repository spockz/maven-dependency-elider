/* WHY: Verifies malformed detached graph payloads fail before they cross Maven realms. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;

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
}
