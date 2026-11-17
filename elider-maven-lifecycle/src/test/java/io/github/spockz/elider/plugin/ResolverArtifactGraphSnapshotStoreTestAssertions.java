/* WHY: Provides precise assertions for malformed payloads without inflating fixture helpers. */

package io.github.spockz.elider.plugin;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.assertj.core.api.Assertions;

/** Recomputes test fingerprints and checks targeted schema failures. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class ResolverArtifactGraphSnapshotStoreTestAssertions {
  private ResolverArtifactGraphSnapshotStoreTestAssertions() {
    throw new AssertionError("No instances");
  }

  static void recomputeFingerprint(final Map<String, Object> payload) {
    recomputeFingerprint(payload, ResolverArtifactGraphSnapshotStoreTestSupport.PROJECT_KEY);
  }

  // WHY: Linked maps preserve null roots and stable fingerprint field order.
  @SuppressWarnings("PMD.UseConcurrentHashMap")
  static void recomputeFingerprint(final Map<String, Object> payload, final String projectKey) {
    final Map<String, Object> snapshot = snapshotPayload(payload, projectKey);
    final Map<String, Object> structure = new LinkedHashMap<>();
    structure.put("rootNodeId", snapshot.get("rootNodeId"));
    structure.put("nodes", snapshot.get("nodes"));
    structure.put("edges", snapshot.get("edges"));
    try {
      final byte[] digest =
          MessageDigest.getInstance("SHA-256")
              .digest(
                  ResolverArtifactGraphSnapshot.canonicalJson(structure)
                      .getBytes(StandardCharsets.UTF_8));
      snapshot.put("graphFingerprint", java.util.HexFormat.of().formatHex(digest));
    } catch (NoSuchAlgorithmException exception) {
      throw new AssertionError("SHA-256 is unavailable", exception);
    }
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> snapshotPayload(
      final Map<String, Object> payload, final String projectKey) {
    final Map<?, ?> snapshots = (Map<?, ?>) payload.get("snapshots");
    final List<?> values = (List<?>) snapshots.get(projectKey);
    return (Map<String, Object>) values.getFirst();
  }

  static void assertInvalidWithMessage(final Map<String, Object> payload, final String message) {
    Assertions.assertThatThrownBy(() -> ResolverArtifactGraphSnapshotStore.fromPayload(payload))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining(message);
  }

  static void assertInvalid(final Map<String, Object> payload) {
    Assertions.assertThatThrownBy(() -> ResolverArtifactGraphSnapshotStore.fromPayload(payload))
        .isInstanceOf(IllegalStateException.class);
  }
}
