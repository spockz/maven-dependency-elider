/* WHY: Recomputes fingerprints so mutated detached structures cannot be accepted as authentic. */

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

/** Recomputes the structural SHA-256 for one graph snapshot. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class ResolverArtifactGraphFingerprintValidator {
  /** Keeps canonical JSON key ordering stable across Maven sessions. */
  private static final ObjectMapper JSON =
      new ObjectMapper().enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS);

  private ResolverArtifactGraphFingerprintValidator() {
    throw new AssertionError("No instances");
  }

  static void validate(
      final String expected, final Object rootNodeId, final List<?> nodes, final List<?> edges) {
    final Map<String, Object> structure = structure(rootNodeId, nodes, edges);
    try {
      final String json = JSON.writeValueAsString(structure);
      final String actual = fingerprint(json);
      if (!expected.equals(actual)) {
        throw ResolverArtifactGraphPayloadChecks.invalid(
            "graph fingerprint does not match snapshot data");
      }
    } catch (JsonProcessingException exception) {
      throw new IllegalStateException("Cannot serialize graph snapshot fingerprint", exception);
    }
  }

  // A linked map keeps canonical field order and accepts a null root ID.
  @SuppressWarnings("PMD.UseConcurrentHashMap")
  private static Map<String, Object> structure(
      final Object rootNodeId, final List<?> nodes, final List<?> edges) {
    final Map<String, Object> structure = new java.util.LinkedHashMap<>();
    structure.put(ResolverArtifactGraphSnapshotSchema.ROOT_NODE_ID, rootNodeId);
    structure.put(ResolverArtifactGraphSnapshotSchema.NODES, nodes);
    structure.put(ResolverArtifactGraphSnapshotSchema.EDGES, edges);
    return structure;
  }

  private static String fingerprint(final String value) {
    try {
      return HexFormat.of()
          .formatHex(
              MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
    } catch (NoSuchAlgorithmException exception) {
      throw new AssertionError("SHA-256 is unavailable", exception);
    }
  }
}
