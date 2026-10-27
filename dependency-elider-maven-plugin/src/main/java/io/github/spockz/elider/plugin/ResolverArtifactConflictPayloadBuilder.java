/* WHY: Keeps Maven conflict metadata serialization separate from ordinary artifact coordinates. */

package io.github.spockz.elider.plugin;

import java.util.Map;
import org.eclipse.aether.graph.DependencyNode;
import org.eclipse.aether.util.graph.transformer.ConflictResolver;

/** Appends the known conflict-resolution provenance fields for a node. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class ResolverArtifactConflictPayloadBuilder {
  private ResolverArtifactConflictPayloadBuilder() {
    throw new AssertionError("No instances");
  }

  static void add(
      final Map<String, Object> payload,
      final DependencyNode node,
      final Map<DependencyNode, String> nodeIds) {
    final Map<?, ?> data = nodeData(node);
    final boolean hasWinner = data.containsKey(ConflictResolver.NODE_DATA_WINNER);
    final Object winner = data.get(ConflictResolver.NODE_DATA_WINNER);
    payload.put("conflictWinnerPresent", hasWinner);
    payload.put(
        "conflictWinnerNodeId",
        winner instanceof DependencyNode winnerNode ? nodeIds.get(winnerNode) : null);
    payload.put(
        "conflictWinnerExternalArtifact",
        winner instanceof DependencyNode winnerNode && nodeIds.get(winnerNode) == null
            ? ResolverArtifactValuePayloadBuilder.artifact(winnerNode.getArtifact())
            : null);
    payload.put(
        "conflictWinnerValueType",
        winner == null || winner instanceof DependencyNode ? null : winner.getClass().getName());
    payload.put(
        "originalScopePresent", data.containsKey(ConflictResolver.NODE_DATA_ORIGINAL_SCOPE));
    payload.put(
        "originalScope", metadataString(data.get(ConflictResolver.NODE_DATA_ORIGINAL_SCOPE)));
    payload.put(
        "originalOptionalityPresent",
        data.containsKey(ConflictResolver.NODE_DATA_ORIGINAL_OPTIONALITY));
    payload.put(
        "originalOptionality",
        metadataOptionality(data.get(ConflictResolver.NODE_DATA_ORIGINAL_OPTIONALITY)));
  }

  private static Map<?, ?> nodeData(final DependencyNode node) {
    final Map<?, ?> data = node.getData();
    return data == null ? Map.of() : data;
  }

  private static String metadataString(final Object value) {
    if (value == null || value instanceof String) {
      return (String) value;
    }
    throw new IllegalArgumentException("Unsupported original scope metadata type");
  }

  private static Object metadataOptionality(final Object value) {
    if (value == null || value instanceof Boolean || value instanceof String) {
      return value;
    }
    throw new IllegalArgumentException("Unsupported original optionality metadata type");
  }
}
