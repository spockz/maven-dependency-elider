/* WHY: Captures Maven's mediated dependency graph as detached values without changing it. */

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.eclipse.aether.graph.DependencyNode;
import org.eclipse.aether.util.graph.transformer.ConflictResolver;

/** Immutable JDK-only view of one transformed dependency graph. */
@SuppressWarnings({
  "PMD.CommentDefaultAccessModifier",
  "PMD.CommentRequired",
  "PMD.UseConcurrentHashMap"
})
record ResolverArtifactGraphSnapshot(
    String graphFingerprint,
    String projectKey,
    boolean planPresent,
    String planFingerprint,
    long planGeneration,
    long captureGeneration,
    String rootNodeId,
    List<Map<String, Object>> nodes,
    List<Map<String, Object>> edges) {
  private static final ObjectMapper JSON =
      new ObjectMapper().enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS);

  private static final String NODE_DATA_WINNER = ConflictResolver.NODE_DATA_WINNER;

  ResolverArtifactGraphSnapshot {
    Objects.requireNonNull(graphFingerprint, "graphFingerprint");
    Objects.requireNonNull(projectKey, "projectKey");
    if (planPresent != (planFingerprint != null)) {
      throw new IllegalArgumentException("Plan presence and fingerprint disagree");
    }
    nodes = immutableMaps(nodes);
    edges = immutableMaps(edges);
  }

  static ResolverArtifactGraphSnapshot capture(
      final DependencyNode root,
      final String projectKey,
      final boolean planPresent,
      final String planFingerprint,
      final long planGeneration,
      final long generation) {
    final GraphTraversal traversal = GraphTraversal.of(root);
    final List<Map<String, Object>> nodePayloads = traversal.nodePayloads();
    final List<Map<String, Object>> edgePayloads = traversal.edgePayloads();
    return new ResolverArtifactGraphSnapshot(
        structuralFingerprint(traversal.rootNodeId(), nodePayloads, edgePayloads),
        projectKey,
        planPresent,
        planFingerprint,
        planGeneration,
        generation,
        traversal.rootNodeId(),
        nodePayloads,
        edgePayloads);
  }

  static String structuralFingerprint(
      final String rootNodeId,
      final List<Map<String, Object>> nodes,
      final List<Map<String, Object>> edges) {
    final Map<String, Object> structure = new LinkedHashMap<>();
    structure.put("rootNodeId", rootNodeId);
    structure.put("nodes", nodes);
    structure.put("edges", edges);
    return sha256(canonicalJson(structure));
  }

  Map<String, Object> toPayload() {
    final Map<String, Object> payload = new LinkedHashMap<>();
    payload.put("graphFingerprint", graphFingerprint);
    payload.put("projectKey", projectKey);
    payload.put("planPresent", planPresent);
    payload.put("planFingerprint", planFingerprint);
    payload.put("planGeneration", planGeneration);
    payload.put("captureGeneration", captureGeneration);
    payload.put("rootNodeId", rootNodeId);
    payload.put("nodes", nodes);
    payload.put("edges", edges);
    return Collections.unmodifiableMap(payload);
  }

  ResolverArtifactGraphSnapshot withCaptureGeneration(final long generation) {
    return new ResolverArtifactGraphSnapshot(
        graphFingerprint,
        projectKey,
        planPresent,
        planFingerprint,
        planGeneration,
        generation,
        rootNodeId,
        nodes,
        edges);
  }

  static ResolverArtifactGraphSnapshot fromPayload(
      final Object rawPayload, final String expectedProjectKey) {
    if (!(rawPayload instanceof Map<?, ?> raw)) {
      throw new IllegalStateException("Graph snapshot must be an object");
    }
    final Map<String, Object> payload = new LinkedHashMap<>();
    raw.forEach(
        (key, value) -> {
          if (!(key instanceof String stringKey)) {
            throw new IllegalStateException("Graph snapshot field must be a string");
          }
          payload.put(stringKey, value);
        });
    ResolverArtifactGraphSnapshotPayloadValidator.validate(payload, expectedProjectKey);
    return new ResolverArtifactGraphSnapshot(
        (String) payload.get(ResolverArtifactGraphSnapshotSchema.GRAPH_FINGERPRINT),
        (String) payload.get(ResolverArtifactGraphSnapshotSchema.PROJECT_KEY),
        (Boolean) payload.get(ResolverArtifactGraphSnapshotSchema.PLAN_PRESENT),
        (String) payload.get(ResolverArtifactGraphSnapshotSchema.PLAN_FINGERPRINT),
        (Long) payload.get(ResolverArtifactGraphSnapshotSchema.PLAN_GENERATION),
        (Long) payload.get(ResolverArtifactGraphSnapshotSchema.CAPTURE_GENERATION),
        (String) payload.get(ResolverArtifactGraphSnapshotSchema.ROOT_NODE_ID),
        castMaps(payload.get(ResolverArtifactGraphSnapshotSchema.NODES)),
        castMaps(payload.get(ResolverArtifactGraphSnapshotSchema.EDGES)));
  }

  @SuppressWarnings("unchecked")
  private static List<Map<String, Object>> castMaps(final Object value) {
    return (List<Map<String, Object>>) value;
  }

  private static List<Map<String, Object>> immutableMaps(final List<Map<String, Object>> values) {
    return values.stream().map(ResolverArtifactGraphSnapshot::immutableMap).toList();
  }

  private static Map<String, Object> immutableMap(final Map<String, Object> value) {
    final Map<String, Object> copy = new LinkedHashMap<>();
    value.forEach((key, entry) -> copy.put(key, immutableValue(entry)));
    return Collections.unmodifiableMap(copy);
  }

  private static Object immutableValue(final Object value) {
    if (value == null
        || value instanceof String
        || value instanceof Boolean
        || value instanceof Integer
        || value instanceof Long) {
      return value;
    }
    if (value instanceof Map<?, ?> raw) {
      final Map<String, Object> copy = new LinkedHashMap<>();
      raw.forEach(
          (key, entry) -> {
            if (!(key instanceof String stringKey)) {
              throw new IllegalArgumentException("Graph snapshot map key must be a string");
            }
            copy.put(stringKey, immutableValue(entry));
          });
      return Collections.unmodifiableMap(copy);
    }
    if (value instanceof List<?> raw) {
      return raw.stream().map(ResolverArtifactGraphSnapshot::immutableValue).toList();
    }
    throw new IllegalArgumentException(
        "Graph snapshot contains a non-JDK value: " + value.getClass().getName());
  }

  static String canonicalJson(final Object value) {
    try {
      return JSON.writeValueAsString(value);
    } catch (JsonProcessingException exception) {
      throw new IllegalStateException("Cannot serialize graph snapshot fingerprint", exception);
    }
  }

  private static String sha256(final String value) {
    try {
      return java.util.HexFormat.of()
          .formatHex(
              MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
    } catch (NoSuchAlgorithmException exception) {
      throw new AssertionError("SHA-256 is unavailable", exception);
    }
  }

  // Identity maps and FIFO traversal preserve references and child order.
  @SuppressWarnings("PMD.LooseCoupling")
  private static final class GraphTraversal {
    private final DependencyNode root;

    private final IdentityHashMap<DependencyNode, String> ids = new IdentityHashMap<>();

    private final Set<DependencyNode> reachable =
        Collections.newSetFromMap(new IdentityHashMap<>());

    private final List<DependencyNode> nodes = new ArrayList<>();

    private final List<Map<String, Object>> edges = new ArrayList<>();

    private GraphTraversal(final DependencyNode root) {
      this.root = root;
      visitReachableNodes();
      addExternalWinnerNodes();
    }

    static GraphTraversal of(final DependencyNode root) {
      return new GraphTraversal(root);
    }

    String rootNodeId() {
      return root == null ? null : ids.get(root);
    }

    List<Map<String, Object>> nodePayloads() {
      final List<Map<String, Object>> payloads = new ArrayList<>();
      for (final DependencyNode node : nodes) {
        payloads.add(ResolverArtifactGraphNodeSnapshotBuilder.payload(node, ids, reachable));
      }
      return List.copyOf(payloads);
    }

    List<Map<String, Object>> edgePayloads() {
      return immutableMaps(edges);
    }

    private void visitReachableNodes() {
      if (root == null) {
        return;
      }
      final ArrayDeque<DependencyNode> queue = new ArrayDeque<>();
      assign(root, true);
      queue.add(root);
      while (!queue.isEmpty()) {
        final DependencyNode parent = queue.removeFirst();
        final List<DependencyNode> children = parent.getChildren();
        if (children == null) {
          continue;
        }
        for (final DependencyNode child : children) {
          if (child == null) {
            edges.add(edgePayload(ids.get(parent), null));
            continue;
          }
          final boolean unseen = !reachable.contains(child);
          final String childId = assign(child, true);
          edges.add(edgePayload(ids.get(parent), childId));
          if (unseen) {
            queue.addLast(child);
          }
        }
      }
    }

    private void addExternalWinnerNodes() {
      final int reachableCount = nodes.size();
      for (int index = 0; index < reachableCount; index++) {
        final Object winner = nodeData(nodes.get(index)).get(NODE_DATA_WINNER);
        if (winner instanceof DependencyNode winnerNode) {
          assign(winnerNode, false);
        }
      }
    }

    private static Map<?, ?> nodeData(final DependencyNode node) {
      final Map<?, ?> data = node.getData();
      return data == null ? Map.of() : data;
    }

    private String assign(final DependencyNode node, final boolean isReachable) {
      String nodeId = ids.get(node);
      if (nodeId == null) {
        nodeId = "n" + nodes.size();
        ids.put(node, nodeId);
        nodes.add(node);
      }
      if (isReachable) {
        reachable.add(node);
      }
      return nodeId;
    }

    private static Map<String, Object> edgePayload(
        final String parentNodeId, final String childNodeId) {
      final Map<String, Object> payload = new LinkedHashMap<>();
      payload.put("parentNodeId", parentNodeId);
      payload.put("childNodeId", childNodeId);
      return Collections.unmodifiableMap(payload);
    }
  }
}
