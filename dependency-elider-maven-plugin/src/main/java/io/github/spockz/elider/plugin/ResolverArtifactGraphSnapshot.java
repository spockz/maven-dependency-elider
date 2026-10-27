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
import java.util.Comparator;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import org.eclipse.aether.artifact.Artifact;
import org.eclipse.aether.graph.Dependency;
import org.eclipse.aether.graph.DependencyNode;
import org.eclipse.aether.graph.Exclusion;
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

  private static final String NODE_DATA_ORIGINAL_SCOPE = ConflictResolver.NODE_DATA_ORIGINAL_SCOPE;

  private static final String NODE_DATA_ORIGINAL_OPTIONALITY =
      ConflictResolver.NODE_DATA_ORIGINAL_OPTIONALITY;

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
    final Map<String, Object> structure = new LinkedHashMap<>();
    structure.put("rootNodeId", traversal.rootNodeId());
    structure.put("nodes", nodePayloads);
    structure.put("edges", edgePayloads);
    return new ResolverArtifactGraphSnapshot(
        sha256(canonicalJson(structure)),
        projectKey,
        planPresent,
        planFingerprint,
        planGeneration,
        generation,
        traversal.rootNodeId(),
        nodePayloads,
        edgePayloads);
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

  private static List<Map<String, Object>> immutableMaps(final List<Map<String, Object>> values) {
    return values.stream()
        .map(value -> Collections.unmodifiableMap(new LinkedHashMap<>(value)))
        .toList();
  }

  private static String canonicalJson(final Object value) {
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
  @SuppressWarnings({"PMD.LooseCoupling", "PMD.TooManyMethods"})
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
        payloads.add(nodePayload(node));
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

    // Dependency carries effective scope; DependencyNode has no scope getter.
    @SuppressWarnings("PMD.LawOfDemeter")
    private Map<String, Object> nodePayload(final DependencyNode node) {
      final Map<String, Object> payload = new LinkedHashMap<>();
      payload.put("id", ids.get(node));
      payload.put("reachable", reachable.contains(node));
      payload.put("artifact", artifactPayload(node.getArtifact()));
      final Dependency dependency = node.getDependency();
      payload.put("dependency", dependencyPayload(dependency));
      payload.put("effectiveScope", dependency == null ? null : dependency.getScope());
      payload.put("managedBits", node.getManagedBits());
      payload.put("versionConstraint", stringValue(node.getVersionConstraint()));
      payload.put("version", stringValue(node.getVersion()));
      payload.put("childrenPresent", node.getChildren() != null);
      payload.put("aliases", artifactList(node.getAliases()));
      payload.put("relocations", artifactList(node.getRelocations()));
      addConflictMetadata(payload, node);
      return Collections.unmodifiableMap(payload);
    }

    private static Map<String, Object> edgePayload(
        final String parentNodeId, final String childNodeId) {
      final Map<String, Object> payload = new LinkedHashMap<>();
      payload.put("parentNodeId", parentNodeId);
      payload.put("childNodeId", childNodeId);
      return Collections.unmodifiableMap(payload);
    }

    private void addConflictMetadata(final Map<String, Object> payload, final DependencyNode node) {
      final Map<?, ?> data = nodeData(node);
      final boolean hasWinner = data.containsKey(NODE_DATA_WINNER);
      final Object winner = data.get(NODE_DATA_WINNER);
      payload.put("conflictWinnerPresent", hasWinner);
      payload.put(
          "conflictWinnerNodeId",
          winner instanceof DependencyNode winnerNode ? ids.get(winnerNode) : null);
      payload.put(
          "conflictWinnerExternalArtifact",
          winner instanceof DependencyNode winnerNode && ids.get(winnerNode) == null
              ? artifactPayload(winnerNode.getArtifact())
              : null);
      payload.put(
          "conflictWinnerValueType",
          winner == null || winner instanceof DependencyNode ? null : winner.getClass().getName());
      payload.put("originalScopePresent", data.containsKey(NODE_DATA_ORIGINAL_SCOPE));
      payload.put("originalScope", stringValue(data.get(NODE_DATA_ORIGINAL_SCOPE)));
      payload.put("originalOptionalityPresent", data.containsKey(NODE_DATA_ORIGINAL_OPTIONALITY));
      final Object originalOptionality = data.get(NODE_DATA_ORIGINAL_OPTIONALITY);
      payload.put(
          "originalOptionality",
          originalOptionality == null || originalOptionality instanceof Boolean
              ? originalOptionality
              : stringValue(originalOptionality));
    }

    private static Map<?, ?> nodeData(final DependencyNode node) {
      final Map<?, ?> data = node.getData();
      return data == null ? Map.of() : data;
    }

    private static Object dependencyPayload(final Dependency dependency) {
      if (dependency == null) {
        return null;
      }
      final Map<String, Object> payload = new LinkedHashMap<>();
      payload.put("artifact", artifactPayload(dependency.getArtifact()));
      payload.put("scope", dependency.getScope());
      payload.put("optional", dependency.getOptional());
      payload.put(
          "exclusions",
          dependency.getExclusions().stream()
              .map(GraphTraversal::exclusionPayload)
              .sorted(Comparator.comparing(ResolverArtifactGraphSnapshot::canonicalJson))
              .toList());
      return Collections.unmodifiableMap(payload);
    }

    private static Map<String, Object> exclusionPayload(final Exclusion exclusion) {
      final Map<String, Object> payload = new LinkedHashMap<>();
      payload.put("groupId", exclusion.getGroupId());
      payload.put("artifactId", exclusion.getArtifactId());
      payload.put("classifier", exclusion.getClassifier());
      payload.put("extension", exclusion.getExtension());
      return Collections.unmodifiableMap(payload);
    }

    private static List<Map<String, Object>> artifactList(
        final Iterable<? extends Artifact> artifacts) {
      final List<Map<String, Object>> payloads = new ArrayList<>();
      if (artifacts != null) {
        for (final Artifact artifact : artifacts) {
          payloads.add(artifactPayload(artifact));
        }
      }
      payloads.sort(Comparator.comparing(ResolverArtifactGraphSnapshot::canonicalJson));
      return List.copyOf(payloads);
    }

    // Null preserves a missing artifact node.
    @SuppressWarnings("PMD.ReturnEmptyCollectionRatherThanNull")
    private static Map<String, Object> artifactPayload(final Artifact artifact) {
      if (artifact == null) {
        return null;
      }
      final Map<String, Object> payload = new LinkedHashMap<>();
      payload.put("groupId", artifact.getGroupId());
      payload.put("artifactId", artifact.getArtifactId());
      payload.put("version", artifact.getVersion());
      payload.put("baseVersion", artifact.getBaseVersion());
      payload.put("extension", artifact.getExtension());
      payload.put("classifier", artifact.getClassifier());
      final Map<String, String> properties = artifact.getProperties();
      payload.put(
          "properties",
          properties == null ? null : Collections.unmodifiableMap(new TreeMap<>(properties)));
      return Collections.unmodifiableMap(payload);
    }

    private static String stringValue(final Object value) {
      return value == null ? null : value.toString();
    }
  }
}
