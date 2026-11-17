/* WHY: Converts Resolver artifact-shaped values into stable detached JDK
 * payloads. */

package io.github.spockz.elider.plugin;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import org.eclipse.aether.artifact.Artifact;
import org.eclipse.aether.graph.Dependency;
import org.eclipse.aether.graph.DependencyNode;
import org.eclipse.aether.graph.Exclusion;
import org.eclipse.aether.util.graph.transformer.ConflictResolver;

/** Serializes artifacts, dependencies, exclusions, aliases, and relocations. */
// Ordered maps preserve schema field order and nullable payload values.
@SuppressWarnings({"PMD.CommentDefaultAccessModifier", "PMD.UseConcurrentHashMap"})
final class ResolverArtifactValuePayloadBuilder {
  private ResolverArtifactValuePayloadBuilder() {
    throw new AssertionError("No instances");
  }

  @SuppressWarnings({"PMD.UseConcurrentHashMap", "PMD.LawOfDemeter"})
  static Map<String, Object> nodePayload(
      final DependencyNode node,
      final Map<DependencyNode, String> nodeIds,
      final Set<DependencyNode> reachableNodes) {
    // Linked order preserves schema order and permits explicit null metadata.
    final Map<String, Object> payload = new LinkedHashMap<>();
    payload.put("id", nodeIds.get(node));
    payload.put("reachable", reachableNodes.contains(node));
    payload.put("artifact", artifact(node.getArtifact()));
    final Dependency dependency = node.getDependency();
    payload.put("dependency", dependency(dependency));
    payload.put("effectiveScope", dependency == null ? null : dependency.getScope());
    payload.put("managedBits", node.getManagedBits());
    payload.put("versionConstraint", stringValue(node.getVersionConstraint()));
    payload.put("version", stringValue(node.getVersion()));
    payload.put("childrenPresent", node.getChildren() != null);
    payload.put("aliases", artifactSet(node.getAliases()));
    payload.put("relocations", artifactSequence(node.getRelocations()));
    addConflictMetadata(payload, node, nodeIds);
    return Collections.unmodifiableMap(payload);
  }

  private static void addConflictMetadata(
      final Map<String, Object> payload,
      final DependencyNode node,
      final Map<DependencyNode, String> nodeIds) {
    final Map<?, ?> rawData = node.getData();
    final Map<?, ?> data = rawData == null ? Map.of() : rawData;
    final boolean hasWinner = data.containsKey(ConflictResolver.NODE_DATA_WINNER);
    final Object winner = data.get(ConflictResolver.NODE_DATA_WINNER);
    payload.put("conflictWinnerPresent", hasWinner);
    payload.put(
        "conflictWinnerNodeId",
        winner instanceof DependencyNode winnerNode ? nodeIds.get(winnerNode) : null);
    payload.put(
        "conflictWinnerExternalArtifact",
        winner instanceof DependencyNode winnerNode && nodeIds.get(winnerNode) == null
            ? artifact(winnerNode.getArtifact())
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

  static Object dependency(final Dependency dependency) {
    if (dependency == null) {
      return null;
    }
    final Map<String, Object> payload = new LinkedHashMap<>();
    payload.put("artifact", artifact(dependency.getArtifact()));
    payload.put("scope", dependency.getScope());
    payload.put("optional", dependency.getOptional());
    payload.put(
        "exclusions",
        dependency.getExclusions().stream()
            .map(ResolverArtifactValuePayloadBuilder::exclusion)
            .sorted(Comparator.comparing(ResolverArtifactGraphSnapshot::canonicalJson))
            .toList());
    return Collections.unmodifiableMap(payload);
  }

  static List<Map<String, Object>> artifactSet(final Iterable<? extends Artifact> artifacts) {
    return artifactSequence(artifacts).stream()
        .sorted(Comparator.comparing(ResolverArtifactGraphSnapshot::canonicalJson))
        .toList();
  }

  static List<Map<String, Object>> artifactSequence(final Iterable<? extends Artifact> artifacts) {
    final List<Map<String, Object>> payloads = new ArrayList<>();
    if (artifacts != null) {
      for (final Artifact artifact : artifacts) {
        payloads.add(artifact(artifact));
      }
    }
    return List.copyOf(payloads);
  }

  static String stringValue(final Object value) {
    return value == null ? null : value.toString();
  }

  @SuppressWarnings("PMD.ReturnEmptyCollectionRatherThanNull")
  static Map<String, Object> artifact(final Artifact artifact) {
    if (artifact == null) {
      return null;
    }
    // Linked order permits nullable coordinates and fixes the serialized field order.
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

  private static Map<String, Object> exclusion(final Exclusion exclusion) {
    final Map<String, Object> payload = new LinkedHashMap<>();
    payload.put("groupId", exclusion.getGroupId());
    payload.put("artifactId", exclusion.getArtifactId());
    payload.put("classifier", exclusion.getClassifier());
    payload.put("extension", exclusion.getExtension());
    return Collections.unmodifiableMap(payload);
  }
}
