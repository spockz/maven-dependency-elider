/* WHY: Serializes Aether nodes while keeping traversal and metadata rules separate. */

package io.github.spockz.elider.plugin;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import org.eclipse.aether.graph.Dependency;
import org.eclipse.aether.graph.DependencyNode;

/** Builds one detached Resolver node payload. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class ResolverArtifactGraphNodeSnapshotBuilder {
  private ResolverArtifactGraphNodeSnapshotBuilder() {
    throw new AssertionError("No instances");
  }

  @SuppressWarnings({"PMD.UseConcurrentHashMap", "PMD.LawOfDemeter"})
  static Map<String, Object> payload(
      final DependencyNode node,
      final Map<DependencyNode, String> nodeIds,
      final Set<DependencyNode> reachableNodes) {
    // Linked order preserves schema order and permits explicit null metadata.
    final Map<String, Object> payload = new LinkedHashMap<>();
    payload.put("id", nodeIds.get(node));
    payload.put("reachable", reachableNodes.contains(node));
    payload.put("artifact", ResolverArtifactValuePayloadBuilder.artifact(node.getArtifact()));
    final Dependency dependency = node.getDependency();
    payload.put("dependency", ResolverArtifactValuePayloadBuilder.dependency(dependency));
    payload.put("effectiveScope", dependency == null ? null : dependency.getScope());
    payload.put("managedBits", node.getManagedBits());
    payload.put(
        "versionConstraint",
        ResolverArtifactValuePayloadBuilder.stringValue(node.getVersionConstraint()));
    payload.put("version", ResolverArtifactValuePayloadBuilder.stringValue(node.getVersion()));
    payload.put("childrenPresent", node.getChildren() != null);
    payload.put("aliases", ResolverArtifactValuePayloadBuilder.artifactSet(node.getAliases()));
    payload.put(
        "relocations", ResolverArtifactValuePayloadBuilder.artifactSequence(node.getRelocations()));
    ResolverArtifactConflictPayloadBuilder.add(payload, node, nodeIds);
    return Collections.unmodifiableMap(payload);
  }
}
