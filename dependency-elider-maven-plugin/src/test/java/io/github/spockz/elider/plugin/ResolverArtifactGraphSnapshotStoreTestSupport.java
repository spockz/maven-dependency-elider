/* WHY: Shares mutable malformed-payload fixtures without weakening production validation. */

package io.github.spockz.elider.plugin;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.eclipse.aether.graph.DefaultDependencyNode;
import org.eclipse.aether.graph.Dependency;
import org.eclipse.aether.graph.DependencyNode;

/** Builds and mutates detached payloads for schema rejection tests. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class ResolverArtifactGraphSnapshotStoreTestSupport {
  /** Stable project key used by the mutable schema fixtures. */
  static final String PROJECT_KEY = "fixture-project";

  private ResolverArtifactGraphSnapshotStoreTestSupport() {
    throw new AssertionError("No instances");
  }

  static Map<String, Object> mutablePayload() {
    final DependencyNode root = node("root");
    root.setChildren(List.of(node("child")));
    final ResolverArtifactGraphSnapshot snapshot =
        ResolverArtifactGraphSnapshot.capture(root, PROJECT_KEY, false, null, 0, 1);
    final ResolverArtifactGraphSnapshotStore store =
        ResolverArtifactGraphSnapshotStore.empty().append(snapshot);
    return (Map<String, Object>) mutableValue(store.toPayload());
  }

  static Map<String, Object> payloadSnapshot(final Map<String, Object> payload) {
    final Map<?, ?> snapshots = (Map<?, ?>) payload.get("snapshots");
    final List<?> values = (List<?>) snapshots.get(PROJECT_KEY);
    return (Map<String, Object>) values.getFirst();
  }

  static Map<String, Object> nodePayload(final Map<String, Object> payload, final int index) {
    final List<?> nodes = (List<?>) payloadSnapshot(payload).get("nodes");
    return (Map<String, Object>) nodes.get(index);
  }

  @SuppressWarnings("unchecked")
  static void putArtifactProperty(
      final Map<String, Object> node, final String name, final Object value) {
    final Map<String, Object> artifact = (Map<String, Object>) node.get("artifact");
    final Map<String, Object> properties = (Map<String, Object>) artifact.get("properties");
    properties.put(name, value);
  }

  @SuppressWarnings("unchecked")
  static void putGeneration(final Map<String, Object> payload, final Long generation) {
    ((Map<String, Object>) payload.get("generations")).put(PROJECT_KEY, generation);
  }

  static DependencyNode node(final String artifactId) {
    return new DefaultDependencyNode(new DefaultArtifact("fixture", artifactId, "", "jar", "1.0"));
  }

  static DependencyNode dependencyNode(final String artifactId, final Boolean optional) {
    return new DefaultDependencyNode(
        new Dependency(
            new DefaultArtifact("fixture", artifactId, "", "jar", "1.0"), "compile", optional));
  }

  @SuppressWarnings("PMD.UseConcurrentHashMap")
  private static Object mutableValue(final Object value) {
    if (value instanceof Map<?, ?> map) {
      // Preserve order and nulls while producing an editable adversarial fixture.
      final Map<String, Object> copy = new LinkedHashMap<>();
      map.forEach((key, entry) -> copy.put((String) key, mutableValue(entry)));
      return copy;
    }
    if (value instanceof List<?> list) {
      final List<Object> copy = new ArrayList<>();
      list.forEach(entry -> copy.add(mutableValue(entry)));
      return copy;
    }
    return value;
  }
}
