/* WHY: Converts Resolver artifact-shaped values into stable detached JDK payloads. */

package io.github.spockz.elider.plugin;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.eclipse.aether.artifact.Artifact;
import org.eclipse.aether.graph.Dependency;
import org.eclipse.aether.graph.Exclusion;

/** Serializes artifacts, dependencies, exclusions, aliases, and relocations. */
// Ordered maps preserve schema field order and nullable payload values.
@SuppressWarnings({"PMD.CommentDefaultAccessModifier", "PMD.UseConcurrentHashMap"})
final class ResolverArtifactValuePayloadBuilder {
  private ResolverArtifactValuePayloadBuilder() {
    throw new AssertionError("No instances");
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
