// WHY: Carries each artifact's class names from ZIP scanning to later pruning without exposing ZIP
// internals.

package io.github.spockz.elider.scanner;

import io.github.spockz.elider.model.ArtifactFileRef;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/** Maps each resolved artifact to its class names in dotted notation. */
public record ArtifactClassIndex(Map<ArtifactFileRef, Set<String>> classesByArtifact) {
  /** Copies the mapping and each class set so callers cannot mutate the index. */
  public ArtifactClassIndex {
    Objects.requireNonNull(classesByArtifact, "classesByArtifact must not be null");
    classesByArtifact =
        classesByArtifact.entrySet().stream()
            .collect(
                java.util.stream.Collectors.toUnmodifiableMap(
                    Map.Entry::getKey, entry -> Set.copyOf(entry.getValue())));
  }

  /** Returns the classes found in an artifact, or an empty set if it was not indexed. */
  public Set<String> classesFor(final ArtifactFileRef artifact) {
    return classesByArtifact.getOrDefault(artifact, Set.of());
  }

  /** Returns an immutable copy of the artifact-to-class mapping. */
  @Override
  public Map<ArtifactFileRef, Set<String>> classesByArtifact() {
    return Map.copyOf(classesByArtifact);
  }
}
