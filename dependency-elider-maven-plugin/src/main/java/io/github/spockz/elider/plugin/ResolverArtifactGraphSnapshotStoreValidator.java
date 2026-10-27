// WHY: Keeps cross-project invariants separate from immutable store parsing.

package io.github.spockz.elider.plugin;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Checks relationships between decoded snapshots, capture pairs, and generations. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class ResolverArtifactGraphSnapshotStoreValidator {
  private ResolverArtifactGraphSnapshotStoreValidator() {
    throw new AssertionError("No instances");
  }

  static void validate(final ResolverArtifactGraphSnapshotStore store) {
    if (!store.snapshots().keySet().equals(store.capturePairs().keySet())) {
      throw new IllegalStateException("Graph snapshots and capture pairs do not match projects");
    }
    store.snapshots().forEach((projectKey, entries) -> validateProject(store, projectKey, entries));
    if (!store.snapshots().keySet().equals(store.generations().keySet())) {
      throw new IllegalStateException("Graph snapshot generations do not match projects");
    }
  }

  private static void validateProject(
      final ResolverArtifactGraphSnapshotStore store,
      final String projectKey,
      final List<Map<String, Object>> entries) {
    if (entries.isEmpty()) {
      throw new IllegalStateException("Graph snapshot project has no captures");
    }
    final List<Map<String, Object>> pairs = store.capturePairs().get(projectKey);
    if (pairs.size() != entries.size()) {
      throw new IllegalStateException("Graph capture pair count is inconsistent");
    }
    validateProjectCaptures(store, projectKey, entries, pairs);
  }

  private static void validateProjectCaptures(
      final ResolverArtifactGraphSnapshotStore store,
      final String projectKey,
      final List<Map<String, Object>> entries,
      final List<Map<String, Object>> pairs) {
    final Set<String> captureTokens = new HashSet<>();
    for (int index = 0; index < entries.size(); index++) {
      final Map<String, Object> entry = entries.get(index);
      final long expectedGeneration = index + 1L;
      validateCapture(projectKey, entry, pairs.get(index), expectedGeneration, captureTokens);
    }
    if (!Long.valueOf(entries.size()).equals(store.generations().get(projectKey))) {
      throw new IllegalStateException("Graph snapshot store generation is inconsistent");
    }
  }

  private static void validateCapture(
      final String projectKey,
      final Map<String, Object> entry,
      final Map<String, Object> pairPayload,
      final long expectedGeneration,
      final Set<String> captureTokens) {
    ResolverArtifactGraphSnapshotPayloadValidator.validate(entry, projectKey);
    if (!Long.valueOf(expectedGeneration).equals(entry.get("captureGeneration"))) {
      throw new IllegalStateException("Graph snapshot capture generations are inconsistent");
    }
    final ResolverArtifactGraphCapturePair pair =
        ResolverArtifactGraphCapturePair.fromPayload(pairPayload);
    if (!pair.projectKey().equals(projectKey)
        || pair.captureGeneration() != expectedGeneration
        || !pair.after().toPayload().equals(entry)
        || !captureTokens.add(pair.captureToken())) {
      throw new IllegalStateException("Graph capture pair provenance is inconsistent");
    }
  }
}
