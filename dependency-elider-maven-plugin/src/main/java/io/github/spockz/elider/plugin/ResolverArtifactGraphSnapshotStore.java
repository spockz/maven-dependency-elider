/* WHY: Stores detached graphs in Maven session data. */

package io.github.spockz.elider.plugin;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/** Immutable project-scoped graph snapshot store. */
// Ordered maps keep the immutable JDK payload deterministic.
@SuppressWarnings({
  "PMD.CommentDefaultAccessModifier",
  "PMD.CommentRequired",
  "PMD.UseConcurrentHashMap"
})
record ResolverArtifactGraphSnapshotStore(
    Map<String, List<Map<String, Object>>> snapshots, Map<String, Long> generations) {
  private static final int SCHEMA_VERSION = 1;

  private static final String SCHEMA_FIELD = "schemaVersion";

  private static final String SNAPSHOTS_FIELD = "snapshots";

  private static final String GENERATIONS_FIELD = "generations";

  ResolverArtifactGraphSnapshotStore {
    Objects.requireNonNull(snapshots, "snapshots");
    Objects.requireNonNull(generations, "generations");
    final Map<String, List<Map<String, Object>>> snapshotCopy = new LinkedHashMap<>();
    snapshots.forEach(
        (projectKey, values) ->
            snapshotCopy.put(
                projectKey,
                values.stream().map(ResolverArtifactGraphSnapshotStore::immutableMap).toList()));
    snapshots = Collections.unmodifiableMap(snapshotCopy);
    generations = Collections.unmodifiableMap(new LinkedHashMap<>(generations));
  }

  static ResolverArtifactGraphSnapshotStore empty() {
    return new ResolverArtifactGraphSnapshotStore(Map.of(), Map.of());
  }

  static ResolverArtifactGraphSnapshotStore fromPayload(final Object payload) {
    if (payload == null) {
      return empty();
    }
    final Map<?, ?> root = requireMap(payload, "graph snapshot store");
    if (!Integer.valueOf(SCHEMA_VERSION).equals(root.get(SCHEMA_FIELD))) {
      throw new IllegalStateException("Unsupported graph snapshot store schema");
    }
    final Map<String, List<Map<String, Object>>> snapshots = new LinkedHashMap<>();
    requireMap(root.get(SNAPSHOTS_FIELD), SNAPSHOTS_FIELD)
        .forEach(
            (projectKeyValue, entriesValue) -> {
              final String projectKey = requireString(projectKeyValue, "project key");
              final List<Map<String, Object>> entries =
                  requireList(entriesValue, "project snapshots").stream()
                      .map(value -> immutableMap(requireObjectMap(value, "snapshot")))
                      .toList();
              snapshots.put(projectKey, entries);
            });
    final Map<String, Long> generations = new LinkedHashMap<>();
    requireMap(root.get(GENERATIONS_FIELD), GENERATIONS_FIELD)
        .forEach(
            (projectKeyValue, generationValue) -> {
              final String projectKey = requireString(projectKeyValue, "project key");
              if (!(generationValue instanceof Long generation) || generation < 0) {
                throw new IllegalStateException("Invalid graph snapshot generation");
              }
              generations.put(projectKey, generation);
            });
    return new ResolverArtifactGraphSnapshotStore(snapshots, generations);
  }

  long nextGeneration(final String projectKey) {
    return generations.getOrDefault(Objects.requireNonNull(projectKey, "projectKey"), 0L) + 1L;
  }

  ResolverArtifactGraphSnapshotStore append(final ResolverArtifactGraphSnapshot snapshot) {
    Objects.requireNonNull(snapshot, "snapshot");
    final String projectKey = snapshot.projectKey();
    final Map<String, Object> payload = snapshot.toPayload();
    final List<Map<String, Object>> current = snapshots.getOrDefault(projectKey, List.of());
    if (current.stream().anyMatch(existing -> sameCapture(existing, payload))) {
      return this;
    }
    final Map<String, List<Map<String, Object>>> nextSnapshots = new LinkedHashMap<>(snapshots);
    final List<Map<String, Object>> updated = new ArrayList<>(current);
    updated.add(payload);
    nextSnapshots.put(projectKey, List.copyOf(updated));
    final Map<String, Long> nextGenerations = new LinkedHashMap<>(generations);
    nextGenerations.put(projectKey, snapshot.captureGeneration());
    return new ResolverArtifactGraphSnapshotStore(nextSnapshots, nextGenerations);
  }

  Map<String, Object> toPayload() {
    final Map<String, Object> payload = new LinkedHashMap<>();
    payload.put(SCHEMA_FIELD, SCHEMA_VERSION);
    payload.put(SNAPSHOTS_FIELD, snapshots);
    payload.put(GENERATIONS_FIELD, generations);
    return Collections.unmodifiableMap(payload);
  }

  private static boolean sameCapture(
      final Map<String, Object> left, final Map<String, Object> right) {
    return Objects.equals(left.get("graphFingerprint"), right.get("graphFingerprint"))
        && Objects.equals(left.get("planPresent"), right.get("planPresent"))
        && Objects.equals(left.get("planFingerprint"), right.get("planFingerprint"))
        && Objects.equals(left.get("planGeneration"), right.get("planGeneration"));
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
              throw new IllegalStateException("Graph snapshot map key must be a string");
            }
            copy.put(stringKey, immutableValue(entry));
          });
      return Collections.unmodifiableMap(copy);
    }
    if (value instanceof List<?> raw) {
      return raw.stream().map(ResolverArtifactGraphSnapshotStore::immutableValue).toList();
    }
    throw new IllegalStateException(
        "Graph snapshot payload contains a non-JDK value: " + value.getClass().getName());
  }

  private static Map<?, ?> requireMap(final Object value, final String field) {
    if (value instanceof Map<?, ?> result) {
      return result;
    }
    throw new IllegalStateException(field + " must be a map");
  }

  private static Map<String, Object> requireObjectMap(final Object value, final String field) {
    final Map<?, ?> raw = requireMap(value, field);
    final Map<String, Object> result = new LinkedHashMap<>();
    raw.forEach(
        (key, entry) -> {
          if (!(key instanceof String stringKey)) {
            throw new IllegalStateException(field + " contains a non-string key");
          }
          result.put(stringKey, entry);
        });
    return result;
  }

  private static List<?> requireList(final Object value, final String field) {
    if (value instanceof List<?> result) {
      return result;
    }
    throw new IllegalStateException(field + " must be a list");
  }

  private static String requireString(final Object value, final String field) {
    if (value instanceof String result) {
      return result;
    }
    throw new IllegalStateException(field + " must be a string");
  }
}
