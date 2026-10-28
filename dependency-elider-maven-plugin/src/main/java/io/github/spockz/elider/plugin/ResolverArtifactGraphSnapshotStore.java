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
    Map<String, List<Map<String, Object>>> snapshots,
    Map<String, Long> generations,
    Map<String, PlanObservation> observations,
    Map<String, List<Map<String, Object>>> capturePairs) {
  private static final int SCHEMA_VERSION = 1;

  private static final String SCHEMA_FIELD = "schemaVersion";

  private static final String SNAPSHOTS_FIELD = "snapshots";

  private static final String GENERATIONS_FIELD = "generations";

  private static final String OBSERVATIONS_FIELD = "planObservations";

  private static final String CAPTURE_PAIRS_FIELD = "capturePairs";

  ResolverArtifactGraphSnapshotStore {
    Objects.requireNonNull(snapshots, "snapshots");
    Objects.requireNonNull(generations, "generations");
    Objects.requireNonNull(observations, "observations");
    Objects.requireNonNull(capturePairs, "capturePairs");
    final Map<String, List<Map<String, Object>>> snapshotCopy = new LinkedHashMap<>();
    snapshots.forEach(
        (projectKey, values) ->
            snapshotCopy.put(
                projectKey,
                values.stream().map(ResolverArtifactGraphSnapshotStore::immutableMap).toList()));
    snapshots = Collections.unmodifiableMap(snapshotCopy);
    generations = Collections.unmodifiableMap(new LinkedHashMap<>(generations));
    observations = Collections.unmodifiableMap(new LinkedHashMap<>(observations));
    final Map<String, List<Map<String, Object>>> pairCopy = new LinkedHashMap<>();
    capturePairs.forEach(
        (projectKey, values) ->
            pairCopy.put(
                projectKey,
                values.stream().map(ResolverArtifactGraphSnapshotStore::immutableMap).toList()));
    capturePairs = Collections.unmodifiableMap(pairCopy);
  }

  static ResolverArtifactGraphSnapshotStore empty() {
    return new ResolverArtifactGraphSnapshotStore(Map.of(), Map.of(), Map.of(), Map.of());
  }

  static ResolverArtifactGraphSnapshotStore fromPayload(final Object payload) {
    if (payload == null) {
      return empty();
    }
    final Map<?, ?> root = requireMap(payload, "graph snapshot store");
    if (!root.keySet()
        .equals(
            java.util.Set.of(
                SCHEMA_FIELD,
                SNAPSHOTS_FIELD,
                GENERATIONS_FIELD,
                OBSERVATIONS_FIELD,
                CAPTURE_PAIRS_FIELD))) {
      throw new IllegalStateException("Graph snapshot store fields do not match the schema");
    }
    if (!Integer.valueOf(SCHEMA_VERSION).equals(root.get(SCHEMA_FIELD))) {
      throw new IllegalStateException("Unsupported graph snapshot store schema");
    }
    final ResolverArtifactGraphSnapshotStore store =
        new ResolverArtifactGraphSnapshotStore(
            parseSnapshots(root.get(SNAPSHOTS_FIELD)),
            parseGenerations(root.get(GENERATIONS_FIELD)),
            parseObservations(root.get(OBSERVATIONS_FIELD)),
            parseCapturePairs(root.get(CAPTURE_PAIRS_FIELD)));
    ResolverArtifactGraphSnapshotStoreValidator.validate(store);
    return store;
  }

  private static Map<String, List<Map<String, Object>>> parseSnapshots(final Object value) {
    final Map<String, List<Map<String, Object>>> snapshots = new LinkedHashMap<>();
    requireMap(value, SNAPSHOTS_FIELD)
        .forEach(
            (key, entriesValue) -> {
              final String projectKey = requireString(key, "project key");
              final List<Map<String, Object>> entries =
                  requireList(entriesValue, "project snapshots").stream()
                      .map(entry -> immutableMap(requireObjectMap(entry, "snapshot")))
                      .toList();
              snapshots.put(projectKey, entries);
            });
    return snapshots;
  }

  private static Map<String, Long> parseGenerations(final Object value) {
    final Map<String, Long> generations = new LinkedHashMap<>();
    requireMap(value, GENERATIONS_FIELD)
        .forEach(
            (key, generationValue) -> {
              final String projectKey = requireString(key, "project key");
              if (!(generationValue instanceof Long generation) || generation < 0) {
                throw new IllegalStateException("Invalid graph snapshot generation");
              }
              generations.put(projectKey, generation);
            });
    return generations;
  }

  private static Map<String, PlanObservation> parseObservations(final Object value) {
    final Map<String, PlanObservation> observations = new LinkedHashMap<>();
    requireMap(value, OBSERVATIONS_FIELD)
        .forEach(
            (key, observationValue) -> {
              final String projectKey = requireString(key, "observation project key");
              final PlanObservation observation = parseObservation(observationValue);
              observations.put(projectKey, observation);
            });
    return observations;
  }

  private static Map<String, List<Map<String, Object>>> parseCapturePairs(final Object value) {
    final Map<String, List<Map<String, Object>>> pairs = new LinkedHashMap<>();
    requireMap(value, CAPTURE_PAIRS_FIELD)
        .forEach(
            (key, pairValues) -> {
              final String projectKey = requireString(key, "capture pair project key");
              final List<Map<String, Object>> decoded =
                  requireList(pairValues, "project capture pairs").stream()
                      .map(entry -> immutableMap(requireObjectMap(entry, "capture pair")))
                      .toList();
              pairs.put(projectKey, decoded);
            });
    return pairs;
  }

  private static PlanObservation parseObservation(final Object value) {
    final Map<?, ?> observation = requireMap(value, "plan observation");
    final boolean present = parsePresence(observation.get("present"));
    final String fingerprint = parseFingerprint(observation.get("fingerprint"));
    final long generation = parsePlanGeneration(observation.get("generation"));
    validateObservation(observation, present, fingerprint, generation);
    return new PlanObservation(present, fingerprint, generation);
  }

  private static boolean parsePresence(final Object value) {
    if (value instanceof Boolean result) {
      return result;
    }
    throw new IllegalStateException("Invalid plan observation presence");
  }

  private static String parseFingerprint(final Object value) {
    if (value == null || value instanceof String) {
      return (String) value;
    }
    throw new IllegalStateException("Invalid plan observation fingerprint");
  }

  private static long parsePlanGeneration(final Object value) {
    if (value instanceof Long generation && generation >= 0) {
      return generation;
    }
    throw new IllegalStateException("Invalid plan observation generation");
  }

  private static void validateObservation(
      final Map<?, ?> observation,
      final boolean present,
      final String fingerprint,
      final long generation) {
    if (present != (fingerprint != null)
        || (fingerprint != null && !fingerprint.matches("[0-9a-f]{64}"))
        || (present && generation == 0L)
        || !observation.keySet().equals(java.util.Set.of("present", "fingerprint", "generation"))) {
      throw new IllegalStateException("Inconsistent plan observation");
    }
  }

  long nextGeneration(final String projectKey) {
    return generations.getOrDefault(Objects.requireNonNull(projectKey, "projectKey"), 0L) + 1L;
  }

  PlanObservation observePlan(
      final String projectKey, final boolean planPresent, final String planFingerprint) {
    if (planPresent != (planFingerprint != null)) {
      throw new IllegalArgumentException("Plan presence and fingerprint disagree");
    }
    final PlanObservation previous =
        observations.getOrDefault(projectKey, new PlanObservation(false, null, 0L));
    if (previous.present() == planPresent
        && Objects.equals(previous.fingerprint(), planFingerprint)) {
      return previous;
    }
    return new PlanObservation(planPresent, planFingerprint, previous.generation() + 1L);
  }

  ResolverArtifactGraphSnapshotStore withObservation(
      final String projectKey, final PlanObservation observation) {
    final Map<String, PlanObservation> nextObservations = new LinkedHashMap<>(observations);
    nextObservations.put(projectKey, observation);
    return new ResolverArtifactGraphSnapshotStore(
        snapshots, generations, nextObservations, capturePairs);
  }

  ResolverArtifactGraphSnapshotStore append(final ResolverArtifactGraphSnapshot snapshot) {
    Objects.requireNonNull(snapshot, "snapshot");
    final String token =
        "single-"
            + snapshot.projectKey().length()
            + ":"
            + snapshot.projectKey()
            + "-"
            + snapshot.captureGeneration();
    return append(
        new ResolverArtifactGraphCapturePair(
            snapshot.projectKey(),
            token,
            snapshot.captureGeneration(),
            snapshot.planPresent(),
            snapshot.planFingerprint(),
            snapshot.planGeneration(),
            snapshot,
            snapshot));
  }

  ResolverArtifactGraphSnapshotStore append(final ResolverArtifactGraphCapturePair pair) {
    Objects.requireNonNull(pair, "pair");
    final String projectKey = pair.projectKey();
    final Map<String, Object> beforePayload = pair.before().toPayload();
    final Map<String, Object> afterPayload = pair.after().toPayload();
    ResolverArtifactGraphSnapshotPayloadValidator.validate(beforePayload, projectKey);
    ResolverArtifactGraphSnapshotPayloadValidator.validate(afterPayload, projectKey);
    if (pair.captureGeneration() != nextGeneration(projectKey)) {
      throw new IllegalArgumentException("Capture pair generation is not the next project value");
    }
    final List<Map<String, Object>> current = snapshots.getOrDefault(projectKey, List.of());
    final List<Map<String, Object>> currentPairs = capturePairs.getOrDefault(projectKey, List.of());
    final Map<String, Object> pairPayload = pair.toPayload();
    final Map<String, List<Map<String, Object>>> nextSnapshots = new LinkedHashMap<>(snapshots);
    final List<Map<String, Object>> updatedSnapshots = new ArrayList<>(current);
    updatedSnapshots.add(afterPayload);
    nextSnapshots.put(projectKey, List.copyOf(updatedSnapshots));
    final Map<String, List<Map<String, Object>>> nextPairs = new LinkedHashMap<>(capturePairs);
    final List<Map<String, Object>> updatedPairs = new ArrayList<>(currentPairs);
    updatedPairs.add(pairPayload);
    nextPairs.put(projectKey, List.copyOf(updatedPairs));
    final Map<String, Long> nextGenerations = new LinkedHashMap<>(generations);
    nextGenerations.put(projectKey, pair.captureGeneration());
    return new ResolverArtifactGraphSnapshotStore(
        nextSnapshots, nextGenerations, observations, nextPairs);
  }

  List<ResolverArtifactGraphCapturePair> capturePairs(final String projectKey) {
    return capturePairs.getOrDefault(projectKey, List.of()).stream()
        .map(ResolverArtifactGraphCapturePair::fromPayload)
        .toList();
  }

  Map<String, Object> toPayload() {
    final Map<String, Object> payload = new LinkedHashMap<>();
    payload.put(SCHEMA_FIELD, SCHEMA_VERSION);
    payload.put(SNAPSHOTS_FIELD, snapshots);
    payload.put(GENERATIONS_FIELD, generations);
    final Map<String, Object> observationPayloads = new LinkedHashMap<>();
    observations.forEach(
        (projectKey, observation) -> {
          final Map<String, Object> observationPayload = new LinkedHashMap<>();
          observationPayload.put("present", observation.present());
          observationPayload.put("fingerprint", observation.fingerprint());
          observationPayload.put("generation", observation.generation());
          observationPayloads.put(projectKey, Collections.unmodifiableMap(observationPayload));
        });
    payload.put(OBSERVATIONS_FIELD, Collections.unmodifiableMap(observationPayloads));
    payload.put(CAPTURE_PAIRS_FIELD, capturePairs);
    return Collections.unmodifiableMap(payload);
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

  record PlanObservation(boolean present, String fingerprint, long generation) {}
}
