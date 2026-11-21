/* WHY: Stores detached graphs in Maven session data. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.HexDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/** Immutable project-scoped graph snapshot store. */
// Ordered maps keep the immutable JDK payload deterministic.
@SuppressWarnings({
  "PMD.CommentDefaultAccessModifier",
  "PMD.CommentRequired",
  "PMD.UseConcurrentHashMap",
  "PMD.CyclomaticComplexity",
  "PMD.TooManyMethods",
  "PMD.AvoidFieldNameMatchingMethodName"
})
final class ResolverArtifactGraphSnapshotStore {
  private static final int SCHEMA_VERSION = 1;

  private static final String SCHEMA_FIELD = "schemaVersion";

  private static final String SNAPSHOTS_FIELD = "snapshots";

  private static final String GENERATIONS_FIELD = "generations";

  private static final String OBSERVATIONS_FIELD = "planObservations";

  private static final String CAPTURE_PAIRS_FIELD = "capturePairs";

  private final Map<String, List<Map<String, Object>>> snapshots;

  private final Map<String, Long> generations;

  private final Map<String, PlanObservation> observations;

  private final Map<String, List<Map<String, Object>>> capturePairs;

  private ResolverArtifactGraphSnapshotStore(
      final Map<String, List<Map<String, Object>>> snapshots,
      final Map<String, Long> generations,
      final Map<String, PlanObservation> observations,
      final Map<String, List<Map<String, Object>>> capturePairs) {
    this.snapshots = Objects.requireNonNull(snapshots, "snapshots");
    this.generations = Objects.requireNonNull(generations, "generations");
    this.observations = Objects.requireNonNull(observations, "observations");
    this.capturePairs = Objects.requireNonNull(capturePairs, "capturePairs");
  }

  Map<String, List<Map<String, Object>>> snapshots() {
    return snapshots;
  }

  Map<String, Long> generations() {
    return generations;
  }

  Map<String, PlanObservation> observations() {
    return observations;
  }

  Map<String, List<Map<String, Object>>> capturePairs() {
    return capturePairs;
  }

  List<ResolverArtifactGraphCapturePair> capturePairs(final String projectKey) {
    return capturePairs.getOrDefault(projectKey, List.of()).stream()
        .map(ResolverArtifactGraphCapturePair::fromPayload)
        .toList();
  }

  @Override
  public boolean equals(final Object other) {
    if (this == other) {
      return true;
    }
    if (!(other instanceof ResolverArtifactGraphSnapshotStore store)) {
      return false;
    }
    return snapshots.equals(store.snapshots)
        && generations.equals(store.generations)
        && observations.equals(store.observations)
        && capturePairs.equals(store.capturePairs);
  }

  @Override
  public int hashCode() {
    return Objects.hash(snapshots, generations, observations, capturePairs);
  }

  @Override
  public String toString() {
    return "ResolverArtifactGraphSnapshotStore["
        + "snapshots="
        + snapshots
        + ", generations="
        + generations
        + ", observations="
        + observations
        + ", capturePairs="
        + capturePairs
        + ']';
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
            Set.of(
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
            Collections.unmodifiableMap(parseSnapshots(root.get(SNAPSHOTS_FIELD))),
            Collections.unmodifiableMap(parseGenerations(root.get(GENERATIONS_FIELD))),
            Collections.unmodifiableMap(parseObservations(root.get(OBSERVATIONS_FIELD))),
            Collections.unmodifiableMap(parseCapturePairs(root.get(CAPTURE_PAIRS_FIELD))));
    validateStore(store);
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
        || (fingerprint != null && !HexDigest.isLowercaseHex(fingerprint, 64))
        || (present && generation == 0L)
        || !observation.keySet().equals(Set.of("present", "fingerprint", "generation"))) {
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
    if (Objects.equals(observation, observations.get(projectKey))) {
      return this;
    }
    final Map<String, PlanObservation> nextObservations = new LinkedHashMap<>(observations);
    nextObservations.put(projectKey, observation);
    return new ResolverArtifactGraphSnapshotStore(
        snapshots, generations, Collections.unmodifiableMap(nextObservations), capturePairs);
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
    final Map<String, Object> pairPayload = immutableMap(pair.toPayload());
    final Map<String, List<Map<String, Object>>> nextSnapshots = new LinkedHashMap<>(snapshots);
    final List<Map<String, Object>> updatedSnapshots = new ArrayList<>(current);
    updatedSnapshots.add(immutableMap(afterPayload));
    nextSnapshots.put(projectKey, List.copyOf(updatedSnapshots));
    final Map<String, List<Map<String, Object>>> nextPairs = new LinkedHashMap<>(capturePairs);
    final List<Map<String, Object>> updatedPairs = new ArrayList<>(currentPairs);
    updatedPairs.add(pairPayload);
    nextPairs.put(projectKey, List.copyOf(updatedPairs));
    final Map<String, Long> nextGenerations = new LinkedHashMap<>(generations);
    nextGenerations.put(projectKey, pair.captureGeneration());
    return new ResolverArtifactGraphSnapshotStore(
        Collections.unmodifiableMap(nextSnapshots),
        Collections.unmodifiableMap(nextGenerations),
        observations,
        Collections.unmodifiableMap(nextPairs));
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
    return StorePayloadSupport.requireMap(value, field);
  }

  private static Map<String, Object> requireObjectMap(final Object value, final String field) {
    return StorePayloadSupport.requireObjectMap(value, field);
  }

  private static List<?> requireList(final Object value, final String field) {
    return StorePayloadSupport.requireList(value, field);
  }

  private static String requireString(final Object value, final String field) {
    return StorePayloadSupport.requireString(value, field);
  }

  private static void validateStore(final ResolverArtifactGraphSnapshotStore store) {
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
    final Set<String> captureTokens = new HashSet<>();
    for (int index = 0; index < entries.size(); index++) {
      final Map<String, Object> entry = entries.get(index);
      final long expectedGeneration = index + 1L;
      if (!Long.valueOf(expectedGeneration).equals(entry.get("captureGeneration"))) {
        throw new IllegalStateException("Graph snapshot capture generations are inconsistent");
      }
      final Map<String, Object> pairPayload = pairs.get(index);
      if (!entry.equals(pairPayload.get("after"))) {
        ResolverArtifactGraphSnapshotPayloadValidator.validate(entry, projectKey);
        throw new IllegalStateException("Graph capture pair provenance is inconsistent");
      }
      final ResolverArtifactGraphCapturePair pair =
          ResolverArtifactGraphCapturePair.fromPayload(pairPayload);
      if (!pair.projectKey().equals(projectKey)
          || pair.captureGeneration() != expectedGeneration
          || !captureTokens.add(pair.captureToken())) {
        throw new IllegalStateException("Graph capture pair provenance is inconsistent");
      }
    }
    if (!Long.valueOf(entries.size()).equals(store.generations().get(projectKey))) {
      throw new IllegalStateException("Graph snapshot store generation is inconsistent");
    }
  }

  record PlanObservation(boolean present, String fingerprint, long generation) {}
}
