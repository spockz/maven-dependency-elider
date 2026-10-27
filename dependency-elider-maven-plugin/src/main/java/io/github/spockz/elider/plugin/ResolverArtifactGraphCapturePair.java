// WHY: Binds the graph before and after Maven transformation to one resolver invocation.

package io.github.spockz.elider.plugin;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/** One atomic before/after capture with shared project and plan provenance. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
record ResolverArtifactGraphCapturePair(
    String projectKey,
    String captureToken,
    long captureGeneration,
    boolean planPresent,
    String planFingerprint,
    long planGeneration,
    ResolverArtifactGraphSnapshot before,
    ResolverArtifactGraphSnapshot after) {
  /** Serialized project identity field. */
  private static final String PROJECT_KEY = "projectKey";

  /** Serialized resolver invocation identity field. */
  private static final String CAPTURE_TOKEN = "captureToken";

  /** Serialized append-order generation field. */
  private static final String CAPTURE_GENERATION = "captureGeneration";

  /** Serialized plan-presence provenance field. */
  private static final String PLAN_PRESENT = "planPresent";

  /** Serialized plan-content provenance field. */
  private static final String PLAN_FINGERPRINT = "planFingerprint";

  /** Serialized plan-decoration generation field. */
  private static final String PLAN_GENERATION = "planGeneration";

  /** Serialized graph captured before Maven's transformer. */
  private static final String BEFORE = "before";

  /** Serialized graph returned by Maven's transformer. */
  private static final String AFTER = "after";

  /** Exact payload key set accepted by the schema reader. */
  private static final java.util.Set<String> FIELDS =
      java.util.Set.of(
          PROJECT_KEY,
          CAPTURE_TOKEN,
          CAPTURE_GENERATION,
          PLAN_PRESENT,
          PLAN_FINGERPRINT,
          PLAN_GENERATION,
          BEFORE,
          AFTER);

  ResolverArtifactGraphCapturePair {
    Objects.requireNonNull(projectKey, "projectKey");
    if (captureToken == null || captureToken.isBlank()) {
      throw new IllegalArgumentException("Capture token must not be blank");
    }
    if (captureGeneration < 1L || planGeneration < 0L) {
      throw new IllegalArgumentException("Capture and plan generations are invalid");
    }
    if (planPresent != (planFingerprint != null)) {
      throw new IllegalArgumentException("Plan presence and fingerprint disagree");
    }
    Objects.requireNonNull(before, "before");
    Objects.requireNonNull(after, "after");
    if (!projectKey.equals(before.projectKey()) || !projectKey.equals(after.projectKey())) {
      throw new IllegalArgumentException("Capture pair project keys differ");
    }
    if (before.captureGeneration() != captureGeneration
        || after.captureGeneration() != captureGeneration
        || before.planPresent() != planPresent
        || after.planPresent() != planPresent
        || !Objects.equals(before.planFingerprint(), planFingerprint)
        || !Objects.equals(after.planFingerprint(), planFingerprint)
        || before.planGeneration() != planGeneration
        || after.planGeneration() != planGeneration) {
      throw new IllegalArgumentException("Capture pair provenance differs");
    }
  }

  // WHY: Linked insertion order makes session payload snapshots reproducible.
  @SuppressWarnings("PMD.UseConcurrentHashMap")
  Map<String, Object> toPayload() {
    final Map<String, Object> payload = new LinkedHashMap<>();
    payload.put(PROJECT_KEY, projectKey);
    payload.put(CAPTURE_TOKEN, captureToken);
    payload.put(CAPTURE_GENERATION, captureGeneration);
    payload.put(PLAN_PRESENT, planPresent);
    payload.put(PLAN_FINGERPRINT, planFingerprint);
    payload.put(PLAN_GENERATION, planGeneration);
    payload.put(BEFORE, before.toPayload());
    payload.put(AFTER, after.toPayload());
    return Collections.unmodifiableMap(payload);
  }

  static ResolverArtifactGraphCapturePair fromPayload(final Object rawPayload) {
    if (!(rawPayload instanceof Map<?, ?> payload) || !payload.keySet().equals(FIELDS)) {
      throw new IllegalStateException("Graph capture pair fields do not match the schema");
    }
    final String projectKey = requireString(payload.get(PROJECT_KEY), PROJECT_KEY);
    final String captureToken = requireString(payload.get(CAPTURE_TOKEN), CAPTURE_TOKEN);
    final long captureGeneration = requireLong(payload.get(CAPTURE_GENERATION), CAPTURE_GENERATION);
    final boolean planPresent = requireBoolean(payload.get(PLAN_PRESENT), PLAN_PRESENT);
    final Object rawFingerprint = payload.get(PLAN_FINGERPRINT);
    if (rawFingerprint != null && !(rawFingerprint instanceof String)) {
      throw new IllegalStateException("Invalid graph capture plan fingerprint");
    }
    final long planGeneration = requireLong(payload.get(PLAN_GENERATION), PLAN_GENERATION);
    return new ResolverArtifactGraphCapturePair(
        projectKey,
        captureToken,
        captureGeneration,
        planPresent,
        (String) rawFingerprint,
        planGeneration,
        ResolverArtifactGraphSnapshot.fromPayload(payload.get(BEFORE), projectKey),
        ResolverArtifactGraphSnapshot.fromPayload(payload.get(AFTER), projectKey));
  }

  private static String requireString(final Object value, final String field) {
    if (value instanceof String text && !text.isBlank()) {
      return text;
    }
    throw new IllegalStateException("Invalid graph capture " + field);
  }

  private static long requireLong(final Object value, final String field) {
    if (value instanceof Long number && number >= 0L) {
      return number;
    }
    throw new IllegalStateException("Invalid graph capture " + field);
  }

  private static boolean requireBoolean(final Object value, final String field) {
    if (value instanceof Boolean result) {
      return result;
    }
    throw new IllegalStateException("Invalid graph capture " + field);
  }
}
