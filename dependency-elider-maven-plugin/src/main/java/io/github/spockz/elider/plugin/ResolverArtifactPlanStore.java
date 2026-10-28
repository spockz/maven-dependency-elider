// WHY: Encodes per-project resolver plans as immutable JDK collections safe across Maven class
// realms.

package io.github.spockz.elider.plugin;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/** Immutable collection of project-specific resolver plans. */
@SuppressWarnings({
  "PMD.AvoidInstantiatingObjectsInLoops",
  "PMD.CommentDefaultAccessModifier",
  "PMD.CommentRequired",
  "PMD.UseConcurrentHashMap"
})
record ResolverArtifactPlanStore(
    Map<ResolverArtifactPlan.ProjectIdentity, ResolverArtifactPlan> plans) {
  private static final int PROJECT_FIELD_COUNT = 4;

  private static final int REPLACEMENT_FIELD_COUNT = 7;

  private static final int SCHEMA_VERSION = 2;

  private static final Set<String> PROJECTION_FIELDS =
      Set.of("captureToken", "sourceFingerprint", "projectedFingerprint", "removedNodeIds");

  private static final String SCHEMA_FIELD = "schemaVersion";

  private static final String PLANS_FIELD = "plans";

  ResolverArtifactPlanStore {
    Objects.requireNonNull(plans, "plans");
    plans = Collections.unmodifiableMap(new LinkedHashMap<>(plans));
  }

  static ResolverArtifactPlanStore empty() {
    return new ResolverArtifactPlanStore(Map.of());
  }

  static ResolverArtifactPlanStore fromPayload(final Object payload) {
    if (payload == null) {
      return empty();
    }
    final Map<?, ?> root = requireMap(payload, "resolver plan store");
    if (!Integer.valueOf(SCHEMA_VERSION).equals(root.get(SCHEMA_FIELD))) {
      throw new IllegalStateException("Unsupported resolver plan store schema");
    }
    final Map<?, ?> encodedPlans = requireMap(root.get(PLANS_FIELD), PLANS_FIELD);
    final Map<ResolverArtifactPlan.ProjectIdentity, ResolverArtifactPlan> decoded =
        new LinkedHashMap<>();
    for (final Map.Entry<?, ?> entry : encodedPlans.entrySet()) {
      final String projectKey = requireString(entry.getKey(), "project key");
      final ResolverArtifactPlan plan = decodePlan(entry.getValue());
      if (!projectKey(plan.project()).equals(projectKey)) {
        throw new IllegalStateException("Resolver plan project key does not match its payload");
      }
      if (decoded.put(plan.project(), plan) != null) {
        throw new IllegalStateException("Duplicate project resolver plan: " + projectKey);
      }
    }
    return new ResolverArtifactPlanStore(decoded);
  }

  @SuppressWarnings("PMD.UseConcurrentHashMap")
  ResolverArtifactPlanStore withPlan(final ResolverArtifactPlan plan) {
    Objects.requireNonNull(plan, "plan");
    final Map<ResolverArtifactPlan.ProjectIdentity, ResolverArtifactPlan> updated =
        new LinkedHashMap<>(plans);
    updated.put(plan.project(), plan);
    return new ResolverArtifactPlanStore(updated);
  }

  ResolverArtifactPlan find(final ResolverArtifactPlan.ProjectIdentity project) {
    return plans.get(Objects.requireNonNull(project, "project"));
  }

  @SuppressWarnings("PMD.UseConcurrentHashMap")
  Map<String, Object> toPayload() {
    final Map<String, Object> encodedPlans = new LinkedHashMap<>();
    plans.values().forEach(plan -> encodedPlans.put(projectKey(plan.project()), encodePlan(plan)));
    final Map<String, Object> payload = new LinkedHashMap<>();
    payload.put(SCHEMA_FIELD, SCHEMA_VERSION);
    payload.put(PLANS_FIELD, Collections.unmodifiableMap(encodedPlans));
    return Collections.unmodifiableMap(payload);
  }

  static String projectKey(final ResolverArtifactPlan.ProjectIdentity project) {
    return encodeTuple(
        List.of(
            project.baseDirectory().toString(),
            project.groupId(),
            project.artifactId(),
            project.version()));
  }

  private static Map<String, Object> encodePlan(final ResolverArtifactPlan plan) {
    final List<List<String>> replacements = new ArrayList<>();
    plan.replacements()
        .forEach(
            (identity, replacement) ->
                replacements.add(
                    List.of(
                        identity.groupId(),
                        identity.artifactId(),
                        identity.version(),
                        identity.extension(),
                        identity.classifier(),
                        replacement.path().toString(),
                        replacement.sha256())));
    final Map<String, Object> result = new LinkedHashMap<>();
    result.put(
        "project",
        List.of(
            plan.project().baseDirectory().toString(),
            plan.project().groupId(),
            plan.project().artifactId(),
            plan.project().version()));
    result.put("replacements", List.copyOf(replacements));
    result.put("graphProjection", encodeProjection(plan.graphProjection()));
    return Collections.unmodifiableMap(result);
  }

  private static Object encodeProjection(final ResolverArtifactGraphProjection projection) {
    if (projection == null) {
      return null;
    }
    final Map<String, Object> result = new LinkedHashMap<>();
    result.put("captureToken", projection.captureToken());
    result.put("sourceFingerprint", projection.sourceFingerprint());
    result.put("projectedFingerprint", projection.projectedFingerprint());
    result.put("removedNodeIds", projection.removedNodeIds());
    return Collections.unmodifiableMap(result);
  }

  private static ResolverArtifactPlan decodePlan(final Object value) {
    final Map<?, ?> encoded = requireMap(value, "project plan");
    final List<?> projectFields = requireList(encoded.get("project"), "project identity");
    if (projectFields.size() != PROJECT_FIELD_COUNT) {
      throw new IllegalStateException("Project identity must have four fields");
    }
    final ResolverArtifactPlan.ProjectIdentity project =
        new ResolverArtifactPlan.ProjectIdentity(
            Path.of(requireString(projectFields.get(0), "project base directory")),
            requireString(projectFields.get(1), "project groupId"),
            requireString(projectFields.get(2), "project artifactId"),
            requireString(projectFields.get(3), "project version"));
    final List<?> encodedReplacements = requireList(encoded.get("replacements"), "replacements");
    final Map<ResolverArtifactPlan.ArtifactIdentity, ResolverArtifactPlan.Replacement>
        replacements = new LinkedHashMap<>();
    for (final Object rowValue : encodedReplacements) {
      final List<?> row = requireList(rowValue, "replacement entry");
      if (row.size() != REPLACEMENT_FIELD_COUNT) {
        throw new IllegalStateException("Replacement entry must have seven fields");
      }
      final ResolverArtifactPlan.ArtifactIdentity identity =
          new ResolverArtifactPlan.ArtifactIdentity(
              requireString(row.get(0), "artifact groupId"),
              requireString(row.get(1), "artifact artifactId"),
              requireString(row.get(2), "artifact version"),
              requireString(row.get(3), "artifact extension"),
              requireString(row.get(4), "artifact classifier"));
      final ResolverArtifactPlan.Replacement replacement =
          new ResolverArtifactPlan.Replacement(
              Path.of(requireString(row.get(5), "replacement path")),
              requireString(row.get(6), "replacement SHA-256"));
      if (replacements.put(identity, replacement) != null) {
        throw new IllegalStateException("Duplicate resolver artifact identity: " + identity);
      }
    }
    return new ResolverArtifactPlan(
        project, replacements, decodeProjection(encoded.get("graphProjection")));
  }

  private static ResolverArtifactGraphProjection decodeProjection(final Object value) {
    if (value == null) {
      return null;
    }
    final Map<?, ?> encoded = requireMap(value, "graph projection");
    if (!encoded.keySet().equals(PROJECTION_FIELDS)) {
      throw new IllegalStateException("Resolver graph projection fields do not match the schema");
    }
    final List<?> rawNodeIds = requireList(encoded.get("removedNodeIds"), "removed node IDs");
    final List<String> nodeIds =
        rawNodeIds.stream().map(item -> requireString(item, "removed node ID")).toList();
    return new ResolverArtifactGraphProjection(
        requireString(encoded.get("captureToken"), "graph capture token"),
        requireString(encoded.get("sourceFingerprint"), "source graph fingerprint"),
        requireString(encoded.get("projectedFingerprint"), "projected graph fingerprint"),
        nodeIds);
  }

  private static String encodeTuple(final List<String> fields) {
    return fields.stream()
        .map(
            value ->
                Base64.getUrlEncoder()
                    .withoutPadding()
                    .encodeToString(value.getBytes(StandardCharsets.UTF_8)))
        .collect(java.util.stream.Collectors.joining("."));
  }

  private static Map<?, ?> requireMap(final Object value, final String field) {
    if (value instanceof Map<?, ?> map) {
      return map;
    }
    throw new IllegalStateException("Resolver plan " + field + " is not a map");
  }

  private static List<?> requireList(final Object value, final String field) {
    if (value instanceof List<?> list) {
      return list;
    }
    throw new IllegalStateException("Resolver plan " + field + " is not a list");
  }

  private static String requireString(final Object value, final String field) {
    if (value instanceof String string) {
      return string;
    }
    throw new IllegalStateException("Resolver plan " + field + " is not a string");
  }
}
