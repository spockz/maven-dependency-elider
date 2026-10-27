// WHY: Builds self-consistent adversarial graph snapshots for policy protection tests.

package io.github.spockz.elider.plugin;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import org.eclipse.aether.graph.DependencyNode;

/** Creates graph pairs with valid altered snapshot payloads for safety tests. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class EffectiveGraphPolicySafetyTestSupport {
  /** Cast suppression shared by the detached payload accessors. */
  private static final String UNCHECKED_CAST = "unchecked";

  private EffectiveGraphPolicySafetyTestSupport() {
    throw new AssertionError("No instances");
  }

  static ResolverArtifactGraphCapturePair externalWinnerPair(
      final DependencyNode root, final String token) {
    final ResolverArtifactGraphCapturePair ordinary =
        EffectiveGraphPolicyTestSupport.pair(root, root, token);
    return withModifiedAfter(
        ordinary,
        snapshot -> {
          final Map<String, Object> candidate = nodePayload(snapshot, 1);
          candidate.put("conflictWinnerPresent", true);
          candidate.put("conflictWinnerNodeId", null);
          candidate.put(
              "conflictWinnerExternalArtifact",
              Map.of(
                  "groupId", "fixture",
                  "artifactId", EffectiveGraphPolicyTestSupport.KEEP_ID,
                  "version", EffectiveGraphPolicyTestSupport.TEST_VERSION,
                  "baseVersion", EffectiveGraphPolicyTestSupport.TEST_VERSION,
                  "extension", EffectiveGraphPolicyTestSupport.JAR_EXTENSION,
                  "classifier", "",
                  "properties", Map.of()));
          candidate.put("conflictWinnerValueType", null);
        });
  }

  static ResolverArtifactGraphCapturePair withModifiedAfter(
      final DependencyNode root,
      final String token,
      final Consumer<Map<String, Object>> modification) {
    return withModifiedAfter(EffectiveGraphPolicyTestSupport.pair(root, root, token), modification);
  }

  private static ResolverArtifactGraphCapturePair withModifiedAfter(
      final ResolverArtifactGraphCapturePair ordinary,
      final Consumer<Map<String, Object>> modification) {
    final Map<String, Object> payload =
        mutableMap(ResolverArtifactGraphSnapshotStore.empty().append(ordinary.after()).toPayload());
    final Map<String, Object> snapshot = snapshotPayload(payload, ordinary.projectKey());
    modification.accept(snapshot);
    ResolverArtifactGraphSnapshotStoreTestAssertions.recomputeFingerprint(
        payload, ordinary.projectKey());
    final ResolverArtifactGraphSnapshot after =
        ResolverArtifactGraphSnapshot.fromPayload(snapshot, ordinary.projectKey());
    return new ResolverArtifactGraphCapturePair(
        ordinary.projectKey(),
        ordinary.captureToken(),
        ordinary.captureGeneration(),
        ordinary.planPresent(),
        ordinary.planFingerprint(),
        ordinary.planGeneration(),
        ordinary.before(),
        after);
  }

  static ResolverArtifactGraphCapturePair withModifiedBefore(
      final DependencyNode root,
      final String token,
      final Consumer<Map<String, Object>> modification) {
    final ResolverArtifactGraphCapturePair ordinary =
        EffectiveGraphPolicyTestSupport.pair(root, root, token);
    final Map<String, Object> payload =
        mutableMap(
            ResolverArtifactGraphSnapshotStore.empty().append(ordinary.before()).toPayload());
    final Map<String, Object> snapshot = snapshotPayload(payload, ordinary.projectKey());
    modification.accept(snapshot);
    ResolverArtifactGraphSnapshotStoreTestAssertions.recomputeFingerprint(
        payload, ordinary.projectKey());
    final ResolverArtifactGraphSnapshot before =
        ResolverArtifactGraphSnapshot.fromPayload(snapshot, ordinary.projectKey());
    return new ResolverArtifactGraphCapturePair(
        ordinary.projectKey(),
        ordinary.captureToken(),
        ordinary.captureGeneration(),
        ordinary.planPresent(),
        ordinary.planFingerprint(),
        ordinary.planGeneration(),
        before,
        ordinary.after());
  }

  @SuppressWarnings(UNCHECKED_CAST)
  static Map<String, Object> nodePayload(final Map<String, Object> snapshot, final int index) {
    return (Map<String, Object>) ((List<?>) snapshot.get("nodes")).get(index);
  }

  @SuppressWarnings(UNCHECKED_CAST)
  private static Map<String, Object> snapshotPayload(
      final Map<String, Object> payload, final String projectKey) {
    final Map<String, Object> snapshots = (Map<String, Object>) payload.get("snapshots");
    return (Map<String, Object>) ((List<?>) snapshots.get(projectKey)).getFirst();
  }

  // WHY: Preserve serialized order while making the fixture editable.
  @SuppressWarnings("PMD.UseConcurrentHashMap")
  private static Map<String, Object> mutableMap(final Map<String, Object> source) {
    final Map<String, Object> result = new LinkedHashMap<>();
    source.forEach((key, value) -> result.put(key, mutableValue(value)));
    return result;
  }

  // WHY: Preserve nested order while making a snapshot copy editable.
  @SuppressWarnings("PMD.UseConcurrentHashMap")
  private static Object mutableValue(final Object value) {
    if (value instanceof Map<?, ?> map) {
      final Map<String, Object> result = new LinkedHashMap<>();
      map.forEach((key, child) -> result.put((String) key, mutableValue(child)));
      return result;
    }
    if (value instanceof List<?> list) {
      final List<Object> result = new ArrayList<>();
      list.forEach(child -> result.add(mutableValue(child)));
      return result;
    }
    return value;
  }
}
