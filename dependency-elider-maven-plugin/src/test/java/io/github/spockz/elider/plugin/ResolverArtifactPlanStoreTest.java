// WHY: Proves session plans round-trip as detached JDK collections across Maven class realms.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Covers resolver plan encoding, immutability, and project isolation. */
@SuppressWarnings({"PMD.AtLeastOneConstructor", "PMD.CommentDefaultAccessModifier"})
final class ResolverArtifactPlanStoreTest {
  /** Payload key containing project-scoped plans. */
  private static final String PLANS_KEY = "plans";

  /** Temporary location used to distinguish project identities. */
  @TempDir Path temporaryDirectory;

  @Test
  @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
  // One round-trip assertion checks the complete detached payload contract.
  void roundTripsOnlyJdkPayloadAndKeepsPlansIsolatedByProject() {
    final ResolverArtifactPlan.ProjectIdentity firstProject =
        new ResolverArtifactPlan.ProjectIdentity(
            temporaryDirectory.resolve("one"), "example", "one", "1.0");
    final ResolverArtifactPlan.ProjectIdentity secondProject =
        new ResolverArtifactPlan.ProjectIdentity(
            temporaryDirectory.resolve("two"), "example", "one", "1.0");
    final ResolverArtifactPlan.ArtifactIdentity artifact =
        new ResolverArtifactPlan.ArtifactIdentity("lib", "keep", "2.0", "jar", "");
    final Path firstReplacement = temporaryDirectory.resolve("one.jar");
    final Path secondReplacement = temporaryDirectory.resolve("two.jar");
    final ResolverArtifactGraphProjection projection =
        new ResolverArtifactGraphProjection(
            "capture-token", "a".repeat(64), "b".repeat(64), List.of("n1"));
    final ResolverArtifactPlanStore store =
        ResolverArtifactPlanStore.empty()
            .withPlan(
                new ResolverArtifactPlan(
                    firstProject,
                    Map.of(
                        artifact,
                        new ResolverArtifactPlan.Replacement(firstReplacement, "a".repeat(64))),
                    projection))
            .withPlan(
                new ResolverArtifactPlan(
                    secondProject,
                    Map.of(
                        artifact,
                        new ResolverArtifactPlan.Replacement(secondReplacement, "b".repeat(64)))));

    final Map<String, Object> payload = store.toPayload();
    final ResolverArtifactPlanStore restored = ResolverArtifactPlanStore.fromPayload(payload);

    assertThat(payload.get("schemaVersion")).isEqualTo(2);
    assertThat(payload.values()).allSatisfy(ResolverArtifactPlanStoreTest::assertJdkPayloadValue);
    assertThat(restored.find(firstProject).replacements().get(artifact).path())
        .isEqualTo(firstReplacement.toAbsolutePath().normalize());
    assertThat(restored.find(firstProject).graphProjection()).isEqualTo(projection);
    assertThat(restored.find(secondProject).replacements().get(artifact).path())
        .isEqualTo(secondReplacement.toAbsolutePath().normalize());
    assertThat(ResolverArtifactPlanStore.projectKey(firstProject))
        .isNotEqualTo(ResolverArtifactPlanStore.projectKey(secondProject));
    assertThatThrownBy(() -> restored.plans().clear())
        .isInstanceOf(UnsupportedOperationException.class);
  }

  @Test
  void rejectsUnknownPayloadSchema() {
    assertThatThrownBy(
            () ->
                ResolverArtifactPlanStore.fromPayload(
                    Map.of("schemaVersion", 9, PLANS_KEY, Map.of())))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("Unsupported");
  }

  @Test
  void rejectsMalformedPlanPayload() {
    assertThatThrownBy(
            () ->
                ResolverArtifactPlanStore.fromPayload(
                    Map.of("schemaVersion", 2, PLANS_KEY, Map.of("invalid", Map.of()))))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("not a list");
  }

  @Test
  @SuppressWarnings({"unchecked", "PMD.UseConcurrentHashMap"})
  // Mutable maps allow isolated malformed-payload construction.
  void rejectsUnexpectedGraphProjectionFields() {
    final ResolverArtifactPlan.ProjectIdentity project =
        new ResolverArtifactPlan.ProjectIdentity(
            temporaryDirectory.resolve("malformed"), "example", "malformed", "1.0");
    final ResolverArtifactGraphProjection projection =
        new ResolverArtifactGraphProjection(
            "capture-token", "a".repeat(64), "b".repeat(64), List.of("n1"));
    final Object payloadValue =
        ResolverArtifactPlanStore.empty()
            .withPlan(new ResolverArtifactPlan(project, Map.of(), projection))
            .toPayload();
    final Map<String, Object> payload = new HashMap<>((Map<String, Object>) payloadValue);
    final Map<String, Object> plans = new HashMap<>((Map<String, Object>) payload.get(PLANS_KEY));
    final String projectKey = ResolverArtifactPlanStore.projectKey(project);
    final Map<String, Object> encodedPlan =
        new HashMap<>((Map<String, Object>) plans.get(projectKey));
    final Map<String, Object> encodedProjection =
        new HashMap<>((Map<String, Object>) encodedPlan.get("graphProjection"));
    encodedProjection.put("unexpected", "not allowed");
    encodedPlan.put("graphProjection", encodedProjection);
    plans.put(projectKey, encodedPlan);
    payload.put(PLANS_KEY, plans);

    assertThatThrownBy(() -> ResolverArtifactPlanStore.fromPayload(payload))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("projection fields do not match");
  }

  private static void assertJdkPayloadValue(final Object value) {
    if (value == null) {
      return;
    }
    assertThat(value).isInstanceOfAny(Map.class, List.class, String.class, Integer.class);
    if (value instanceof Map<?, ?> map) {
      map.values().forEach(ResolverArtifactPlanStoreTest::assertJdkPayloadValue);
    }
    if (value instanceof List<?> list) {
      list.forEach(ResolverArtifactPlanStoreTest::assertJdkPayloadValue);
    }
  }
}
