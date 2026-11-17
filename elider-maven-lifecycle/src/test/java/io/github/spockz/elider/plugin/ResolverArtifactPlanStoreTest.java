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

  /** Schema key used by detached session payloads. */
  private static final String SCHEMA_KEY = "schemaVersion";

  /** Stable Maven project group for payload fixtures. */
  private static final String PROJECT_GROUP = "example";

  /** Stable Maven project version for payload fixtures. */
  private static final String PROJECT_VERSION = "1.0";

  /** Name of the plan's project tuple field. */
  private static final String PROJECT_FIELD = "project";

  /** Name of the plan's replacement rows field. */
  private static final String REPLACEMENTS_FIELD = "replacements";

  /** Name of the plan's optional validated graph projection field. */
  private static final String GRAPH_PROJECTION_FIELD = "graphProjection";

  /** Temporary location used to distinguish project identities. */
  @TempDir Path temporaryDirectory;

  @Test
  @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
  // One round-trip assertion checks the complete detached payload contract.
  void roundTripsOnlyJdkPayloadAndKeepsPlansIsolatedByProject() {
    final ResolverArtifactPlan.ProjectIdentity firstProject =
        new ResolverArtifactPlan.ProjectIdentity(
            temporaryDirectory.resolve("one"), PROJECT_GROUP, "one", PROJECT_VERSION);
    final ResolverArtifactPlan.ProjectIdentity secondProject =
        new ResolverArtifactPlan.ProjectIdentity(
            temporaryDirectory.resolve("two"), PROJECT_GROUP, "one", PROJECT_VERSION);
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

    assertThat(payload.get(SCHEMA_KEY)).isEqualTo(1);
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
            () -> ResolverArtifactPlanStore.fromPayload(Map.of(SCHEMA_KEY, 2, PLANS_KEY, Map.of())))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("Unsupported");
  }

  @Test
  void rejectsSchemaOneDraftWithoutCurrentPlanFields() {
    final Map<String, Object> preReleasePlan =
        Map.of(
            PROJECT_FIELD,
            List.of(temporaryDirectory.toString(), PROJECT_GROUP, "old", PROJECT_VERSION),
            REPLACEMENTS_FIELD,
            List.of());

    assertThatThrownBy(
            () ->
                ResolverArtifactPlanStore.fromPayload(
                    Map.of(SCHEMA_KEY, 1, PLANS_KEY, Map.of("old-plan", preReleasePlan))))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("project plan fields do not match");
  }

  @Test
  void rejectsMalformedPlanPayload() {
    assertThatThrownBy(
            () ->
                ResolverArtifactPlanStore.fromPayload(
                    Map.of(
                        SCHEMA_KEY,
                        1,
                        PLANS_KEY,
                        Map.of(
                            "invalid",
                            Map.of(
                                PROJECT_FIELD, "not a list",
                                REPLACEMENTS_FIELD, List.of(),
                                GRAPH_PROJECTION_FIELD, "reserved")))))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("not a list");
  }

  @Test
  @SuppressWarnings({"unchecked", "PMD.UseConcurrentHashMap"})
  // Mutable maps allow isolated malformed-payload construction.
  void rejectsUnexpectedGraphProjectionFields() {
    final ResolverArtifactPlan.ProjectIdentity project =
        new ResolverArtifactPlan.ProjectIdentity(
            temporaryDirectory.resolve("malformed"), PROJECT_GROUP, "malformed", PROJECT_VERSION);
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
        new HashMap<>((Map<String, Object>) encodedPlan.get(GRAPH_PROJECTION_FIELD));
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
