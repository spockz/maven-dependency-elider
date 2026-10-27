// WHY: Proves session plans round-trip as detached JDK collections across Maven class realms.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Covers resolver plan encoding, immutability, and project isolation. */
@SuppressWarnings({
  "PMD.AtLeastOneConstructor",
  "PMD.CommentDefaultAccessModifier",
  "PMD.UnitTestContainsTooManyAsserts"
})
final class ResolverArtifactPlanStoreTest {
  /** Temporary location used to distinguish project identities. */
  @TempDir Path temporaryDirectory;

  @Test
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
    final ResolverArtifactPlanStore store =
        ResolverArtifactPlanStore.empty()
            .withPlan(
                new ResolverArtifactPlan(
                    firstProject,
                    Map.of(
                        artifact,
                        new ResolverArtifactPlan.Replacement(firstReplacement, "a".repeat(64)))))
            .withPlan(
                new ResolverArtifactPlan(
                    secondProject,
                    Map.of(
                        artifact,
                        new ResolverArtifactPlan.Replacement(secondReplacement, "b".repeat(64)))));

    final Map<String, Object> payload = store.toPayload();
    final ResolverArtifactPlanStore restored = ResolverArtifactPlanStore.fromPayload(payload);

    assertThat(payload.get("schemaVersion")).isEqualTo(1);
    assertThat(payload.values()).allSatisfy(ResolverArtifactPlanStoreTest::assertJdkPayloadValue);
    assertThat(restored.find(firstProject).replacements().get(artifact).path())
        .isEqualTo(firstReplacement.toAbsolutePath().normalize());
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
                    Map.of("schemaVersion", 9, "plans", Map.of())))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("Unsupported");
  }

  @Test
  void rejectsMalformedPlanPayload() {
    assertThatThrownBy(
            () ->
                ResolverArtifactPlanStore.fromPayload(
                    Map.of("schemaVersion", 1, "plans", Map.of("invalid", Map.of()))))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("not a list");
  }

  private static void assertJdkPayloadValue(final Object value) {
    assertThat(value).isInstanceOfAny(Map.class, java.util.List.class, String.class, Integer.class);
    if (value instanceof Map<?, ?> map) {
      map.values().forEach(ResolverArtifactPlanStoreTest::assertJdkPayloadValue);
    }
    if (value instanceof java.util.List<?> list) {
      list.forEach(ResolverArtifactPlanStoreTest::assertJdkPayloadValue);
    }
  }
}
