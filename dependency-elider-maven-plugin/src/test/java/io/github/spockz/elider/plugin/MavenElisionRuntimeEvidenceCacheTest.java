// WHY: Isolates runtime-evidence cache identity from the larger archive-repair suite.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.apache.maven.plugin.MojoFailureException;
import org.junit.jupiter.api.Test;

/** Verifies cache identity includes normalized runtime policy. */
@SuppressWarnings("PMD.AtLeastOneConstructor")
final class MavenElisionRuntimeEvidenceCacheTest extends MavenElisionServiceEffectiveOutputSupport {
  @Test
  void runtimeEvidencePolicyChangesMissCacheAndReorderedEquivalentInputsReuseIt() throws Exception {
    final Fixture fixture = fixture(false);
    final Path classList = temporaryDirectory.resolve("runtime-policy.lst");
    final Path classLoadLog = temporaryDirectory.resolve("runtime-policy.log");
    Files.writeString(classList, "closure/a/Entry\n");
    Files.writeString(
        classLoadLog, "[info][class,load] closure.a.Entry source: file:/fixture/runtime.jar\n");

    final ServiceOperation classListOnly = evidenceOperation(fixture, List.of(classList));
    final TrimResult first = trimEffective(classListOnly);
    final TrimResult warm = trimEffective(classListOnly);
    final ServiceOperation classLoadOnly = evidenceOperation(fixture, List.of(classLoadLog));
    final TrimResult changedKind = trimEffective(classLoadOnly);
    final ServiceOperation bothInputs =
        evidenceOperation(fixture, List.of(classLoadLog, classList));
    final TrimResult firstMixedOrder = trimEffective(bothInputs);
    final ServiceOperation reversedInputs =
        evidenceOperation(fixture, List.of(classList, classLoadLog));
    final TrimResult reversedMixedOrder = trimEffective(reversedInputs);
    final int firstHits = first.cacheHits();
    final int warmHits = warm.cacheHits();
    final int changedKindHits = changedKind.cacheHits();
    final int firstMixedHits = firstMixedOrder.cacheHits();
    final int reversedMixedHits = reversedMixedOrder.cacheHits();
    final String classListFingerprint =
        classListOnly.prepared().graphBinding().operationFingerprint();
    final String classLoadFingerprint =
        classLoadOnly.prepared().graphBinding().operationFingerprint();
    final String bothFingerprint = bothInputs.prepared().graphBinding().operationFingerprint();
    final String reversedFingerprint =
        reversedInputs.prepared().graphBinding().operationFingerprint();

    assertAll(
        "cache identity includes policy but ignores explicit input ordering",
        () -> assertEquals(0, firstHits, "first policy use must miss cache"),
        () -> assertTrue(warmHits > 0, "same policy must reuse cache"),
        () -> assertThat(classListFingerprint).isNotEqualTo(classLoadFingerprint),
        () -> assertEquals(0, changedKindHits, "evidence kind changes policy identity"),
        () -> assertEquals(0, firstMixedHits, "new input set must miss cache"),
        () -> assertThat(reversedFingerprint).isEqualTo(bothFingerprint),
        () -> assertTrue(reversedMixedHits > 0, "input order does not change policy identity"));
  }

  private ServiceOperation evidenceOperation(final Fixture fixture, final List<Path> evidence)
      throws IOException, MojoFailureException {
    return buildOperation(
        fixture,
        evidence,
        null,
        List.of(),
        true,
        List.of(),
        MavenDependencyTrimmer.MRJAR_VERTICAL_SHADING,
        MavenPluginDescriptorFixtures.releasedProducerResolution(),
        true);
  }
}
