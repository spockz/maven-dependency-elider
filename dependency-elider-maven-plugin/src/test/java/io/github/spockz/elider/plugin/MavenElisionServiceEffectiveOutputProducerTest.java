// WHY: Proves trim-cache producer identity gates and the no-identity output path.

package io.github.spockz.elider.plugin;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.spockz.elider.trimmer.ArtifactDigests;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

/** Verifies effective trim-cache producer identity behavior. */
final class MavenElisionServiceEffectiveOutputProducerTest
    extends MavenElisionServiceEffectiveOutputSupport {
  /** Entry root shared by producer-specific scenarios. */
  private static final String ENTRY_TRACE = "closure/a/Entry";

  /** Creates shared fixture support for producer identity scenarios. */
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  MavenElisionServiceEffectiveOutputProducerTest() {
    super();
  }

  @Test
  void effectiveCacheMissesWhenSnapshotProducerBuildChanges() throws Exception {
    final Fixture fixture = fixture(false);
    final Path trace = trace(temporaryDirectory, ENTRY_TRACE);
    final String originalDigest = ArtifactDigests.read(fixture.snapshot("a").filePath()).sha256();
    final ServiceOperation firstOperation =
        operationWithProducer(
            fixture,
            trace,
            MavenPluginDescriptorFixtures.snapshotProducerResolution("a".repeat(64)));
    final TrimResult first = trimEffective(firstOperation);
    final TrimResult warm = trimEffective(firstOperation);
    final ArtifactTrimRecord firstRecord =
        EffectiveOutputCacheTestFiles.record(first.records(), fixture.coordinate("a"));
    final ServiceOperation secondOperation =
        operationWithProducer(
            fixture,
            trace,
            MavenPluginDescriptorFixtures.snapshotProducerResolution("b".repeat(64)));
    final TrimResult second = trimEffective(secondOperation);
    final ArtifactTrimRecord secondRecord =
        EffectiveOutputCacheTestFiles.record(second.records(), fixture.coordinate("a"));
    final com.fasterxml.jackson.databind.JsonNode manifest =
        new ObjectMapper()
            .readTree(EffectiveOutputCacheTestFiles.cacheManifest(fixture.mavenProject()).toFile());
    final int firstCacheHits = first.cacheHits();
    final int warmCacheHits = warm.cacheHits();
    final int warmAnalysisRuns = warm.analysisRuns();
    final int secondCacheHits = second.cacheHits();
    final int secondAnalysisRuns = second.analysisRuns();
    final Path firstOutput = firstRecord.trimmedPath();
    final Path secondOutput = secondRecord.trimmedPath();
    final String producerDigest = manifest.path("producer").path("buildIdentity").asText();
    final String currentInputDigest =
        ArtifactDigests.read(fixture.snapshot("a").filePath()).sha256();

    assertAll(
        "snapshot producer changes invalidate effective output cache entries",
        () ->
            assertEquals(0, firstCacheHits, "the first producer build must populate a cold cache"),
        () -> assertTrue(warmCacheHits > 0, "same producer build reuses its cached output"),
        () -> assertEquals(0, warmAnalysisRuns, "warm output requires no new analysis"),
        () -> assertEquals(0, secondCacheHits, "the changed build must not reuse the prior cache"),
        () -> assertTrue(secondAnalysisRuns > 0, "the changed build must be analyzed"),
        () ->
            org.junit.jupiter.api.Assertions.assertNotEquals(
                firstOutput, secondOutput, "the changed build gets a new generation"),
        () ->
            assertEquals(
                "b".repeat(64), producerDigest, "manifest stores the current build digest"),
        () ->
            assertEquals(
                originalDigest, currentInputDigest, "producer changes do not alter inputs"));
  }

  @Test
  void releaseCacheCompatibilityIgnoresOptionalBuildDigest() throws Exception {
    final Fixture fixture = fixture(false);
    final Path trace = trace(temporaryDirectory, ENTRY_TRACE);
    final ServiceOperation firstOperation =
        operationWithProducer(
            fixture,
            trace,
            MavenPluginDescriptorFixtures.releasedProducerResolution("a".repeat(64)));
    final TrimResult first = trimEffective(firstOperation);
    final ArtifactTrimRecord firstRecord =
        EffectiveOutputCacheTestFiles.record(first.records(), fixture.coordinate("a"));
    final ServiceOperation secondOperation =
        operationWithProducer(
            fixture,
            trace,
            MavenPluginDescriptorFixtures.releasedProducerResolution("b".repeat(64)));
    final TrimResult second = trimEffective(secondOperation);
    final ArtifactTrimRecord secondRecord =
        EffectiveOutputCacheTestFiles.record(second.records(), fixture.coordinate("a"));

    assertAll(
        "release compatibility is determined by exact GAV and ignores optional digest metadata",
        () -> assertEquals(0, first.cacheHits(), "first release identity populates the cache"),
        () -> assertTrue(second.cacheHits() > 0, "same release GAV reuses cached outputs"),
        () -> assertEquals(0, second.analysisRuns(), "compatible release output avoids analysis"),
        () ->
            assertEquals(
                firstRecord.trimmedPath(),
                secondRecord.trimmedPath(),
                "compatible release producer identity selects the same generation"));
  }

  @Test
  void unavailableProducerUsesUsableEphemeralOutputWithoutPersistentCache() throws Exception {
    final Fixture fixture = fixture(false);
    final ServiceOperation operation =
        operationWithProducer(
            fixture,
            trace(temporaryDirectory, ENTRY_TRACE),
            MavenPluginDescriptorFixtures.unavailableProducerResolution());
    final ElisionAnalysisModel.EffectiveAnalysis effective =
        operation.service().finishAnalysis(operation.prepared());
    final TrimResult first = MavenDependencyTrimmer.trimEffectiveOutputs(effective);
    final ArtifactTrimRecord firstRecord =
        EffectiveOutputCacheTestFiles.record(first.records(), fixture.coordinate("a"));
    final TrimResult second = MavenDependencyTrimmer.trimEffectiveOutputs(effective);
    final ArtifactTrimRecord secondRecord =
        EffectiveOutputCacheTestFiles.record(second.records(), fixture.coordinate("a"));
    final int firstCacheHits = first.cacheHits();
    final int secondCacheHits = second.cacheHits();
    final Path firstOutput = firstRecord.trimmedPath();
    final Path secondOutput = secondRecord.trimmedPath();
    final String firstOutputDigest = ArtifactDigests.read(firstOutput).sha256();
    final String secondOutputDigest = ArtifactDigests.read(secondOutput).sha256();
    final Path cacheManifest = EffectiveOutputCacheTestFiles.cacheManifest(fixture.mavenProject());
    final Path generations =
        EffectiveOutputCacheTestFiles.generationDirectory(fixture.mavenProject());

    assertAll(
        "missing producer disables persistence but returns usable trimmed JARs",
        () -> assertEquals(0, firstCacheHits, "first ephemeral output cannot be a cache hit"),
        () -> assertEquals(0, secondCacheHits, "second ephemeral output cannot be a cache hit"),
        () -> assertTrue(firstOutput.toFile().isFile(), "first output remains a regular file"),
        () -> assertTrue(secondOutput.toFile().isFile(), "second output remains a regular file"),
        () ->
            assertEquals(
                firstRecord.trimmedSha256(), firstOutputDigest, "first output digest is recorded"),
        () ->
            assertEquals(
                secondRecord.trimmedSha256(),
                secondOutputDigest,
                "second output digest is recorded"),
        () ->
            org.junit.jupiter.api.Assertions.assertNotEquals(
                firstOutput, secondOutput, "each run receives an isolated generation"),
        () ->
            assertFalse(
                firstOutput.toString().contains(".generations"),
                "ephemeral output stays outside the project cache"),
        () ->
            assertFalse(
                secondOutput.toString().contains(".generations"),
                "ephemeral output stays outside the project cache"),
        () -> assertFalse(cacheManifest.toFile().exists(), "no project manifest is written"),
        () ->
            assertFalse(
                generations.toFile().exists(), "no project generation directory is written"));
  }
}
