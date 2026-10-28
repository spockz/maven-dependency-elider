// WHY: Verifies cache validation and repair for effective per-artifact analyses.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.spockz.elider.trimmer.ArtifactDigests;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.apache.maven.plugin.MojoFailureException;
import org.junit.jupiter.api.Test;

/** Validates cache hits against analysis metadata and both output digests. */
@SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
final class MavenElisionServiceEffectiveOutputCacheTest
    extends MavenElisionServiceEffectiveOutputSupport {
  /** Shared root included by every cache fixture. */
  private static final String ENTRY_TRACE = "closure/a/Entry";

  /** Creates the effective cache fixture. */
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  MavenElisionServiceEffectiveOutputCacheTest() {
    super();
  }

  @Test
  void damagedTrimmedJarGetsRepairedAndMissingFileGetsRebuilt() throws Exception {
    final Fixture fixture = fixture(false);
    final ServiceOperation operation =
        operation(fixture, trace(temporaryDirectory, ENTRY_TRACE), null);
    final ArtifactTrimRecord first = outputRecord(trimEffective(operation), fixture);

    Files.writeString(first.trimmedPath(), "corrupt output");
    final String corruptDigest = ArtifactDigests.read(first.trimmedPath()).sha256();
    final MavenDependencyTrimmer.TrimResult repaired = trimEffective(operation);
    final ArtifactTrimRecord repairedRecord = outputRecord(repaired, fixture);
    assertThat(repaired.cacheHits()).isZero();
    assertThat(ArtifactDigests.read(repairedRecord.trimmedPath()).sha256())
        .isEqualTo(repairedRecord.trimmedSha256())
        .isNotEqualTo(corruptDigest);

    Files.delete(repairedRecord.trimmedPath());
    final MavenDependencyTrimmer.TrimResult rebuilt = trimEffective(operation);
    final ArtifactTrimRecord rebuiltRecord = outputRecord(rebuilt, fixture);
    assertThat(rebuilt.cacheHits()).isZero();
    assertThat(rebuiltRecord.trimmedPath()).isRegularFile();
    assertThat(ArtifactDigests.read(rebuiltRecord.trimmedPath()).sha256())
        .isEqualTo(rebuiltRecord.trimmedSha256());
  }

  @Test
  void effectiveCacheRejectsStaleAnalysisMetadataAndSha1Digest() throws Exception {
    final Fixture fixture = fixture(false);
    final ServiceOperation operation =
        operation(fixture, trace(temporaryDirectory, ENTRY_TRACE), null);
    final ArtifactTrimRecord original = outputRecord(trimEffective(operation), fixture);
    final Path manifest = EffectiveOutputCacheTestFiles.cacheManifest(fixture.mavenProject());

    EffectiveOutputCacheTestFiles.mutateCacheEntry(
        manifest, entry -> entry.putArray("roots").add("closure.a.Extra"));
    final MavenDependencyTrimmer.TrimResult rootRepair = trimEffective(operation);
    assertThat(rootRepair.cacheHits()).isZero();

    EffectiveOutputCacheTestFiles.mutateCacheEntry(
        manifest, entry -> entry.put("trimmedSha1", "0".repeat(40)));
    final MavenDependencyTrimmer.TrimResult digestRepair = trimEffective(operation);
    assertThat(digestRepair.cacheHits()).isZero();
    final ArtifactTrimRecord repaired = outputRecord(digestRepair, fixture);
    assertThat(repaired.trimmedSha256()).isEqualTo(original.trimmedSha256());
    assertThat(ArtifactDigests.read(repaired.trimmedPath()).sha1())
        .isEqualTo(repaired.trimmedSha1());
  }

  @Test
  void effectiveCacheRejectsMalformedManifestAndEntryShapes() throws Exception {
    final Fixture fixture = fixture(false);
    final ServiceOperation operation =
        operation(fixture, trace(temporaryDirectory, ENTRY_TRACE), null);
    outputRecord(trimEffective(operation), fixture);
    final Path manifest = EffectiveOutputCacheTestFiles.cacheManifest(fixture.mavenProject());
    final ObjectMapper mapper = new ObjectMapper();
    final JsonNode original = mapper.readTree(manifest.toFile());
    final String fingerprint = original.path("fingerprint").asText();

    Files.writeString(manifest, "null");
    assertCacheMiss(operation);

    final ObjectNode missingEntries = EffectiveOutputCacheTestFiles.manifestNode(fingerprint);
    missingEntries.putNull("entries");
    EffectiveOutputCacheTestFiles.writeManifest(manifest, missingEntries);
    assertCacheMiss(operation);

    final ObjectNode nullEntry = EffectiveOutputCacheTestFiles.manifestNode(fingerprint);
    nullEntry.putArray("entries").addNull();
    EffectiveOutputCacheTestFiles.writeManifest(manifest, nullEntry);
    assertCacheMiss(operation);

    EffectiveOutputCacheTestFiles.mutateCacheEntry(
        manifest, entry -> entry.putNull("trimmedSha256"));
    assertCacheMiss(operation);

    EffectiveOutputCacheTestFiles.mutateCacheEntry(
        manifest, entry -> entry.put("originalSha1", "0".repeat(40)));
    assertCacheMiss(operation);

    for (final String field : List.of("roots", "retainedClassNames", "reachableLibraryClasses")) {
      EffectiveOutputCacheTestFiles.mutateCacheEntry(
          manifest, entry -> entry.putArray(field).addNull());
      assertCacheMiss(operation);
    }
  }

  private static ArtifactTrimRecord outputRecord(
      final MavenDependencyTrimmer.TrimResult result, final Fixture fixture) {
    return EffectiveOutputCacheTestFiles.record(result.records(), fixture.coordinate("a"));
  }

  private void assertCacheMiss(final ServiceOperation operation)
      throws IOException, MojoFailureException {
    assertThat(trimEffective(operation).cacheHits()).isZero();
  }
}
