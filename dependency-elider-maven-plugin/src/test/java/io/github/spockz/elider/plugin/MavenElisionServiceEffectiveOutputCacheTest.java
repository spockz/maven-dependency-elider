// WHY: Verifies cache validation and repair for effective per-artifact analyses.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.spockz.elider.model.ArtifactDigests;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import org.apache.maven.plugin.MojoFailureException;
import org.junit.jupiter.api.Test;

/** Validates cache hits against analysis metadata and both output digests. */
@SuppressWarnings({"PMD.AvoidDuplicateLiterals", "PMD.TooManyMethods"})
final class MavenElisionServiceEffectiveOutputCacheTest
    extends MavenElisionServiceEffectiveOutputSupport {
  /** Shared root included by every cache fixture. */
  private static final String ENTRY_TRACE = "closure/a/Entry";

  /** Manifest field identifying its independent format version. */
  private static final String SCHEMA_VERSION_PROPERTY = "schemaVersion";

  /** Manifest field identifying the effective operation. */
  private static final String FINGERPRINT_PROPERTY = "fingerprint";

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
    final TrimResult repaired = trimEffective(operation);
    final ArtifactTrimRecord repairedRecord = outputRecord(repaired, fixture);
    assertThat(repaired.cacheHits()).isZero();
    assertThat(ArtifactDigests.read(repairedRecord.trimmedPath()).sha256())
        .isEqualTo(repairedRecord.trimmedSha256())
        .isNotEqualTo(corruptDigest);

    Files.delete(repairedRecord.trimmedPath());
    final TrimResult rebuilt = trimEffective(operation);
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
    final TrimResult rootRepair = trimEffective(operation);
    assertThat(rootRepair.cacheHits()).isZero();

    EffectiveOutputCacheTestFiles.mutateCacheEntry(
        manifest, entry -> entry.put("trimmedSha1", "0".repeat(40)));
    final TrimResult digestRepair = trimEffective(operation);
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
    final ElisionAnalysisModel.EffectiveAnalysis effective =
        operation.service().finishAnalysis(operation.prepared());
    outputRecord(MavenDependencyTrimmer.trimEffectiveOutputs(effective), fixture);
    final Path manifest = EffectiveOutputCacheTestFiles.cacheManifest(fixture.mavenProject());
    final ObjectMapper mapper = new ObjectMapper();
    final JsonNode original = mapper.readTree(manifest.toFile());

    final ObjectNode unsupportedVersion = original.deepCopy();
    unsupportedVersion.put(SCHEMA_VERSION_PROPERTY, 13);
    EffectiveOutputCacheTestFiles.writeManifest(manifest, unsupportedVersion);
    assertCacheMiss(effective);

    final ObjectNode incompatibleVersionOneDraft = mapper.readTree(manifest.toFile()).deepCopy();
    incompatibleVersionOneDraft.remove("formatId");
    EffectiveOutputCacheTestFiles.writeManifest(manifest, incompatibleVersionOneDraft);
    assertCacheMiss(effective);

    Files.writeString(manifest, "null");
    assertCacheMiss(effective);

    final ObjectNode missingEntries = (ObjectNode) original.deepCopy();
    missingEntries.remove("entries");
    EffectiveOutputCacheTestFiles.writeManifest(manifest, missingEntries);
    assertCacheMiss(effective);

    final ObjectNode nullEntry = (ObjectNode) original.deepCopy();
    ((com.fasterxml.jackson.databind.node.ArrayNode) nullEntry.get("entries"))
        .set(0, mapper.getNodeFactory().nullNode());
    EffectiveOutputCacheTestFiles.writeManifest(manifest, nullEntry);
    assertCacheMiss(effective);

    EffectiveOutputCacheTestFiles.mutateCacheEntry(
        manifest, entry -> entry.putNull("trimmedSha256"));
    assertCacheMiss(effective);

    EffectiveOutputCacheTestFiles.mutateCacheEntry(
        manifest, entry -> entry.put("originalSha1", "0".repeat(40)));
    assertCacheMiss(effective);

    for (final String field : List.of("roots", "retainedClassNames", "reachableLibraryClasses")) {
      EffectiveOutputCacheTestFiles.mutateCacheEntry(
          manifest, entry -> entry.putArray(field).addNull());
      assertCacheMiss(effective);
    }
  }

  @Test
  void multiReleaseFingerprintTracksSourceTargetStrategyAndTierPlatformIdentity() throws Exception {
    final Fixture fixture = fixture(false, false, false, false, 11);
    fixture.mavenProject().getProperties().remove("maven.compiler.release");
    fixture.mavenProject().getProperties().setProperty("maven.compiler.source", "8");
    fixture.mavenProject().getProperties().setProperty("maven.compiler.target", "11");
    writeMultiReleaseInput(fixture, 1, false, false);
    final Path trace = trace(temporaryDirectory, ENTRY_TRACE);
    final ServiceOperation targetEleven =
        operation(fixture, trace, null, true, List.of(), "vertical-shading");
    final ElisionAnalysisModel.EffectiveAnalysis firstEffective =
        targetEleven.service().finishAnalysis(targetEleven.prepared());
    assertAll(
        "source 8 and target 11 use target 11 while retaining the active runtime boundary",
        () -> assertThat(firstEffective.trimAnalysis().targetRelease()).isEqualTo(11),
        () ->
            assertThat(firstEffective.trimAnalysis().runtimeRelease())
                .isEqualTo(Runtime.version().feature()),
        () ->
            assertThat(firstEffective.trimAnalysis().analyzedTiers())
                .containsExactly(11, 17, Runtime.version().feature()));
    final List<String> firstPlatformIdentities = firstEffective.trimAnalysis().platformIdentities();
    final TrimResult first = MavenDependencyTrimmer.trimEffectiveOutputs(firstEffective);
    final ArtifactTrimRecord firstRecord = outputRecord(first, fixture);
    final JsonNode firstEnvironment = effectiveReportEnvironment(firstEffective, first, fixture);
    assertAll(
        "effective trim outputs carry the resolved target and active runtime",
        () -> assertThat(firstEnvironment.path("targetRelease").asInt()).isEqualTo(11),
        () ->
            assertThat(firstEnvironment.path("runtimeRelease").asInt())
                .isEqualTo(Runtime.version().feature()));
    assertThat(firstRecord.mrjarStatus()).isEqualTo("elevated_and_trimmed");
    assertThat(firstRecord.totalClasses()).isEqualTo(3);
    assertThat(firstRecord.originalPhysicalEntries()).hasValue(6);
    final Path manifest = EffectiveOutputCacheTestFiles.cacheManifest(fixture.mavenProject());
    final ObjectMapper mapper = new ObjectMapper();
    final JsonNode firstManifest = mapper.readTree(manifest.toFile());
    assertThat(firstManifest.path(SCHEMA_VERSION_PROPERTY).asInt())
        .isEqualTo(MavenDependencyTrimmer.CACHE_SCHEMA_VERSION);
    final String firstFingerprint = firstManifest.path(FINGERPRINT_PROPERTY).asText();
    final TrimResult cachedTargetEleven =
        MavenDependencyTrimmer.trimEffectiveOutputs(firstEffective);
    final int cachedTargetElevenCacheHits = cachedTargetEleven.cacheHits();
    final JsonNode cachedEnvironment =
        effectiveReportEnvironment(firstEffective, cachedTargetEleven, fixture);
    assertAll(
        "a validated cache hit retains the current execution environment",
        () ->
            assertTrue(
                cachedTargetElevenCacheHits > 0,
                "a validated cache hit should retain its lookup result"),
        () -> assertThat(cachedEnvironment.path("targetRelease").asInt()).isEqualTo(11),
        () ->
            assertThat(cachedEnvironment.path("runtimeRelease").asInt())
                .isEqualTo(Runtime.version().feature()));

    EffectiveOutputCacheTestFiles.mutateCacheEntry(
        manifest, entry -> entry.put("retainedClasses", 1));
    assertThat(trimEffective(targetEleven).cacheHits()).isZero();
    EffectiveOutputCacheTestFiles.mutateCacheEntry(
        manifest,
        entry ->
            entry.put(
                "originalPhysicalEntries", entry.path("originalPhysicalEntries").asInt() + 1));
    assertThat(trimEffective(targetEleven).cacheHits()).isZero();
    EffectiveOutputCacheTestFiles.mutateCacheEntry(
        manifest,
        entry ->
            entry.put("trimmedPhysicalEntries", entry.path("trimmedPhysicalEntries").asInt() + 1));
    assertThat(trimEffective(targetEleven).cacheHits()).isZero();

    writeMultiReleaseInput(fixture, 2, false, false);
    final ServiceOperation changedMrInput =
        operation(fixture, trace, null, true, List.of(), "vertical-shading");
    final TrimResult changedMrResult = trimEffective(changedMrInput);
    final ArtifactTrimRecord revisionTwoRecord = outputRecord(changedMrResult, fixture);
    assertThat(changedMrResult.cacheHits()).isZero();
    final String changedInputFingerprint =
        mapper.readTree(manifest.toFile()).path(FINGERPRINT_PROPERTY).asText();
    assertThat(changedInputFingerprint).isNotEqualTo(firstFingerprint);

    assertMrjarInventoryInvalidation(fixture, trace, revisionTwoRecord);

    fixture.mavenProject().getProperties().remove("maven.compiler.source");
    fixture.mavenProject().getProperties().remove("maven.compiler.target");
    fixture.mavenProject().getProperties().setProperty("maven.compiler.release", "17");
    final ServiceOperation targetSeventeen =
        operation(fixture, trace, null, true, List.of(), "vertical-shading");
    final ElisionAnalysisModel.EffectiveAnalysis targetSeventeenEffective =
        targetSeventeen.service().finishAnalysis(targetSeventeen.prepared());
    assertAll(
        "target release changes MR selection without changing the active JDK class table",
        () -> assertThat(targetSeventeenEffective.trimAnalysis().targetRelease()).isEqualTo(17),
        () ->
            assertThat(targetSeventeenEffective.trimAnalysis().runtimeRelease())
                .isEqualTo(Runtime.version().feature()),
        () ->
            assertThat(targetSeventeenEffective.trimAnalysis().analyzedTiers())
                .containsExactly(17, Runtime.version().feature()),
        () ->
            assertThat(targetSeventeenEffective.trimAnalysis().platformIdentities())
                .isEqualTo(firstPlatformIdentities));
    assertThat(MavenDependencyTrimmer.trimEffectiveOutputs(targetSeventeenEffective).cacheHits())
        .isZero();
    final String targetFingerprint =
        mapper.readTree(manifest.toFile()).path(FINGERPRINT_PROPERTY).asText();
    assertThat(targetFingerprint).isNotEqualTo(changedInputFingerprint);

    final ServiceOperation passThrough =
        operation(fixture, trace, null, true, List.of(), "pass-through");
    assertThat(trimEffective(passThrough).cacheHits()).isZero();
    assertThat(mapper.readTree(manifest.toFile()).path(FINGERPRINT_PROPERTY).asText())
        .isNotEqualTo(targetFingerprint);
    assertThat(mapper.readTree(manifest.toFile()).path(SCHEMA_VERSION_PROPERTY).asInt())
        .isEqualTo(1);
  }

  private void writeMultiReleaseInput(
      final Fixture fixture,
      final int revision,
      final boolean includeUpperTierExtra,
      final boolean includeTargetUnused)
      throws IOException {
    final Path source = fixture.snapshot("a").filePath();
    final Path versionedJar = temporaryDirectory.resolve("versioned-a.jar");
    final Map<String, String> upperTierSources = new java.util.concurrent.ConcurrentHashMap<>();
    upperTierSources.put(
        "Entry.java",
        "package closure.a; public class Entry { public Object make() { "
            + "return new closure.d.Ancestor(); } }");
    upperTierSources.put("VersionOnly.java", "package closure.a; class VersionOnly {}");
    if (includeUpperTierExtra) {
      upperTierSources.put("ExtraUpperTier.java", "package closure.a; class ExtraUpperTier {}");
    }
    io.github.spockz.elider.test.CompilationFixtureSupport.compileToJar(
        versionedJar,
        temporaryDirectory.resolve("versioned-a-src"),
        upperTierSources,
        fixture.snapshot("d").filePath(),
        17);
    final Path targetUnusedJar = temporaryDirectory.resolve("target-unused-a.jar");
    if (includeTargetUnused) {
      io.github.spockz.elider.test.CompilationFixtureSupport.compileToJar(
          targetUnusedJar,
          temporaryDirectory.resolve("target-unused-a-src"),
          Map.of("TargetUnused.java", "package closure.a; class TargetUnused {}"),
          null,
          8);
    }
    final Path rewritten = temporaryDirectory.resolve("a-mr.jar");
    final Manifest manifest;
    try (JarFile input = new JarFile(source.toFile())) {
      manifest = input.getManifest() == null ? new Manifest() : new Manifest(input.getManifest());
      manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
      manifest.getMainAttributes().putValue("Multi-Release", "true");
      manifest.getMainAttributes().putValue("X-Test-Revision", Integer.toString(revision));
      try (JarFile versioned = new JarFile(versionedJar.toFile());
          JarOutputStream output =
              new JarOutputStream(Files.newOutputStream(rewritten), manifest)) {
        copyEntries(
            input,
            output,
            "",
            Set.of(
                "META-INF/versions/17/closure/a/Entry.class",
                "META-INF/versions/17/closure/a/VersionOnly.class",
                "META-INF/versions/17/closure/a/ExtraUpperTier.class",
                "closure/a/TargetUnused.class"));
        copyEntries(versioned, output, "META-INF/versions/17/", Set.of());
        if (includeTargetUnused) {
          try (JarFile unused = new JarFile(targetUnusedJar.toFile())) {
            copyEntries(unused, output, "", Set.of());
          }
        }
      }
    }
    Files.move(rewritten, source, StandardCopyOption.REPLACE_EXISTING);
  }

  private static void copyEntries(
      final JarFile input,
      final JarOutputStream output,
      final String prefix,
      final Set<String> replacedEntries)
      throws IOException {
    for (final JarEntry entry : input.stream().toList()) {
      if (entry.isDirectory()
          || "META-INF/MANIFEST.MF".equalsIgnoreCase(entry.getName())
          || replacedEntries.contains(entry.getName())) {
        continue;
      }
      copyEntry(input, output, prefix, entry);
    }
  }

  private static void copyEntry(
      final JarFile input, final JarOutputStream output, final String prefix, final JarEntry entry)
      throws IOException {
    output.putNextEntry(new JarEntry(prefix + entry.getName()));
    try (InputStream contents = input.getInputStream(entry)) {
      contents.transferTo(output);
    }
    output.closeEntry();
  }

  private static ArtifactTrimRecord outputRecord(final TrimResult result, final Fixture fixture) {
    return EffectiveOutputCacheTestFiles.record(result.records(), fixture.coordinate("a"));
  }

  private void assertCacheMiss(final ElisionAnalysisModel.EffectiveAnalysis effective)
      throws IOException, MojoFailureException {
    assertThat(MavenDependencyTrimmer.trimEffectiveOutputs(effective).cacheHits()).isZero();
  }

  private void assertMrjarInventoryInvalidation(
      final Fixture fixture, final Path trace, final ArtifactTrimRecord baselineRecord)
      throws IOException, MojoFailureException {
    final String upperTierEntry = "META-INF/versions/17/closure/a/ExtraUpperTier.class";
    writeMultiReleaseInput(fixture, 2, true, false);
    final boolean upperTierPresentInInput;
    try (JarFile inputJar = new JarFile(fixture.snapshot("a").filePath().toFile())) {
      upperTierPresentInInput = inputJar.getEntry(upperTierEntry) != null;
    }
    final ServiceOperation upperTierOperation =
        operation(fixture, trace, null, true, List.of(), "vertical-shading");
    final TrimResult upperTierResult = trimEffective(upperTierOperation);
    final ArtifactTrimRecord upperTierRecord = outputRecord(upperTierResult, fixture);
    final ArtifactDigests expectedUpperTierDigests =
        ArtifactDigests.read(fixture.snapshot("a").filePath());
    final boolean upperTierPreservedInOutput;
    try (JarFile upperOutputJar = new JarFile(upperTierRecord.trimmedPath().toFile())) {
      upperTierPreservedInOutput = upperOutputJar.getEntry(upperTierEntry) != null;
    }

    final String targetUnusedEntry = "closure/a/TargetUnused.class";
    writeMultiReleaseInput(fixture, 2, false, true);
    final boolean targetUnusedPresentInInput;
    try (JarFile inputJar = new JarFile(fixture.snapshot("a").filePath().toFile())) {
      targetUnusedPresentInInput = inputJar.getEntry(targetUnusedEntry) != null;
    }
    final ServiceOperation targetUnusedOperation =
        operation(fixture, trace, null, true, List.of(), "vertical-shading");
    final TrimResult targetUnusedResult = trimEffective(targetUnusedOperation);
    final ArtifactTrimRecord targetUnusedRecord = outputRecord(targetUnusedResult, fixture);
    final ArtifactDigests expectedTargetUnusedDigests =
        ArtifactDigests.read(fixture.snapshot("a").filePath());
    final boolean targetUnusedRemovedFromOutput;
    try (JarFile targetOutputJar = new JarFile(targetUnusedRecord.trimmedPath().toFile())) {
      targetUnusedRemovedFromOutput = targetOutputJar.getEntry(targetUnusedEntry) == null;
    }

    assertAll(
        "MRJAR upper-tier preservation and target-tier trimming on inventory change",
        () -> assertTrue(upperTierPresentInInput, "added upper-tier entry must exist in input"),
        () ->
            org.junit.jupiter.api.Assertions.assertEquals(
                0, upperTierResult.cacheHits(), "upper-tier inventory change should miss cache"),
        () ->
            org.junit.jupiter.api.Assertions.assertEquals(
                expectedUpperTierDigests.sha256(),
                upperTierRecord.originalSha256(),
                "upper-tier provenance should match updated MRJAR SHA-256"),
        () ->
            assertTrue(
                upperTierRecord.totalClasses() > baselineRecord.totalClasses(),
                "upper-tier addition should increase totalClasses"),
        () ->
            assertTrue(
                upperTierPreservedInOutput,
                "above-target versioned entry should be preserved in published output"),
        () ->
            assertTrue(
                targetUnusedPresentInInput, "added target-visible entry must exist in input"),
        () ->
            org.junit.jupiter.api.Assertions.assertEquals(
                0,
                targetUnusedResult.cacheHits(),
                "target-tier inventory change should miss cache"),
        () ->
            org.junit.jupiter.api.Assertions.assertEquals(
                expectedTargetUnusedDigests.sha256(),
                targetUnusedRecord.originalSha256(),
                "target-tier provenance should match updated MRJAR SHA-256"),
        () ->
            assertTrue(
                targetUnusedRecord.totalClasses() > baselineRecord.totalClasses(),
                "target-visible addition should increase totalClasses"),
        () ->
            assertTrue(
                targetUnusedRemovedFromOutput,
                "unreferenced target-visible entry should be removed from published output"));
  }

  private JsonNode effectiveReportEnvironment(
      final ElisionAnalysisModel.EffectiveAnalysis effective,
      final TrimResult trimResult,
      final Fixture fixture)
      throws IOException {
    final ElisionAnalysisModel.Analysis analysis =
        MavenEffectiveAnalysisReport.create(effective, trimResult);
    return new ObjectMapper()
        .valueToTree(MavenElisionReportSnapshot.from(fixture.mavenProject(), analysis))
        .path("executionEnvironment");
  }
}
