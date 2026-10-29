// WHY: Verifies cache validation and repair for effective per-artifact analyses.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.spockz.elider.trimmer.ArtifactDigests;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Enumeration;
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
@SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
final class MavenElisionServiceEffectiveOutputCacheTest
    extends MavenElisionServiceEffectiveOutputSupport {
  /** Shared root included by every cache fixture. */
  private static final String ENTRY_TRACE = "closure/a/Entry";

  /** Cache manifest property used to identify the effective operation. */
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
    final MavenElisionService.EffectiveAnalysis effective =
        operation.service().finishAnalysis(operation.prepared());
    outputRecord(MavenDependencyTrimmer.trimEffectiveOutputs(effective), fixture);
    final Path manifest = EffectiveOutputCacheTestFiles.cacheManifest(fixture.mavenProject());
    final ObjectMapper mapper = new ObjectMapper();
    final JsonNode original = mapper.readTree(manifest.toFile());
    final String fingerprint = original.path(FINGERPRINT_PROPERTY).asText();

    final ObjectNode unsupportedVersion = original.deepCopy();
    unsupportedVersion.put("schemaVersion", 13);
    EffectiveOutputCacheTestFiles.writeManifest(manifest, unsupportedVersion);
    assertCacheMiss(effective);

    final ObjectNode incompatibleVersionOneDraft = mapper.readTree(manifest.toFile()).deepCopy();
    incompatibleVersionOneDraft.remove("formatId");
    EffectiveOutputCacheTestFiles.writeManifest(manifest, incompatibleVersionOneDraft);
    assertCacheMiss(effective);

    Files.writeString(manifest, "null");
    assertCacheMiss(effective);

    final ObjectNode missingEntries = EffectiveOutputCacheTestFiles.manifestNode(fingerprint);
    missingEntries.putNull("entries");
    EffectiveOutputCacheTestFiles.writeManifest(manifest, missingEntries);
    assertCacheMiss(effective);

    final ObjectNode nullEntry = EffectiveOutputCacheTestFiles.manifestNode(fingerprint);
    nullEntry.putArray("entries").addNull();
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
    writeMultiReleaseInput(fixture, 1);
    final Path trace = trace(temporaryDirectory, ENTRY_TRACE);
    final ServiceOperation targetEleven =
        operation(fixture, trace, null, true, List.of(), "vertical-shading");
    final MavenElisionService.EffectiveAnalysis firstEffective =
        targetEleven.service().finishAnalysis(targetEleven.prepared());
    assertThat(firstEffective.trimAnalysis().analyzedTiers()).containsExactly(11, 17, 21);
    final List<String> firstPlatformIdentities = firstEffective.trimAnalysis().platformIdentities();
    final MavenDependencyTrimmer.TrimResult first =
        MavenDependencyTrimmer.trimEffectiveOutputs(firstEffective);
    final ArtifactTrimRecord firstRecord = outputRecord(first, fixture);
    assertThat(firstRecord.mrjarStatus()).isEqualTo("elevated_and_trimmed");
    assertThat(firstRecord.totalClasses()).isEqualTo(3);
    assertThat(firstRecord.originalPhysicalEntries()).hasValue(6);
    final Path manifest = EffectiveOutputCacheTestFiles.cacheManifest(fixture.mavenProject());
    final ObjectMapper mapper = new ObjectMapper();
    final JsonNode firstManifest = mapper.readTree(manifest.toFile());
    assertThat(firstManifest.path("schemaVersion").asInt())
        .isEqualTo(MavenDependencyTrimmer.CACHE_SCHEMA_VERSION);
    final String firstFingerprint = firstManifest.path(FINGERPRINT_PROPERTY).asText();
    assertThat(trimEffective(targetEleven).cacheHits()).isPositive();

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

    writeMultiReleaseInput(fixture, 2);
    final ServiceOperation changedMrInput =
        operation(fixture, trace, null, true, List.of(), "vertical-shading");
    assertThat(trimEffective(changedMrInput).cacheHits()).isZero();
    final String changedInputFingerprint =
        mapper.readTree(manifest.toFile()).path(FINGERPRINT_PROPERTY).asText();
    assertThat(changedInputFingerprint).isNotEqualTo(firstFingerprint);

    fixture.mavenProject().getProperties().setProperty("maven.compiler.release", "17");
    final ServiceOperation targetSeventeen =
        operation(fixture, trace, null, true, List.of(), "vertical-shading");
    final MavenElisionService.EffectiveAnalysis targetSeventeenEffective =
        targetSeventeen.service().finishAnalysis(targetSeventeen.prepared());
    assertThat(targetSeventeenEffective.trimAnalysis().analyzedTiers()).containsExactly(17, 21);
    assertThat(targetSeventeenEffective.trimAnalysis().platformIdentities())
        .isNotEqualTo(firstPlatformIdentities);
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
    assertThat(mapper.readTree(manifest.toFile()).path("schemaVersion").asInt()).isEqualTo(1);
  }

  private void writeMultiReleaseInput(final Fixture fixture, final int revision)
      throws IOException {
    final Path source = fixture.snapshot("a").filePath();
    final Path versionedJar = temporaryDirectory.resolve("versioned-a.jar");
    io.github.spockz.elider.test.CompilationFixtureSupport.compileToJar(
        versionedJar,
        temporaryDirectory.resolve("versioned-a-src"),
        Map.of(
            "Entry.java",
            "package closure.a; public class Entry { public Object make() { "
                + "return new closure.d.Ancestor(); } }",
            "VersionOnly.java",
            "package closure.a; class VersionOnly {}"),
        fixture.snapshot("d").filePath(),
        17);
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
                "META-INF/versions/17/closure/a/VersionOnly.class"));
        copyEntries(versioned, output, "META-INF/versions/17/", Set.of());
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
    final Enumeration<JarEntry> entries = input.entries();
    while (entries.hasMoreElements()) {
      final JarEntry entry = entries.nextElement();
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

  private static ArtifactTrimRecord outputRecord(
      final MavenDependencyTrimmer.TrimResult result, final Fixture fixture) {
    return EffectiveOutputCacheTestFiles.record(result.records(), fixture.coordinate("a"));
  }

  private void assertCacheMiss(final MavenElisionService.EffectiveAnalysis effective)
      throws IOException, MojoFailureException {
    assertThat(MavenDependencyTrimmer.trimEffectiveOutputs(effective).cacheHits()).isZero();
  }
}
