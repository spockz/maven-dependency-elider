/* WHY: Verifies typed package and unresolved routine claims survive indexing and assessment. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.OsvAdvisoryRecord;
import io.github.spockz.elider.scanner.OsvSnapshotIndexer;
import io.github.spockz.elider.scanner.VulnerabilityCacheEnvelopeWriter;
import io.github.spockz.elider.scanner.VulnerabilityCacheManager;
import io.github.spockz.elider.trimmer.ArtifactDigests;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Tests review-only source retention after package matching and trimming. */
class MavenAdvisoryReviewRetentionTest {
  /** Dummy archive payload for class entries. */
  private static final byte[] DUMMY_BYTE = {0};

  /** Temporary workspace for source, cache, and artifact fixtures. */
  @TempDir private Path tempDir;

  /** Creates an isolated review-retention test fixture. */
  /* package */
  MavenAdvisoryReviewRetentionTest() {
    // JUnit constructs one instance per test method.
  }

  /** Confirms routine-only CNA and package-only OSV claims remain review context. */
  /* package */
  @Test
  void routineOnlySourceClaimsSurviveIndexCacheAndAssessmentAsReviewContext() throws IOException {
    final Path cveFile = tempDir.resolve("cves/2025/12xxx/CVE-2025-12345.json");
    Files.createDirectories(cveFile.getParent());
    Files.writeString(
        cveFile,
        """
        {
          "containers":{"cna":{"affected":[{
            "vendor":"Example",
            "product":"demo",
            "packageURL":"pkg:maven/org.example/demo",
            "defaultStatus":"affected",
            "versions":[{"version":"1.0","status":"affected","versionType":"semver","lessThan":"2.0","lessThanOrEqual":null,"changes":[{"at":"1.5","status":"unaffected"}]}],
            "programRoutines":[{"name":"parse"}]
          }]}}
        }
        """);
    final byte[] snapshot = routineOnlySnapshot();
    final List<OsvAdvisoryRecord> indexed =
        new OsvSnapshotIndexer().indexZip(new ByteArrayInputStream(snapshot), tempDir);
    final Path cache = Files.createDirectories(tempDir.resolve("routine-cache"));
    Files.write(
        cache.resolve("index.json"),
        new VulnerabilityCacheEnvelopeWriter()
            .encode(MavenAssessmentFixtures.CACHE_PRODUCER, indexed));

    final ArtifactCoordinate coordinate = ArtifactCoordinate.of("org.example", "demo", "1.0");
    final Path original = tempDir.resolve("routine-original.jar");
    final Path trimmed = tempDir.resolve("routine-trimmed.jar");
    writeJar(original, "org/example/Absent.class");
    writeJar(trimmed);
    final ArtifactDigests originalDigest = ArtifactDigests.read(original);
    final ArtifactDigests trimmedDigest = ArtifactDigests.read(trimmed);
    final ArtifactTrimRecord trimRecord =
        new ArtifactTrimRecord(
            coordinate,
            original,
            originalDigest.sha256(),
            originalDigest.sha1(),
            trimmed,
            trimmedDigest.sha256(),
            trimmedDigest.sha1(),
            1,
            0,
            32);
    final VulnerabilityCacheManager.CacheConfig cacheConfig =
        new VulnerabilityCacheManager.CacheConfig(
            cache,
            null,
            null,
            Duration.ofHours(24),
            false,
            true,
            VulnerabilityCacheManager.bundledEmptySeed(),
            MavenAssessmentFixtures.CACHE_PRODUCER);
    final MavenVulnerabilityAssessment.Result result =
        new MavenVulnerabilityAssessment(new RecordingMavenLog())
            .assess(
                cacheConfig,
                ConfiguredVulnerabilityMappings.empty(),
                List.of(trimRecord),
                List.of(),
                List.of(coordinate));

    assertAll(
        "routine-only and package-only source context remains review-only through assessment",
        () -> assertThat(result.attestations()).isEmpty(),
        () -> assertThat(result.provenVulnerableCodeAbsent()).isEmpty(),
        () -> assertThat(result.inactiveDueToMissingPrerequisites()).isEmpty(),
        () -> assertThat(result.matchedAdvisoryEvidence()).hasSize(2),
        () -> assertThat(result.packageAdvisoryFindings()).hasSize(2),
        () ->
            assertThat(result.packageAdvisoryFindings())
                .filteredOn(value -> "GHSA-no-cve".equals(value.osvId()))
                .singleElement()
                .satisfies(
                    value ->
                        assertAll(
                            () -> assertThat(value.coordinate()).isEqualTo(coordinate),
                            () -> assertThat(value.aliases()).containsExactly("GHSA-alias"),
                            () ->
                                assertThat(value.applicability())
                                    .isEqualTo(OsvPackageApplicability.Status.APPLICABLE),
                            () ->
                                assertThat(value.inventoryDisposition())
                                    .isEqualTo(
                                        MavenVulnerabilityAssessment.InventoryDisposition
                                            .RETAINED_AND_TRIMMED))),
        () -> assertThat(result.heuristicAdvisoryFindings()).isEmpty(),
        () ->
            assertThat(result.matchedAdvisoryRecords())
                .extracting(value -> value.advisoryRecord().osvId())
                .containsExactly("GHSA-no-cve", "GHSA-routine"),
        () ->
            assertThat(result.matchedAdvisoryRecords())
                .filteredOn(value -> "GHSA-no-cve".equals(value.advisoryRecord().osvId()))
                .singleElement()
                .satisfies(
                    value ->
                        assertThat(
                                value
                                    .matchedAffectedPackages()
                                    .getFirst()
                                    .ranges()
                                    .getFirst()
                                    .repo())
                            .isEqualTo("https://github.com/example/repo")),
        () ->
            assertThat(result.matchedAdvisoryRecords())
                .filteredOn(value -> "GHSA-routine".equals(value.advisoryRecord().osvId()))
                .singleElement()
                .satisfies(
                    value ->
                        assertThat(value.advisoryRecord().cnaAffectedEntries().getFirst())
                            .satisfies(
                                entry ->
                                    assertAll(
                                        () -> assertThat(entry.programRoutines()).contains("parse"),
                                        () ->
                                            assertThat(entry.defaultStatus()).isEqualTo("affected"),
                                        () ->
                                            assertThat(entry.versions().getFirst().lessThan())
                                                .isEqualTo("2.0"),
                                        () ->
                                            assertThat(entry.versions().getFirst().changes())
                                                .containsExactly(
                                                    Map.of(
                                                        "at", "1.5", "status", "unaffected"))))));
  }

  private byte[] routineOnlySnapshot() throws IOException {
    final String cveRecord =
        """
        {"id":"GHSA-routine","aliases":["CVE-2025-12345"],"affected":[{"package":{"ecosystem":"Maven","name":"org.example:demo"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0"},{"fixed":"2.0"}]}]}]}
        """;
    final String packageRecord =
        """
        {"id":"GHSA-no-cve","aliases":["GHSA-alias"],"affected":[{"package":{"ecosystem":"Maven:custom","name":"org.example:demo"},"versions":["1.0"],"ranges":[{"type":"GIT","repo":"https://github.com/example/repo","events":[{"introduced":"1.0"},{"fixed":"2.0"}]}]}]}
        """;
    final ByteArrayOutputStream output = new ByteArrayOutputStream();
    try (ZipOutputStream zip = new ZipOutputStream(output)) {
      writeZipEntry(zip, "first.json", cveRecord);
      writeZipEntry(zip, "second.json", packageRecord);
    }
    return output.toByteArray();
  }

  private static void writeZipEntry(
      final ZipOutputStream zip, final String name, final String content) throws IOException {
    zip.putNextEntry(new ZipEntry(name));
    zip.write(content.getBytes(StandardCharsets.UTF_8));
    zip.closeEntry();
  }

  private static void writeJar(final Path path, final String... entries) throws IOException {
    Files.createDirectories(path.getParent());
    try (JarOutputStream jar = new JarOutputStream(Files.newOutputStream(path))) {
      for (final String name : entries) {
        writeJarEntry(jar, name);
      }
    }
  }

  private static void writeJarEntry(final JarOutputStream jar, final String name)
      throws IOException {
    jar.putNextEntry(new JarEntry(name));
    jar.write(DUMMY_BYTE);
    jar.closeEntry();
  }
}
