/* WHY: Proves CVE indexing reconciles the checkout independently of OSV aliases. */

package io.github.spockz.elider.scanner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.model.VersionApplicability;
import io.github.spockz.elider.model.VersionCoverageClaim;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Verifies complete and changed-path indexing against local CVE records. */
@SuppressWarnings({"PMD.AtLeastOneConstructor", "PMD.AvoidDuplicateLiterals"})
// Repeated record identities keep the independent source snapshots readable.
class CveListFindingIndexerTest {
  /** Isolates each test's source checkout. */
  @TempDir /* default */ Path tempDir;

  @Test
  void eachCheckoutScanReconcilesCurrentCveRecordsAndRemovesDeletedClaims() throws IOException {
    writeRecord("CVE-2026-12345", "pkg:maven/org.example/first", "1.0.0");
    writeRecord("CVE-2026-12346", "pkg:maven/org.example/second", "2.0.0");
    final CveListFindingIndexer indexer = new CveListFindingIndexer();

    final CveListFindingIndexer.IndexResult first = indexer.index(tempDir);
    Files.delete(recordPath("CVE-2026-12345"));
    final CveListFindingIndexer.IndexResult afterDeletion = indexer.index(tempDir);

    assertAll(
        () -> assertThat(first.contributions()).hasSize(2),
        () ->
            assertThat(afterDeletion.contributions())
                .singleElement()
                .satisfies(
                    contribution ->
                        assertThat(contribution.vulnerabilityId()).isEqualTo("CVE-2026-12346")),
        () -> assertThat(first.revision()).isNotEqualTo(afterDeletion.revision()));
  }

  @Test
  void changedRecordIndexingParsesOnlyTheSelectedCanonicalPath() throws IOException {
    writeRecord("CVE-2026-12345", "pkg:maven/org.example/first", "1.0.0");
    writeRecord("CVE-2026-12346", "pkg:maven/org.example/second", "2.0.0");
    final CveListFindingIndexer indexer = new CveListFindingIndexer();
    indexer.index(tempDir);
    writeRecord("CVE-2026-12345", "pkg:maven/org.example/first", "1.1.0");

    final CveListFindingIndexer.IndexResult changed =
        indexer.indexPaths(tempDir, List.of(Path.of("cves/2026/12xxx/CVE-2026-12345.json")));

    assertAll(
        () -> assertThat(changed.sourceRecordCount()).isEqualTo(1),
        () ->
            assertThat(changed.contributions())
                .singleElement()
                .satisfies(
                    contribution ->
                        assertAll(
                            () ->
                                assertThat(contribution.vulnerabilityId())
                                    .isEqualTo("CVE-2026-12345"),
                            () ->
                                assertThat(contribution.versionClaims())
                                    .filteredOn(
                                        claim -> claim.status() == VersionApplicability.AFFECTED)
                                    .extracting(VersionCoverageClaim::normalizedMavenRange)
                                    .containsExactly("[1.1.0,1.1.0]"))));
  }

  @Test
  void unsupportedPublishedPackageIdentityIsReportedWithoutInventingMavenCoordinates()
      throws IOException {
    final Path path = recordPath("CVE-2026-12345");
    Files.createDirectories(path.getParent());
    Files.writeString(
        path,
        """
        {"cveMetadata":{"cveId":"CVE-2026-12345","state":"PUBLISHED"},
         "containers":{"cna":{"affected":[
           {"product":"widget","packageURL":"pkg:npm/example/widget",
            "versions":[{"version":"1.0.0","status":"affected","versionType":"npm"}]}
         ]}}}
        """);

    final CveListFindingIndexer.IndexResult result = new CveListFindingIndexer().index(tempDir);

    assertAll(
        () -> assertThat(result.contributions()).isEmpty(),
        () ->
            assertThat(result.observationDiagnostics())
                .containsExactly(
                    "1 published affected entries lacked a supported Maven package identity"),
        () -> assertThat(result.sourceRecordCount()).isEqualTo(1));
  }

  private void writeRecord(final String cveId, final String purl, final String version)
      throws IOException {
    final Path path = recordPath(cveId);
    Files.createDirectories(path.getParent());
    Files.writeString(
        path,
        """
        {"cveMetadata":{"cveId":"%s","state":"PUBLISHED"},
         "containers":{"cna":{"affected":[
           {"product":"library","packageURL":"%s",
            "versions":[{"version":"%s","status":"affected","versionType":"maven"}]}
         ]}}}
        """
            .formatted(cveId, purl, version));
  }

  private Path recordPath(final String cveId) {
    return tempDir.resolve("cves/2026/12xxx/" + cveId + ".json");
  }
}
