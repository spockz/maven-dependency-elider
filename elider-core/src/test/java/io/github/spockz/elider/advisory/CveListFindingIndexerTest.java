/* WHY: Proves CVE indexing reconciles the checkout independently of OSV aliases. */

package io.github.spockz.elider.advisory;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.model.VersionApplicability;
import io.github.spockz.elider.model.VersionCoverageClaim;
import io.github.spockz.elider.model.VulnerabilityFindingContribution;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Verifies complete and changed-path indexing against local CVE records. */
@SuppressWarnings({"PMD.AtLeastOneConstructor", "PMD.AvoidDuplicateLiterals", "PMD.TooManyMethods"})
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
  void fullScanIgnoresCveListDeltaMetadataFiles() throws IOException {
    writeRecord("CVE-2026-12345", "pkg:maven/org.example/first", "1.0.0");
    Files.writeString(tempDir.resolve("cves/delta.json"), "{\"delta\":true}");
    Files.writeString(tempDir.resolve("cves/deltaLog.json"), "[]");

    final CveListFindingIndexer.IndexResult result = new CveListFindingIndexer().index(tempDir);

    assertAll(
        "checkout delta metadata is not treated as an advisory record",
        () -> assertThat(result.sourceRecordCount()).isEqualTo(1),
        () ->
            assertThat(result.contributions())
                .extracting(VulnerabilityFindingContribution::vulnerabilityId)
                .containsExactly("CVE-2026-12345"),
        () -> assertThat(result.observationDiagnostics()).isEmpty());
  }

  @Test
  void publishedRecordMissingContainersIsPartialButRejectedRecordMayOmitThem() throws IOException {
    final Path incomplete = recordPath("CVE-2026-12345");
    Files.createDirectories(incomplete.getParent());
    Files.writeString(
        incomplete, "{\"cveMetadata\":{\"cveId\":\"CVE-2026-12345\",\"state\":\"PUBLISHED\"}}");
    final Path rejected = recordPath("CVE-2026-12346");
    Files.createDirectories(rejected.getParent());
    Files.writeString(
        rejected, "{\"cveMetadata\":{\"cveId\":\"CVE-2026-12346\",\"state\":\"REJECTED\"}}");

    final CveListFindingIndexer.IndexResult result = new CveListFindingIndexer().index(tempDir);

    assertAll(
        "published missing scope remains partial while an intentional rejection is a valid empty",
        () -> assertThat(result.contributions()).isEmpty(),
        () -> assertThat(result.skippedRows()).isEqualTo(1),
        () ->
            assertThat(result.observationDiagnostics())
                .anySatisfy(
                    diagnostic -> assertThat(diagnostic).contains("CVE-2026-12345", "containers")),
        () ->
            assertThat(result.observationDiagnostics())
                .noneMatch(diagnostic -> diagnostic.contains("CVE-2026-12346")));
  }

  @Test
  void missingCnaAffectedContainerDoesNotDiscardValidAdpAssertions() throws IOException {
    final Path missingCna = recordPath("CVE-2026-12345");
    Files.createDirectories(missingCna.getParent());
    Files.writeString(
        missingCna,
        """
        {"cveMetadata":{"cveId":"CVE-2026-12345","state":"PUBLISHED"},
         "containers":{"adp":[{"affected":[
           {"product":"missing-cna","packageURL":"pkg:maven/org.example/missing-cna",
            "versions":[{"version":"2.0.0","status":"affected","versionType":"maven"}]}
         ]}]}}
        """);
    final Path missingAffected = recordPath("CVE-2026-12346");
    Files.createDirectories(missingAffected.getParent());
    Files.writeString(
        missingAffected,
        """
        {"cveMetadata":{"cveId":"CVE-2026-12346","state":"PUBLISHED"},
         "containers":{"cna":{},"adp":[{"affected":[
           {"product":"missing-affected","packageURL":"pkg:maven/org.example/missing-affected",
            "versions":[{"version":"3.0.0","status":"affected","versionType":"maven"}]}
         ]}]}}
        """);

    final CveListFindingIndexer.IndexResult result = new CveListFindingIndexer().index(tempDir);

    assertAll(
        "valid ADP contributions survive missing required CNA affected containers",
        () ->
            assertThat(result.contributions())
                .extracting(VulnerabilityFindingContribution::artifactId)
                .containsExactly("missing-cna", "missing-affected"),
        () -> assertThat(result.skippedRows()).isEqualTo(2),
        () ->
            assertThat(result.observationDiagnostics())
                .anySatisfy(
                    diagnostic ->
                        assertThat(diagnostic)
                            .contains("CVE-2026-12345", "containers.cna.affected")),
        () ->
            assertThat(result.observationDiagnostics())
                .anySatisfy(
                    diagnostic ->
                        assertThat(diagnostic)
                            .contains("CVE-2026-12346", "containers.cna.affected")));
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

  @Test
  void malformedAffectedEntryDoesNotDiscardValidCnaAndAdpSiblings() throws IOException {
    final String cveId = "CVE-2026-12345";
    final Path path = recordPath(cveId);
    Files.createDirectories(path.getParent());
    Files.writeString(
        path,
        """
        {"cveMetadata":{"cveId":"CVE-2026-12345","state":"PUBLISHED"},
         "containers":{"cna":{"affected":[
           {"product":"first","packageURL":"pkg:maven/org.example/first",
            "versions":[{"version":"1.0.0","status":"affected","versionType":"maven"}]},
           {"product":"malformed","packageURL":"pkg:maven/org.example/malformed",
            "versions":[{"version":7,"status":"affected","versionType":"maven"}]}
         ]},"adp":[{"affected":[
           {"product":"last","packageURL":"pkg:maven/org.example/last",
            "versions":[{"version":"3.0.0","status":"affected","versionType":"maven"}]}
         ]}]}}
        """);

    final CveListFindingIndexer.IndexResult result = new CveListFindingIndexer().index(tempDir);

    assertAll(
        "a malformed affected row is isolated while neighboring source locators remain stable",
        () ->
            assertThat(result.contributions())
                .extracting(VulnerabilityFindingContribution::artifactId)
                .containsExactly("first", "last"),
        () ->
            assertThat(result.contributions())
                .extracting(VulnerabilityFindingContribution::provenance)
                .anyMatch(value -> value.contains("containers.cna.affected[0]")),
        () ->
            assertThat(result.contributions())
                .extracting(VulnerabilityFindingContribution::provenance)
                .anyMatch(value -> value.contains("containers.adp[0].affected[0]")),
        () ->
            assertThat(result.observationDiagnostics())
                .anySatisfy(
                    diagnostic ->
                        assertAll(
                            () -> assertThat(diagnostic).contains(cveId),
                            () -> assertThat(diagnostic).contains("containers.cna.affected[1]"))),
        () -> assertThat(result.sourceRecordCount()).isEqualTo(1));
  }

  @Test
  void malformedAdpContainerDoesNotDiscardValidCnaOrLaterAdpEntries() throws IOException {
    final String cveId = "CVE-2026-12345";
    final Path path = recordPath(cveId);
    Files.createDirectories(path.getParent());
    Files.writeString(
        path,
        """
        {"cveMetadata":{"cveId":"CVE-2026-12345","state":"PUBLISHED"},
         "containers":{"cna":{"affected":[
           {"product":"first","packageURL":"pkg:maven/org.example/first",
            "versions":[{"version":"1.0.0","status":"affected","versionType":"maven"}]}
         ]},"adp":[
           {"affected":[
             {"product":"second","packageURL":"pkg:maven/org.example/second",
              "versions":[{"version":"2.0.0","status":"affected","versionType":"maven"}]}
           ]},
           {"affected":"malformed"},
           {"affected":[
             {"product":"third","packageURL":"pkg:maven/org.example/third",
              "versions":[{"version":"3.0.0","status":"affected","versionType":"maven"}]}
           ]}
         ]}}
        """);

    final CveListFindingIndexer.IndexResult result = new CveListFindingIndexer().index(tempDir);

    assertAll(
        "a malformed ADP container is isolated without renumbering later source entries",
        () ->
            assertThat(result.contributions())
                .extracting(VulnerabilityFindingContribution::artifactId)
                .containsExactly("first", "second", "third"),
        () ->
            assertThat(result.contributions())
                .extracting(VulnerabilityFindingContribution::provenance)
                .anyMatch(value -> value.contains("containers.adp[2].affected[0]")),
        () ->
            assertThat(result.observationDiagnostics())
                .anySatisfy(
                    diagnostic ->
                        assertThat(diagnostic).contains(cveId, "containers.adp[1].affected")),
        () -> assertThat(result.skippedRows()).isEqualTo(1));
  }

  @Test
  void malformedCnaAffectedArrayDoesNotDiscardValidAdpEntries() throws IOException {
    final String cveId = "CVE-2026-12345";
    final Path path = recordPath(cveId);
    Files.createDirectories(path.getParent());
    Files.writeString(
        path,
        """
        {"cveMetadata":{"cveId":"CVE-2026-12345","state":"PUBLISHED"},
         "containers":{"cna":{"affected":"malformed"},"adp":[
           {"affected":[
             {"product":"second","packageURL":"pkg:maven/org.example/second",
              "versions":[{"version":"2.0.0","status":"affected","versionType":"maven"}]}
           ]},
           {"affected":[
             {"product":"third","packageURL":"pkg:maven/org.example/third",
              "versions":[{"version":"3.0.0","status":"affected","versionType":"maven"}]}
           ]}
         ]}}
        """);

    final CveListFindingIndexer.IndexResult result = new CveListFindingIndexer().index(tempDir);

    assertAll(
        "a malformed CNA affected array is isolated from independently valid ADP entries",
        () ->
            assertThat(result.contributions())
                .extracting(VulnerabilityFindingContribution::artifactId)
                .containsExactly("second", "third"),
        () ->
            assertThat(result.observationDiagnostics())
                .anySatisfy(
                    diagnostic ->
                        assertThat(diagnostic).contains(cveId, "containers.cna.affected")),
        () -> assertThat(result.skippedRows()).isEqualTo(1));
  }

  @Test
  void malformedJsonAndMetadataRecordsAreSkippedWithoutDroppingOtherCurrentRecords()
      throws IOException {
    writeRecord("CVE-2026-12345", "pkg:maven/org.example/first", "1.0.0");
    writeRecord("CVE-2026-12346", "pkg:maven/org.example/second", "2.0.0");
    final Path malformedJson = recordPath("CVE-2026-12347");
    Files.createDirectories(malformedJson.getParent());
    Files.writeString(
        malformedJson, "{\"cveMetadata\":{\"cveId\":\"CVE-2026-12347\",\"state\":\"PUBLISHED\"},");
    final Path malformedMetadata = recordPath("CVE-2026-12348");
    Files.createDirectories(malformedMetadata.getParent());
    Files.writeString(
        malformedMetadata,
        """
        {"cveMetadata":{"cveId":"CVE-2026-12349","state":"PUBLISHED"},
         "containers":{"cna":{"affected":[
           {"product":"not-indexed","packageURL":"pkg:maven/org.example/not-indexed",
            "versions":[{"version":"1.0.0","status":"affected","versionType":"maven"}]}
         ]}}}
        """);

    final CveListFindingIndexer.IndexResult result = new CveListFindingIndexer().index(tempDir);

    assertAll(
        "an invalid source record remains visible without masking valid records",
        () ->
            assertThat(result.contributions())
                .extracting(VulnerabilityFindingContribution::vulnerabilityId)
                .containsExactly("CVE-2026-12345", "CVE-2026-12346"),
        () ->
            assertThat(result.observationDiagnostics())
                .anySatisfy(diagnostic -> assertThat(diagnostic).contains("CVE-2026-12347")),
        () ->
            assertThat(result.observationDiagnostics())
                .anySatisfy(diagnostic -> assertThat(diagnostic).contains("CVE-2026-12348")),
        () -> assertThat(result.sourceRecordCount()).isEqualTo(4));
  }

  @Test
  void malformedVersionCannotTurnDefaultAffectedIntoBroadCoverage() throws IOException {
    final Path path = recordPath("CVE-2026-12345");
    Files.createDirectories(path.getParent());
    Files.writeString(
        path,
        """
        {"cveMetadata":{"cveId":"CVE-2026-12345","state":"PUBLISHED"},
         "containers":{"cna":{"affected":[
           {"product":"library","packageURL":"pkg:maven/org.example/library",
            "defaultStatus":"affected",
            "versions":[{"version":7,"status":"unaffected","versionType":"maven"}]}
         ]}}}
        """);

    final CveListFindingIndexer.IndexResult result = new CveListFindingIndexer().index(tempDir);

    assertAll(
        "invalid explicit versions cannot broaden a default affected declaration",
        () ->
            assertThat(
                    result.contributions().stream()
                        .flatMap(contribution -> contribution.versionClaims().stream())
                        .filter(claim -> claim.status() == VersionApplicability.AFFECTED))
                .isEmpty(),
        () ->
            assertThat(result.observationDiagnostics())
                .anySatisfy(diagnostic -> assertThat(diagnostic).contains("CVE-2026-12345")));
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
