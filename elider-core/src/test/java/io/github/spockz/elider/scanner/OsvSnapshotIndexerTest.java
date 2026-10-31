/* WHY: Verifies OSV ownership and preservation of distinct advisory evidence sources. */

package io.github.spockz.elider.scanner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.model.EvidenceOrigin;
import io.github.spockz.elider.model.HeuristicCandidateEvidence;
import io.github.spockz.elider.model.OsvAdvisoryRecord;
import io.github.spockz.elider.model.StructuredSourceClassEvidence;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

@SuppressWarnings({
  "PMD.CommentDefaultAccessModifier",
  "PMD.AtLeastOneConstructor",
  "PMD.CommentRequired",
  "PMD.LiteralsFirstInComparisons",
  "PMD.LambdaCanBeMethodReference",
  "PMD.ShortVariable",
  "PMD.AvoidInstantiatingObjectsInLoops"
})
class OsvSnapshotIndexerTest {
  @TempDir Path tempDir;

  @Test
  void preservesOsvOwnershipScopesCnaAndIndependentSourceOrigins() throws IOException {
    final Path cvePath = tempDir.resolve("cves/2025/12xxx/CVE-2025-12345.json");
    Files.createDirectories(cvePath.getParent());
    Files.writeString(
        cvePath,
        """
        {
          "containers": {
            "cna": {
              "descriptions": [{"lang":"en","value":"org.example.One is affected"}],
              "affected": [
                {
                  "vendor":"Example One",
                  "product":"library-one",
                  "packageURL":"pkg:maven/org.example/library-one",
                  "defaultStatus":"affected",
                  "versions":[{"version":"1.0","status":"affected","versionType":"semver","lessThan":"2.0","lessThanOrEqual":null,"changes":[{"at":"1.5","status":"unaffected"}]}],
                  "programFiles":["src/main/java/org/example/One.java"],
                  "programRoutines":["parse"]
                },
                {
                  "vendor":"Example Two",
                  "product":"library-two",
                  "packageURL":"pkg:maven/org.example/library-two",
                  "versions":[{"version":"2.0","status":"affected"}],
                  "programRoutines":[{"name":"decode"}]
                },
                {
                  "vendor":"Unmatched Example",
                  "product":"library-one",
                  "packageURL":"pkg:maven/other/library-three",
                  "versions":[{"version":"1.0","status":"affected"}],
                  "programRoutines":["unmatchedRoutine"]
                }
              ],
              "references":[{"url":"https://example.test/fix"}]
            }
          }
        }
        """);
    final String first =
        """
        {
          "id":"GHSA-owner-one",
          "aliases":["CVE-2025-12345","GHSA-alias-one"],
          "summary":"Vulnerability in org.example.One",
          "details":"org.example.Two is a separate candidate",
          "references":[{"type":"FIX","url":"https://github.com/example/repo/commit/abc/src/main/java/org/example/One.java"}],
          "affected":[
            {"package":{"ecosystem":"Maven","name":"org.example:library-one"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.0"}]},{"type":"GIT","repo":"https://github.com/example/repo","events":[{"introduced":"0"},{"fixed":"2.0"}]}]},
            {"package":{"ecosystem":"Maven:https://repo.example.test","name":"org.example:library-two"},"versions":["2.0","3.0"]}
          ]
        }
        """;
    final String second =
        """
        {
          "id":"GHSA-owner-two",
          "aliases":["CVE-2025-12345"],
          "affected":[{"package":{"ecosystem":"Maven","name":"org.example:library-one"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0"},{"last_affected":"1.5"}]}]}]
        }
        """;
    final String noCve =
        """
        {
          "id":"GHSA-without-cve",
          "aliases":["GHSA-alias-only"],
          "affected":[{"package":{"ecosystem":"Maven:custom","name":"org.example:library-three"},"versions":["3.1"],"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"3.0"},{"fixed":"3.2"}]}]}]
        }
        """;

    final List<OsvAdvisoryRecord> records =
        new OsvSnapshotIndexer()
            .indexZip(
                new ByteArrayInputStream(
                    createZip(
                        List.of(
                            new ZipItem("first.json", first),
                            new ZipItem("second.json", second),
                            new ZipItem("no-cve.json", noCve)))),
                tempDir);
    final OsvAdvisoryRecord firstRecord = find(records, "GHSA-owner-one");
    final OsvAdvisoryRecord secondRecord = find(records, "GHSA-owner-two");
    final OsvAdvisoryRecord noCveRecord = find(records, "GHSA-without-cve");
    final List<StructuredSourceClassEvidence> structuredEvidence =
        firstRecord.evidence().stream()
            .filter(StructuredSourceClassEvidence.class::isInstance)
            .map(StructuredSourceClassEvidence.class::cast)
            .toList();
    final List<HeuristicCandidateEvidence> referenceCandidates =
        firstRecord.evidence().stream()
            .filter(HeuristicCandidateEvidence.class::isInstance)
            .map(HeuristicCandidateEvidence.class::cast)
            .filter(value -> value.provenance().origin() == EvidenceOrigin.REFERENCE_URL)
            .toList();

    assertAll(
        "each OSV record retains its own aliases and package scopes",
        () -> assertThat(records).hasSize(3),
        () ->
            assertThat(firstRecord.aliases())
                .containsExactlyInAnyOrder("CVE-2025-12345", "GHSA-alias-one"),
        () -> assertThat(secondRecord.aliases()).containsExactly("CVE-2025-12345"),
        () -> assertThat(firstRecord.affectedPackages()).hasSize(2),
        () ->
            assertThat(firstRecord.affectedPackages().getFirst().ranges().get(1).repo())
                .isEqualTo("https://github.com/example/repo"),
        () -> assertThat(firstRecord.affectedPackages().get(1).ecosystem()).startsWith("Maven"),
        () ->
            assertThat(firstRecord.affectedPackages().get(1).packageName())
                .isEqualTo("org.example:library-two"),
        () ->
            assertThat(firstRecord.evidence())
                .extracting(value -> value.provenance().origin())
                .contains(
                    EvidenceOrigin.OSV,
                    EvidenceOrigin.DESCRIPTION,
                    EvidenceOrigin.REFERENCE_URL,
                    EvidenceOrigin.CVE_LIST),
        () -> assertThat(structuredEvidence).hasSize(2),
        () -> assertThat(referenceCandidates).hasSize(4),
        () ->
            assertThat(referenceCandidates)
                .allSatisfy(
                    value ->
                        assertAll(
                            () -> assertThat(value.candidateClasses()).isEmpty(),
                            () ->
                                assertThat(value.provenance().origin())
                                    .isEqualTo(EvidenceOrigin.REFERENCE_URL))),
        () ->
            assertThat(structuredEvidence)
                .filteredOn(
                    value -> value.scope().affectedCoordinate().artifactId().equals("library-one"))
                .singleElement()
                .satisfies(
                    value ->
                        assertThat(value.programFiles())
                            .contains("src/main/java/org/example/One.java")),
        () ->
            assertThat(structuredEvidence)
                .filteredOn(
                    value -> value.scope().affectedCoordinate().artifactId().equals("library-two"))
                .singleElement()
                .satisfies(value -> assertThat(value.programRoutines()).contains("decode")),
        () ->
            assertThat(firstRecord.cnaAffectedEntries())
                .extracting(value -> value.entryIdentity())
                .containsExactly(
                    "containers.cna.affected[0]",
                    "containers.cna.affected[1]",
                    "containers.cna.affected[2]"),
        () ->
            assertThat(firstRecord.cnaAffectedEntries().get(2).programRoutines())
                .containsExactly("unmatchedRoutine"),
        () ->
            assertThat(structuredEvidence)
                .noneMatch(value -> value.programRoutines().contains("unmatchedRoutine")),
        () ->
            assertThat(
                    firstRecord.cnaAffectedEntries().getFirst().versions().getFirst().versionType())
                .isEqualTo("semver"),
        () ->
            assertThat(firstRecord.cnaAffectedEntries().getFirst().defaultStatus())
                .isEqualTo("affected"),
        () ->
            assertThat(firstRecord.cnaAffectedEntries().getFirst().versions().getFirst())
                .satisfies(
                    claim ->
                        assertAll(
                            () -> assertThat(claim.lessThan()).isEqualTo("2.0"),
                            () -> assertThat(claim.lessThanOrEqual()).isNull(),
                            () ->
                                assertThat(claim.changes())
                                    .containsExactly(
                                        java.util.Map.of("at", "1.5", "status", "unaffected")))),
        () -> assertThat(noCveRecord.aliases()).containsExactly("GHSA-alias-only"),
        () -> assertThat(noCveRecord.evidence()).isEmpty(),
        () ->
            assertThat(noCveRecord.affectedPackages())
                .singleElement()
                .satisfies(value -> assertThat(value.versions()).containsExactly("3.1")));
  }

  private static OsvAdvisoryRecord find(final List<OsvAdvisoryRecord> records, final String id) {
    return records.stream().filter(record -> record.osvId().equals(id)).findFirst().orElseThrow();
  }

  private static byte[] createZip(final List<ZipItem> items) throws IOException {
    final ByteArrayOutputStream output = new ByteArrayOutputStream();
    try (ZipOutputStream zip = new ZipOutputStream(output)) {
      for (final ZipItem item : items) {
        zip.putNextEntry(new ZipEntry(item.name()));
        zip.write(item.content().getBytes(StandardCharsets.UTF_8));
        zip.closeEntry();
      }
    }
    return output.toByteArray();
  }

  private record ZipItem(String name, String content) {}
}
