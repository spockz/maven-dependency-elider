/* WHY: Verifies OSV snapshot indexing, version ranges, and class symbol extraction. */

package io.github.spockz.elider.scanner;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.spockz.elider.model.VulnerabilitySymbolMapping;
import io.github.spockz.elider.model.VulnerabilitySymbolMapping.ConfidenceLevel;
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
  "PMD.UnitTestContainsTooManyAsserts",
  "PMD.AvoidInstantiatingObjectsInLoops"
})
class OsvSnapshotIndexerTest {
  @TempDir Path tempDir;

  @Test
  void indexesMavenAdvisoryWithClassSymbolsFromDetails() throws IOException {
    final String advisoryJson =
        """
        {
          "schema_version": "1.9.0",
          "id": "GHSA-test-1234",
          "aliases": ["CVE-2024-26308"],
          "summary": "Pack200 parsing denial of service",
          "details": "Vulnerability in org.apache.commons.compress.compressors.pack200.Pack200CompressorInputStream allows CPU loop",
          "affected": [
            {
              "package": {
                "name": "org.apache.commons:commons-compress",
                "ecosystem": "Maven"
              },
              "ranges": [
                {
                  "type": "ECOSYSTEM",
                  "events": [
                    {"introduced": "0"},
                    {"fixed": "1.28.0"}
                  ]
                }
              ]
            }
          ],
          "references": [
            {"type": "ADVISORY", "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-26308"},
            {"type": "FIX", "url": "https://github.com/apache/commons-compress/commit/abcd1234#diff-src/main/java/org/apache/commons/compress/compressors/pack200/Pack200CompressorInputStream.java"}
          ]
        }
        """;

    final byte[] zipBytes = createZip(List.of(new ZipItem("GHSA-test-1234.json", advisoryJson)));
    final OsvSnapshotIndexer indexer = new OsvSnapshotIndexer();
    final List<VulnerabilitySymbolMapping> mappings =
        indexer.indexZip(new ByteArrayInputStream(zipBytes), null);

    assertThat(mappings).hasSize(1);
    final VulnerabilitySymbolMapping mapping = mappings.get(0);
    assertThat(mapping.cveId()).isEqualTo("CVE-2024-26308");
    assertThat(mapping.affectedCoordinate().groupId()).isEqualTo("org.apache.commons");
    assertThat(mapping.affectedCoordinate().artifactId()).isEqualTo("commons-compress");
    assertThat(mapping.versionRangeSpec()).isEqualTo("(,1.28.0)");
    assertThat(mapping.vulnerableClasses())
        .containsExactly(
            "org.apache.commons.compress.compressors.pack200.Pack200CompressorInputStream");
    assertThat(mapping.confidenceLevel()).isEqualTo(ConfidenceLevel.HIGH);
    assertThat(mapping.sourceAdvisoryUrl())
        .isEqualTo(
            java.net.URI.create(
                "https://github.com/apache/commons-compress/commit/abcd1234#diff-src/main/java/org/apache/commons/compress/compressors/pack200/Pack200CompressorInputStream.java"));
  }

  @Test
  void ignoresNonMavenOrWithdrawnAdvisories() throws IOException {
    final String npmJson =
        """
        {
          "id": "GHSA-npm-1",
          "aliases": ["CVE-2024-0001"],
          "details": "Class org.example.Foo",
          "affected": [{"package": {"name": "lodash", "ecosystem": "npm"}}]
        }
        """;
    final String withdrawnJson =
        """
        {
          "id": "GHSA-withdrawn-1",
          "aliases": ["CVE-2024-0002"],
          "withdrawn": "2024-01-01T00:00:00Z",
          "details": "Class org.apache.commons.Bar",
          "affected": [{"package": {"name": "org.apache.commons:commons-lang3", "ecosystem": "Maven"}}]
        }
        """;

    final byte[] zipBytes =
        createZip(
            List.of(
                new ZipItem("npm.json", npmJson), new ZipItem("withdrawn.json", withdrawnJson)));
    final OsvSnapshotIndexer indexer = new OsvSnapshotIndexer();
    final List<VulnerabilitySymbolMapping> mappings =
        indexer.indexZip(new ByteArrayInputStream(zipBytes), null);

    assertThat(mappings).isEmpty();
  }

  @Test
  void enrichesFromCveListV5WhenPresent() throws IOException {
    final Path cveDir = tempDir.resolve("cves/2020/25xxx");
    Files.createDirectories(cveDir);
    final String cveJson =
        """
        {
          "containers": {
            "cna": {
              "affected": [
                {
                  "programFiles": [
                    "src/main/java/com/fasterxml/jackson/databind/ext/DOMDeserializer.java"
                  ]
                }
              ]
            }
          }
        }
        """;
    Files.writeString(cveDir.resolve("CVE-2020-25649.json"), cveJson);

    final String advisoryJson =
        """
        {
          "id": "GHSA-jackson-1",
          "aliases": ["CVE-2020-25649"],
          "affected": [
            {
              "package": {
                "name": "com.fasterxml.jackson.core:jackson-databind",
                "ecosystem": "Maven"
              },
              "ranges": [
                {
                  "type": "ECOSYSTEM",
                  "events": [
                    {"introduced": "2.10.0"},
                    {"fixed": "2.11.0"}
                  ]
                }
              ]
            }
          ]
        }
        """;

    final byte[] zipBytes = createZip(List.of(new ZipItem("jackson.json", advisoryJson)));
    final OsvSnapshotIndexer indexer = new OsvSnapshotIndexer();
    final List<VulnerabilitySymbolMapping> mappings =
        indexer.indexZip(new ByteArrayInputStream(zipBytes), tempDir);

    assertThat(mappings).hasSize(1);
    final VulnerabilitySymbolMapping mapping = mappings.get(0);
    assertThat(mapping.cveId()).isEqualTo("CVE-2020-25649");
    assertThat(mapping.affectedCoordinate().groupId()).isEqualTo("com.fasterxml.jackson.core");
    assertThat(mapping.affectedCoordinate().artifactId()).isEqualTo("jackson-databind");
    assertThat(mapping.versionRangeSpec()).isEqualTo("[2.10.0,2.11.0)");
    assertThat(mapping.vulnerableClasses())
        .containsExactly("com.fasterxml.jackson.databind.ext.DOMDeserializer");
  }

  private static byte[] createZip(final List<ZipItem> items) throws IOException {
    final ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (ZipOutputStream zos = new ZipOutputStream(baos)) {
      for (final ZipItem item : items) {
        final ZipEntry entry = new ZipEntry(item.name());
        zos.putNextEntry(entry);
        zos.write(item.content().getBytes(StandardCharsets.UTF_8));
        zos.closeEntry();
      }
    }
    return baos.toByteArray();
  }

  private record ZipItem(String name, String content) {}
}
