// WHY: Pins the saved report contract for explicit catalog selection and empty catalogs.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Verifies strict, deterministic persistence of catalog adoption evidence. */
@SuppressWarnings("PMD.AtLeastOneConstructor")
final class MavenElisionCatalogAdoptionPayloadTest {
  /** WHY: Payload mutations are built with the same Jackson tree type as the codec. */
  private static final ObjectMapper JSON = new ObjectMapper();

  @Test
  void roundTripsSelectedCoordinateDigestAndEmptyCatalogIdentity() throws IOException {
    final MavenVulnerabilityMappingCatalogResolver.Adoption emptyCatalog = adoption();
    final ArrayNode encoded = MavenElisionReportCatalogAdoptionPayload.write(List.of(emptyCatalog));
    final List<MavenVulnerabilityMappingCatalogResolver.Adoption> decoded =
        MavenElisionReportCatalogAdoptionPayload.read(encoded);

    assertAll(
        "an adopted catalog is visible even when no finding row matched",
        () -> assertThat(decoded).containsExactly(emptyCatalog),
        () -> assertThat(decoded.getFirst().mappingIds()).isEmpty(),
        () -> assertThat(decoded.getFirst().coordinate().groupId()).isEqualTo("catalog.fixture"),
        () -> assertThat(decoded.getFirst().coordinate().artifactId()).isEqualTo("empty-policy"),
        () -> assertThat(decoded.getFirst().coordinate().classifier()).isEqualTo("rules"),
        () -> assertThat(decoded.getFirst().sha256()).isEqualTo("a".repeat(64)));
  }

  @Test
  void roundTripsPopulatedCatalogAdoptionEvidence() throws IOException {
    final MavenVulnerabilityMappingCatalogResolver.Adoption populated = populatedAdoption();
    final ArrayNode encoded = MavenElisionReportCatalogAdoptionPayload.write(List.of(populated));
    final List<MavenVulnerabilityMappingCatalogResolver.Adoption> decoded =
        MavenElisionReportCatalogAdoptionPayload.read(encoded);

    assertAll(
        "all adoption evidence is preserved on report replay",
        () -> assertThat(decoded).containsExactly(populated),
        () -> assertThat(decoded.getFirst().catalogId()).isEqualTo("policy-catalog"),
        () -> assertThat(decoded.getFirst().schemaVersion()).isEqualTo(1),
        () ->
            assertThat(decoded.getFirst().provenance())
                .isEqualTo("explicit-maven-catalog-coordinate"),
        () -> assertThat(decoded.getFirst().coordinate().type()).isEqualTo("zip"),
        () -> assertThat(decoded.getFirst().coordinate().classifier()).isEqualTo("rules"),
        () -> assertThat(decoded.getFirst().sha256()).isEqualTo("c".repeat(64)),
        () -> assertThat(decoded.getFirst().mappingIds()).containsExactly("mapping-valid"),
        () ->
            assertThat(decoded.getFirst().unresolvedMappingIds())
                .containsExactly("mapping-unresolved"),
        () ->
            assertThat(decoded.getFirst().advisoryUris())
                .containsExactly("https://example.test/advisories/CVE-2026-20001"),
        () -> assertThat(decoded.getFirst().exclusions()).containsExactly("explicit-exclusion"),
        () ->
            assertThat(decoded.getFirst().diagnostics())
                .containsExactly("mapping-unresolved: invalid prerequisite group"));
  }

  @Test
  void rejectsNonHttpAdvisoryUris() throws IOException {
    final ObjectNode adoptionRow =
        (ObjectNode)
            MavenElisionReportCatalogAdoptionPayload.write(List.of(populatedAdoption())).get(0);
    adoptionRow.withArray("advisoryUris").removeAll();
    adoptionRow.withArray("advisoryUris").add("ftp://example.test/advisory");

    assertThatThrownBy(
            () ->
                MavenElisionReportCatalogAdoptionPayload.read(
                    JSON.createArrayNode().add(adoptionRow)))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("advisory URI");
  }

  @Test
  void rejectsUnknownFields() throws IOException {
    final ObjectNode row =
        (ObjectNode) MavenElisionReportCatalogAdoptionPayload.write(List.of(adoption())).get(0);
    row.put("unexpected", true);
    assertThatThrownBy(
            () -> MavenElisionReportCatalogAdoptionPayload.read(JSON.createArrayNode().add(row)))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("catalog adoption");
  }

  @Test
  void rejectsDuplicateRowIds() throws IOException {
    final ObjectNode duplicateIds =
        (ObjectNode) MavenElisionReportCatalogAdoptionPayload.write(List.of(adoption())).get(0);
    duplicateIds.withArray("mappingIds").add("row-one").add("row-one");
    assertThatThrownBy(
            () ->
                MavenElisionReportCatalogAdoptionPayload.read(
                    JSON.createArrayNode().add(duplicateIds)))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("mappingIds");
  }

  @Test
  void rejectsInvalidCoordinates() throws IOException {
    final ObjectNode invalidCoordinate =
        (ObjectNode) MavenElisionReportCatalogAdoptionPayload.write(List.of(adoption())).get(0);
    ((ObjectNode) invalidCoordinate.get("coordinate")).put("version", "1.2.3-SNAPSHOT");
    assertThatThrownBy(
            () ->
                MavenElisionReportCatalogAdoptionPayload.read(
                    JSON.createArrayNode().add(invalidCoordinate)))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("coordinate");
  }

  private static MavenVulnerabilityMappingCatalogResolver.Adoption adoption() {
    return new MavenVulnerabilityMappingCatalogResolver.Adoption(
        new MavenVulnerabilityMappingCatalogResolver.Coordinate(
            "catalog.fixture", "empty-policy", "1.2.3", "jar", "rules"),
        "a".repeat(64),
        "empty-catalog",
        1,
        List.of(),
        List.of(),
        List.of(),
        List.of(),
        "explicit-maven-catalog-coordinate",
        List.of());
  }

  private static MavenVulnerabilityMappingCatalogResolver.Adoption populatedAdoption() {
    return new MavenVulnerabilityMappingCatalogResolver.Adoption(
        new MavenVulnerabilityMappingCatalogResolver.Coordinate(
            "catalog.fixture", "policy", "2.3.4", "zip", "rules"),
        "c".repeat(64),
        "policy-catalog",
        1,
        List.of("mapping-valid"),
        List.of("mapping-unresolved"),
        List.of("https://example.test/advisories/CVE-2026-20001"),
        List.of("explicit-exclusion"),
        "explicit-maven-catalog-coordinate",
        List.of("mapping-unresolved: invalid prerequisite group"));
  }
}
