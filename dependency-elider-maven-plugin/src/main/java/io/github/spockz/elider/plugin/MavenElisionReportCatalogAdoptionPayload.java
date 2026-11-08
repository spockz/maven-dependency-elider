// WHY: Persists Maven catalog adoption as build-input evidence, including catalogs with no rows.

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Strict schema-v1 codec for the catalogs selected during assessment preparation. */
@SuppressWarnings("PMD.AvoidDuplicateLiterals")
final class MavenElisionReportCatalogAdoptionPayload {
  /** WHY: A shared mapper applies the same JSON rules to every saved adoption row. */
  private static final ObjectMapper JSON = new ObjectMapper();

  /** WHY: Schema version 1 rejects unrecognized top-level row fields. */
  private static final Set<String> ADOPTION_FIELDS =
      Set.of(
          "coordinate",
          "sha256",
          "catalogId",
          "schemaVersion",
          "mappingIds",
          "unresolvedMappingIds",
          "advisoryUris",
          "exclusions",
          "provenance",
          "diagnostics");

  /** WHY: Nested Maven coordinates have an independently strict field set. */
  private static final Set<String> COORDINATE_FIELDS =
      Set.of("groupId", "artifactId", "version", "type", "classifier");

  private MavenElisionReportCatalogAdoptionPayload() {}

  /* default */ static ArrayNode write(
      final List<MavenVulnerabilityMappingCatalogResolver.Adoption> adoptions) {
    final ArrayNode rows = JSON.createArrayNode();
    adoptions.stream()
        .sorted(Comparator.comparing(value -> value.coordinate().toString()))
        .forEach(value -> rows.add(write(value)));
    return rows;
  }

  private static ObjectNode write(
      final MavenVulnerabilityMappingCatalogResolver.Adoption adoption) {
    final ObjectNode row = JSON.createObjectNode();
    final MavenVulnerabilityMappingCatalogResolver.Coordinate coordinate = adoption.coordinate();
    row.set("coordinate", JSON.valueToTree(coordinate));
    row.put("sha256", adoption.sha256());
    row.put("catalogId", adoption.catalogId());
    row.put("schemaVersion", adoption.schemaVersion());
    row.set("mappingIds", JSON.valueToTree(adoption.mappingIds()));
    row.set("unresolvedMappingIds", JSON.valueToTree(adoption.unresolvedMappingIds()));
    row.set("advisoryUris", JSON.valueToTree(adoption.advisoryUris()));
    row.set("exclusions", JSON.valueToTree(adoption.exclusions()));
    row.put("provenance", adoption.provenance());
    row.set("diagnostics", JSON.valueToTree(adoption.diagnostics()));
    return row;
  }

  /* default */ static List<MavenVulnerabilityMappingCatalogResolver.Adoption> read(
      final JsonNode node) throws IOException {
    MavenElisionReportJsonPayloadShape.requireArray(node, "catalogAdoptions");
    final List<MavenVulnerabilityMappingCatalogResolver.Adoption> adoptions = new ArrayList<>();
    final Set<String> coordinates = new HashSet<>();
    for (final JsonNode row : node) {
      adoptions.add(readOne(row));
      final String coordinate = adoptions.getLast().coordinate().toString();
      if (!coordinates.add(coordinate)) {
        throw new IOException("Elision report catalog adoptions contain a duplicate coordinate");
      }
    }
    return List.copyOf(adoptions);
  }

  private static MavenVulnerabilityMappingCatalogResolver.Adoption readOne(final JsonNode row)
      throws IOException {
    MavenElisionReportJsonPayloadShape.requireObject(row, ADOPTION_FIELDS, "catalog adoption");
    final MavenVulnerabilityMappingCatalogResolver.Coordinate coordinate =
        readCoordinate(row.get("coordinate"));
    final String sha256 = text(row, "sha256", "[0-9a-f]{64}");
    final String catalogId = text(row, "catalogId", ".+");
    final JsonNode schemaVersion = row.get("schemaVersion");
    if (schemaVersion == null
        || !schemaVersion.isIntegralNumber()
        || !schemaVersion.canConvertToInt()
        || schemaVersion.intValue() != 1) {
      throw new IOException("Elision report catalog schemaVersion is invalid");
    }
    final RowIds rowIds = readRowIds(row);
    final List<String> advisoryUris = readAdvisoryUris(row);
    final List<String> exclusions = stringArray(row.get("exclusions"), "exclusions");
    final String provenance = text(row, "provenance", ".+");
    final List<String> diagnostics = stringArray(row.get("diagnostics"), "diagnostics");
    try {
      return new MavenVulnerabilityMappingCatalogResolver.Adoption(
          coordinate,
          sha256,
          catalogId,
          schemaVersion.intValue(),
          rowIds.mappingIds(),
          rowIds.unresolvedIds(),
          advisoryUris,
          exclusions,
          provenance,
          diagnostics);
    } catch (final IllegalArgumentException exception) {
      throw new IOException("Elision report catalog adoption is invalid", exception);
    }
  }

  private static RowIds readRowIds(final JsonNode row) throws IOException {
    final List<String> mappingIds = stringArray(row.get("mappingIds"), "mappingIds");
    final List<String> unresolvedIds =
        stringArray(row.get("unresolvedMappingIds"), "unresolvedMappingIds");
    if (!java.util.Collections.disjoint(mappingIds, unresolvedIds)) {
      throw new IOException("Elision report catalog row IDs cannot be both valid and unresolved");
    }
    return new RowIds(mappingIds, unresolvedIds);
  }

  private static List<String> readAdvisoryUris(final JsonNode row) throws IOException {
    final List<String> advisoryUris = stringArray(row.get("advisoryUris"), "advisoryUris");
    for (final String advisory : advisoryUris) {
      final URI uri;
      try {
        uri = URI.create(advisory);
      } catch (final IllegalArgumentException exception) {
        throw new IOException("Elision report catalog advisory URI is invalid", exception);
      }
      if (!isHttpUri(uri)) {
        throw new IOException("Elision report catalog advisory URI must use HTTP or HTTPS");
      }
    }
    return advisoryUris;
  }

  private static boolean isHttpUri(final URI uri) {
    return uri.isAbsolute()
        && ("http".equalsIgnoreCase(uri.getScheme()) || "https".equalsIgnoreCase(uri.getScheme()));
  }

  private static MavenVulnerabilityMappingCatalogResolver.Coordinate readCoordinate(
      final JsonNode node) throws IOException {
    MavenElisionReportJsonPayloadShape.requireObject(node, COORDINATE_FIELDS, "catalog coordinate");
    try {
      return new MavenVulnerabilityMappingCatalogResolver.Coordinate(
          text(node, "groupId", ".+"),
          text(node, "artifactId", ".+"),
          text(node, "version", ".+"),
          text(node, "type", ".+"),
          text(node, "classifier", ".*"));
    } catch (final IllegalArgumentException exception) {
      throw new IOException("Elision report catalog coordinate is invalid", exception);
    }
  }

  private static List<String> stringArray(final JsonNode node, final String field)
      throws IOException {
    MavenElisionReportJsonPayloadShape.stringArray(node, field);
    final List<String> values = new ArrayList<>();
    String previous = null;
    for (final JsonNode value : node) {
      final String text = value.textValue();
      if (previous != null && previous.compareTo(text) >= 0) {
        throw new IOException("Elision report " + field + " must be sorted and distinct");
      }
      values.add(text);
      previous = text;
    }
    return List.copyOf(values);
  }

  private static String text(final JsonNode node, final String field, final String pattern)
      throws IOException {
    MavenElisionReportJsonPayloadShape.requireText(node.get(field), field, pattern);
    return node.get(field).textValue();
  }

  private record RowIds(List<String> mappingIds, List<String> unresolvedIds) {}
}
