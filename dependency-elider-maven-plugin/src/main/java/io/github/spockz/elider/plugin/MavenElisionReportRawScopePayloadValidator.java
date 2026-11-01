// WHY: Keeps persisted raw OSV/CNA applicability claims strict and independently auditable.

package io.github.spockz.elider.plugin;

import static io.github.spockz.elider.plugin.MavenElisionReportJsonPayloadShape.optionalText;
import static io.github.spockz.elider.plugin.MavenElisionReportJsonPayloadShape.requireArray;
import static io.github.spockz.elider.plugin.MavenElisionReportJsonPayloadShape.requireObject;
import static io.github.spockz.elider.plugin.MavenElisionReportJsonPayloadShape.requireText;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

/** Validates the raw scope portion of a saved structured proof. */
final class MavenElisionReportRawScopePayloadValidator {
  /** Shared JSON field name for raw Maven range type. */
  private static final String TYPE = "type";

  /** Shared JSON field name for exact version values. */
  private static final String VERSION = "version";

  /** Shared JSON field name for affected status values. */
  private static final String STATUS = "status";

  /** Exact root fields stored for source applicability provenance. */
  private static final Set<String> RAW_SCOPE_FIELDS =
      Set.of(
          "osvModified",
          "osvEcosystem",
          "osvPackageName",
          "osvVersions",
          "osvRanges",
          "cveState",
          "cnaDefaultStatus",
          "cnaVersions",
          "osvStatus",
          "cnaStatus",
          "osvRationale",
          "cnaRationale");

  /** Exact fields accepted for each raw OSV range. */
  private static final Set<String> RANGE_FIELDS = Set.of(TYPE, "repo", "events");

  /** Exact fields accepted for one CNA version claim. */
  private static final Set<String> VERSION_FIELDS =
      Set.of(VERSION, STATUS, "versionType", "lessThan", "lessThanOrEqual", "changes");

  /** Exact fields accepted for one CNA status transition. */
  private static final Set<String> CHANGE_FIELDS = Set.of("at", STATUS);

  /** CVE lifecycle field whose proof-bound value must be published. */
  private static final String CVE_STATE = "cveState";

  /** OSV evaluator result retained with its raw claim. */
  private static final String OSV_STATUS = "osvStatus";

  /** CNA evaluator result retained with its raw claim. */
  private static final String CNA_STATUS = "cnaStatus";

  private MavenElisionReportRawScopePayloadValidator() {}

  /* default */ static void validate(final JsonNode node) throws IOException {
    requireObject(node, RAW_SCOPE_FIELDS, "raw scope evidence");
    for (final String field :
        Set.of("osvModified", "osvEcosystem", "osvPackageName", "osvRationale", "cnaRationale")) {
      requireText(node.get(field), field, ".+");
    }
    requireText(node.get(CVE_STATE), CVE_STATE, "PUBLISHED");
    requireText(node.get(OSV_STATUS), OSV_STATUS, "AFFECTED");
    requireText(node.get(CNA_STATUS), CNA_STATUS, "AFFECTED");
    optionalText(node.get("cnaDefaultStatus"), "cnaDefaultStatus");
    MavenElisionReportJsonPayloadShape.stringArray(node.get("osvVersions"), "osvVersions");
    validateCnaVersions(node.get("cnaVersions"));
    final JsonNode ranges = node.get("osvRanges");
    requireArray(ranges, "osvRanges");
    for (final JsonNode range : ranges) {
      validateRange(range);
    }
  }

  private static void validateRange(final JsonNode node) throws IOException {
    requireObject(node, RANGE_FIELDS, "OSV range");
    requireText(node.get(TYPE), TYPE, ".+");
    optionalText(node.get("repo"), "repo");
    final JsonNode events = node.get("events");
    requireArray(events, "events");
    for (final JsonNode event : events) {
      if (!event.isObject() || event.isEmpty()) {
        throw new IOException("Elision report OSV range events must be nonempty objects");
      }
      final Iterator<Map.Entry<String, JsonNode>> fields = event.fields();
      while (fields.hasNext()) {
        final Map.Entry<String, JsonNode> field = fields.next();
        requireText(field.getValue(), field.getKey(), ".+");
      }
    }
  }

  private static void validateCnaVersions(final JsonNode node) throws IOException {
    requireArray(node, "cnaVersions");
    for (final JsonNode version : node) {
      requireObject(version, VERSION_FIELDS, "CNA version claim");
      requireText(version.get(VERSION), VERSION, ".+");
      requireText(version.get(STATUS), STATUS, ".+");
      optionalText(version.get("versionType"), "versionType");
      optionalText(version.get("lessThan"), "lessThan");
      optionalText(version.get("lessThanOrEqual"), "lessThanOrEqual");
      final JsonNode changes = version.get("changes");
      requireArray(changes, "changes");
      for (final JsonNode change : changes) {
        requireObject(change, CHANGE_FIELDS, "CNA version change");
        requireText(change.get("at"), "at", ".+");
        requireText(change.get(STATUS), STATUS, ".+");
      }
    }
  }
}
