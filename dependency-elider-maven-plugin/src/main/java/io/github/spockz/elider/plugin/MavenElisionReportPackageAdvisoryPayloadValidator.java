// WHY: Validates raw OSV package claims without flattening their scope or applicability.

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.util.List;
import java.util.Set;

/** Validates package advisory rows in the historical report. */
final class MavenElisionReportPackageAdvisoryPayloadValidator {
  /** Field names shared by package row construction and validation. */
  private static final String OSV_ID = "osvId";

  /** Alias field name. */
  private static final String ALIASES = "aliases";

  /** Exact component field name. */
  private static final String COORDINATE = "coordinate";

  /** OSV ecosystem field name. */
  private static final String ECOSYSTEM = "ecosystem";

  /** OSV package identity field name. */
  private static final String PACKAGE_NAME = "packageName";

  /** Exact affected versions field name. */
  private static final String AFFECTED_VERSIONS = "affectedVersions";

  /** Raw OSV ranges field name. */
  private static final String RANGES = "ranges";

  /** Applicability field name. */
  private static final String APPLICABILITY = "applicability";

  /** Applicability rationale field name. */
  private static final String APPLICABILITY_RATIONALE = "applicabilityRationale";

  /** Inventory disposition field name. */
  private static final String INVENTORY_DISPOSITION = "inventoryDisposition";

  /** Source record digest field name. */
  private static final String SOURCE_SHA = "sourceRecordSha256";

  /** Exact fields for package-advisory rows. */
  private static final Set<String> PACKAGE_FIELDS =
      Set.of(
          OSV_ID,
          ALIASES,
          COORDINATE,
          ECOSYSTEM,
          PACKAGE_NAME,
          AFFECTED_VERSIONS,
          RANGES,
          APPLICABILITY,
          APPLICABILITY_RATIONALE,
          INVENTORY_DISPOSITION,
          SOURCE_SHA);

  /** Range repository field name. */
  private static final String REPO = "repo";

  /** Exact fields for unflattened OSV ranges. */
  private static final Set<String> RANGE_FIELDS = Set.of("type", REPO, "events");

  /** Supported report applicability values. */
  private static final Set<String> APPLICABILITY_VALUES =
      Set.of("APPLICABLE", "NOT_APPLICABLE", "UNRESOLVED");

  /** Inventory facts recorded alongside each package finding. */
  private static final Set<String> DISPOSITION_VALUES =
      Set.of("REMOVED", "RETAINED_AND_TRIMMED", "RETAINED_UNCHANGED");

  private MavenElisionReportPackageAdvisoryPayloadValidator() {}

  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  static void validate(final JsonNode rows) throws IOException {
    requireArray(rows, "packageAdvisories");
    for (final JsonNode row : rows) {
      validateRow(row);
    }
  }

  private static void validateRow(final JsonNode row) throws IOException {
    MavenElisionReportAdvisoryPayloadSupport.requireFields(
        row, PACKAGE_FIELDS, "Elision report package advisory fields do not match schema v1");
    MavenElisionReportAdvisoryPayloadSupport.text(row.get(OSV_ID), "package advisory osvId");
    MavenElisionReportAdvisoryPayloadSupport.stringArray(row.get(ALIASES), ALIASES);
    MavenElisionReportAdvisoryPayloadSupport.coordinate(row.get(COORDINATE));
    MavenElisionReportAdvisoryPayloadSupport.text(row.get(ECOSYSTEM), ECOSYSTEM);
    MavenElisionReportAdvisoryPayloadSupport.text(row.get(PACKAGE_NAME), PACKAGE_NAME);
    validatePackageIdentity(row);
    MavenElisionReportAdvisoryPayloadSupport.stringArray(
        row.get(AFFECTED_VERSIONS), AFFECTED_VERSIONS);
    validateRanges(row.get(RANGES));
    MavenElisionReportAdvisoryPayloadSupport.enumValue(
        row.get(APPLICABILITY), APPLICABILITY_VALUES, "package applicability");
    MavenElisionReportAdvisoryPayloadSupport.text(
        row.get(APPLICABILITY_RATIONALE), APPLICABILITY_RATIONALE);
    MavenElisionReportAdvisoryPayloadSupport.enumValue(
        row.get(INVENTORY_DISPOSITION), DISPOSITION_VALUES, INVENTORY_DISPOSITION);
    MavenElisionReportAdvisoryPayloadSupport.optionalSha(row.get(SOURCE_SHA), SOURCE_SHA);
    validateRawApplicability(row);
  }

  private static void validatePackageIdentity(final JsonNode row) throws IOException {
    try {
      MavenElisionReportAdvisoryInvariants.validatePackageIdentity(
          row.get(COORDINATE).textValue(),
          row.get(ECOSYSTEM).textValue(),
          row.get(PACKAGE_NAME).textValue());
    } catch (final IllegalArgumentException exception) {
      throw new IOException(exception.getMessage(), exception);
    }
  }

  private static void validateRawApplicability(final JsonNode row) throws IOException {
    final List<String> versions =
        MavenElisionReportAffectedRangePayloadReader.versions(row.get(AFFECTED_VERSIONS));
    final List<MavenElisionReportSnapshot.AffectedRange> ranges =
        MavenElisionReportAffectedRangePayloadReader.ranges(row.get(RANGES));
    try {
      MavenElisionReportAdvisoryInvariants.validatePackageApplicability(
          row.get(COORDINATE).textValue(),
          versions,
          ranges,
          OsvPackageApplicability.Status.valueOf(row.get(APPLICABILITY).textValue()));
    } catch (final IllegalArgumentException exception) {
      throw new IOException(exception.getMessage(), exception);
    }
  }

  private static void validateRanges(final JsonNode ranges) throws IOException {
    requireArray(ranges, RANGES);
    for (final JsonNode range : ranges) {
      validateRange(range);
    }
  }

  private static void validateRange(final JsonNode range) throws IOException {
    MavenElisionReportAdvisoryPayloadSupport.requireFields(
        range, RANGE_FIELDS, "Elision report package advisory range fields are invalid");
    MavenElisionReportAdvisoryPayloadSupport.text(range.get("type"), "range type");
    MavenElisionReportAdvisoryPayloadSupport.nullableText(range.get(REPO), "range repo");
    final JsonNode events = range.get("events");
    requireArray(events, "package range events");
    for (final JsonNode event : events) {
      MavenElisionReportAdvisoryPayloadSupport.validateTextEvent(event);
    }
  }

  private static void requireArray(final JsonNode value, final String field) throws IOException {
    if (value == null || !value.isArray()) {
      throw new IOException("Elision report " + field + " must be an array");
    }
  }
}
