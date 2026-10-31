// WHY: Keeps heuristic advisory rows review-only and validates their preserved provenance.

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/** Validates heuristic advisory rows in the historical report. */
final class MavenElisionReportHeuristicAdvisoryPayloadValidator {
  /** Field names shared by heuristic row construction and validation. */
  private static final String OSV_ID = "osvId";

  /** Alias field name. */
  private static final String ALIASES = "aliases";

  /** CVE field name. */
  private static final String CVE_ID = "cveId";

  /** Exact component field name. */
  private static final String COORDINATE = "coordinate";

  /** OSV ecosystem of the unique raw package owner. */
  private static final String ECOSYSTEM = "ecosystem";

  /** OSV package identity of the unique raw package owner. */
  private static final String PACKAGE_NAME = "packageName";

  /** Original advisory range field name. */
  private static final String RANGE_SPEC = "versionRangeSpec";

  /** Applicability field name. */
  private static final String APPLICABILITY = "applicability";

  /** Applicability rationale field name. */
  private static final String APPLICABILITY_RATIONALE = "applicabilityRationale";

  /** Inventory disposition field name. */
  private static final String INVENTORY_DISPOSITION = "inventoryDisposition";

  /** Candidate provenance origin field name. */
  private static final String ORIGIN = "origin";

  /** Source record identifier field name. */
  private static final String SOURCE_RECORD_ID = "sourceRecordId";

  /** Source URL field name. */
  private static final String SOURCE_URL = "sourceUrl";

  /** Source record digest field name. */
  private static final String SOURCE_SHA = "sourceRecordSha256";

  /** Descriptive confidence field name. */
  private static final String CONFIDENCE = "confidence";

  /** Candidate class names field name. */
  private static final String CANDIDATE_CLASSES = "candidateClasses";

  /** Candidate dependency names field name. */
  private static final String CANDIDATE_DEPENDENCIES = "candidateDependencies";

  /** Exact fields for heuristic advisory rows. */
  private static final Set<String> HEURISTIC_FIELDS =
      Set.of(
          OSV_ID,
          ALIASES,
          CVE_ID,
          COORDINATE,
          ECOSYSTEM,
          PACKAGE_NAME,
          RANGE_SPEC,
          APPLICABILITY,
          APPLICABILITY_RATIONALE,
          INVENTORY_DISPOSITION,
          ORIGIN,
          SOURCE_RECORD_ID,
          SOURCE_URL,
          SOURCE_SHA,
          CONFIDENCE,
          CANDIDATE_CLASSES,
          CANDIDATE_DEPENDENCIES);

  /** Applicability values accepted by the saved report. */
  private static final Set<String> APPLICABILITY_VALUES =
      Set.of("APPLICABLE", "NOT_APPLICABLE", "UNRESOLVED");

  /** Inventory disposition values are descriptive, not mitigations. */
  private static final Set<String> DISPOSITION_VALUES =
      Set.of("REMOVED", "RETAINED_AND_TRIMMED", "RETAINED_UNCHANGED");

  private MavenElisionReportHeuristicAdvisoryPayloadValidator() {}

  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  static void validate(final JsonNode rows) throws IOException {
    requireArray(rows);
    for (final JsonNode row : rows) {
      validateRow(row);
    }
  }

  private static void validateRow(final JsonNode row) throws IOException {
    MavenElisionReportAdvisoryPayloadSupport.requireFields(
        row, HEURISTIC_FIELDS, "Elision report heuristic advisory fields do not match schema v1");
    MavenElisionReportAdvisoryPayloadSupport.text(row.get(OSV_ID), "heuristic advisory osvId");
    MavenElisionReportAdvisoryPayloadSupport.stringArray(row.get(ALIASES), ALIASES);
    MavenElisionReportAdvisoryPayloadSupport.nullableCve(row.get(CVE_ID));
    MavenElisionReportAdvisoryPayloadSupport.coordinate(row.get(COORDINATE));
    MavenElisionReportAdvisoryPayloadSupport.text(row.get(ECOSYSTEM), ECOSYSTEM);
    MavenElisionReportAdvisoryPayloadSupport.text(row.get(PACKAGE_NAME), PACKAGE_NAME);
    MavenElisionReportAdvisoryPayloadSupport.text(row.get(RANGE_SPEC), RANGE_SPEC);
    MavenElisionReportAdvisoryPayloadSupport.enumValue(
        row.get(APPLICABILITY), APPLICABILITY_VALUES, APPLICABILITY);
    MavenElisionReportAdvisoryPayloadSupport.text(
        row.get(APPLICABILITY_RATIONALE), APPLICABILITY_RATIONALE);
    MavenElisionReportAdvisoryPayloadSupport.enumValue(
        row.get(INVENTORY_DISPOSITION), DISPOSITION_VALUES, INVENTORY_DISPOSITION);
    MavenElisionReportAdvisoryPayloadSupport.enumValue(
        row.get(ORIGIN), Set.of("DESCRIPTION", "REFERENCE_URL"), ORIGIN);
    MavenElisionReportAdvisoryPayloadSupport.text(row.get(SOURCE_RECORD_ID), SOURCE_RECORD_ID);
    validateSourceUrl(row.get(SOURCE_URL));
    MavenElisionReportAdvisoryPayloadSupport.optionalSha(row.get(SOURCE_SHA), SOURCE_SHA);
    MavenElisionReportAdvisoryPayloadSupport.enumValue(
        row.get(CONFIDENCE), Set.of("MEDIUM"), "heuristic confidence");
    validateCandidates(row);
    validateOwnerAndCandidates(row);
  }

  private static void validateOwnerAndCandidates(final JsonNode row) throws IOException {
    try {
      MavenElisionReportAdvisoryInvariants.validateHeuristicIdentity(
          row.get(OSV_ID).textValue(),
          textValues(row.get(ALIASES)),
          row.get(CVE_ID).isNull() ? null : row.get(CVE_ID).textValue(),
          row.get(COORDINATE).textValue(),
          row.get(ECOSYSTEM).textValue(),
          row.get(PACKAGE_NAME).textValue(),
          row.get(SOURCE_RECORD_ID).textValue(),
          textValues(row.get(CANDIDATE_CLASSES)),
          textValues(row.get(CANDIDATE_DEPENDENCIES)));
    } catch (final IllegalArgumentException exception) {
      throw new IOException(exception.getMessage(), exception);
    }
  }

  private static List<String> textValues(final JsonNode values) {
    final List<String> result = new ArrayList<>();
    values.forEach(value -> result.add(value.textValue()));
    return List.copyOf(result);
  }

  private static void validateCandidates(final JsonNode row) throws IOException {
    final JsonNode classes = row.get(CANDIDATE_CLASSES);
    final JsonNode dependencies = row.get(CANDIDATE_DEPENDENCIES);
    MavenElisionReportAdvisoryPayloadSupport.stringArray(classes, CANDIDATE_CLASSES);
    MavenElisionReportAdvisoryPayloadSupport.stringArray(dependencies, CANDIDATE_DEPENDENCIES);
    if (classes.isEmpty() && dependencies.isEmpty()) {
      throw new IOException("Elision report heuristic advisory requires a candidate");
    }
  }

  private static void validateSourceUrl(final JsonNode value) throws IOException {
    MavenElisionReportAdvisoryPayloadSupport.nullableText(value, SOURCE_URL);
    if (value == null || value.isNull()) {
      return;
    }
    validateHttpUrl(value.textValue());
  }

  private static void validateHttpUrl(final String text) throws IOException {
    try {
      final URI uri = URI.create(text);
      if (!uri.isAbsolute()
          || !("http".equalsIgnoreCase(uri.getScheme())
              || "https".equalsIgnoreCase(uri.getScheme()))) {
        throw new IOException("Elision report heuristic sourceUrl must be absolute HTTP(S)");
      }
    } catch (final IllegalArgumentException exception) {
      throw new IOException("Elision report heuristic sourceUrl is invalid", exception);
    }
  }

  private static void requireArray(final JsonNode rows) throws IOException {
    if (rows == null || !rows.isArray()) {
      throw new IOException("Elision report heuristicAdvisories must be an array");
    }
  }
}
