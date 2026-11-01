// WHY: Keeps strict validation for historical source-review rows separate from report metrics.

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

/** Validates the review-only source rows in an elision report payload. */
final class MavenElisionReportSourcePayloadValidator {
  /** Structured source-file claim field. */
  private static final String PROGRAM_FILES = "programFiles";

  /** Structured source-routine claim field. */
  private static final String PROGRAM_ROUTINES = "programRoutines";

  /** Exact fields for historical structured-source review rows. */
  private static final Set<String> SOURCE_REVIEW_FIELDS =
      Set.of(
          "osvId",
          "cveId",
          "coordinate",
          "sourceRecordSha256",
          "cnaAffectedEntryIdentity",
          "affectedProductIdentity",
          PROGRAM_FILES,
          PROGRAM_ROUTINES,
          "conventionalLayoutAssumed",
          "matches",
          "applicability",
          "applicabilityRationale",
          "unresolvedRationale");

  private MavenElisionReportSourcePayloadValidator() {}

  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  static void validate(final JsonNode rows, final boolean snapshotAssumption) throws IOException {
    if (rows == null || !rows.isArray()) {
      throw new IOException("Elision report sourceReviewFindings must be an array");
    }
    for (final JsonNode row : rows) {
      validateRow(row, snapshotAssumption);
    }
  }

  private static void validateRow(final JsonNode row, final boolean snapshotAssumption)
      throws IOException {
    if (!row.isObject() || !fieldNames(row).equals(SOURCE_REVIEW_FIELDS)) {
      throw new IOException(
          "Elision report source review row fields do not match schema version 1");
    }
    validateNonBlank(row.get("osvId"), "osvId");
    validateCveId(row.get("cveId"));
    MavenElisionReportSourceCoordinateValidator.validate(row.get("coordinate"));
    validateSha256(row.get("sourceRecordSha256"));
    validateNonBlank(row.get("cnaAffectedEntryIdentity"), "cnaAffectedEntryIdentity");
    validateNonBlank(row.get("affectedProductIdentity"), "affectedProductIdentity");
    validateClaims(row);
    final JsonNode assumption = row.get("conventionalLayoutAssumed");
    if (assumption == null || !assumption.isBoolean()) {
      throw new IOException("Elision report source review assumption must be a JSON boolean");
    }
    if (assumption.booleanValue() != snapshotAssumption) {
      throw new IOException("Elision report source review assumption must match snapshot flag");
    }
    validateNonBlank(row.get("unresolvedRationale"), "unresolvedRationale");
    validateApplicability(row.get("applicability"));
    validateNonBlank(row.get("applicabilityRationale"), "applicabilityRationale");
    MavenElisionReportSourceMatchPayloadValidator.validate(
        row.get("matches"), row.get(PROGRAM_FILES));
  }

  private static void validateApplicability(final JsonNode value) throws IOException {
    if (value == null
        || !value.isTextual()
        || java.util.Arrays.stream(OsvPackageApplicability.Status.values())
            .noneMatch(status -> status.name().equals(value.textValue()))) {
      throw new IOException("Elision report source review applicability must be a known status");
    }
  }

  private static void validateSha256(final JsonNode value) throws IOException {
    if (value == null || !value.isTextual() || !value.textValue().matches("[0-9a-f]{64}")) {
      throw new IOException("Elision report sourceRecordSha256 must be a lowercase SHA-256");
    }
  }

  private static void validateCveId(final JsonNode cveId) throws IOException {
    if (cveId == null
        || !cveId.isTextual()
        || !cveId.textValue().matches("CVE-[0-9]{4}-[0-9]{4,}")) {
      throw new IOException("Elision report CVE row cveId must be a valid CVE identifier");
    }
  }

  private static void validateNonBlank(final JsonNode value, final String name) throws IOException {
    if (value == null || !value.isTextual() || value.textValue().isBlank()) {
      throw new IOException("Elision report source review " + name + " must be nonblank text");
    }
  }

  private static void validateStringArray(final JsonNode values, final String name)
      throws IOException {
    if (values == null || !values.isArray()) {
      throw new IOException("Elision report source review " + name + " must be an array");
    }
    for (final JsonNode value : values) {
      validateNonBlank(value, name + " item");
    }
  }

  private static void validateClaims(final JsonNode row) throws IOException {
    final JsonNode files = row.get(PROGRAM_FILES);
    final JsonNode routines = row.get(PROGRAM_ROUTINES);
    validateStringArray(files, PROGRAM_FILES);
    validateStringArray(routines, PROGRAM_ROUTINES);
    if (files.isEmpty() && routines.isEmpty()) {
      throw new IOException("Elision report source review row requires a file or routine claim");
    }
  }

  private static Set<String> fieldNames(final JsonNode row) {
    final Set<String> names = new HashSet<>();
    row.fieldNames().forEachRemaining(names::add);
    return names;
  }
}
