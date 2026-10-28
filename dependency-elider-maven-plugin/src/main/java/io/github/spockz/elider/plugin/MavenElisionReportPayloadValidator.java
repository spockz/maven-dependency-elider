// WHY: Rejects malformed persisted report shapes before Jackson can coerce primitive fields.

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/** Validates schema-one JSON types and row shapes before snapshot deserialization. */
@SuppressWarnings({"PMD.GodClass", "PMD.AvoidDuplicateLiterals", "PMD.TooManyMethods"})
final class MavenElisionReportPayloadValidator {
  /** Count of classes pruned from retained artifacts. */
  private static final String PROGRAM_CLASSES_PRUNED = "programClassesPruned";

  /** Uncompressed bytes for classes pruned from retained artifacts. */
  private static final String UNCOMPRESSED_PROGRAM_CLASS_BYTES_PRUNED =
      "uncompressedProgramClassBytesPruned";

  /** Exact schema fields for the persisted report. */
  private static final Set<String> SNAPSHOT_FIELDS =
      Set.of(
          "schemaVersion",
          "projectGroupId",
          "projectArtifactId",
          "projectVersion",
          "projectBaseDirectory",
          "generatedAt",
          "wholeArtifactsDropped",
          "originalJarBytesDropped",
          "droppedProgramClassEntries",
          "droppedProgramClassBytes",
          "droppedArtifacts",
          "rawDroppedCoordinates",
          PROGRAM_CLASSES_PRUNED,
          UNCOMPRESSED_PROGRAM_CLASS_BYTES_PRUNED,
          "trimmedArtifacts",
          "removedCveComponents",
          "provenAbsentCves",
          "mediatedGraph");

  /** Exact fields for CVE finding rows. */
  private static final Set<String> CVE_FIELDS = Set.of("cveId", "coordinate");

  /** Whole-artifact rows retain original-JAR and removed-class metrics. */
  private static final Map<String, Long> DROPPED_METRICS =
      Map.of(
          "originalJarBytes", Long.MAX_VALUE,
          "programClassesRemoved", (long) Integer.MAX_VALUE,
          "uncompressedProgramClassBytesRemoved", Long.MAX_VALUE);

  /** Retained-JAR rows contain only their own pruning totals. */
  private static final Map<String, Long> TRIMMED_METRICS =
      Map.of(
          PROGRAM_CLASSES_PRUNED,
          (long) Integer.MAX_VALUE,
          UNCOMPRESSED_PROGRAM_CLASS_BYTES_PRUNED,
          Long.MAX_VALUE);

  /** Exact fields for whole-artifact rows. */
  private static final Set<String> DROPPED_FIELDS =
      Set.of(
          "coordinate",
          "originalJarBytes",
          "programClassesRemoved",
          "uncompressedProgramClassBytesRemoved");

  /** Exact fields for retained-artifact rows. */
  private static final Set<String> TRIMMED_FIELDS =
      Set.of("coordinate", PROGRAM_CLASSES_PRUNED, UNCOMPRESSED_PROGRAM_CLASS_BYTES_PRUNED);

  /** Nonnegative ranges for count and byte fields. */
  private static final Map<String, Long> SNAPSHOT_METRICS =
      Map.of(
          "wholeArtifactsDropped",
          (long) Integer.MAX_VALUE,
          "originalJarBytesDropped",
          Long.MAX_VALUE,
          "droppedProgramClassEntries",
          (long) Integer.MAX_VALUE,
          "droppedProgramClassBytes",
          Long.MAX_VALUE,
          PROGRAM_CLASSES_PRUNED,
          (long) Integer.MAX_VALUE,
          UNCOMPRESSED_PROGRAM_CLASS_BYTES_PRUNED,
          Long.MAX_VALUE);

  private MavenElisionReportPayloadValidator() {}

  /** Validates the report payload before Jackson binds primitive record fields. */
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  static void validate(final JsonNode payload) throws IOException {
    validateSchemaVersion(payload);
    validateSnapshotShape(payload);
    validateMetrics(payload, SNAPSHOT_METRICS, "Elision report metric");
    validateRows(payload.get("droppedArtifacts"), DROPPED_FIELDS, DROPPED_METRICS);
    validateRows(payload.get("trimmedArtifacts"), TRIMMED_FIELDS, TRIMMED_METRICS);
    validateCveRows(payload.get("removedCveComponents"));
    validateCveRows(payload.get("provenAbsentCves"));
    MavenElisionReportGraphPayloadValidator.validate(payload.get("mediatedGraph"));
  }

  private static void validateCveRows(final JsonNode rows) throws IOException {
    if (rows == null || !rows.isArray()) {
      throw new IOException("Elision report CVE rows must be arrays");
    }
    for (final JsonNode row : rows) {
      validateCveRow(row);
    }
  }

  private static void validateCveRow(final JsonNode row) throws IOException {
    if (!row.isObject()) {
      throw new IOException("Elision report CVE rows must be objects");
    }
    if (!fieldNames(row).equals(CVE_FIELDS)) {
      throw new IOException(
          "Elision report CVE row fields do not match schema version "
              + MavenElisionReportSnapshot.SCHEMA_VERSION
              + "; run dependency-elider:elide to write a current report");
    }
    validateCveId(row.get("cveId"));
    validateCoordinateField(row.get("coordinate"));
  }

  private static void validateCveId(final JsonNode cveId) throws IOException {
    if (cveId == null
        || !cveId.isTextual()
        || !cveId.textValue().matches("CVE-[0-9]{4}-[0-9]{4,}")) {
      throw new IOException("Elision report CVE row cveId must be a valid CVE identifier");
    }
  }

  private static void validateCoordinateField(final JsonNode coordinate) throws IOException {
    if (coordinate == null || !coordinate.isTextual() || coordinate.textValue().isBlank()) {
      throw new IOException("Elision report CVE row coordinate must be nonblank text");
    }
  }

  private static void validateSchemaVersion(final JsonNode payload) throws IOException {
    final JsonNode version = payload == null ? null : payload.get("schemaVersion");
    if (version == null
        || !version.isInt()
        || version.intValue() != MavenElisionReportSnapshot.SCHEMA_VERSION) {
      final String actual = version == null ? "missing" : version.asText();
      throw new IOException(
          "Unsupported elision report schema version "
              + actual
              + "; run dependency-elider:elide to write a current report before using this goal");
    }
  }

  private static void validateSnapshotShape(final JsonNode payload) throws IOException {
    if (payload == null || !payload.isObject()) {
      throw new IOException("Elision report snapshot must be a JSON object");
    }
    if (!fieldNames(payload).equals(SNAPSHOT_FIELDS)) {
      throw new IOException(
          "Elision report fields do not match schema version "
              + MavenElisionReportSnapshot.SCHEMA_VERSION
              + "; run dependency-elider:elide to write a current report");
    }
  }

  private static void validateRows(
      final JsonNode rows, final Set<String> fields, final Map<String, Long> metrics)
      throws IOException {
    if (rows == null || !rows.isArray()) {
      throw new IOException("Elision report artifact rows must be arrays");
    }
    for (final JsonNode row : rows) {
      validateRow(row, fields, metrics);
    }
  }

  private static void validateRow(
      final JsonNode row, final Set<String> fields, final Map<String, Long> metrics)
      throws IOException {
    if (!row.isObject()) {
      throw new IOException("Elision report artifact rows must be objects");
    }
    if (!fieldNames(row).equals(fields)) {
      throw new IOException(
          "Elision report artifact row fields do not match schema version "
              + MavenElisionReportSnapshot.SCHEMA_VERSION
              + "; run dependency-elider:elide to write a current report");
    }
    final JsonNode coordinate = row.get("coordinate");
    if (!coordinate.isTextual() || coordinate.textValue().isBlank()) {
      throw new IOException("Elision report artifact coordinate must be nonblank text");
    }
    validateMetrics(row, metrics, "Elision report artifact metric");
  }

  private static void validateMetrics(
      final JsonNode value, final Map<String, Long> metrics, final String label)
      throws IOException {
    for (final Map.Entry<String, Long> metric : metrics.entrySet()) {
      final JsonNode number = value.get(metric.getKey());
      if (number == null
          || !number.isIntegralNumber()
          || !number.canConvertToLong()
          || number.longValue() < 0
          || number.longValue() > metric.getValue()) {
        throw new IOException(label + " must be a nonnegative integer: " + metric.getKey());
      }
    }
  }

  private static Set<String> fieldNames(final JsonNode value) {
    final Set<String> fields = new HashSet<>();
    value.fieldNames().forEachRemaining(fields::add);
    return fields;
  }
}
