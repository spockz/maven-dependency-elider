// WHY: Rejects malformed persisted report shapes before Jackson can coerce primitive fields.

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Validates schema-one JSON types and row shapes before snapshot deserialization. */
@SuppressWarnings({
  "PMD.GodClass",
  "PMD.AvoidDuplicateLiterals",
  "PMD.TooManyMethods",
  "PMD.CyclomaticComplexity"
})
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
          "inactivePreconditionCves",
          "potentiallyConservativeCves",
          "mediatedGraph",
          "assumeConventionalJavaSourceLayout",
          "sourceReviewFindings",
          "advisoryReview",
          "verifiedStructuredProofs",
          "policy",
          "exclusionReview",
          "appliedBans");

  /** Exact fields persisted for each applied ban outcome. */
  private static final Set<String> APPLIED_BAN_FIELDS =
      Set.of("dependency", "status", "matchedArtifacts", "originalArtifacts", "applied");

  /** Exact fields for the producing policy and operation identity. */
  private static final Set<String> POLICY_FIELDS =
      Set.of("retainedArtifacts", "banishedDependencies", "operationFingerprint");

  /** Exact fields for CVE finding rows. */
  private static final Set<String> CVE_FIELDS = Set.of("cveId", "coordinate");

  /** Exact fields for conservative CVE finding rows. */
  private static final Set<String> CONSERVATIVE_CVE_FIELDS =
      Set.of("cveId", "coordinate", "reason", "pomOverrideSnippet");

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
    validateCveRows(payload.get("inactivePreconditionCves"));
    validateConservativeCveRows(payload.get("potentiallyConservativeCves"));
    validateLayoutFlag(payload.get("assumeConventionalJavaSourceLayout"));
    validatePolicy(payload.get("policy"));
    MavenElisionReportSourcePayloadValidator.validate(
        payload.get("sourceReviewFindings"),
        payload.get("assumeConventionalJavaSourceLayout").booleanValue());
    MavenElisionReportAdvisoryPayloadValidator.validate(payload.get("advisoryReview"));
    MavenElisionReportStructuredProofPayloadValidator.validate(
        payload.get("verifiedStructuredProofs"),
        payload.get("assumeConventionalJavaSourceLayout").booleanValue());
    ExclusionReviewPayloadValidator.validate(payload.get("exclusionReview"));
    validateAppliedBans(
        payload.get("appliedBans"), textValues(payload.path("policy").get("banishedDependencies")));
    MavenElisionReportGraphPayloadValidator.validate(payload.get("mediatedGraph"));
  }

  private static void validateAppliedBans(
      final JsonNode rows, final List<String> policyDependencies) throws IOException {
    if (rows == null || !rows.isArray()) {
      throw new IOException("Elision report appliedBans must be an array");
    }
    final List<String> rowDependencies = new java.util.ArrayList<>();
    for (final JsonNode row : rows) {
      rowDependencies.add(validateAppliedBanRow(row));
    }
    if (!rowDependencies.equals(policyDependencies)) {
      throw new IOException("Elision report applied bans do not match policy banishedDependencies");
    }
  }

  private static String validateAppliedBanRow(final JsonNode row) throws IOException {
    if (!row.isObject() || !fieldNames(row).equals(APPLIED_BAN_FIELDS)) {
      throw new IOException("Elision report ban row fields do not match schema version 1");
    }
    final JsonNode dependencyNode = row.get("dependency");
    final JsonNode statusNode = row.get("status");
    if (dependencyNode == null
        || !dependencyNode.isTextual()
        || dependencyNode.textValue().isBlank()) {
      throw new IOException("Elision report ban dependency must be nonblank text");
    }
    if (statusNode == null || !statusNode.isTextual()) {
      throw new IOException("Elision report ban status must be text");
    }
    final String dependency = dependencyNode.textValue();
    final BanishedDependency parsedDependency = parseBanDependency(dependency);
    if (!parsedDependency.toString().equals(dependency)) {
      throw new IOException("Elision report ban dependency is not canonical");
    }
    final MavenBanPlan.Entry.Status parsedStatus = parseBanStatus(statusNode.textValue());
    final JsonNode matched = row.get("matchedArtifacts");
    final JsonNode original = row.get("originalArtifacts");
    final JsonNode applied = row.get("applied");
    if (!canonicalTextArray(matched)
        || !canonicalTextArray(original)
        || applied == null
        || !applied.isBoolean()) {
      throw new IOException("Elision report ban artifact lists or applied flag are malformed");
    }
    final List<String> matchedValues = textValues(matched);
    final List<String> originalValues = textValues(original);
    validateBanArtifactCoordinates(matchedValues, parsedDependency);
    validateBanArtifactCoordinates(originalValues, parsedDependency);
    validateAppliedBanOutcome(parsedStatus, applied.booleanValue(), matchedValues, originalValues);
    return dependency;
  }

  private static BanishedDependency parseBanDependency(final String value) throws IOException {
    try {
      return BanishedDependencyPolicy.normalize(List.of(value)).getFirst();
    } catch (final org.apache.maven.plugin.MojoFailureException exception) {
      throw new IOException("Elision report ban dependency is invalid", exception);
    }
  }

  private static MavenBanPlan.Entry.Status parseBanStatus(final String value) throws IOException {
    try {
      return MavenBanPlan.Entry.Status.valueOf(value);
    } catch (final IllegalArgumentException exception) {
      throw new IOException("Elision report ban status is invalid", exception);
    }
  }

  private static void validateAppliedBanOutcome(
      final MavenBanPlan.Entry.Status status,
      final boolean applied,
      final List<String> matched,
      final List<String> original)
      throws IOException {
    if (applied != (status != MavenBanPlan.Entry.Status.UNMATCHED)
        || !matched.equals(matched.stream().distinct().sorted().toList())
        || !original.equals(original.stream().distinct().sorted().toList())
        || !original.containsAll(matched)) {
      throw new IOException("Elision report ban outcome is inconsistent");
    }
    if (status == MavenBanPlan.Entry.Status.FORCED_ABSENT_AFTER_RESOLUTION && matched.isEmpty()) {
      throw new IOException("Forced-absent ban has no effective match");
    }
    if (status == MavenBanPlan.Entry.Status.EXCLUDED_BEFORE_RESOLUTION
        && (!matched.isEmpty() || original.isEmpty())) {
      throw new IOException("Excluded-before-resolution ban has inconsistent matches");
    }
    if (status == MavenBanPlan.Entry.Status.UNMATCHED
        && (!matched.isEmpty() || !original.isEmpty())) {
      throw new IOException("Unmatched ban carries artifact matches");
    }
  }

  private static void validateBanArtifactCoordinates(
      final List<String> coordinates, final BanishedDependency dependency) throws IOException {
    for (final String text : coordinates) {
      final io.github.spockz.elider.model.ArtifactCoordinate coordinate;
      try {
        coordinate = MavenElisionReportSourceCoordinateValidator.parseCanonical(text);
      } catch (final IllegalArgumentException exception) {
        throw new IOException("Elision report ban artifact coordinate is not canonical", exception);
      }
      if (!"jar".equals(coordinate.type())
          || !Set.of("compile", "runtime").contains(coordinate.scope())) {
        throw new IOException("Elision report ban artifact must be a compile/runtime JAR");
      }
      if (!dependency.groupId().equals(coordinate.groupId())
          || !dependency.artifactId().equals(coordinate.artifactId())) {
        throw new IOException("Elision report ban artifact G:A does not match its dependency");
      }
    }
  }

  @SuppressWarnings("PMD.CyclomaticComplexity")
  private static void validatePolicy(final JsonNode policy) throws IOException {
    if (policy == null || !policy.isObject() || !fieldNames(policy).equals(POLICY_FIELDS)) {
      throw new IOException("Elision report policy fields do not match schema version 1");
    }
    final JsonNode retained = policy.get("retainedArtifacts");
    final JsonNode banished = policy.get("banishedDependencies");
    final JsonNode fingerprint = policy.get("operationFingerprint");
    if (!canonicalTextArray(retained)
        || !canonicalTextArray(banished)
        || fingerprint == null
        || !fingerprint.isTextual()
        || !fingerprint.textValue().matches("[0-9a-f]{64}")) {
      throw new IOException("Elision report policy values are malformed");
    }
    try {
      final List<String> retainedValues = textValues(retained);
      final List<String> banishedValues = textValues(banished);
      final List<String> canonicalRetained =
          ElisionArtifactPolicy.parseRetentionCoordinates(retainedValues).stream()
              .map(MavenElisionPolicyIdentity::retentionCoordinate)
              .sorted()
              .toList();
      final List<String> canonicalBanished =
          BanishedDependencyPolicy.normalize(banishedValues).stream()
              .map(Object::toString)
              .toList();
      if (!canonicalRetained.equals(retainedValues) || !canonicalBanished.equals(banishedValues)) {
        throw new IOException("Elision report policy coordinates are not canonical");
      }
    } catch (final org.apache.maven.plugin.MojoFailureException exception) {
      throw new IOException("Elision report policy coordinates are invalid", exception);
    }
  }

  private static boolean canonicalTextArray(final JsonNode value) {
    if (value == null || !value.isArray()) {
      return false;
    }
    for (final JsonNode item : value) {
      if (!item.isTextual() || item.textValue().isBlank()) {
        return false;
      }
    }
    return true;
  }

  private static List<String> textValues(final JsonNode value) {
    final List<String> result = new java.util.ArrayList<>();
    value.forEach(item -> result.add(item.textValue()));
    return List.copyOf(result);
  }

  private static void validateLayoutFlag(final JsonNode value) throws IOException {
    if (value == null || !value.isBoolean()) {
      throw new IOException("Elision report layout assumption must be a JSON boolean");
    }
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

  private static void validateConservativeCveRows(final JsonNode rows) throws IOException {
    if (rows == null || !rows.isArray()) {
      throw new IOException("Elision report potentiallyConservativeCves rows must be arrays");
    }
    for (final JsonNode row : rows) {
      validateConservativeCveRow(row);
    }
  }

  private static void validateConservativeCveRow(final JsonNode row) throws IOException {
    if (!row.isObject()) {
      throw new IOException("Elision report conservative CVE rows must be objects");
    }
    if (!fieldNames(row).equals(CONSERVATIVE_CVE_FIELDS)) {
      throw new IOException(
          "Elision report conservative CVE row fields do not match schema version "
              + MavenElisionReportSnapshot.SCHEMA_VERSION
              + "; run dependency-elider:elide to write a current report");
    }
    validateCveId(row.get("cveId"));
    validateCoordinateField(row.get("coordinate"));
    validateTextField(row.get("reason"), "reason");
    validateTextField(row.get("pomOverrideSnippet"), "pomOverrideSnippet");
  }

  private static void validateTextField(final JsonNode field, final String name)
      throws IOException {
    if (field == null || !field.isTextual() || field.textValue().isBlank()) {
      throw new IOException(
          "Elision report conservative CVE " + name + " must be a non-blank string");
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
