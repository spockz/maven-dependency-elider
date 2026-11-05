// WHY: Rejects malformed persisted report shapes before Jackson can coerce primitive fields.

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.spockz.elider.model.ArtifactCoordinate;
import java.io.IOException;
import java.util.HashMap;
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
          "executionEnvironment",
          "wholeArtifactsDropped",
          "originalJarBytesDropped",
          "droppedProgramClassEntries",
          "droppedProgramClassBytes",
          "droppedArtifacts",
          "rawDroppedCoordinates",
          PROGRAM_CLASSES_PRUNED,
          UNCOMPRESSED_PROGRAM_CLASS_BYTES_PRUNED,
          "trimmedArtifacts",
          "mediatedGraph",
          "assumeConventionalJavaSourceLayout",
          "policy",
          "exclusionReview",
          "appliedBans",
          "toleratedDuplicates",
          "genericFindings",
          "sourceObservations");

  /** Exact fields persisted for each tolerated duplicate class. */
  private static final Set<String> TOLERATED_DUPLICATE_FIELDS =
      Set.of("className", "action", "owners");

  /** Exact target and active runtime releases saved for report replay. */
  private static final Set<String> EXECUTION_ENVIRONMENT_FIELDS =
      Set.of("targetRelease", "runtimeRelease");

  /** Exact fields persisted for each applied ban outcome. */
  private static final Set<String> APPLIED_BAN_FIELDS =
      Set.of("dependency", "status", "matchedArtifacts", "originalArtifacts", "applied");

  /** Exact fields for the producing policy and operation identity. */
  private static final Set<String> POLICY_FIELDS =
      Set.of("retainedArtifacts", "banishedDependencies", "operationFingerprint");

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

  /** Reachable dispositions that leave an artifact in the effective output. */
  private static final Set<String> RETAINED_GRAPH_DISPOSITIONS =
      Set.of(
          EffectiveGraphPolicy.NodeDisposition.RETAINED.name(),
          EffectiveGraphPolicy.NodeDisposition.PROTECTED.name(),
          EffectiveGraphPolicy.NodeDisposition.ANCESTOR_PROMOTED.name());

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
    validateExecutionEnvironment(payload.get("executionEnvironment"));
    validateMetrics(payload, SNAPSHOT_METRICS, "Elision report metric");
    validateRows(payload.get("droppedArtifacts"), DROPPED_FIELDS, DROPPED_METRICS);
    validateRows(payload.get("trimmedArtifacts"), TRIMMED_FIELDS, TRIMMED_METRICS);
    validateLayoutFlag(payload.get("assumeConventionalJavaSourceLayout"));
    validatePolicy(payload.get("policy"));
    MavenElisionReportJsonPayloadShape.requireArray(
        payload.get("genericFindings"), "genericFindings");
    MavenElisionReportJsonPayloadShape.requireArray(
        payload.get("sourceObservations"), "sourceObservations");
    ExclusionReviewPayloadValidator.validate(payload.get("exclusionReview"));
    validateAppliedBans(
        payload.get("appliedBans"), textValues(payload.path("policy").get("banishedDependencies")));
    validateToleratedDuplicates(payload.get("toleratedDuplicates"));
    final Set<ArtifactCoordinate> retainedPolicy =
        retentionCoordinates(payload.path("policy").get("retainedArtifacts"));
    final MediatedGraphReport mediatedGraph =
        MavenElisionReportGraphPayloadValidator.validateAndRead(payload.get("mediatedGraph"));
    validateAppliedBanCrossSections(payload, mediatedGraph, retainedPolicy);
  }

  private static void validateAppliedBanCrossSections(
      final JsonNode payload,
      final MediatedGraphReport mediatedGraph,
      final Set<ArtifactCoordinate> retainedPolicy)
      throws IOException {
    final Set<String> dropped = artifactCoordinates(payload.get("droppedArtifacts"));
    for (final JsonNode row : payload.path("appliedBans")) {
      final MavenBanPlan.Entry.Status status = parseBanStatus(row.path("status").textValue());
      final BanishedDependency dependency = parseBanDependency(row.path("dependency").textValue());
      validateBanPolicyRetentionConflict(dependency, retainedPolicy);
      if (status == MavenBanPlan.Entry.Status.UNMATCHED) {
        validateUnmatchedBan(payload, mediatedGraph, dependency);
        continue;
      }
      if (!mediatedGraph.available()) {
        throw new IOException("Applied ban outcomes require an available mediated graph");
      }
      if (status == MavenBanPlan.Entry.Status.FORCED_ABSENT_AFTER_RESOLUTION) {
        validateForcedAbsentOutput(row, dropped);
      }
      validateNoRetainedOrTrimmedOutput(status, payload, mediatedGraph, dependency);
    }
  }

  private static void validateUnmatchedBan(
      final JsonNode payload, final MediatedGraphReport graph, final BanishedDependency dependency)
      throws IOException {
    if (hasArtifactForDependency(payload.get("droppedArtifacts"), dependency)
        || hasArtifactForDependency(payload.get("trimmedArtifacts"), dependency)
        || graph.available() && hasGraphNodeForDependency(graph, dependency, false)) {
      throw new IOException("Unmatched ban appears in the persisted artifact inventory");
    }
  }

  private static void validateBanPolicyRetentionConflict(
      final BanishedDependency dependency, final Set<ArtifactCoordinate> retainedPolicy)
      throws IOException {
    if (matchesRetainedDependency(dependency, retainedPolicy)) {
      throw new IOException("Elision report ban conflicts with retained-artifact policy");
    }
  }

  private static void validateForcedAbsentOutput(final JsonNode row, final Set<String> dropped)
      throws IOException {
    for (final String coordinate : textValues(row.path("matchedArtifacts"))) {
      if (!dropped.contains(coordinate)) {
        throw new IOException("Forced-absent matched artifact is missing from droppedArtifacts");
      }
    }
  }

  private static void validateNoRetainedOrTrimmedOutput(
      final MavenBanPlan.Entry.Status status,
      final JsonNode payload,
      final MediatedGraphReport mediatedGraph,
      final BanishedDependency dependency)
      throws IOException {
    if (hasGraphNodeForDependency(mediatedGraph, dependency, true)
        || hasArtifactForDependency(payload.get("trimmedArtifacts"), dependency)) {
      final String reason =
          status == MavenBanPlan.Entry.Status.FORCED_ABSENT_AFTER_RESOLUTION
              ? "Forced-absent matched artifact also appears in retained or trimmed artifacts"
              : "Excluded-before-resolution ban appears in retained or trimmed artifacts";
      throw new IOException(reason);
    }
  }

  private static Set<ArtifactCoordinate> retentionCoordinates(final JsonNode retained)
      throws IOException {
    try {
      return ElisionArtifactPolicy.parseRetentionCoordinates(textValues(retained));
    } catch (final org.apache.maven.plugin.MojoFailureException exception) {
      throw new IOException("Elision report retained-artifact policy is invalid", exception);
    }
  }

  private static boolean matchesRetainedDependency(
      final BanishedDependency dependency, final Set<ArtifactCoordinate> retained) {
    return retained.stream()
        .anyMatch(
            coordinate ->
                dependency.groupId().equals(coordinate.groupId())
                    && dependency.artifactId().equals(coordinate.artifactId()));
  }

  @SuppressWarnings("PMD.UseConcurrentHashMap")
  // This index is local to one validated report traversal.
  private static boolean hasGraphNodeForDependency(
      final MediatedGraphReport graph,
      final BanishedDependency dependency,
      final boolean retainedOnly) {
    final Map<String, String> dispositions = new HashMap<>();
    graph.nodeStatuses().forEach(status -> dispositions.put(status.nodeId(), status.disposition()));
    final ResolverArtifactGraphSnapshot snapshot = graph.snapshot();
    for (final Map<String, Object> node : snapshot.nodes()) {
      final String nodeId = (String) node.get(ResolverArtifactGraphSnapshotSchema.NODE_ID);
      if (!Boolean.TRUE.equals(node.get(ResolverArtifactGraphSnapshotSchema.REACHABLE))
          || snapshot.rootNodeId().equals(nodeId)
          || retainedOnly && !RETAINED_GRAPH_DISPOSITIONS.contains(dispositions.get(nodeId))) {
        continue;
      }
      final Map<?, ?> artifact = (Map<?, ?>) node.get(ResolverArtifactGraphSnapshotSchema.ARTIFACT);
      if (dependency.groupId().equals(artifact.get(ResolverArtifactGraphSnapshotSchema.GROUP_ID))
          && dependency
              .artifactId()
              .equals(artifact.get(ResolverArtifactGraphSnapshotSchema.ARTIFACT_ID))) {
        return true;
      }
    }
    return false;
  }

  private static boolean hasArtifactForDependency(
      final JsonNode rows, final BanishedDependency dependency) throws IOException {
    for (final JsonNode row : rows) {
      final ArtifactCoordinate coordinate;
      try {
        coordinate =
            MavenElisionReportSourceCoordinateValidator.parseCanonical(
                row.path("coordinate").textValue());
      } catch (final IllegalArgumentException exception) {
        throw new IOException("Elision report artifact coordinate is not canonical", exception);
      }
      if (dependency.groupId().equals(coordinate.groupId())
          && dependency.artifactId().equals(coordinate.artifactId())) {
        return true;
      }
    }
    return false;
  }

  private static Set<String> artifactCoordinates(final JsonNode rows) {
    final Set<String> coordinates = new HashSet<>();
    rows.forEach(row -> coordinates.add(row.path("coordinate").textValue()));
    return Set.copyOf(coordinates);
  }

  private static void validateToleratedDuplicates(final JsonNode rows) throws IOException {
    if (rows == null || !rows.isArray()) {
      throw new IOException("Elision report toleratedDuplicates must be an array");
    }
    String previous = null;
    for (final JsonNode row : rows) {
      final String className = validateToleratedDuplicateRow(row);
      if (previous != null && previous.compareTo(className) >= 0) {
        throw new IOException("Elision report tolerated duplicates must be sorted and distinct");
      }
      previous = className;
    }
  }

  private static String validateToleratedDuplicateRow(final JsonNode row) throws IOException {
    if (!row.isObject() || !fieldNames(row).equals(TOLERATED_DUPLICATE_FIELDS)) {
      throw new IOException(
          "Elision report tolerated duplicate row fields do not match schema version 1");
    }
    final JsonNode className = row.get("className");
    final JsonNode action = row.get("action");
    if (className == null || !className.isTextual() || className.textValue().isBlank()) {
      throw new IOException("Elision report tolerated duplicate className must be nonblank text");
    }
    if (action == null
        || !action.isTextual()
        || java.util.Arrays.stream(DuplicateClassPolicy.Action.values())
            .noneMatch(candidate -> candidate.name().equals(action.textValue()))) {
      throw new IOException("Elision report tolerated duplicate action is invalid");
    }
    if (!canonicalSortedDistinctTextArray(row.get("owners")) || row.get("owners").size() < 2) {
      throw new IOException(
          "Elision report tolerated duplicate owners must be a sorted array of two or more");
    }
    return className.textValue();
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
      final ArtifactCoordinate coordinate;
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

  private static boolean canonicalSortedDistinctTextArray(final JsonNode value) {
    if (!canonicalTextArray(value)) {
      return false;
    }
    String previous = null;
    for (final JsonNode item : value) {
      if (previous != null && previous.compareTo(item.textValue()) >= 0) {
        return false;
      }
      previous = item.textValue();
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

  private static void validateExecutionEnvironment(final JsonNode environment) throws IOException {
    if (environment == null || !environment.isObject()) {
      throw new IOException("Elision report executionEnvironment must be an object");
    }
    if (!fieldNames(environment).equals(EXECUTION_ENVIRONMENT_FIELDS)) {
      throw new IOException(
          "Elision report executionEnvironment fields do not match schema version "
              + MavenElisionReportSnapshot.SCHEMA_VERSION);
    }
    validateRelease(environment.get("targetRelease"), "targetRelease", 8);
    validateRelease(environment.get("runtimeRelease"), "runtimeRelease", 21);
  }

  private static void validateRelease(final JsonNode release, final String name, final int minimum)
      throws IOException {
    if (release == null
        || !release.isIntegralNumber()
        || !release.canConvertToInt()
        || release.intValue() < minimum) {
      throw new IOException(
          "Elision report executionEnvironment "
              + name
              + " must be an integer greater than or equal to "
              + minimum);
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
