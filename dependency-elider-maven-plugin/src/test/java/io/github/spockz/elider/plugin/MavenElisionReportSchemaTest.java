// WHY: Verifies unsupported and incompatible persisted report drafts fail before deserialization.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.spockz.elider.model.ArtifactCoordinate;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Covers report schema-version and exact-field rejection. */
@SuppressWarnings({
  "PMD.AtLeastOneConstructor",
  "PMD.CommentDefaultAccessModifier",
  "PMD.TooManyMethods",
  "PMD.AvoidDuplicateLiterals"
})
final class MavenElisionReportSchemaTest {
  /** Dropped-row collection key. */
  private static final String DROPPED_ROWS = "droppedArtifacts";

  /** Removed class count key on a whole-artifact row. */
  private static final String DROPPED_CLASSES = "programClassesRemoved";

  /** Removed class payload byte key on a whole-artifact row. */
  private static final String DROPPED_CLASS_BYTES = "uncompressedProgramClassBytesRemoved";

  /** Retained-JAR pruned class count key. */
  private static final String TRIMMED_CLASSES = "programClassesPruned";

  /** Retained-JAR pruned class payload byte key. */
  private static final String TRIMMED_CLASS_BYTES = "uncompressedProgramClassBytesPruned";

  /** JSON builder for adversarial report drafts. */
  private static final ObjectMapper JSON = new ObjectMapper();

  /** First release greater than the largest Java int. */
  private static final long FIRST_INT_OVERFLOW_RELEASE = 2_147_483_648L;

  /** Temporary report directory. */
  @TempDir Path temporaryDirectory;

  @Test
  void rejectsUnsupportedNonOneSnapshotWithRerunGuidance() throws IOException {
    final Path previous = temporaryDirectory.resolve("previous-report.json");
    java.nio.file.Files.writeString(previous, "{\"schemaVersion\":4}");

    assertThatThrownBy(() -> MavenElisionReportWriter.read(previous))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Unsupported elision report schema version 4")
        .hasMessageContaining("run dependency-elider:elide");
  }

  @Test
  void readsAndReplaysSavedExecutionEnvironmentWithoutUsingCurrentRuntime() throws IOException {
    final ObjectNode payload = currentReportShapeWithDroppedRow();
    payload.put("wholeArtifactsDropped", 0);
    payload.put("originalJarBytesDropped", 0);
    payload.put("droppedProgramClassEntries", 0);
    payload.put("droppedProgramClassBytes", 0);
    payload.putArray(DROPPED_ROWS);
    payload.set(
        "mediatedGraph",
        JSON.valueToTree(MediatedGraphReportTestSupport.emptyGraph("fixture:consumer:1.0")));
    final int savedRuntimeRelease = Runtime.version().feature() == 21 ? 25 : 21;
    executionEnvironment(payload).put("targetRelease", 11);
    executionEnvironment(payload).put("runtimeRelease", savedRuntimeRelease);
    final Path report = writeReport("saved-execution-environment.json", payload);

    final MavenElisionReportSnapshot snapshot = MavenElisionReportWriter.read(report);
    final JsonNode replayed = JSON.valueToTree(snapshot);

    assertAll(
        "report replay uses the saved execution environment",
        () -> assertThat(replayed.path("schemaVersion").asInt()).isEqualTo(1),
        () ->
            assertThat(replayed.path("executionEnvironment").path("targetRelease").asInt())
                .isEqualTo(11),
        () ->
            assertThat(replayed.path("executionEnvironment").path("runtimeRelease").asInt())
                .isEqualTo(savedRuntimeRelease),
        () -> assertThat(savedRuntimeRelease).isNotEqualTo(Runtime.version().feature()),
        () -> {
          final List<String> rendered = MavenElisionReportWriter.render(snapshot);
          assertAll(
              "rendered report retains both saved release values",
              () -> assertThat(rendered).contains("Analysis target JDK release: 11"),
              () ->
                  assertThat(rendered)
                      .contains("Elider runtime JDK release: " + savedRuntimeRelease));
        });
  }

  @Test
  void rejectsMissingOrMalformedExecutionEnvironmentFields() {
    final ObjectNode missingEnvironment = currentReportShapeWithDroppedRow();
    missingEnvironment.remove("executionEnvironment");
    final ObjectNode nullEnvironment = currentReportShapeWithDroppedRow();
    nullEnvironment.putNull("executionEnvironment");
    final ObjectNode missingTarget = currentReportShapeWithDroppedRow();
    executionEnvironment(missingTarget).remove("targetRelease");
    final ObjectNode nullTarget = currentReportShapeWithDroppedRow();
    executionEnvironment(nullTarget).putNull("targetRelease");
    final ObjectNode textualTarget = currentReportShapeWithDroppedRow();
    executionEnvironment(textualTarget).put("targetRelease", "11");
    final ObjectNode invalidTarget = currentReportShapeWithDroppedRow();
    executionEnvironment(invalidTarget).put("targetRelease", 7);
    final ObjectNode oversizedTarget = currentReportShapeWithDroppedRow();
    executionEnvironment(oversizedTarget).put("targetRelease", FIRST_INT_OVERFLOW_RELEASE);
    final ObjectNode missingRuntime = currentReportShapeWithDroppedRow();
    executionEnvironment(missingRuntime).remove("runtimeRelease");
    final ObjectNode nullRuntime = currentReportShapeWithDroppedRow();
    executionEnvironment(nullRuntime).putNull("runtimeRelease");
    final ObjectNode textualRuntime = currentReportShapeWithDroppedRow();
    executionEnvironment(textualRuntime).put("runtimeRelease", "25");
    final ObjectNode oversizedRuntime = currentReportShapeWithDroppedRow();
    executionEnvironment(oversizedRuntime).put("runtimeRelease", FIRST_INT_OVERFLOW_RELEASE);
    final ObjectNode invalidRuntime = currentReportShapeWithDroppedRow();
    executionEnvironment(invalidRuntime).put("runtimeRelease", 20);
    final ObjectNode fractionalRuntime = currentReportShapeWithDroppedRow();
    executionEnvironment(fractionalRuntime).put("runtimeRelease", 21.5);
    final ObjectNode unknownEnvironmentField = currentReportShapeWithDroppedRow();
    executionEnvironment(unknownEnvironmentField).put("vendor", "example");

    assertAll(
        "schema-one execution environment is required and strictly typed",
        () ->
            assertInvalidEnvironment(
                "missing-execution-environment.json",
                missingEnvironment,
                "Elision report fields do not match schema version 1"),
        () ->
            assertInvalidEnvironment(
                "null-execution-environment.json",
                nullEnvironment,
                "executionEnvironment must be an object"),
        () ->
            assertInvalidEnvironment(
                "missing-target-release.json",
                missingTarget,
                "executionEnvironment fields do not match schema version 1"),
        () ->
            assertInvalidEnvironment(
                "null-target-release.json",
                nullTarget,
                "targetRelease must be an integer greater than or equal to 8"),
        () ->
            assertInvalidEnvironment(
                "textual-target-release.json",
                textualTarget,
                "targetRelease must be an integer greater than or equal to 8"),
        () ->
            assertInvalidEnvironment(
                "invalid-target-release.json",
                invalidTarget,
                "targetRelease must be an integer greater than or equal to 8"),
        () ->
            assertInvalidEnvironment(
                "oversized-target-release.json",
                oversizedTarget,
                "targetRelease must be an integer greater than or equal to 8"),
        () ->
            assertInvalidEnvironment(
                "missing-runtime-release.json",
                missingRuntime,
                "executionEnvironment fields do not match schema version 1"),
        () ->
            assertInvalidEnvironment(
                "null-runtime-release.json",
                nullRuntime,
                "runtimeRelease must be an integer greater than or equal to 21"),
        () ->
            assertInvalidEnvironment(
                "textual-runtime-release.json",
                textualRuntime,
                "runtimeRelease must be an integer greater than or equal to 21"),
        () ->
            assertInvalidEnvironment(
                "oversized-runtime-release.json",
                oversizedRuntime,
                "runtimeRelease must be an integer greater than or equal to 21"),
        () ->
            assertInvalidEnvironment(
                "invalid-runtime-release.json",
                invalidRuntime,
                "runtimeRelease must be an integer greater than or equal to 21"),
        () ->
            assertInvalidEnvironment(
                "fractional-runtime-release.json",
                fractionalRuntime,
                "runtimeRelease must be an integer greater than or equal to 21"),
        () ->
            assertInvalidEnvironment(
                "unknown-execution-environment-field.json",
                unknownEnvironmentField,
                "executionEnvironment fields do not match schema version 1"));
  }

  @Test
  void requiresCanonicalToleratedDuplicateRows() throws IOException {
    final ObjectNode missing = currentReportShapeWithDroppedRow();
    missing.remove("toleratedDuplicates");
    final ObjectNode malformedRow = currentReportShapeWithDroppedRow();
    malformedRow.putArray("toleratedDuplicates").addObject().put("className", "dup.Type");
    final ObjectNode invalidAction = duplicatePayload();
    ((ObjectNode) invalidAction.withArray("toleratedDuplicates").get(0)).put("action", "KEEP_SOME");
    final ObjectNode invalidOwners = duplicatePayload();
    ((ObjectNode) invalidOwners.withArray("toleratedDuplicates").get(0))
        .putArray("owners")
        .add("example:z:jar:1.0")
        .add("example:a:jar:1.0");
    final ObjectNode unsortedRows = duplicatePayload();
    unsortedRows
        .withArray("toleratedDuplicates")
        .addObject()
        .put("className", "dup.A")
        .put("action", "RETAIN_JARS")
        .putArray("owners")
        .add("example:a:jar:1.0")
        .add("example:b:jar:1.0");

    assertAll(
        () -> assertInvalidDuplicate(missing, "fields do not match schema version 1"),
        () -> assertInvalidDuplicate(malformedRow, "row fields do not match"),
        () -> assertInvalidDuplicate(invalidAction, "action is invalid"),
        () -> assertInvalidDuplicate(invalidOwners, "owners must be a sorted array"),
        () -> assertInvalidDuplicate(unsortedRows, "must be sorted and distinct"));
  }

  private void assertInvalidDuplicate(final ObjectNode payload, final String diagnostic)
      throws IOException {
    final Path report =
        writeReport("invalid-duplicates-" + diagnostic.hashCode() + ".json", payload);
    assertThatThrownBy(() -> MavenElisionReportWriter.read(report))
        .isInstanceOf(IOException.class)
        .hasMessageContaining(diagnostic);
  }

  private static ObjectNode duplicatePayload() {
    final ObjectNode payload = currentReportShapeWithDroppedRow();
    payload
        .withArray("toleratedDuplicates")
        .addObject()
        .put("className", "dup.B")
        .put("action", "RETAIN_JARS")
        .putArray("owners")
        .add("example:a:jar:1.0")
        .add("example:b:jar:1.0");
    return payload;
  }

  @Test
  void rejectsSchemaOneDraftWithIncompatibleTopLevelFields() throws IOException {
    final Path previous = temporaryDirectory.resolve("incompatible-report-draft.json");
    java.nio.file.Files.writeString(previous, "{\"schemaVersion\":1,\"projectGroupId\":\"draft\"}");

    assertThatThrownBy(() -> MavenElisionReportWriter.read(previous))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Elision report fields do not match schema version 1")
        .hasMessageContaining("run dependency-elider:elide");
  }

  @Test
  void rejectsMissingOrMalformedPolicyIdentity() throws IOException {
    final ObjectNode missingPolicy = currentReportShapeWithDroppedRow();
    missingPolicy.remove("policy");
    final Path missing = temporaryDirectory.resolve("missing-policy.json");
    JSON.writeValue(missing.toFile(), missingPolicy);

    final ObjectNode malformedPolicy = currentReportShapeWithDroppedRow();
    malformedPolicy.with("policy").put("operationFingerprint", "not-a-digest");
    final Path malformed = temporaryDirectory.resolve("malformed-policy.json");
    JSON.writeValue(malformed.toFile(), malformedPolicy);

    final ObjectNode noncanonicalPolicy = currentReportShapeWithDroppedRow();
    noncanonicalPolicy
        .with("policy")
        .putArray("retainedArtifacts")
        .add("org.example:kept::jar:")
        .add("org.example:kept::jar:");
    final Path noncanonical = temporaryDirectory.resolve("noncanonical-policy.json");
    JSON.writeValue(noncanonical.toFile(), noncanonicalPolicy);

    final ObjectNode invalidCoordinatePolicy = currentReportShapeWithDroppedRow();
    invalidCoordinatePolicy.with("policy").putArray("banishedDependencies").add("org.example:*");
    final Path invalidCoordinate = temporaryDirectory.resolve("invalid-policy-coordinate.json");
    JSON.writeValue(invalidCoordinate.toFile(), invalidCoordinatePolicy);

    assertAll(
        "schema-one policy identity is required and structurally valid",
        () ->
            assertThatThrownBy(() -> MavenElisionReportWriter.read(missing))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("Elision report fields do not match schema version 1"),
        () ->
            assertThatThrownBy(() -> MavenElisionReportWriter.read(malformed))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("Elision report policy values are malformed"),
        () ->
            assertThatThrownBy(() -> MavenElisionReportWriter.read(noncanonical))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("Elision report policy coordinates are not canonical"),
        () ->
            assertThatThrownBy(() -> MavenElisionReportWriter.read(invalidCoordinate))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("Elision report policy coordinates are invalid"));
  }

  @Test
  void rejectsDroppedArtifactMissingClassMetrics() throws IOException {
    final ObjectNode payload = currentReportShapeWithDroppedRow();
    final ObjectNode row = (ObjectNode) payload.withArray(DROPPED_ROWS).get(0);
    row.remove(DROPPED_CLASSES);
    row.remove(DROPPED_CLASS_BYTES);
    final Path previous = temporaryDirectory.resolve("missing-class-metrics.json");
    JSON.writeValue(previous.toFile(), payload);

    assertThatThrownBy(() -> MavenElisionReportWriter.read(previous))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Elision report artifact row fields do not match schema version 1")
        .hasMessageContaining("run dependency-elider:elide");
  }

  @Test
  void validatesAppliedBanCoordinatesAndPolicyCorrespondence() throws IOException {
    final ObjectNode valid = appliedBanReport("example:drop", "example:drop:jar:1.0 (runtime)");
    final Path validPath = temporaryDirectory.resolve("valid-applied-ban.json");
    JSON.writeValue(validPath.toFile(), valid);

    final ObjectNode wrongFamily =
        appliedBanReport("example:drop", "example:other:jar:1.0 (runtime)");
    final Path wrongFamilyPath = temporaryDirectory.resolve("wrong-ban-family.json");
    JSON.writeValue(wrongFamilyPath.toFile(), wrongFamily);

    final ObjectNode unsupportedType =
        appliedBanReport("example:drop", "example:drop:zip:1.0 (runtime)");
    final Path unsupportedTypePath = temporaryDirectory.resolve("unsupported-ban-type.json");
    JSON.writeValue(unsupportedTypePath.toFile(), unsupportedType);

    final ObjectNode unsupportedScope =
        appliedBanReport("example:drop", "example:drop:jar:1.0 (test)");
    final Path unsupportedScopePath = temporaryDirectory.resolve("unsupported-ban-scope.json");
    JSON.writeValue(unsupportedScopePath.toFile(), unsupportedScope);

    final ObjectNode policyMismatch =
        appliedBanReport("example:drop", "example:drop:jar:1.0 (runtime)");
    policyMismatch.with("policy").putArray("banishedDependencies").add("example:other");
    final Path policyMismatchPath = temporaryDirectory.resolve("applied-ban-policy-mismatch.json");
    JSON.writeValue(policyMismatchPath.toFile(), policyMismatch);

    assertAll(
        "applied ban outcomes correspond exactly to normalized policy and supported GAVCE values",
        () -> MavenElisionReportPayloadValidator.validate(valid),
        () -> assertThat(valid.path("appliedBans")).hasSize(1),
        () -> assertInvalidAppliedBan(wrongFamilyPath, "G:A does not match its dependency"),
        () -> assertInvalidAppliedBan(unsupportedTypePath, "must be a compile/runtime JAR"),
        () -> assertInvalidAppliedBan(unsupportedScopePath, "must be a compile/runtime JAR"),
        () -> assertInvalidAppliedBan(policyMismatchPath, "do not match policy"));
  }

  @Test
  void rejectsAppliedBanThatDoesNotMatchWholeArtifactOutputDisposition() throws IOException {
    final ObjectNode missingDrop =
        appliedBanReport("example:drop", "example:drop:jar:1.0 (runtime)");
    missingDrop.withArray(DROPPED_ROWS).removeAll();
    final Path missingDropPath = temporaryDirectory.resolve("ban-without-drop.json");
    JSON.writeValue(missingDropPath.toFile(), missingDrop);

    final ObjectNode missingGraph =
        appliedBanReport("example:drop", "example:drop:jar:1.0 (runtime)");
    setGraph(missingGraph, MediatedGraphReport.unavailable("No graph was provided"));
    final Path missingGraphPath = temporaryDirectory.resolve("ban-without-graph.json");
    JSON.writeValue(missingGraphPath.toFile(), missingGraph);

    final ObjectNode retained = appliedBanReport("example:drop", "example:drop:jar:1.0 (runtime)");
    setGraph(
        retained,
        MediatedGraphBanReportTestSupport.droppedAndRetained(
            banArtifact("1.0", ""), banArtifact("1.0", ""), "example:consumer:1.0"));
    final Path retainedPath = temporaryDirectory.resolve("ban-also-retained.json");
    JSON.writeValue(retainedPath.toFile(), retained);

    final ObjectNode retainedPolicyOtherVersion =
        appliedBanReport("example:drop", "example:drop:jar:1.0 (runtime)");
    retainedPolicyOtherVersion
        .with("policy")
        .putArray("retainedArtifacts")
        .add("example:drop:2.0:jar:tests");
    final Path retainedPolicyPath =
        temporaryDirectory.resolve("ban-conflicts-with-retention-policy.json");
    JSON.writeValue(retainedPolicyPath.toFile(), retainedPolicyOtherVersion);

    final ObjectNode trimmed = appliedBanReport("example:drop", "example:drop:jar:1.0 (runtime)");
    trimmed
        .withArray("trimmedArtifacts")
        .addObject()
        .put("coordinate", "example:drop:jar:1.0 (runtime)")
        .put(TRIMMED_CLASSES, 0)
        .put(TRIMMED_CLASS_BYTES, 0);
    final Path trimmedPath = temporaryDirectory.resolve("ban-also-trimmed.json");
    JSON.writeValue(trimmedPath.toFile(), trimmed);

    assertAll(
        "forced absence agrees with every persisted artifact disposition",
        () -> assertInvalidAppliedBan(missingDropPath, "missing from droppedArtifacts"),
        () -> assertInvalidAppliedBan(missingGraphPath, "require an available mediated graph"),
        () ->
            assertInvalidAppliedBan(retainedPolicyPath, "conflicts with retained-artifact policy"),
        () -> assertInvalidAppliedBan(retainedPath, "also appears in retained or trimmed"),
        () -> assertInvalidAppliedBan(trimmedPath, "also appears in retained or trimmed"));
  }

  @Test
  void rejectsBanIdentityFamilyPresentInAnyPersistedOutputDisposition() throws IOException {
    final ObjectNode excludedWithOriginalAuditOnly = excludedBanReport("example:drop");
    final Path validExcludedPath =
        writeReport("valid-excluded-ban-original-audit.json", excludedWithOriginalAuditOnly);

    final ObjectNode forcedRetainedOtherVersion =
        appliedBanReport("example:drop", "example:drop:jar:1.0 (runtime)");
    setGraph(
        forcedRetainedOtherVersion,
        MediatedGraphBanReportTestSupport.droppedAndRetained(
            banArtifact("1.0", ""), banArtifact("2.0", "tests"), "example:consumer:1.0"));
    final Path forcedRetainedPath =
        writeReport("forced-ban-retained-other-version.json", forcedRetainedOtherVersion);

    final ObjectNode forcedTrimmedOtherVersion =
        appliedBanReport("example:drop", "example:drop:jar:1.0 (runtime)");
    addTrimmedArtifact(forcedTrimmedOtherVersion, "example:drop:jar:2.0:tests (runtime)");
    setGraph(
        forcedTrimmedOtherVersion,
        MediatedGraphBanReportTestSupport.droppedAndTrimmed(
            banArtifact("1.0", ""), banArtifact("2.0", "tests"), "example:consumer:1.0"));
    final Path forcedTrimmedPath =
        writeReport("forced-ban-trimmed-other-version.json", forcedTrimmedOtherVersion);

    final ObjectNode excludedRetained = excludedBanReport("example:drop");
    setGraph(
        excludedRetained,
        MediatedGraphBanReportTestSupport.retained(
            banArtifact("2.0", "tests"), "example:consumer:1.0"));
    final Path excludedRetainedPath =
        writeReport("excluded-ban-retained-output.json", excludedRetained);

    final ObjectNode excludedTrimmed = excludedBanReport("example:drop");
    addTrimmedArtifact(excludedTrimmed, "example:drop:jar:2.0:tests (runtime)");
    setGraph(
        excludedTrimmed,
        MediatedGraphBanReportTestSupport.trimmed(
            banArtifact("2.0", "tests"), "example:consumer:1.0"));
    final Path excludedTrimmedPath =
        writeReport("excluded-ban-trimmed-output.json", excludedTrimmed);

    assertAll(
        "ban status is consistent with the complete G:A output disposition",
        () -> MavenElisionReportWriter.read(validExcludedPath),
        () -> assertInvalidAppliedBan(forcedRetainedPath, "also appears in retained or trimmed"),
        () -> assertInvalidAppliedBan(forcedTrimmedPath, "also appears in retained or trimmed"),
        () ->
            assertInvalidAppliedBan(
                excludedRetainedPath,
                "Excluded-before-resolution ban appears in retained or trimmed"),
        () ->
            assertInvalidAppliedBan(
                excludedTrimmedPath,
                "Excluded-before-resolution ban appears in retained or trimmed"));
  }

  @Test
  void unmatchedBanMustBeAbsentFromEveryPersistedInventorySection() throws IOException {
    final ObjectNode valid = excludedBanReport("example:drop");
    markBanUnmatched(valid);
    final Path validPath = writeReport("valid-unmatched-ban.json", valid);
    final ObjectNode unavailableGraph = valid.deepCopy();
    setGraph(unavailableGraph, MediatedGraphReport.unavailable("No graph was provided"));
    final Path unavailableGraphPath =
        writeReport("valid-unmatched-ban-without-graph.json", unavailableGraph);
    final ObjectNode unrelated = valid.deepCopy();
    setGraph(
        unrelated,
        MediatedGraphBanReportTestSupport.retained(
            ArtifactCoordinate.of("example", "other", "1.0"), "example:consumer:1.0"));
    final Path unrelatedPath = writeReport("valid-unmatched-ban-unrelated-graph.json", unrelated);

    final ObjectNode retained = valid.deepCopy();
    setGraph(
        retained,
        MediatedGraphBanReportTestSupport.retained(
            banArtifact("2.0", "tests"), "example:consumer:1.0"));
    final Path retainedPath = writeReport("unmatched-ban-retained.json", retained);

    final ObjectNode dropped = appliedBanReport("example:drop", "example:drop:jar:1.0 (runtime)");
    markBanUnmatched(dropped);
    final Path droppedPath = writeReport("unmatched-ban-dropped.json", dropped);
    setGraph(dropped, MediatedGraphReport.unavailable("No graph was provided"));
    final Path droppedWithoutGraphPath =
        writeReport("unmatched-ban-dropped-without-graph.json", dropped);

    final ObjectNode trimmed = unavailableGraph.deepCopy();
    addTrimmedArtifact(trimmed, "example:drop:jar:2.0:tests (runtime)");
    final Path trimmedPath = writeReport("unmatched-ban-trimmed-without-graph.json", trimmed);

    final ObjectNode graphOnly = valid.deepCopy();
    setGraph(
        graphOnly,
        MediatedGraphBanReportTestSupport.dropped(banArtifact("1.0", ""), "example:consumer:1.0"));
    final Path graphOnlyPath = writeReport("unmatched-ban-elided-graph-node.json", graphOnly);

    assertAll(
        "unmatched requests cannot conceal any resolved G:A match, regardless of disposition",
        () -> MavenElisionReportWriter.read(validPath),
        () -> MavenElisionReportWriter.read(unavailableGraphPath),
        () -> MavenElisionReportWriter.read(unrelatedPath),
        () -> assertInvalidAppliedBan(retainedPath, "Unmatched ban appears"),
        () -> assertInvalidAppliedBan(droppedPath, "Unmatched ban appears"),
        () -> assertInvalidAppliedBan(droppedWithoutGraphPath, "Unmatched ban appears"),
        () -> assertInvalidAppliedBan(trimmedPath, "Unmatched ban appears"),
        () -> assertInvalidAppliedBan(graphOnlyPath, "Unmatched ban appears"));
  }

  private static void markBanUnmatched(final ObjectNode payload) {
    final ObjectNode ban = (ObjectNode) payload.withArray("appliedBans").get(0);
    ban.put("status", "UNMATCHED");
    ban.put("applied", false);
    ban.withArray("matchedArtifacts").removeAll();
    ban.withArray("originalArtifacts").removeAll();
  }

  private ObjectNode excludedBanReport(final String dependency) throws IOException {
    final ObjectNode payload = appliedBanReport(dependency, dependency + ":jar:1.0 (runtime)");
    payload.withArray(DROPPED_ROWS).removeAll();
    payload.put("wholeArtifactsDropped", 0);
    payload.put("originalJarBytesDropped", 0);
    payload.put("droppedProgramClassEntries", 0);
    payload.put("droppedProgramClassBytes", 0);
    final ObjectNode ban = (ObjectNode) payload.withArray("appliedBans").get(0);
    ban.put("status", "EXCLUDED_BEFORE_RESOLUTION");
    ban.withArray("matchedArtifacts").removeAll();
    setGraph(payload, MediatedGraphBanReportTestSupport.empty("example:consumer:1.0"));
    return payload;
  }

  private static void addTrimmedArtifact(final ObjectNode payload, final String coordinate) {
    payload
        .withArray("trimmedArtifacts")
        .addObject()
        .put("coordinate", coordinate)
        .put(TRIMMED_CLASSES, 0)
        .put(TRIMMED_CLASS_BYTES, 0);
  }

  private ObjectNode appliedBanReport(final String dependency, final String coordinate)
      throws IOException {
    final ObjectNode payload = currentReportShapeWithDroppedRow();
    payload.put("wholeArtifactsDropped", 1);
    payload.put("originalJarBytesDropped", 0);
    payload.put("droppedProgramClassEntries", 0);
    payload.put("droppedProgramClassBytes", 0);
    payload
        .putArray(DROPPED_ROWS)
        .removeAll()
        .addObject()
        .put("coordinate", coordinate)
        .put("originalJarBytes", 0)
        .put(DROPPED_CLASSES, 0)
        .put(DROPPED_CLASS_BYTES, 0);
    payload.with("policy").putArray("banishedDependencies").add(dependency);
    final ObjectNode ban = payload.putArray("appliedBans").addObject();
    ban.put("dependency", dependency);
    ban.put("status", "FORCED_ABSENT_AFTER_RESOLUTION");
    ban.putArray("matchedArtifacts").add(coordinate);
    ban.putArray("originalArtifacts").add(coordinate);
    ban.put("applied", true);
    setGraph(
        payload,
        MediatedGraphBanReportTestSupport.dropped(banArtifact("1.0", ""), "example:consumer:1.0"));
    return payload;
  }

  private static void setGraph(final ObjectNode payload, final MediatedGraphReport graph) {
    payload.set("mediatedGraph", JSON.valueToTree(graph));
  }

  private static ArtifactCoordinate banArtifact(final String version, final String classifier) {
    return new ArtifactCoordinate("example", "drop", version, "jar", classifier, "runtime");
  }

  private void assertInvalidAppliedBan(final Path path, final String message) {
    assertThatThrownBy(() -> MavenElisionReportWriter.read(path))
        .isInstanceOf(IOException.class)
        .hasMessageContaining(message);
  }

  @Test
  void rejectsNullDroppedArtifactClassMetrics() throws IOException {
    final ObjectNode payload = currentReportShapeWithDroppedRow();
    final ObjectNode row = (ObjectNode) payload.withArray(DROPPED_ROWS).get(0);
    row.putNull(DROPPED_CLASSES);
    row.putNull(DROPPED_CLASS_BYTES);
    final Path previous = temporaryDirectory.resolve("null-dropped-metrics.json");
    JSON.writeValue(previous.toFile(), payload);

    assertThatThrownBy(() -> MavenElisionReportWriter.read(previous))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Elision report artifact metric must be a nonnegative integer");
  }

  @Test
  void rejectsStringDroppedArtifactClassCount() throws IOException {
    final ObjectNode payload = currentReportShapeWithDroppedRow();
    final ObjectNode row = (ObjectNode) payload.withArray(DROPPED_ROWS).get(0);
    row.put(DROPPED_CLASSES, "0");
    row.put(DROPPED_CLASS_BYTES, 0);
    final Path previous = temporaryDirectory.resolve("wrong-type-dropped-metrics.json");
    JSON.writeValue(previous.toFile(), payload);

    assertThatThrownBy(() -> MavenElisionReportWriter.read(previous))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("nonnegative integer: programClassesRemoved");
  }

  @Test
  void rejectsOutOfRangeDroppedArtifactClassCount() throws IOException {
    final ObjectNode payload = currentReportShapeWithDroppedRow();
    final ObjectNode row = (ObjectNode) payload.withArray(DROPPED_ROWS).get(0);
    row.put(DROPPED_CLASSES, 2_147_483_648L);
    final Path previous = temporaryDirectory.resolve("out-of-range-dropped-count.json");
    JSON.writeValue(previous.toFile(), payload);

    assertThatThrownBy(() -> MavenElisionReportWriter.read(previous))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("nonnegative integer: programClassesRemoved");
  }

  @Test
  void rejectsNullTrimmedArtifactClassCount() throws IOException {
    final ObjectNode payload = currentReportShapeWithDroppedRow();
    final ObjectNode trimmed =
        payload
            .withArray("trimmedArtifacts")
            .addObject()
            .put("coordinate", "example:trimmed:jar:1.0")
            .put(TRIMMED_CLASSES, 1)
            .put(TRIMMED_CLASS_BYTES, 10);
    trimmed.putNull(TRIMMED_CLASSES);
    final Path previous = temporaryDirectory.resolve("null-trimmed-metric.json");
    JSON.writeValue(previous.toFile(), payload);

    assertThatThrownBy(() -> MavenElisionReportWriter.read(previous))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("nonnegative integer: programClassesPruned");
  }

  @Test
  void rejectsNonTextArtifactCoordinate() throws IOException {
    final ObjectNode payload = currentReportShapeWithDroppedRow();
    payload
        .withArray("trimmedArtifacts")
        .addObject()
        .put("coordinate", 7)
        .put(TRIMMED_CLASSES, 1)
        .put(TRIMMED_CLASS_BYTES, 10);
    final Path previous = temporaryDirectory.resolve("non-text-coordinate.json");
    JSON.writeValue(previous.toFile(), payload);

    assertThatThrownBy(() -> MavenElisionReportWriter.read(previous))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("artifact coordinate must be nonblank text");
  }

  @Test
  void rejectsNonBooleanSavedLayoutAssumption() throws IOException {
    final ObjectNode payload = currentReportShapeWithDroppedRow();
    payload.put("assumeConventionalJavaSourceLayout", "false");
    final Path previous = temporaryDirectory.resolve("invalid-layout-flag.json");
    JSON.writeValue(previous.toFile(), payload);

    assertThatThrownBy(() -> MavenElisionReportWriter.read(previous))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("layout assumption must be a JSON boolean");
  }

  @Test
  void rejectsDuplicateKeysAndTrailingReportDocuments() throws IOException {
    final Path duplicate = temporaryDirectory.resolve("duplicate-report-key.json");
    final Path duplicateSource = temporaryDirectory.resolve("duplicate-source-review-key.json");
    final Path trailing = temporaryDirectory.resolve("trailing-report-document.json");
    java.nio.file.Files.writeString(duplicate, "{\"schemaVersion\":1,\"schemaVersion\":1}");
    java.nio.file.Files.writeString(
        duplicateSource,
        "{\"sourceReviewFindings\":[{\"coordinate\":\"a\",\"coordinate\":\"b\"}]}");
    java.nio.file.Files.writeString(trailing, "{\"schemaVersion\":1} {}");

    assertAll(
        () ->
            assertThatThrownBy(() -> MavenElisionReportWriter.read(duplicate))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("Duplicate field 'schemaVersion'"),
        () ->
            assertThatThrownBy(() -> MavenElisionReportWriter.read(duplicateSource))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("Duplicate field 'coordinate'"),
        () ->
            assertThatThrownBy(() -> MavenElisionReportWriter.read(trailing))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("Trailing data in elision report"));
  }

  private Path writeReport(final String name, final ObjectNode payload) throws IOException {
    final Path report = temporaryDirectory.resolve(name);
    JSON.writeValue(report.toFile(), payload);
    return report;
  }

  private static ObjectNode executionEnvironment(final ObjectNode payload) {
    return (ObjectNode) payload.get("executionEnvironment");
  }

  private void assertInvalidEnvironment(
      final String name, final ObjectNode payload, final String diagnostic) throws IOException {
    final Path report = writeReport(name, payload);
    assertThatThrownBy(() -> MavenElisionReportWriter.read(report))
        .isInstanceOf(IOException.class)
        .hasMessageContaining(diagnostic);
  }

  static ObjectNode currentReportShapeWithDroppedRow() {
    final ObjectNode payload = JSON.createObjectNode();
    payload.put("schemaVersion", 1);
    payload.put("projectGroupId", "example");
    payload.put("projectArtifactId", "consumer");
    payload.put("projectVersion", "1.0");
    payload.put("projectBaseDirectory", "/tmp/consumer");
    payload.put("generatedAt", "2026-10-28T00:00:00Z");
    payload.put("wholeArtifactsDropped", 1);
    payload.put("originalJarBytesDropped", 1);
    payload.put("droppedProgramClassEntries", 0);
    payload.put("droppedProgramClassBytes", 0);
    payload
        .putArray(DROPPED_ROWS)
        .addObject()
        .put("coordinate", "example:old:jar:1.0 (compile)")
        .put("originalJarBytes", 1)
        .put(DROPPED_CLASSES, 0)
        .put(DROPPED_CLASS_BYTES, 0);
    payload.putArray("rawDroppedCoordinates");
    payload.put("programClassesPruned", 0);
    payload.put("uncompressedProgramClassBytesPruned", 0);
    payload.putObject("executionEnvironment").put("targetRelease", 11).put("runtimeRelease", 25);
    payload.putArray("trimmedArtifacts");
    payload.put("assumeConventionalJavaSourceLayout", false);
    final ObjectNode policy = payload.putObject("policy");
    policy.putArray("retainedArtifacts");
    policy.putArray("banishedDependencies");
    policy.put("operationFingerprint", MavenElisionGraphBinding.sha256(List.of()));
    payload.putArray("genericFindings");
    payload.putArray("sourceObservations");
    payload.set(
        "exclusionReview",
        JSON.valueToTree(
            ExclusionReview.unavailable("No pre-injection declaration capture is available")));
    payload.putArray("appliedBans");
    payload.putArray("toleratedDuplicates");
    final ObjectNode graph = payload.putObject("mediatedGraph");
    graph.put("available", false);
    graph.put("unavailableReason", "No graph was provided");
    graph.putNull("captureToken");
    graph.putNull("projectKey");
    graph.putNull("beforeFingerprint");
    graph.putNull("snapshot");
    graph.putArray("nodeStatuses");
    graph.putArray("artifactPaths");
    return payload;
  }
}
