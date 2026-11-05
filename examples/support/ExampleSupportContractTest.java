// WHY: Guards the example report verifier against JSON type coercion regressions.

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.stream.Stream;

public final class ExampleSupportContractTest {
  private static final ObjectMapper JSON = new ObjectMapper();

  private ExampleSupportContractTest() {}

  public static void main(final String[] arguments) throws Exception {
    rejectsRelativePath();
    verifiesReactorReportMetricComparison();
    final Path productionOutput = Files.createTempDirectory("example-support-contract-").toRealPath();
    try {
      final ObjectNode nonBoolean = report(productionOutput);
      nonBoolean.put("staticEvidenceAvailable", "true");
      rejects(nonBoolean, productionOutput, "boolean");

      final ObjectNode nonStringPath = report(productionOutput);
      nonStringPath.put("productionOutput", 17);
      rejects(nonStringPath, productionOutput, "JSON string");

      final ObjectNode nonStringClass = report(productionOutput);
      ((ArrayNode) nonStringClass.path("runtimeObservedClasses")).add(17);
      rejects(nonStringClass, productionOutput, "class name to be a JSON string");

      final ObjectNode malformedPrediction = report(productionOutput);
      malformedPrediction.putObject("dependencyPrediction").put("provenance", "unknown");
      rejects(malformedPrediction, productionOutput, "provenance is unsupported");

      final ObjectNode malformedPredictionCoordinates = report(productionOutput);
      final ObjectNode prediction = prediction(malformedPredictionCoordinates);
      prediction.putArray("retainedArtifacts").add(17);
      prediction.putArray("wouldElideArtifacts");
      prediction.putArray("plannedClassRemovals");
      rejects(
          malformedPredictionCoordinates,
          productionOutput,
          "coordinates must be non-empty strings");

      final ObjectNode nonCanonicalPlannedRemovals = report(productionOutput);
      final ObjectNode plannedPrediction = prediction(nonCanonicalPlannedRemovals);
      plannedPrediction.putArray("retainedArtifacts").add("org.example:library:jar:1.0 (compile)");
      plannedPrediction.putArray("wouldElideArtifacts");
      final ObjectNode planned = plannedPrediction.putArray("plannedClassRemovals").addObject();
      planned.put("status", "PLANNED_UNVERIFIED");
      planned.put("coordinate", "org.example:library:jar:1.0 (compile)");
      planned.putArray("classes").add("z.Last").add("a.First");
      rejects(nonCanonicalPlannedRemovals, productionOutput, "classes are not canonical");

      final ObjectNode malformedCanonicalCoordinate = report(productionOutput);
      final ObjectNode canonicalPrediction = prediction(malformedCanonicalCoordinate);
      canonicalPrediction.putArray("retainedArtifacts").add("org.example:library:jar:1.0");
      canonicalPrediction.putArray("wouldElideArtifacts");
      canonicalPrediction.putArray("plannedClassRemovals");
      rejects(malformedCanonicalCoordinate, productionOutput, "coordinate is not canonical");

      final ObjectNode duplicateCoordinate = report(productionOutput);
      final ObjectNode duplicatePrediction = prediction(duplicateCoordinate);
      duplicatePrediction
          .putArray("retainedArtifacts")
          .add("org.example:library:jar:1.0 (compile)")
          .add("org.example:library:jar:1.0 (compile)");
      duplicatePrediction.putArray("wouldElideArtifacts");
      duplicatePrediction.putArray("plannedClassRemovals");
      rejects(duplicateCoordinate, productionOutput, "coordinates are not canonical");

      final ObjectNode overlapCoordinate = report(productionOutput);
      final ObjectNode overlapPrediction = prediction(overlapCoordinate);
      overlapPrediction.putArray("retainedArtifacts").add("org.example:library:jar:1.0 (compile)");
      overlapPrediction.putArray("wouldElideArtifacts").add("org.example:library:jar:1.0 (compile)");
      overlapPrediction.putArray("plannedClassRemovals");
      rejects(overlapCoordinate, productionOutput, "coordinates overlap");

      final ObjectNode plannedElidedCoordinate = report(productionOutput);
      final ObjectNode plannedElidedPrediction = prediction(plannedElidedCoordinate);
      plannedElidedPrediction.putArray("retainedArtifacts");
      plannedElidedPrediction
          .putArray("wouldElideArtifacts")
          .add("org.example:library:jar:1.0 (compile)");
      final ObjectNode plannedElided =
          plannedElidedPrediction.putArray("plannedClassRemovals").addObject();
      plannedElided.put("status", "PLANNED_UNVERIFIED");
      plannedElided.put("coordinate", "org.example:library:jar:1.0 (compile)");
      plannedElided.putArray("classes").add("example.Removed");
      rejects(
          plannedElidedCoordinate,
          productionOutput,
          "must reference a retained artifact");

      ExampleSupport.validateClassUsageReport(reportWithValidPrediction(productionOutput), productionOutput);
      verifiesBanPlanValidation(productionOutput);
      verifiesExclusionReviewValidation(productionOutput);
      verifiesGenericFindingReportValidation();
    } finally {
      Files.deleteIfExists(productionOutput);
    }
  }

  private static void verifiesExclusionReviewValidation(final Path productionOutput)
      throws IOException {
    final ObjectNode unavailable = reportWithValidPrediction(productionOutput);
    ExampleSupport.validateClassUsageReport(unavailable, productionOutput);

    final ObjectNode missing = unavailable.deepCopy();
    missing.remove("exclusionReview");
    ExampleSupport.validateClassUsageReport(missing, productionOutput);

    final ObjectNode malformed = unavailable.deepCopy();
    ((ObjectNode) malformed.path("exclusionReview")).put("available", "false");
    rejects(malformed, productionOutput, "Invalid exclusionReview payload");

    final ObjectNode extraField = unavailable.deepCopy();
    ((ObjectNode) extraField.path("exclusionReview")).put("unexpected", true);
    rejects(extraField, productionOutput, "Invalid exclusionReview payload");

    final ObjectNode missingReason = unavailable.deepCopy();
    ((ObjectNode) missingReason.path("exclusionReview")).put("unavailableReason", "");
    rejects(missingReason, productionOutput, "Invalid exclusionReview payload");

    final ObjectNode available = reportWithValidPrediction(productionOutput);
    available.set("exclusionReview", availableReview());
    ExampleSupport.validateClassUsageReport(available, productionOutput);

    final ObjectNode tamperedCount = available.deepCopy();
    ((ObjectNode) tamperedCount.path("exclusionReview").path("candidates").get(0))
        .put("count", 3);
    rejects(tamperedCount, productionOutput, "findings do not match their frozen snapshot");

    final ObjectNode repeatedOrdinal = available.deepCopy();
    ((ObjectNode)
            repeatedOrdinal.path("exclusionReview").path("snapshot").path("dependencies").get(1))
        .put("ordinal", 0);
    ((ObjectNode)
            repeatedOrdinal
                .path("exclusionReview")
                .path("candidates")
                .get(0)
                .path("declarations")
                .get(1)
                .path("declaration"))
        .put("ordinal", 0);
    rejects(repeatedOrdinal, productionOutput, "declaration ordinals are not canonical");
  }

  private static void verifiesGenericFindingReportValidation() throws IOException {
    final ObjectNode report = JSON.createObjectNode();
    final ObjectNode finding = report.putArray("genericFindings").addObject();
    finding.put("vulnerabilityId", "CVE-2026-10001");
    finding.put("applicability", "AFFECTED");
    finding.put("outcome", "DECLARED_CODE_ABSENT");
    finding.put("inventoryDisposition", "RETAINED_AND_TRIMMED");
    finding.put("detail", "All declared vulnerable classes were absent from the trimmed artifact.");
    final ObjectNode coordinate = finding.putObject("candidate");
    coordinate.put("groupId", "org.example");
    coordinate.put("artifactId", "library");
    coordinate.put("version", "1.2.3");
    coordinate.put("type", "jar");
    coordinate.put("classifier", "");
    coordinate.put("scope", "compile");
    report.putArray("sourceObservations");

    ExampleSupport.validateGenericFindingReport(report);

    final ObjectNode missingRows = JSON.createObjectNode();
    missingRows.putArray("sourceObservations");
    rejectsGenericFindingReport(missingRows, "genericFindings must be an array");

    final ObjectNode invalidOutcome = report.deepCopy();
    ((ObjectNode) invalidOutcome.path("genericFindings").get(0)).put("outcome", "MITIGATED");
    rejectsGenericFindingReport(invalidOutcome, "finding outcome is unsupported");

    final ObjectNode incompleteCoordinate = report.deepCopy();
    ((ObjectNode) incompleteCoordinate.path("genericFindings").get(0).path("candidate"))
        .remove("version");
    rejectsGenericFindingReport(incompleteCoordinate, "candidate coordinate is incomplete");
  }

  private static void rejectsGenericFindingReport(final JsonNode report, final String expected)
      throws IOException {
    try {
      ExampleSupport.validateGenericFindingReport(report);
    } catch (final IOException exception) {
      if (exception.getMessage().contains(expected)) {
        return;
      }
      throw new AssertionError("Unexpected generic report validation error", exception);
    }
    throw new AssertionError("Malformed generic finding report was accepted: " + report);
  }

  private static ObjectNode availableReview() {
    final ObjectNode review = JSON.createObjectNode();
    review.put("available", true);
    review.put("unavailableReason", "");
    final ObjectNode snapshot = review.putObject("snapshot");
    final ArrayNode dependencies = snapshot.putArray("dependencies");
    final ObjectNode origin = JSON.createObjectNode();
    origin.put("kind", "LOCAL");
    origin.put("modelId", "example:consumer:1");
    origin.put("source", "pom.xml");
    origin.put("line", 5);
    origin.put("column", 3);
    origin.put("profileId", "");
    final ArrayNode observations = JSON.createArrayNode();
    for (int ordinal = 0; ordinal < 2; ordinal++) {
      final ObjectNode declaration = dependencies.addObject();
      declaration.put("ordinal", ordinal);
      declaration.put("groupId", "example");
      declaration.put("artifactId", "source-" + ordinal);
      declaration.put("type", "jar");
      declaration.put("classifier", "");
      declaration.set("origin", origin.deepCopy());
      final ObjectNode exclusion = declaration.putArray("exclusions").addObject();
      exclusion.put("groupId", "unused");
      exclusion.put("artifactId", "library");
      exclusion.set("origin", origin.deepCopy());

      final ObjectNode observation = observations.addObject();
      final ObjectNode reference = observation.putObject("declaration");
      reference.put("ordinal", ordinal);
      reference.put("groupId", "example");
      reference.put("artifactId", "source-" + ordinal);
      reference.put("type", "jar");
      reference.put("classifier", "");
      reference.set("origin", origin.deepCopy());
      observation.putArray("exclusionOrigins").add(origin.deepCopy());
    }
    final ObjectNode managementOrigin = origin.deepCopy();
    managementOrigin.put("line", 8);
    final ObjectNode managed = snapshot.putArray("management").addObject();
    managed.put("ordinal", 0);
    managed.put("groupId", "example");
    managed.put("artifactId", "managed");
    managed.put("type", "jar");
    managed.put("classifier", "");
    managed.set("origin", managementOrigin.deepCopy());
    final ObjectNode managedExclusion = managed.putArray("exclusions").addObject();
    managedExclusion.put("groupId", "other");
    managedExclusion.put("artifactId", "library");
    managedExclusion.set("origin", managementOrigin.deepCopy());
    snapshot.putObject("activeProfiles");
    snapshot.putArray("diagnostics");
    final ObjectNode candidate = review.putArray("candidates").addObject();
    final ObjectNode coordinate = candidate.putObject("coordinate");
    coordinate.put("groupId", "unused");
    coordinate.put("artifactId", "library");
    candidate.put("count", 2);
    candidate.set("declarations", observations);
    final ObjectNode managementRow = review.putArray("management").addObject();
    final ObjectNode managementReference = managementRow.putObject("reference");
    managementReference.put("ordinal", 0);
    managementReference.put("groupId", "example");
    managementReference.put("artifactId", "managed");
    managementReference.put("type", "jar");
    managementReference.put("classifier", "");
    managementReference.set("origin", managementOrigin.deepCopy());
    final ObjectNode managementExclusion = managementRow.putArray("exclusions").addObject();
    final ObjectNode managementCoordinate = managementExclusion.putObject("coordinate");
    managementCoordinate.put("groupId", "other");
    managementCoordinate.put("artifactId", "library");
    managementExclusion.set("origin", managementOrigin.deepCopy());
    return review;
  }

  private static void verifiesBanPlanValidation(final Path productionOutput) throws IOException {
    final ObjectNode valid = reportWithValidPrediction(productionOutput);
    final ObjectNode prediction = (ObjectNode) valid.path("dependencyPrediction");
    prediction.put("banContextFingerprint", "d".repeat(64));
    final ArrayNode rows = prediction.putArray("banPlan");
    final ObjectNode unmatched = rows.addObject();
    unmatched.put("dependency", "org.example:missing");
    unmatched.put("status", "UNMATCHED");
    unmatched.putArray("matchedArtifacts");
    unmatched.putArray("originalArtifacts");
    unmatched.put("applied", false);
    final ObjectNode matched = rows.addObject();
    matched.put("dependency", "org.example:unused");
    matched.put("status", "FORCED_ABSENT_AFTER_RESOLUTION");
    matched.putArray("matchedArtifacts").add("org.example:unused:jar:2.0 (runtime)");
    matched.putArray("originalArtifacts").add("org.example:unused:jar:2.0 (runtime)");
    matched.put("applied", false);
    ExampleSupport.validateClassUsageReport(valid, productionOutput);

    final ObjectNode excluded = valid.deepCopy();
    final ObjectNode excludedRow =
        (ObjectNode) excluded.path("dependencyPrediction").path("banPlan").get(0);
    excludedRow.put("status", "EXCLUDED_BEFORE_RESOLUTION");
    excludedRow
        .putArray("originalArtifacts")
        .add("org.example:missing:jar:3.0 (runtime)");
    ExampleSupport.validateClassUsageReport(excluded, productionOutput);

    final ObjectNode missingPlan = valid.deepCopy();
    ((ObjectNode) missingPlan.path("dependencyPrediction")).remove("banPlan");
    rejects(missingPlan, productionOutput, "ban context and plan must appear together");

    final ObjectNode missingContext = valid.deepCopy();
    ((ObjectNode) missingContext.path("dependencyPrediction")).remove("banContextFingerprint");
    rejects(missingContext, productionOutput, "ban context and plan must appear together");

    final ObjectNode malformedContext = valid.deepCopy();
    ((ObjectNode) malformedContext.path("dependencyPrediction"))
        .put("banContextFingerprint", "bad");
    rejects(malformedContext, productionOutput, "banContextFingerprint must be a SHA-256");

    final ObjectNode capturedPlan = valid.deepCopy();
    ((ObjectNode) capturedPlan.path("dependencyPrediction"))
        .put("provenance", "CAPTURED_EFFECTIVE_RESOLVER");
    ExampleSupport.validateClassUsageReport(capturedPlan, productionOutput);

    final ObjectNode appliedPlan = valid.deepCopy();
    ((ObjectNode) appliedPlan.path("dependencyPrediction").path("banPlan").get(1))
        .put("applied", true);
    rejects(appliedPlan, productionOutput, "ban plan applied must be false");

    final ObjectNode coercedApplied = valid.deepCopy();
    ((ObjectNode) coercedApplied.path("dependencyPrediction").path("banPlan").get(1))
        .put("applied", "false");
    rejects(coercedApplied, productionOutput, "ban plan applied must be false");

    final ObjectNode unsupportedStatus = valid.deepCopy();
    ((ObjectNode) unsupportedStatus.path("dependencyPrediction").path("banPlan").get(1))
        .put("status", "APPLIED");
    rejects(unsupportedStatus, productionOutput, "ban plan status is unsupported");

    final ObjectNode unmatchedWithArtifacts = valid.deepCopy();
    ((ObjectNode) unmatchedWithArtifacts.path("dependencyPrediction").path("banPlan").get(0))
        .putArray("matchedArtifacts")
        .add("org.example:unused:jar:2.0 (runtime)");
    rejects(unmatchedWithArtifacts, productionOutput, "matched artifact has another identity");

    final ObjectNode retainedMatch = valid.deepCopy();
    ((ObjectNode) retainedMatch.path("dependencyPrediction").path("banPlan").get(1))
        .putArray("matchedArtifacts")
        .add("org.example:library:jar:1.0 (compile)");
    rejects(retainedMatch, productionOutput, "matched artifact has another identity");

    final ObjectNode unsupportedType = valid.deepCopy();
    ((ObjectNode) unsupportedType.path("dependencyPrediction"))
        .putArray("wouldElideArtifacts")
        .add("org.example:unused:pom:2.0 (runtime)");
    ((ObjectNode) unsupportedType.path("dependencyPrediction").path("banPlan").get(1))
        .putArray("matchedArtifacts")
        .add("org.example:unused:pom:2.0 (runtime)");
    rejects(unsupportedType, productionOutput, "must be a compile/runtime JAR");

    final ObjectNode unsupportedScope = valid.deepCopy();
    ((ObjectNode) unsupportedScope.path("dependencyPrediction"))
        .putArray("wouldElideArtifacts")
        .add("org.example:unused:jar:2.0 (test)");
    ((ObjectNode) unsupportedScope.path("dependencyPrediction").path("banPlan").get(1))
        .putArray("matchedArtifacts")
        .add("org.example:unused:jar:2.0 (test)");
    rejects(unsupportedScope, productionOutput, "must be a compile/runtime JAR");

    final ObjectNode unlistedMatch = valid.deepCopy();
    ((ObjectNode) unlistedMatch.path("dependencyPrediction").path("banPlan").get(1))
        .putArray("matchedArtifacts");
    rejects(unlistedMatch, productionOutput, "ban plan status disagrees with matches");

    final ObjectNode incompleteMatches = valid.deepCopy();
    ((ObjectNode) incompleteMatches.path("dependencyPrediction"))
        .withArray("wouldElideArtifacts")
        .add("org.example:unused:jar:3.0 (runtime)");
    rejects(incompleteMatches, productionOutput, "matches disagree with artifact inventory");

    final ObjectNode falseStatus = valid.deepCopy();
    ((ObjectNode) falseStatus.path("dependencyPrediction").path("banPlan").get(1))
        .put("status", "UNMATCHED");
    rejects(falseStatus, productionOutput, "ban plan status disagrees with matches");

    final ObjectNode excludedWithoutOriginal = excluded.deepCopy();
    ((ObjectNode) excludedWithoutOriginal.path("dependencyPrediction").path("banPlan").get(0))
        .putArray("originalArtifacts");
    rejects(
        excludedWithoutOriginal,
        productionOutput,
        "ban plan status disagrees with matches");

    final ObjectNode wrongDisposition = valid.deepCopy();
    ((ObjectNode) wrongDisposition.path("dependencyPrediction"))
        .putArray("wouldElideArtifacts");
    rejects(wrongDisposition, productionOutput, "must be in wouldElideArtifacts");

    final ObjectNode reversedRows = valid.deepCopy();
    final ArrayNode reversed =
        ((ObjectNode) reversedRows.path("dependencyPrediction")).putArray("banPlan");
    reversed.add(matched.deepCopy());
    reversed.add(unmatched.deepCopy());
    rejects(reversedRows, productionOutput, "ban plan rows are not canonical");
  }

  private static void verifiesReactorReportMetricComparison() throws Exception {
    final Path root = Files.createTempDirectory("example-reactor-contract-").toRealPath();
    final Path sequential = Files.createDirectories(root.resolve("sequential"));
    final Path threaded = Files.createDirectories(root.resolve("threaded"));
    try {
      for (final String module : new String[] {"reactor-common", "reactor-service", "reactor-app"}) {
        final Path moduleDirectory = Files.createDirectories(root.resolve(module));
        Files.writeString(
            sequential.resolve(module + ".json"),
            JSON.writeValueAsString(reactorReport(module, moduleDirectory)));
        Files.writeString(
            threaded.resolve(module + ".json"),
            JSON.writeValueAsString(reactorReport(module, moduleDirectory)));
      }
      final String[] arguments = {
        "verify-reactor-reports", sequential.toString(), threaded.toString(), root.toString()
      };
      ExampleSupport.main(arguments);

      final Path changedReport = threaded.resolve("reactor-service.json");
      final ObjectNode changed = (ObjectNode) JSON.readTree(changedReport.toFile());
      changed.put("programClassesPruned", 1);
      JSON.writeValue(changedReport.toFile(), changed);
      try {
        ExampleSupport.main(arguments);
      } catch (final IOException exception) {
        if (exception.getMessage().contains("metrics differ")) {
          return;
        }
        throw new AssertionError("Unexpected reactor comparison rejection", exception);
      }
      throw new AssertionError("Reactor report comparison accepted a changed class metric");
    } finally {
      try (Stream<Path> paths = Files.walk(root)) {
        for (final Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
          Files.deleteIfExists(path);
        }
      }
    }
  }

  private static ObjectNode reactorReport(final String module, final Path moduleDirectory) {
    final ObjectNode report = JSON.createObjectNode();
    report.put("schemaVersion", 1);
    report.put("projectGroupId", "io.github.spockz");
    report.put("projectArtifactId", module);
    report.put("projectVersion", "0.1.0-SNAPSHOT");
    report.put("projectBaseDirectory", moduleDirectory.toString());
    report.put("generatedAt", "2026-10-29T00:00:00Z");
    final boolean common = "reactor-common".equals(module);
    report.put("wholeArtifactsDropped", common ? 1 : 0);
    report.put("originalJarBytesDropped", common ? 10 : 0);
    report.put("droppedProgramClassEntries", common ? 1 : 0);
    report.put("droppedProgramClassBytes", common ? 5 : 0);
    report.put("programClassesPruned", common ? 1 : 0);
    report.put("uncompressedProgramClassBytesPruned", common ? 20 : 0);
    final var droppedArtifacts = report.putArray("droppedArtifacts");
    if (common) {
      final ObjectNode dropped = droppedArtifacts.addObject();
      dropped.put("coordinate", "commons-codec:commons-codec:jar:1.19.0");
      dropped.put("originalJarBytes", 10);
      dropped.put("programClassesRemoved", 1);
      dropped.put("uncompressedProgramClassBytesRemoved", 5);
    }
    report.putArray("rawDroppedCoordinates").add("commons-codec:commons-codec:jar:1.19.0");
    final var trimmedArtifacts = report.putArray("trimmedArtifacts");
    if (common) {
      final ObjectNode trimmed = trimmedArtifacts.addObject();
      trimmed.put("coordinate", "org.apache.commons:commons-compress:jar:1.28.0");
      trimmed.put("programClassesPruned", 1);
      trimmed.put("uncompressedProgramClassBytesPruned", 20);
    }
    report.putObject("mediatedGraph").put("available", true);
    return report;
  }

  private static void rejectsRelativePath() throws IOException {
    try {
      ExampleSupport.requireAbsolutePath("target/report.json", "REPORT");
    } catch (final IOException exception) {
      if (exception.getMessage().contains("must be absolute")) {
        return;
      }
      throw new AssertionError("Unexpected relative-path validation error", exception);
    }
    throw new AssertionError("Relative helper path was accepted");
  }

  private static ObjectNode report(final Path productionOutput) {
    final ObjectNode report = JSON.createObjectNode();
    report.put("staticEvidenceAvailable", true);
    report.put("productionOutput", productionOutput.toString());
    final ObjectNode groups = report.putObject("groups");
    groups.putArray("neitherReferencedNorObserved");
    groups.putArray("runtimeObservedWithoutApplicationReference");
    groups.putArray("applicationReferenced");
    report.putArray("runtimeObservedClasses");
    final ObjectNode review = report.putObject("exclusionReview");
    review.put("available", false);
    review.put("unavailableReason", "No pre-injection declaration capture is available");
    review.putNull("snapshot");
    review.putArray("candidates");
    review.putArray("management");
    return report;
  }

  private static ObjectNode prediction(final ObjectNode report) {
    final ObjectNode prediction = report.putObject("dependencyPrediction");
    prediction.put("provenance", "DETACHED_CURRENT_MODEL");
    prediction.put("environmentFingerprint", "c".repeat(64));
    prediction.put("inventoryFingerprint", "a".repeat(64));
    prediction.put("operationFingerprint", "b".repeat(64));
    return prediction;
  }

  private static ObjectNode reportWithValidPrediction(final Path productionOutput) {
    final ObjectNode report = report(productionOutput);
    final ObjectNode groups = (ObjectNode) report.path("groups");
    groups
        .putArray("runtimeObservedWithoutApplicationReference")
        .add("jakarta.mail.Session");
    report.putArray("runtimeObservedClasses").add("jakarta.mail.Session");
    groups
        .putArray("neitherReferencedNorObserved")
        .add("org.apache.commons.codec.binary.Hex");
    final ObjectNode prediction = prediction(report);
    prediction
        .putArray("retainedArtifacts")
        .add("org.example:library:jar:1.0 (compile)")
        .add("org.example:library:jar:tests:1.0 (compile)")
        .add("org.example:library:jar:2.0 (compile)");
    prediction.putArray("wouldElideArtifacts").add("org.example:unused:jar:2.0 (runtime)");
    final ArrayNode plannedRows = prediction.putArray("plannedClassRemovals");
    plannedRow(plannedRows, "org.example:library:jar:1.0 (compile)", "example.Removed");
    plannedRow(plannedRows, "org.example:library:jar:tests:1.0 (compile)", "example.TestsRemoved");
    plannedRow(plannedRows, "org.example:library:jar:2.0 (compile)", "example.NewerRemoved");
    return report;
  }

  private static void plannedRow(
      final ArrayNode rows, final String coordinate, final String className) {
    final ObjectNode planned = rows.addObject();
    planned.put("status", "PLANNED_UNVERIFIED");
    planned.put("coordinate", coordinate);
    planned.putArray("classes").add(className);
  }

  private static void rejects(
      final JsonNode report, final Path productionOutput, final String expectedMessage)
      throws IOException {
    try {
      ExampleSupport.validateClassUsageReport(report, productionOutput);
    } catch (final IOException exception) {
      if (exception.getMessage().contains(expectedMessage)) {
        return;
      }
      throw new AssertionError("Unexpected validation error: " + exception.getMessage(), exception);
    }
    throw new AssertionError("Malformed report was accepted: " + report);
  }
}
