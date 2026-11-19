// WHY: Guards the example report verifier against JSON type coercion regressions.

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;

public final class ExampleSupportContractTest {
  private static final ObjectMapper JSON = new ObjectMapper();

  private ExampleSupportContractTest() {}

  public static void main(final String[] arguments) throws Exception {
    rejectsRelativePath();
    verifiesReactorReportMetricComparison();
    verifiesRawCandidatesCanBeRetainedByGraphSafety();
    verifiesSpringExpectedWholeArtifactDrop();
    verifiesSpringSnakeyamlCandidateCanBeRetainedByGraphSafety();
    verifiesSharedCatalogExampleWiring();
    verifiesRemovedCveDependencyDoesNotClaimAbsence();
    verifiesCveUnusedExpectedWholeArtifactDrop();
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

  private static void verifiesSpringExpectedWholeArtifactDrop() throws Exception {
    final Path reportPath = Files.createTempFile("example-spring-drop-", ".json");
    try {
      final ObjectNode report = JSON.createObjectNode();
      final ArrayNode drops = report.putArray("droppedArtifacts");
      drops.addObject()
          .put("coordinate", "commons-codec:commons-codec:jar:1.21.0 (compile)")
          .put("programClassesRemoved", 109);
      drops.addObject()
          .put("coordinate", "at.yawk.lz4:lz4-java:jar:1.10.1 (runtime)")
          .put("programClassesRemoved", 52);
      drops.addObject()
          .put("coordinate", "com.github.luben:zstd-jni:jar:1.5.7-18 (runtime)")
          .put("programClassesRemoved", 43);
      Files.writeString(reportPath, JSON.writeValueAsString(report));
      ExampleSupport.main(new String[] {"verify-spring-expected-drop", reportPath.toString()});

      ((ObjectNode) report.withArray("droppedArtifacts").get(0))
          .put("coordinate", "org.yaml:snakeyaml:jar:2.6 (compile)");
      Files.writeString(reportPath, JSON.writeValueAsString(report));
      try {
        ExampleSupport.main(new String[] {"verify-spring-expected-drop", reportPath.toString()});
      } catch (final IOException exception) {
        if (exception.getMessage().contains("Unexpected Spring fixture artifact drop:")) {
          return;
        }
        throw new AssertionError("Unexpected Spring drop rejection", exception);
      }
      throw new AssertionError("Spring verifier accepted an unexpected whole-artifact drop");
    } finally {
      Files.deleteIfExists(reportPath);
    }
  }

  private static void verifiesSpringSnakeyamlCandidateCanBeRetainedByGraphSafety()
      throws Exception {
    final Path reportPath = Files.createTempFile("example-spring-snakeyaml-", ".json");
    try {
      final ObjectNode report = JSON.createObjectNode();
      report
          .putArray("rawDroppedCoordinates")
          .add("org.yaml:snakeyaml:jar:2.2 (compile)");
      report.putArray("droppedArtifacts");
      final ObjectNode trim = report.putArray("trimmedArtifacts").addObject();
      trim.put("coordinate", "org.yaml:snakeyaml:jar:2.2 (compile)");
      trim.put("mrjarStatus", "elevated_and_trimmed");
      final ObjectNode graph = report.putObject("mediatedGraph");
      final ObjectNode snapshot = graph.putObject("snapshot");
      final ObjectNode node = snapshot.putArray("nodes").addObject();
      node.put("id", "n1");
      node.put("version", "2.2");
      node.putObject("artifact")
          .put("groupId", "org.yaml")
          .put("artifactId", "snakeyaml")
          .put("version", "2.2");
      node.putObject("dependency").put("scope", "compile");
      graph
          .putArray("nodeStatuses")
          .addObject()
          .put("nodeId", "n1")
          .put("disposition", "RETAINED");
      Files.writeString(reportPath, JSON.writeValueAsString(report));
      ExampleSupport.main(
          new String[] {"verify-spring-snakeyaml-retained", reportPath.toString()});

      trim.put("mrjarStatus", "classpath-only");
      Files.writeString(reportPath, JSON.writeValueAsString(report));
      boolean rejectedInvalidMrjarStatus = false;
      try {
        ExampleSupport.main(
            new String[] {"verify-spring-snakeyaml-retained", reportPath.toString()});
      } catch (final IOException exception) {
        if (exception.getMessage().contains("elevated and trimmed MRJAR status")) {
          rejectedInvalidMrjarStatus = true;
        } else {
          throw new AssertionError("Unexpected SnakeYAML MRJAR status rejection", exception);
        }
      }
      if (!rejectedInvalidMrjarStatus) {
        throw new AssertionError("SnakeYAML verifier accepted a missing elevation result");
      }
      trim.put("mrjarStatus", "elevated_and_trimmed");

      ((ObjectNode) graph.withArray("nodeStatuses").get(0)).put("disposition", "SAFE_ELIDED");
      Files.writeString(reportPath, JSON.writeValueAsString(report));
      try {
        ExampleSupport.main(
            new String[] {"verify-spring-snakeyaml-retained", reportPath.toString()});
      } catch (final IOException exception) {
        if (exception.getMessage().contains("must remain retained by graph safety")) {
          return;
        }
        throw new AssertionError("Unexpected SnakeYAML graph-safety rejection", exception);
      }
      throw new AssertionError("Spring verifier accepted an elided raw SnakeYAML candidate");
    } finally {
      Files.deleteIfExists(reportPath);
    }
  }

  private static void verifiesRawCandidatesCanBeRetainedByGraphSafety() throws Exception {
    final Path reportPath = Files.createTempFile("example-raw-candidate-", ".json");
    try {
      final ObjectNode report = JSON.createObjectNode();
      report.putArray("rawDroppedCoordinates")
          .add("ch.qos.logback:logback-core:jar:1.5.18 (compile)");
      report.putArray("droppedArtifacts");
      report.putObject("mediatedGraph").putArray("artifactPaths");
      Files.writeString(reportPath, JSON.writeValueAsString(report));
      ExampleSupport.main(
          new String[] {"verify-no-whole-artifact-drops", "CVE fixture", reportPath.toString()});
    } finally {
      Files.deleteIfExists(reportPath);
    }
  }

  private static void verifiesSharedCatalogExampleWiring() throws IOException {
    final Path root = Path.of("").toAbsolutePath().normalize();
    final Path catalog =
        root.resolve("examples/logback-vulnerability-mapping-catalog/src/main/resources")
            .resolve("META-INF/elider/vulnerability-mappings.json");
    if (!Files.isRegularFile(catalog)) {
      throw new AssertionError("The shared Logback catalog fixture is missing");
    }
    final JsonNode mappings = JSON.readTree(Files.readString(catalog));
    if (!mappings.path("catalogId").asText().equals("logback-core-cve-2025-11226")
        || mappings.path("schemaVersion").asInt() != 1
        || mappings.path("mappings").size() != 2) {
      throw new AssertionError("The shared catalog identity or row count changed");
    }
    final List<String> expectedRanges = List.of("[1.5.11]", "[1.5.18]");
    for (int index = 0; index < expectedRanges.size(); index++) {
      final JsonNode row = mappings.path("mappings").get(index);
      final JsonNode claim = row.path("versionClaims").get(0);
      if (!row.path("groupId").asText().equals("ch.qos.logback")
          || !row.path("artifactId").asText().equals("logback-core")
          || !row.path("vulnerabilityId").asText().equals("CVE-2025-11226")
          || !row.path("confidenceLevel").asText().equals("HIGH")
          || !row.path("intent").asText().equals("AUTO_VERIFY")
          || !claim.path("range").asText().equals(expectedRanges.get(index))
          || !claim.path("status").asText().equals("EVIDENCE_SCOPE")) {
        throw new AssertionError("Catalog rows must preserve the exact Logback evidence scopes");
      }
      final JsonNode prerequisites = row.path("prerequisiteGroups");
      if (prerequisites.size() != 1
          || !prerequisites.get(0).path("operator").asText().equals("ANY_OF")
          || !prerequisites.get(0).path("members").get(0).path("requiresClass").asText()
              .equals("org.codehaus.janino.ClassBodyEvaluator")) {
        throw new AssertionError("Catalog rows must preserve the Janino prerequisite group");
      }
    }

    final String coordinate =
        "io.github.spockz.catalogs:logback-vulnerability-mapping-catalog:1.0.0";
    for (final String fixture : List.of("example-spring-boot-app", "example-cve-safe-class-app")) {
      final String pom = Files.readString(root.resolve("examples").resolve(fixture).resolve("pom.xml"));
      if (!pom.contains(coordinate)) {
        throw new AssertionError(fixture + " must adopt the shared released catalog artifact");
      }
    }
    final String safeClassPom =
        Files.readString(root.resolve("examples/example-cve-safe-class-app/pom.xml"));
    final String springPom = Files.readString(root.resolve("examples/example-spring-boot-app/pom.xml"));
    if (safeClassPom.contains("<vulnerabilityMappings>")
        || !safeClassPom.contains("<preconditionClassPathComplete>true</preconditionClassPathComplete>")
        || !springPom.contains("<preconditionClassPathComplete>true</preconditionClassPathComplete>")) {
      throw new AssertionError("Catalog examples must retain complete inventory opt-in without inline mappings");
    }
    for (final String script :
        List.of("examples/run-elision-cycle.sh", "scripts/prepare-transcript-examples.sh")) {
      final String contents = Files.readString(root.resolve(script));
      final int install = contents.indexOf("logback-vulnerability-mapping-catalog");
      final int fixture = contents.indexOf("fixture_names=(");
      if (install < 0 || fixture < 0 || install > fixture) {
        throw new AssertionError(script + " must install the catalog before running examples");
      }
      if (script.equals("scripts/prepare-transcript-examples.sh")
          && contents.contains("-Delide.productionClassesComplete=true")) {
        throw new AssertionError(script + " must rely on the process-classes lifecycle default");
      }
    }
    final String cycle = Files.readString(root.resolve("examples/run-elision-cycle.sh"));
    if (!cycle.contains("analysis_report=")
        || !cycle.contains("-Delide.analysisSummaryFile=$analysis_report")
        || !cycle.contains("-Delide.productionClassesComplete=true")
        || !cycle.contains("verify-spring-analysis \"$analysis_report\"")
        || !cycle.contains("if [[ $fixture == example-spring-boot-app || $fixture == example-cve-unused-app")
        || !cycle.contains("catalogId=logback-core-cve-2025-11226")) {
      throw new AssertionError(
          "Spring Analyze must assert catalog adoption and keep the out-of-scope finding unresolved");
    }
    final JsonNode invocations =
        JSON.readTree(Files.readString(root.resolve("scripts/transcripts-manifest.json")))
            .path("invocations");
    boolean foundDirectAnalyze = false;
    for (final JsonNode invocation : invocations) {
      if (!invocation.path("goal").asText().equals("analyze")) {
        continue;
      }
      foundDirectAnalyze = true;
      boolean declaresProductionCompleteness = false;
      for (final JsonNode argument : invocation.path("args")) {
        if (argument.asText().equals("-Delide.productionClassesComplete=true")) {
          declaresProductionCompleteness = true;
          break;
        }
      }
      if (!declaresProductionCompleteness) {
        throw new AssertionError(
            "Direct Analyze transcript goals must assert complete production bytecode because "
                + "they do not run in the process-classes lifecycle");
      }
    }
    if (!foundDirectAnalyze) {
      throw new AssertionError("The transcript manifest must retain direct Analyze examples");
    }
  }

  private static void verifiesRemovedCveDependencyDoesNotClaimAbsence() throws Exception {
    final Path reportPath = Files.createTempFile("example-cve-report-", ".json").toRealPath();
    final Path outputPath = Files.createTempFile("example-cve-report-", ".out").toRealPath();
    try {
      final ObjectNode report = JSON.createObjectNode();
      final ArrayNode findings = report.putArray("genericFindings");
      addCveFinding(
          findings,
          "CVE-2022-42889",
          "commons-text",
          "1.9",
          "RETAINED_AND_TRIMMED",
          "DECLARED_CODE_ABSENT",
          "Commons Text vulnerable code is absent.");
      addCveFinding(
          findings,
          "CVE-2025-48924",
          "commons-lang3",
          "3.17.0",
          "REMOVED",
          "NO_PROOF",
          "No complete physical proof was available.");
      report.putArray("sourceObservations");
      Files.writeString(reportPath, JSON.writeValueAsString(report));
      Files.writeString(
          outputPath,
          cveReportOutput("NO_PROOF", "No complete physical proof was available."));

      ExampleSupport.main(
          new String[] {
            "verify-cve-report", "example-cve-unused-app", reportPath.toString(), outputPath.toString()
          });

      ((ObjectNode) findings.get(1)).put("outcome", "DECLARED_CODE_ABSENT");
      Files.writeString(reportPath, JSON.writeValueAsString(report));
      Files.writeString(
          outputPath,
          cveReportOutput(
              "DECLARED_CODE_ABSENT", "No complete physical proof was available."));
      try {
        ExampleSupport.main(
            new String[] {
              "verify-cve-report",
              "example-cve-unused-app",
              reportPath.toString(),
              outputPath.toString()
            });
      } catch (final IOException exception) {
        if (exception.getMessage().contains("generic finding outcomes changed")) {
          return;
        }
        throw new AssertionError("Unexpected CVE report rejection", exception);
      }
      throw new AssertionError("CVE verifier accepted an unrelated code absence proof");
    } finally {
      Files.deleteIfExists(reportPath);
      Files.deleteIfExists(outputPath);
    }
  }

  private static void verifiesCveUnusedExpectedWholeArtifactDrop() throws Exception {
    final Path reportPath = Files.createTempFile("example-cve-unused-drop-", ".json").toRealPath();
    try {
      final ObjectNode report = JSON.createObjectNode();
      final ObjectNode dropped =
          report.putArray("droppedArtifacts").addObject();
      dropped.put("coordinate", "org.apache.commons:commons-lang3:jar:3.17.0 (compile)");
      dropped.put("programClassesRemoved", 395);
      Files.writeString(reportPath, JSON.writeValueAsString(report));

      ExampleSupport.main(
          new String[] {"verify-cve-unused-expected-drop", reportPath.toString()});

      dropped.put("coordinate", "org.apache.commons:commons-text:jar:1.9 (compile)");
      Files.writeString(reportPath, JSON.writeValueAsString(report));
      try {
        ExampleSupport.main(
            new String[] {"verify-cve-unused-expected-drop", reportPath.toString()});
      } catch (final IOException exception) {
        if (exception.getMessage().contains("unused Commons Lang artifact")) {
          return;
        }
        throw new AssertionError("Unexpected CVE whole-artifact rejection", exception);
      }
      throw new AssertionError("CVE verifier accepted removal of the vulnerable Commons Text artifact");
    } finally {
      Files.deleteIfExists(reportPath);
    }
  }

  private static void addCveFinding(
      final ArrayNode findings,
      final String vulnerabilityId,
      final String artifactId,
      final String version,
      final String inventoryDisposition,
      final String outcome,
      final String detail) {
    final ObjectNode finding = findings.addObject();
    finding.put("vulnerabilityId", vulnerabilityId);
    finding.put("applicability", "AFFECTED");
    finding.put("outcome", outcome);
    finding.put("inventoryDisposition", inventoryDisposition);
    finding.put("detail", detail);
    final ObjectNode candidate = finding.putObject("candidate");
    candidate.put("groupId", "org.apache.commons");
    candidate.put("artifactId", artifactId);
    candidate.put("version", version);
    candidate.put("type", "jar");
    candidate.put("classifier", "");
    candidate.put("scope", "compile");
  }

  private static String cveReportOutput(final String unrelatedOutcome, final String unrelatedDetail) {
    return String.join(
        "\n",
        "[INFO] Vulnerability findings:",
        "[INFO]   - CVE-2022-42889 org.apache.commons:commons-text:jar:1.9 (compile) [RETAINED_AND_TRIMMED]",
        "[INFO]     Applicability: AFFECTED",
        "[INFO]     Outcome: DECLARED_CODE_ABSENT; Commons Text vulnerable code is absent.",
        "[INFO]   - CVE-2025-48924 org.apache.commons:commons-lang3:jar:3.17.0 (compile) [REMOVED]",
        "[INFO]     Applicability: AFFECTED",
        "[INFO]     Outcome: " + unrelatedOutcome + "; " + unrelatedDetail,
        "[INFO] CVE Sources:");
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
    verifiesUnknownOriginDiagnosticForms(available, productionOutput);

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

    final ObjectNode noAffectedAssertion = report.deepCopy();
    ((ObjectNode) noAffectedAssertion.path("genericFindings").get(0))
        .put("applicability", "NO_AFFECTED_ASSERTION");
    ((ObjectNode) noAffectedAssertion.path("genericFindings").get(0)).put("outcome", "UNRESOLVED");
    ExampleSupport.validateGenericFindingReport(noAffectedAssertion);

    final ObjectNode partial = report.deepCopy();
    final ObjectNode observation = partial.withArray("sourceObservations").addObject();
    observation.put("source", "CVE_LIST");
    observation.put("status", "PARTIAL");
    observation.put("revision", "revision-partial");
    observation.put("lastSuccessfulSync", "2026-11-04T00:00:00Z");
    observation.put("diagnostic", "Skipped malformed source data");
    observation.putArray("observationDiagnostics").add("CVE-2026-54321 affected[1] skipped");
    observation.put("contributionCount", 1);
    ExampleSupport.validateGenericFindingReport(partial);

    final ObjectNode snyk = partial.deepCopy();
    ((ObjectNode) snyk.path("sourceObservations").get(0)).put("source", "SNYK");
    ExampleSupport.validateGenericFindingReport(snyk);

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

  private static void verifiesUnknownOriginDiagnosticForms(
      final ObjectNode validReport, final Path productionOutput) throws IOException {
    final ObjectNode withoutLocation = validReport.deepCopy();
    final ObjectNode unknownLocation = unknownOrigin("example:consumer:1", "pom.xml", 0, 0);
    installUnknownOrigin(withoutLocation, unknownLocation);
    diagnosticArray(withoutLocation).add(
        "Incomplete or ambiguous provenance: Maven did not provide a source location for "
            + "example:consumer:1");
    ExampleSupport.validateClassUsageReport(withoutLocation, productionOutput);

    final ObjectNode withoutIdentity = validReport.deepCopy();
    installUnknownOrigin(withoutIdentity, unknownOrigin("", "pom.xml", 5, 3));
    diagnosticArray(withoutIdentity).add(
        "Incomplete or ambiguous provenance: Maven did not provide a source identity for "
            + "pom.xml:5:3");
    ExampleSupport.validateClassUsageReport(withoutIdentity, productionOutput);

    final ObjectNode located = validReport.deepCopy();
    installUnknownOrigin(located, unknownOrigin("example:consumer:1", "pom.xml", 5, 3));
    diagnosticArray(located).add(
        "Incomplete or ambiguous provenance at example:consumer:1:5:3: source model is "
            + "ambiguous");
    ExampleSupport.validateClassUsageReport(located, productionOutput);

    final ObjectNode forged = validReport.deepCopy();
    installUnknownOrigin(forged, unknownOrigin("example:consumer:1", "pom.xml", 0, 0));
    rejects(forged, productionOutput, "Invalid exclusionReview payload");
  }

  private static ObjectNode unknownOrigin(
      final String modelId, final String source, final int line, final int column) {
    final ObjectNode origin = JSON.createObjectNode();
    origin.put("kind", "UNKNOWN");
    origin.put("modelId", modelId);
    origin.put("source", source);
    origin.put("line", line);
    origin.put("column", column);
    origin.put("profileId", "");
    return origin;
  }

  private static void installUnknownOrigin(
      final ObjectNode report, final ObjectNode origin) {
    final ObjectNode review = (ObjectNode) report.path("exclusionReview");
    replaceOrigins(review, origin);
    review.putArray("management");
  }

  private static void replaceOrigins(final JsonNode node, final ObjectNode origin) {
    if (node instanceof final ObjectNode object) {
      if (object.has("kind") && object.has("modelId") && object.has("profileId")) {
        object.removeAll();
        object.setAll(origin.deepCopy());
        return;
      }
      final List<String> fields = new java.util.ArrayList<>();
      object.fieldNames().forEachRemaining(fields::add);
      for (final String field : fields) {
        if ("origin".equals(field)) {
          object.set(field, origin.deepCopy());
        } else {
          replaceOrigins(object.path(field), origin);
        }
      }
    } else if (node instanceof final ArrayNode array) {
      for (final JsonNode child : array) {
        replaceOrigins(child, origin);
      }
    }
  }

  private static ArrayNode diagnosticArray(final ObjectNode report) {
    return (ArrayNode)
        report.path("exclusionReview").path("snapshot").path("diagnostics");
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
