// WHY: Provides JDK-based HTTP and JSON checks for the example lifecycle runner.

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.networknt.schema.JsonSchema;
import com.networknt.schema.JsonSchemaFactory;
import com.networknt.schema.SpecVersion;
import com.networknt.schema.ValidationMessage;
import java.io.IOException;
import java.net.ConnectException;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.TimeUnit;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class ExampleSupport {
  private static final ObjectMapper JSON = new ObjectMapper();
  private static final String SPRING_LOGBACK_VERSION = "1.5.38";

  private ExampleSupport() {}

  public static void main(final String[] arguments) throws Exception {
    if (arguments.length == 0) {
      throw new IllegalArgumentException(
          "Expected run-spring-endpoint, verify-class-report, verify-effective-graph-report, "
              + "verify-cve-report, verify-spring-analysis, "
              + "verify-cve-unused-expected-drop, "
              + "verify-no-whole-artifact-drops, verify-basic-graph-drop, "
              + "verify-test-view-report, "
              + "verify-spring-expected-drop, "
              + "verify-spring-snakeyaml-retained, "
              + "or verify-reactor-reports");
    }
    switch (arguments[0]) {
      case "run-spring-endpoint" -> runSpringEndpoint(arguments);
      case "verify-class-report" -> verifyClassReport(arguments);
      case "verify-effective-graph-report" -> verifyEffectiveGraphReport(arguments);
      case "verify-cve-report" -> verifyCveReport(arguments);
      case "verify-spring-analysis" -> verifySpringAnalysis(arguments);
      case "verify-cve-sboms" -> verifyCveSboms(arguments);
      case "verify-cve-unused-expected-drop" -> verifyCveUnusedExpectedDrop(arguments);
      case "verify-no-whole-artifact-drops" -> verifyNoWholeArtifactDrops(arguments);
      case "verify-basic-graph-drop" -> verifyBasicGraphDrop(arguments);
      case "verify-test-view-report" -> verifyTestViewReport(arguments);
      case "verify-spring-expected-drop" -> verifySpringExpectedDrop(arguments);
      case "verify-spring-snakeyaml-retained" -> verifySpringSnakeyamlRetained(arguments);
      case "verify-reactor-reports" -> verifyReactorReports(arguments);
      default -> throw new IllegalArgumentException("Unsupported operation: " + arguments[0]);
    }
  }

  private static void runSpringEndpoint(final String[] arguments)
      throws IOException, InterruptedException {
    if (arguments.length != 5 && arguments.length != 6) {
      throw new IllegalArgumentException(
          "Usage: run-spring-endpoint JAVA JAR TRACE LOG [EXPECTED_SBOM]");
    }
    final Path java = requireAbsolutePath(arguments[1], "JAVA");
    final Path jar = requireAbsolutePath(arguments[2], "JAR");
    final Path trace = requireAbsolutePath(arguments[3], "TRACE");
    final Path log = requireAbsolutePath(arguments[4], "LOG");
    final Path expectedSbom =
        arguments.length == 6 ? requireAbsolutePath(arguments[5], "EXPECTED_SBOM") : null;
    final Process process =
        new ProcessBuilder(
                java.toString(),
                "-Xlog:class+load=info:file=" + trace,
                "-Djava.io.tmpdir=" + trace.getParent(),
                "-jar",
                jar.toString(),
                "--server.port=0")
            .redirectErrorStream(true)
            .redirectOutput(log.toFile())
            .start();
    try {
      final HttpClient client =
          HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();
      final Pattern portPattern = Pattern.compile("Tomcat started on port (\\d+)");
      int port = 0;
      final long deadline = System.nanoTime() + Duration.ofSeconds(60).toNanos();
      while (System.nanoTime() < deadline) {
        if (!process.isAlive()) {
          process.waitFor();
          throw new IOException("Spring Boot exited before serving the endpoint; see " + log);
        }
        if (port == 0) {
          if (Files.exists(log)) {
            final String logContent = Files.readString(log);
            final Matcher matcher = portPattern.matcher(logContent);
            if (matcher.find()) {
              port = Integer.parseInt(matcher.group(1));
            }
          }
          if (port == 0) {
            TimeUnit.MILLISECONDS.sleep(100);
            continue;
          }
        }
        final HttpRequest request =
            HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/api/hello"))
                .timeout(Duration.ofSeconds(2))
                .GET()
                .build();
        try {
          final HttpResponse<String> response =
              client.send(request, HttpResponse.BodyHandlers.ofString());
          if (response.statusCode() == 200
              && "{\"message\":\"hello\"}".equals(response.body())) {
            verifySpringSbom(client, port, expectedSbom);
            return;
          }
        } catch (final ConnectException | java.net.http.HttpTimeoutException exception) {
          TimeUnit.MILLISECONDS.sleep(250);
        }
      }
      throw new IOException("Spring Boot did not serve the endpoint; see " + log);
    } finally {
      process.destroy();
      if (!process.waitFor(20, TimeUnit.SECONDS)) {
        process.destroyForcibly();
        process.waitFor();
      }
    }
  }

  private static void verifySpringSbom(
      final HttpClient client, final int port, final Path expectedSbom)
      throws IOException, InterruptedException {
    final HttpRequest indexRequest =
        HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/actuator/sbom"))
            .timeout(Duration.ofSeconds(2))
            .GET()
            .build();
    final HttpResponse<String> indexResponse =
        client.send(indexRequest, HttpResponse.BodyHandlers.ofString());
    if (indexResponse.statusCode() != 200) {
      throw new IOException("Spring Boot SBOM index returned HTTP " + indexResponse.statusCode());
    }
    final JsonNode ids = JSON.readTree(indexResponse.body()).path("ids");
    if (!ids.isArray()) {
      throw new IOException("Spring Boot SBOM index response has no ids array");
    }
    final boolean hasApplication = containsText(ids, "application");
    if (expectedSbom != null && !hasApplication) {
      throw new IOException("Staged application SBOM is not available from the actuator endpoint");
    }
    if (hasApplication) {
      final HttpRequest sbomRequest =
          HttpRequest.newBuilder(
                  URI.create("http://127.0.0.1:" + port + "/actuator/sbom/application"))
              .timeout(Duration.ofSeconds(2))
              .GET()
              .build();
      final HttpResponse<String> sbomResponse =
          client.send(sbomRequest, HttpResponse.BodyHandlers.ofString());
      if (sbomResponse.statusCode() != 200) {
        throw new IOException("Spring Boot application SBOM returned HTTP " + sbomResponse.statusCode());
      }
      final JsonNode received = JSON.readTree(sbomResponse.body());
      if (!"CycloneDX".equals(received.path("bomFormat").asText())) {
        throw new IOException("Spring Boot application SBOM is not CycloneDX");
      }
      if (expectedSbom != null
          && !received.equals(JSON.readTree(expectedSbom.toFile()))) {
        throw new IOException("Actuator SBOM differs from the SBOM staged by the plugin");
      }
    }
  }

  private static boolean containsText(final JsonNode values, final String expected) {
    for (final JsonNode value : values) {
      if (value.isTextual() && expected.equals(value.textValue())) {
        return true;
      }
    }
    return false;
  }

  private static void verifyClassReport(final String[] arguments) throws IOException {
    if (arguments.length != 3) {
      throw new IllegalArgumentException("Usage: verify-class-report REPORT PRODUCTION_OUTPUT");
    }
    final Path reportPath = requireAbsolutePath(arguments[1], "REPORT");
    final Path productionOutput =
        requireAbsolutePath(arguments[2], "PRODUCTION_OUTPUT").toRealPath();
    if (!Files.isDirectory(productionOutput)) {
      throw new IOException("Copied baseline production output is missing: " + productionOutput);
    }
    try (var paths = Files.walk(productionOutput)) {
      if (paths.noneMatch(path -> path.toString().endsWith(".class"))) {
        throw new IOException("Copied baseline production output has no class files");
      }
    }
    final JsonNode report = JSON.readTree(reportPath.toFile());
    validateClassUsageReport(report, productionOutput);
  }

  static Path requireAbsolutePath(final String value, final String label) throws IOException {
    final Path path = Path.of(value);
    if (!path.isAbsolute()) {
      throw new IOException(label + " path must be absolute: " + value);
    }
    return path.normalize();
  }

  static void validateClassUsageReport(final JsonNode report, final Path productionOutput)
      throws IOException {
    if (!report.isObject()) {
      throw new IOException("Class usage report root must be a JSON object");
    }
    final JsonNode staticEvidenceAvailable = report.path("staticEvidenceAvailable");
    if (!staticEvidenceAvailable.isBoolean()) {
      throw new IOException("staticEvidenceAvailable must be a JSON boolean");
    }
    if (!staticEvidenceAvailable.booleanValue()) {
      throw new IOException("Static application bytecode evidence is unavailable");
    }
    final JsonNode reportProductionOutput = report.path("productionOutput");
    if (!reportProductionOutput.isTextual()) {
      throw new IOException("Report productionOutput must be a JSON string");
    }
    if (!Path.of(reportProductionOutput.textValue()).toRealPath().equals(productionOutput)) {
      throw new IOException("Report does not identify the copied baseline production output");
    }
    if (report.has("exclusionReview")) {
      validateExclusionReview(report.get("exclusionReview"));
    }
    final JsonNode groups = report.path("groups");
    validateDependencyPrediction(report.get("dependencyPrediction"));
    final Set<String> neither = names(groups.path("neitherReferencedNorObserved"));
    final Set<String> observedMail = matchingMailClasses(report.path("runtimeObservedClasses"));
    final Set<String> runtimeOnlyMail =
        matchingMailClasses(groups.path("runtimeObservedWithoutApplicationReference"));
    final Set<String> applicationMail = matchingMailClasses(groups.path("applicationReferenced"));
    if (observedMail.isEmpty()) {
      throw new IOException("The runtime trace did not observe Jakarta Mail or Angus Mail classes");
    }
    if (!runtimeOnlyMail.containsAll(observedMail)) {
      throw new IOException("Not every observed mail class was classified as runtime-only");
    }
    if (!applicationMail.isEmpty()) {
      throw new IOException(
          "Mail classes were classified as application-referenced: " + applicationMail);
    }
    if (!neither.contains("org.apache.commons.codec.binary.Hex")) {
      throw new IOException(
          "Unused Commons Codec Hex was not classified as neither observed nor referenced");
    }
  }

  static JsonNode validateGenericFindingReport(final JsonNode report) throws IOException {
    final JsonNode findings = report.path("genericFindings");
    if (!findings.isArray()) {
      throw new IOException("genericFindings must be an array");
    }
    final JsonNode observations = report.path("sourceObservations");
    if (!observations.isArray()) {
      throw new IOException("sourceObservations must be an array");
    }
    for (final JsonNode finding : findings) {
      if (!finding.isObject()
          || !nonblankText(finding, "vulnerabilityId")
          || !nonblankText(finding, "applicability")
          || !nonblankText(finding, "outcome")
          || !nonblankText(finding, "inventoryDisposition")
          || !nonblankText(finding, "detail")) {
        throw new IOException("generic finding has missing required fields");
      }
      if (!Set.of("AFFECTED", "NOT_AFFECTED", "UNRESOLVED", "NO_AFFECTED_ASSERTION")
          .contains(finding.path("applicability").asText())) {
        throw new IOException("finding applicability is unsupported");
      }
      if (!Set.of(
              "NOT_AFFECTED",
              "UNRESOLVED",
              "REVIEW_ONLY",
              "DECLARED_CODE_ABSENT",
              "PREREQUISITES_ABSENT",
              "NO_PROOF")
          .contains(finding.path("outcome").asText())) {
        throw new IOException("finding outcome is unsupported");
      }
      if (!Set.of(
              "REMOVED",
              "RETAINED_AND_TRIMMED",
              "RETAINED_UNCHANGED",
              "PLANNED_UNVERIFIED")
          .contains(finding.path("inventoryDisposition").asText())) {
        throw new IOException("finding inventory disposition is unsupported");
      }
      final JsonNode candidate = finding.path("candidate");
      if (!candidate.isObject()
          || !nonblankText(candidate, "groupId")
          || !nonblankText(candidate, "artifactId")
          || !nonblankText(candidate, "version")
          || !nonblankText(candidate, "type")
          || !candidate.path("classifier").isTextual()
          || !nonblankText(candidate, "scope")) {
        throw new IOException("candidate coordinate is incomplete");
      }
    }
    for (final JsonNode observation : observations) {
      final JsonNode source = observation.path("source");
      if (!observation.isObject()
          || !Set.of("CURRENT", "PARTIAL", "STALE", "ERROR", "UNAVAILABLE")
              .contains(observation.path("status").asText())
          || !(source.isNull()
              || source.isMissingNode()
              || Set.of("OSV", "CVE_LIST", "SNYK").contains(source.asText()))) {
        throw new IOException("source observation is invalid");
      }
    }
    return findings;
  }

  private static boolean nonblankText(final JsonNode object, final String field) {
    final JsonNode value = object.path(field);
    return value.isTextual() && !value.textValue().isBlank();
  }

  private static void validateExclusionReview(final JsonNode review) throws IOException {
    requireReviewFields(
        review, Set.of("available", "unavailableReason", "snapshot", "candidates", "management"));
    final JsonNode available = review.path("available");
    final JsonNode reason = review.path("unavailableReason");
    final JsonNode candidates = review.path("candidates");
    final JsonNode management = review.path("management");
    if (!available.isBoolean()
        || !reason.isTextual()
        || !candidates.isArray()
        || !management.isArray()) {
      throw invalidExclusionReview();
    }
    final JsonNode snapshot = review.path("snapshot");
    if (!available.booleanValue()) {
      if (reason.textValue().isBlank()
          || !snapshot.isNull()
          || !candidates.isEmpty()
          || !management.isEmpty()) {
        throw invalidExclusionReview();
      }
      return;
    }
    if (!reason.textValue().isEmpty()) {
      throw invalidExclusionReview();
    }
    requireReviewFields(
        snapshot, Set.of("dependencies", "management", "activeProfiles", "diagnostics"));
    final JsonNode dependencies = snapshot.path("dependencies");
    final JsonNode managed = snapshot.path("management");
    final JsonNode profiles = snapshot.path("activeProfiles");
    final JsonNode diagnostics = snapshot.path("diagnostics");
    validateReviewProfiles(profiles);
    validateReviewStrings(diagnostics);
    validateReviewDeclarations(dependencies, profiles, diagnostics);
    validateReviewDeclarations(managed, profiles, diagnostics);
    if (!candidates.equals(expectedReviewCandidates(dependencies))
        || !management.equals(expectedReviewManagement(dependencies, managed))) {
      throw new IOException("exclusionReview findings do not match their frozen snapshot");
    }
  }

  private static void validateReviewProfiles(final JsonNode profiles) throws IOException {
    if (!profiles.isObject()) {
      throw invalidExclusionReview();
    }
    for (final var profile : profiles.properties()) {
      if (profile.getKey().isBlank()) {
        throw invalidExclusionReview();
      }
      validateReviewStrings(profile.getValue());
      final Set<String> unique = new HashSet<>();
      if (profile.getValue().isEmpty()) {
        throw invalidExclusionReview();
      }
      for (final JsonNode id : profile.getValue()) {
        if (id.textValue().isBlank()
            || !id.textValue().equals(id.textValue().trim())
            || !unique.add(id.textValue())) {
          throw invalidExclusionReview();
        }
      }
    }
  }

  private static void validateReviewStrings(final JsonNode values) throws IOException {
    if (!values.isArray()) {
      throw invalidExclusionReview();
    }
    for (final JsonNode value : values) {
      if (!value.isTextual()) {
        throw invalidExclusionReview();
      }
    }
  }

  private static void validateReviewDeclarations(
      final JsonNode declarations, final JsonNode profiles, final JsonNode diagnostics)
      throws IOException {
    if (!declarations.isArray()) {
      throw invalidExclusionReview();
    }
    for (int ordinal = 0; ordinal < declarations.size(); ordinal++) {
      final JsonNode declaration = declarations.get(ordinal);
      requireReviewFields(
          declaration,
          Set.of("ordinal", "groupId", "artifactId", "type", "classifier", "origin", "exclusions"));
      if (!declaration.path("ordinal").isInt()
          || declaration.path("ordinal").intValue() != ordinal) {
        throw new IOException("exclusionReview declaration ordinals are not canonical");
      }
      for (final String field : List.of("groupId", "artifactId", "type", "classifier")) {
        if (!declaration.path(field).isTextual()) {
          throw invalidExclusionReview();
        }
      }
      validateReviewOrigin(declaration.path("origin"), profiles, diagnostics);
      final JsonNode exclusions = declaration.path("exclusions");
      if (!exclusions.isArray()) {
        throw invalidExclusionReview();
      }
      for (final JsonNode exclusion : exclusions) {
        requireReviewFields(exclusion, Set.of("groupId", "artifactId", "origin"));
        if (!exclusion.path("groupId").isTextual()
            || !exclusion.path("artifactId").isTextual()) {
          throw invalidExclusionReview();
        }
        validateReviewOrigin(exclusion.path("origin"), profiles, diagnostics);
      }
    }
  }

  private static void validateReviewOrigin(
      final JsonNode origin, final JsonNode profiles, final JsonNode diagnostics)
      throws IOException {
    requireReviewFields(
        origin, Set.of("kind", "modelId", "source", "line", "column", "profileId"));
    final JsonNode kind = origin.path("kind");
    final JsonNode model = origin.path("modelId");
    final JsonNode profile = origin.path("profileId");
    final JsonNode line = origin.path("line");
    final JsonNode column = origin.path("column");
    if (!kind.isTextual()
        || !model.isTextual()
        || !origin.path("source").isTextual()
        || !profile.isTextual()
        || !line.isInt()
        || !column.isInt()
        || !Set.of(
                "UNKNOWN", "LOCAL", "INHERITED", "LOCAL_MANAGEMENT", "INHERITED_MANAGEMENT",
                "LOCAL_PROFILE", "INHERITED_PROFILE", "LOCAL_PROFILE_MANAGEMENT",
                "INHERITED_PROFILE_MANAGEMENT")
            .contains(kind.textValue())) {
      throw invalidExclusionReview();
    }
    final boolean unknown = kind.textValue().equals("UNKNOWN");
    if ((!unknown && (model.textValue().isBlank() || line.intValue() < 1 || column.intValue() < 1))
        || (kind.textValue().contains("_PROFILE") != !profile.textValue().isBlank())
        || !profile.textValue().equals(profile.textValue().trim())
        || (unknown && !profile.textValue().isEmpty())) {
      throw invalidExclusionReview();
    }
    if (!profile.textValue().isEmpty()) {
      final JsonNode active = profiles.path(model.textValue());
      if (!active.isArray() || !containsText(active, profile.textValue())) {
        throw invalidExclusionReview();
      }
    }
    if (unknown && !hasUnknownOriginDiagnostic(model, line, column, diagnostics)) {
      throw invalidExclusionReview();
    }
  }

  private static boolean hasUnknownOriginDiagnostic(
      final JsonNode model, final JsonNode line, final JsonNode column, final JsonNode diagnostics) {
    final String legacyLocation =
        "Incomplete or ambiguous provenance at "
            + model.textValue()
            + ":"
            + line.intValue()
            + ":"
            + column.intValue();
    if (line.intValue() < 1 || column.intValue() < 1) {
      return hasDiagnosticPrefix(
              diagnostics,
              "Incomplete or ambiguous provenance: Maven did not provide a source location for ")
          || containsText(diagnostics, legacyLocation);
    }
    if (model.textValue().isBlank()) {
      return hasDiagnosticPrefix(
              diagnostics,
              "Incomplete or ambiguous provenance: Maven did not provide a source identity for ")
          || containsText(diagnostics, legacyLocation);
    }
    return hasDiagnosticPrefix(diagnostics, legacyLocation + ":")
        || containsText(diagnostics, legacyLocation);
  }

  private static boolean hasDiagnosticPrefix(final JsonNode diagnostics, final String prefix) {
    for (final JsonNode diagnostic : diagnostics) {
      if (diagnostic.textValue().startsWith(prefix)) {
        return true;
      }
    }
    return false;
  }

  private static ArrayNode expectedReviewCandidates(final JsonNode dependencies) {
    final Map<ReviewCoordinate, List<JsonNode>> paths = new TreeMap<>();
    for (final JsonNode declaration : dependencies) {
      final Map<ReviewCoordinate, List<JsonNode>> local = new LinkedHashMap<>();
      for (final JsonNode exclusion : declaration.path("exclusions")) {
        final ReviewCoordinate coordinate =
            new ReviewCoordinate(
                exclusion.path("groupId").textValue(), exclusion.path("artifactId").textValue());
        if (coordinate.exact()) {
          final List<JsonNode> origins = local.computeIfAbsent(coordinate, ignored -> new ArrayList<>());
          if (!origins.contains(exclusion.path("origin"))) {
            origins.add(exclusion.path("origin"));
          }
        }
      }
      local.forEach(
          (coordinate, origins) -> {
            final ObjectNode observation = JSON.createObjectNode();
            observation.set("declaration", reviewReference(declaration));
            observation.set("exclusionOrigins", JSON.valueToTree(origins));
            paths.computeIfAbsent(coordinate, ignored -> new ArrayList<>()).add(observation);
          });
    }
    final ArrayNode expected = JSON.createArrayNode();
    paths.forEach(
        (coordinate, observations) -> {
          if (observations.size() >= 2) {
            final ObjectNode candidate = expected.addObject();
            final ObjectNode identity = candidate.putObject("coordinate");
            identity.put("groupId", coordinate.groupId());
            identity.put("artifactId", coordinate.artifactId());
            candidate.put("count", observations.size());
            candidate.set("declarations", JSON.valueToTree(observations));
          }
        });
    return expected;
  }

  private static ArrayNode expectedReviewManagement(
      final JsonNode dependencies, final JsonNode managed) {
    final Set<JsonNode> contributing = new HashSet<>();
    for (final JsonNode declaration : dependencies) {
      for (final JsonNode exclusion : declaration.path("exclusions")) {
        final JsonNode origin = exclusion.path("origin");
        if (!"UNKNOWN".equals(origin.path("kind").textValue())) {
          contributing.add(origin);
        }
      }
    }
    final ArrayNode expected = JSON.createArrayNode();
    for (final JsonNode declaration : managed) {
      final ArrayNode exclusions = JSON.createArrayNode();
      for (final JsonNode exclusion : declaration.path("exclusions")) {
        final JsonNode origin = exclusion.path("origin");
        if (!"UNKNOWN".equals(origin.path("kind").textValue())
            && !contributing.contains(origin)) {
          final ObjectNode nested = exclusions.addObject();
          final ObjectNode coordinate = nested.putObject("coordinate");
          coordinate.put("groupId", exclusion.path("groupId").textValue());
          coordinate.put("artifactId", exclusion.path("artifactId").textValue());
          nested.set("origin", origin.deepCopy());
        }
      }
      if (!exclusions.isEmpty()) {
        final ObjectNode row = expected.addObject();
        row.set("reference", reviewReference(declaration));
        row.set("exclusions", exclusions);
      }
    }
    return expected;
  }

  private static ObjectNode reviewReference(final JsonNode declaration) {
    final ObjectNode reference = JSON.createObjectNode();
    for (final String field : List.of("ordinal", "groupId", "artifactId", "type", "classifier", "origin")) {
      reference.set(field, declaration.path(field).deepCopy());
    }
    return reference;
  }

  private static void requireReviewFields(final JsonNode node, final Set<String> expected)
      throws IOException {
    if (node == null || !node.isObject() || !fieldNames(node).equals(expected)) {
      throw invalidExclusionReview();
    }
  }

  private static IOException invalidExclusionReview() {
    return new IOException("Invalid exclusionReview payload");
  }

  private record ReviewCoordinate(String groupId, String artifactId)
      implements Comparable<ReviewCoordinate> {
    private boolean exact() {
      return !groupId.isBlank()
          && !artifactId.isBlank()
          && !groupId.contains("*")
          && !artifactId.contains("*");
    }

    @Override
    public int compareTo(final ReviewCoordinate other) {
      final int group = groupId.compareTo(other.groupId);
      return group == 0 ? artifactId.compareTo(other.artifactId) : group;
    }
  }

  private static void validateDependencyPrediction(final JsonNode prediction) throws IOException {
    if (prediction == null) {
      return;
    }
    if (!prediction.isObject()) {
      throw new IOException("dependencyPrediction must be a JSON object");
    }
    final JsonNode provenance = prediction.path("provenance");
    if (!provenance.isTextual()
        || !Set.of("CAPTURED_EFFECTIVE_RESOLVER", "DETACHED_CURRENT_MODEL")
            .contains(provenance.textValue())) {
      throw new IOException("dependencyPrediction provenance is unsupported");
    }
    for (final String field :
        List.of("environmentFingerprint", "inventoryFingerprint", "operationFingerprint")) {
      final JsonNode fingerprint = prediction.path(field);
      if (!fingerprint.isTextual() || !fingerprint.textValue().matches("[0-9a-f]{64}")) {
        throw new IOException("dependencyPrediction " + field + " must be a SHA-256 string");
      }
    }
    for (final String field : List.of("retainedArtifacts", "wouldElideArtifacts")) {
      final JsonNode coordinates = prediction.path(field);
      if (!coordinates.isArray()) {
        throw new IOException("dependencyPrediction " + field + " must be an array");
      }
      ReportCoordinate previous = null;
      final Set<String> unique = new HashSet<>();
      for (final JsonNode coordinate : coordinates) {
        if (!coordinate.isTextual() || coordinate.textValue().isBlank()) {
          throw new IOException("dependencyPrediction coordinates must be non-empty strings");
        }
        final String text = coordinate.textValue();
        final ReportCoordinate parsed;
        try {
          parsed = parseCanonicalCoordinate(text);
        } catch (final IllegalArgumentException exception) {
          throw new IOException("dependencyPrediction coordinate is not canonical", exception);
        }
        if (previous != null && previous.compareTo(parsed) >= 0) {
          throw new IOException("dependencyPrediction coordinates are not canonical");
        }
        if (!unique.add(text)) {
          throw new IOException("dependencyPrediction coordinates contain duplicates");
        }
        previous = parsed;
      }
    }
    final Set<String> retained = coordinateTexts(prediction.path("retainedArtifacts"));
    final Set<String> wouldElide = coordinateTexts(prediction.path("wouldElideArtifacts"));
    final Set<String> overlap = new HashSet<>(retained);
    overlap.retainAll(wouldElide);
    if (!overlap.isEmpty()) {
      throw new IOException("dependencyPrediction retained and would-elide coordinates overlap");
    }
    validateBanPlan(prediction, retained, wouldElide);
    final JsonNode plannedRemovals = prediction.path("plannedClassRemovals");
    if (!plannedRemovals.isArray()) {
      throw new IOException("dependencyPrediction plannedClassRemovals must be an array");
    }
    ReportCoordinate previousCoordinate = null;
    for (final JsonNode removal : plannedRemovals) {
      if (!removal.isObject()) {
        throw new IOException("dependencyPrediction planned class removal must be an object");
      }
      if (!"PLANNED_UNVERIFIED".equals(removal.path("status").asText())) {
        throw new IOException("dependencyPrediction planned class removal status is unsupported");
      }
      final JsonNode coordinate = removal.path("coordinate");
      if (!coordinate.isTextual() || coordinate.textValue().isBlank()) {
        throw new IOException("dependencyPrediction planned class removal coordinate is invalid");
      }
      final ReportCoordinate parsedCoordinate;
      try {
        parsedCoordinate = parseCanonicalCoordinate(coordinate.textValue());
      } catch (final IllegalArgumentException exception) {
        throw new IOException(
            "dependencyPrediction planned class removal coordinate is not canonical", exception);
      }
      if (!retained.contains(coordinate.textValue())) {
        throw new IOException(
            "dependencyPrediction planned class removal must reference a retained artifact");
      }
      if (previousCoordinate != null && previousCoordinate.compareTo(parsedCoordinate) >= 0) {
        throw new IOException("dependencyPrediction planned class removals are not canonical");
      }
      previousCoordinate = parsedCoordinate;
      final JsonNode classes = removal.path("classes");
      if (!classes.isArray() || classes.size() == 0) {
        throw new IOException("dependencyPrediction planned removal classes must be non-empty");
      }
      String previousClass = null;
      for (final JsonNode className : classes) {
        if (!className.isTextual() || className.textValue().isBlank()) {
          throw new IOException("dependencyPrediction planned removal classes must be strings");
        }
        if (previousClass != null && previousClass.compareTo(className.textValue()) >= 0) {
          throw new IOException("dependencyPrediction planned removal classes are not canonical");
        }
        previousClass = className.textValue();
      }
    }
  }

  private static void validateBanPlan(
      final JsonNode prediction,
      final Set<String> retained,
      final Set<String> wouldElide)
      throws IOException {
    final JsonNode context = prediction.get("banContextFingerprint");
    final JsonNode plan = prediction.get("banPlan");
    if (context == null && plan == null) {
      return;
    }
    if (context == null || plan == null) {
      throw new IOException("dependencyPrediction ban context and plan must appear together");
    }
    if (!context.isTextual() || !context.textValue().matches("[0-9a-f]{64}")) {
      throw new IOException("dependencyPrediction banContextFingerprint must be a SHA-256 string");
    }
    if (!plan.isArray() || plan.isEmpty()) {
      throw new IOException("dependencyPrediction banPlan must be a non-empty array");
    }
    final Set<String> input = new HashSet<>(retained);
    input.addAll(wouldElide);
    ReportBanIdentity previous = null;
    for (final JsonNode row : plan) {
      if (!row.isObject()
          || !fieldNames(row)
              .equals(
                  Set.of(
                      "dependency", "status", "matchedArtifacts", "originalArtifacts", "applied"))) {
        throw new IOException("dependencyPrediction ban plan row has unsupported fields");
      }
      final ReportBanIdentity dependency = parseBanIdentity(row.path("dependency"));
      if (previous != null && previous.compareTo(dependency) >= 0) {
        throw new IOException("dependencyPrediction ban plan rows are not canonical");
      }
      previous = dependency;
      final JsonNode applied = row.path("applied");
      if (!applied.isBoolean() || applied.booleanValue()) {
        throw new IOException("dependencyPrediction ban plan applied must be false");
      }
      final JsonNode status = row.path("status");
      if (!status.isTextual()
          || !Set.of(
                  "FORCED_ABSENT_AFTER_RESOLUTION",
                  "EXCLUDED_BEFORE_RESOLUTION",
                  "UNMATCHED")
              .contains(status.textValue())) {
        throw new IOException("dependencyPrediction ban plan status is unsupported");
      }
      final Set<String> matched = validateBanMatches(row.path("matchedArtifacts"), dependency, wouldElide);
      final Set<String> original = validateOriginalBanMatches(row.path("originalArtifacts"), dependency);
      final String classification = status.textValue();
      final boolean statusMatches =
          switch (classification) {
            case "FORCED_ABSENT_AFTER_RESOLUTION" -> !matched.isEmpty();
            case "EXCLUDED_BEFORE_RESOLUTION" -> matched.isEmpty() && !original.isEmpty();
            case "UNMATCHED" -> matched.isEmpty() && original.isEmpty();
            default -> false;
          };
      if (!statusMatches) {
        throw new IOException("dependencyPrediction ban plan status disagrees with matches");
      }
      final Set<String> originalIdentities =
          original.stream().map(ExampleSupport::banGavce).collect(java.util.stream.Collectors.toSet());
      if (matched.stream()
          .map(ExampleSupport::banGavce)
          .anyMatch(identity -> !originalIdentities.contains(identity))) {
        throw new IOException("dependencyPrediction original audit does not include effective ban matches");
      }
      final Set<String> expected = new HashSet<>();
      for (final String coordinate : input) {
        if (dependency.matches(parseCanonicalCoordinate(coordinate))) {
          expected.add(coordinate);
        }
      }
      if (!matched.equals(expected)) {
        throw new IOException("dependencyPrediction ban plan matches disagree with artifact inventory");
      }
    }
  }

  private static Set<String> fieldNames(final JsonNode row) {
    final Set<String> names = new HashSet<>();
    for (final var entry : row.properties()) {
      names.add(entry.getKey());
    }
    return names;
  }

  private static Set<String> validateBanMatches(
      final JsonNode matches, final ReportBanIdentity dependency, final Set<String> wouldElide)
      throws IOException {
    if (!matches.isArray()) {
      throw new IOException("dependencyPrediction ban matchedArtifacts must be an array");
    }
    final Set<String> coordinates = new HashSet<>();
    ReportCoordinate previous = null;
    for (final JsonNode match : matches) {
      if (!match.isTextual()) {
        throw new IOException("dependencyPrediction ban matchedArtifacts must be coordinate strings");
      }
      final ReportCoordinate coordinate;
      try {
        coordinate = parseCanonicalCoordinate(match.textValue());
      } catch (final IllegalArgumentException exception) {
        throw new IOException("dependencyPrediction ban matched artifact is not canonical", exception);
      }
      if (!"jar".equals(coordinate.type())
          || !Set.of("compile", "runtime").contains(coordinate.scope())) {
        throw new IOException(
            "dependencyPrediction ban matched artifact must be a compile/runtime JAR");
      }
      if (previous != null && previous.compareTo(coordinate) >= 0) {
        throw new IOException("dependencyPrediction ban matchedArtifacts are not canonical");
      }
      if (!dependency.matches(coordinate)) {
        throw new IOException("dependencyPrediction ban matched artifact has another identity");
      }
      if (!wouldElide.contains(match.textValue())) {
        throw new IOException("dependencyPrediction ban matched artifact must be in wouldElideArtifacts");
      }
      coordinates.add(match.textValue());
      previous = coordinate;
    }
    return coordinates;
  }

  private static Set<String> validateOriginalBanMatches(
      final JsonNode matches, final ReportBanIdentity dependency) throws IOException {
    if (!matches.isArray()) {
      throw new IOException("dependencyPrediction ban originalArtifacts must be an array");
    }
    final Set<String> coordinates = new HashSet<>();
    ReportCoordinate previous = null;
    for (final JsonNode match : matches) {
      if (!match.isTextual()) {
        throw new IOException("dependencyPrediction ban originalArtifacts must be coordinate strings");
      }
      final ReportCoordinate coordinate;
      try {
        coordinate = parseCanonicalCoordinate(match.textValue());
      } catch (final IllegalArgumentException exception) {
        throw new IOException("dependencyPrediction original artifact is not canonical", exception);
      }
      if (!"jar".equals(coordinate.type())
          || !Set.of("compile", "runtime").contains(coordinate.scope())) {
        throw new IOException(
            "dependencyPrediction ban original artifact must be a compile/runtime JAR");
      }
      if (previous != null && previous.compareTo(coordinate) >= 0) {
        throw new IOException("dependencyPrediction ban originalArtifacts are not canonical");
      }
      if (!dependency.matches(coordinate)) {
        throw new IOException("dependencyPrediction original artifact has another identity");
      }
      coordinates.add(match.textValue());
      previous = coordinate;
    }
    return coordinates;
  }

  private static String banGavce(final String coordinateText) {
    final ReportCoordinate coordinate = parseCanonicalCoordinate(coordinateText);
    return coordinate.groupId()
        + ":"
        + coordinate.artifactId()
        + ":"
        + coordinate.version()
        + ":"
        + coordinate.type()
        + ":"
        + coordinate.classifier();
  }

  private static ReportBanIdentity parseBanIdentity(final JsonNode node) throws IOException {
    if (!node.isTextual()) {
      throw new IOException("dependencyPrediction ban dependency must be a G:A string");
    }
    final String[] parts = node.textValue().split(":", -1);
    if (parts.length != 2) {
      throw new IOException("dependencyPrediction ban dependency must be a G:A string");
    }
    for (final String part : parts) {
      if (part.isBlank()
          || part.indexOf('*') >= 0
          || part.indexOf('?') >= 0
          || part.chars().anyMatch(Character::isWhitespace)) {
        throw new IOException("dependencyPrediction ban dependency is not normalized");
      }
    }
    return new ReportBanIdentity(parts[0], parts[1]);
  }

  private static Set<String> coordinateTexts(final JsonNode node) throws IOException {
    if (!node.isArray()) {
      throw new IOException("dependencyPrediction artifact coordinates must be arrays");
    }
    final Set<String> coordinates = new HashSet<>();
    for (final JsonNode coordinate : node) {
      if (!coordinate.isTextual()) {
        throw new IOException("dependencyPrediction coordinates must be non-empty strings");
      }
      coordinates.add(coordinate.textValue());
    }
    return coordinates;
  }

  private static ReportCoordinate parseCanonicalCoordinate(final String text) {
    final int scopeMarker = text.lastIndexOf(" (");
    if (scopeMarker <= 0 || !text.endsWith(")")) {
      throw new IllegalArgumentException("coordinate must include scope");
    }
    final String scope = text.substring(scopeMarker + 2, text.length() - 1);
    final String[] parts = text.substring(0, scopeMarker).split(":", -1);
    if ((parts.length != 4 && parts.length != 5)
        || scope.isBlank()
        || scope.chars().anyMatch(Character::isWhitespace)) {
      throw new IllegalArgumentException("coordinate has malformed components");
    }
    for (final String part : parts) {
      if (part.isBlank() || part.chars().anyMatch(Character::isWhitespace)) {
        throw new IllegalArgumentException("coordinate has a blank or whitespace component");
      }
    }
    final ReportCoordinate coordinate =
        parts.length == 4
            ? new ReportCoordinate(parts[0], parts[1], parts[3], parts[2], "", scope)
            : new ReportCoordinate(parts[0], parts[1], parts[4], parts[2], parts[3], scope);
    if (!coordinate.render().equals(text)) {
      throw new IllegalArgumentException("coordinate is not canonical");
    }
    return coordinate;
  }

  private record ReportBanIdentity(String groupId, String artifactId)
      implements Comparable<ReportBanIdentity> {
    private boolean matches(final ReportCoordinate coordinate) {
      return groupId.equals(coordinate.groupId())
          && artifactId.equals(coordinate.artifactId());
    }

    @Override
    public int compareTo(final ReportBanIdentity other) {
      final int groupComparison = groupId.compareTo(other.groupId);
      return groupComparison == 0 ? artifactId.compareTo(other.artifactId()) : groupComparison;
    }
  }

  private record ReportCoordinate(
      String groupId, String artifactId, String version, String type, String classifier, String scope)
      implements Comparable<ReportCoordinate> {
    private String render() {
      final String artifactIdText =
          classifier.isEmpty()
              ? groupId + ":" + artifactId + ":" + type + ":" + version
              : groupId + ":" + artifactId + ":" + type + ":" + classifier + ":" + version;
      return artifactIdText + " (" + scope + ")";
    }

    @Override
    public int compareTo(final ReportCoordinate other) {
      int compared = groupId.compareTo(other.groupId);
      if (compared == 0) compared = artifactId.compareTo(other.artifactId);
      if (compared == 0) compared = version.compareTo(other.version);
      if (compared == 0) compared = type.compareTo(other.type);
      if (compared == 0) compared = classifier.compareTo(other.classifier);
      if (compared == 0) compared = scope.compareTo(other.scope);
      return compared;
    }
  }

  private static Set<String> names(final JsonNode node) throws IOException {
    if (!node.isArray()) {
      throw new IOException("Expected class usage group to be an array");
    }
    final Set<String> names = new HashSet<>();
    for (final JsonNode value : node) {
      if (!value.isTextual()) {
        throw new IOException("Expected class name to be a JSON string");
      }
      names.add(value.textValue());
    }
    return names;
  }

  private static Set<String> matchingMailClasses(final JsonNode node) throws IOException {
    final Set<String> names = names(node);
    names.removeIf(
        name ->
            !name.startsWith("jakarta.mail.") && !name.startsWith("org.eclipse.angus.mail."));
    return names;
  }

  private static void verifyEffectiveGraphReport(final String[] arguments) throws IOException {
    if (arguments.length != 2 && arguments.length != 3) {
      throw new IllegalArgumentException(
          "Usage: verify-effective-graph-report REPORT_JSON [EXPECTED_DROPS]");
    }
    final Path reportPath = requireAbsolutePath(arguments[1], "REPORT_JSON");
    final Integer expectedDrops =
        arguments.length == 3 && !arguments[2].isBlank()
            ? Integer.valueOf(Integer.parseInt(arguments[2]))
            : null;
    final JsonNode report = JSON.readTree(reportPath.toFile());
    final JsonNode graph = report.path("mediatedGraph");
    if (!graph.path("available").asBoolean(false)) {
      throw new IOException("Example did not capture the configured core-extension graph");
    }
    final JsonNode drops = report.path("droppedArtifacts");
    if (!drops.isArray()) {
      throw new IOException("Report missing valid droppedArtifacts array");
    }
    final List<JsonNode> dropPaths = new ArrayList<>();
    final List<JsonNode> trimPaths = new ArrayList<>();
    for (final JsonNode path : graph.path("artifactPaths")) {
      final String kind = path.path("kind").asText("");
      if ("WHOLE_ARTIFACT_DROPPED".equals(kind)) {
        dropPaths.add(path);
      } else if ("CLASS_TRIMMED".equals(kind)) {
        trimPaths.add(path);
      }
    }
    if (dropPaths.size() != drops.size()
        || report.path("wholeArtifactsDropped").asInt(-1) != drops.size()) {
      throw new IOException("Effective whole-artifact drops lack occurrence-specific graph paths");
    }
    if (expectedDrops != null && drops.size() != expectedDrops.intValue()) {
      throw new IOException(
          "Expected " + expectedDrops + " effective whole-artifact drops, found " + drops.size());
    }
    final JsonNode trimmedArtifacts = report.path("trimmedArtifacts");
    if (trimPaths.size() != trimmedArtifacts.size()) {
      throw new IOException("Trimmed artifacts lack occurrence-specific graph paths");
    }
    final Map<String, String> statuses = new HashMap<>();
    for (final JsonNode item : graph.path("nodeStatuses")) {
      statuses.put(item.path("nodeId").asText(""), item.path("disposition").asText(""));
    }
    for (final JsonNode path : dropPaths) {
      final String disposition = statuses.get(path.path("nodeId").asText(""));
      if (!"SAFE_ELIDED".equals(disposition)) {
        throw new IOException("Effective graph drop path is not marked SAFE_ELIDED: " + disposition);
      }
    }
    validateGenericFindingReport(report);
  }

  private static void verifyNoWholeArtifactDrops(final String[] arguments) throws IOException {
    if (arguments.length != 3) {
      throw new IllegalArgumentException("Usage: verify-no-whole-artifact-drops FIXTURE REPORT_JSON");
    }
    final String fixture = arguments[1];
    final Path reportPath = requireAbsolutePath(arguments[2], "REPORT_JSON");
    final JsonNode report = JSON.readTree(reportPath.toFile());
    if (report.path("droppedArtifacts").size() > 0) {
      throw new IOException(fixture + " expects no effective whole-artifact drops");
    }
    for (final JsonNode path : report.path("mediatedGraph").path("artifactPaths")) {
      if ("WHOLE_ARTIFACT_DROPPED".equals(path.path("kind").asText(""))) {
        throw new IOException(fixture + " must not report whole-artifact removal paths");
      }
    }
  }

  private static void verifyCveUnusedExpectedDrop(final String[] arguments) throws IOException {
    if (arguments.length != 2) {
      throw new IllegalArgumentException("Usage: verify-cve-unused-expected-drop REPORT_JSON");
    }
    final JsonNode drops =
        JSON.readTree(requireAbsolutePath(arguments[1], "REPORT_JSON").toFile())
            .path("droppedArtifacts");
    if (!drops.isArray() || drops.size() != 1) {
      throw new IOException("CVE unused fixture must drop only the unused Commons Lang artifact");
    }
    final JsonNode drop = drops.get(0);
    if (!"org.apache.commons:commons-lang3:jar:3.17.0 (compile)"
            .equals(drop.path("coordinate").asText())
        || drop.path("programClassesRemoved").asInt(0) <= 0) {
      throw new IOException(
          "CVE unused fixture must drop only the unused Commons Lang artifact and its classes");
    }
  }

  private static void verifySpringExpectedDrop(final String[] arguments) throws IOException {
    if (arguments.length != 2) {
      throw new IllegalArgumentException("Usage: verify-spring-expected-drop REPORT_JSON");
    }
    final Path reportPath = requireAbsolutePath(arguments[1], "REPORT_JSON");
    final JsonNode drops = JSON.readTree(reportPath.toFile()).path("droppedArtifacts");
    final Map<String, String> expectedScopes = Map.of(
        "commons-codec:commons-codec", "compile",
        "at.yawk.lz4:lz4-java", "runtime",
        "com.github.luben:zstd-jni", "runtime");
    if (!drops.isArray() || drops.size() != expectedScopes.size()) {
      throw new IOException("Unexpected Spring fixture artifact drops: " + drops);
    }
    final Set<String> observed = new HashSet<>();
    for (final JsonNode drop : drops) {
      final ReportCoordinate coordinate = parseCanonicalCoordinate(drop.path("coordinate").asText());
      final String identity = coordinate.groupId() + ":" + coordinate.artifactId();
      if (!coordinate.scope().equals(expectedScopes.get(identity))
          || !"jar".equals(coordinate.type())
          || !coordinate.classifier().isEmpty()
          || drop.path("programClassesRemoved").asInt(0) <= 0
          || !observed.add(identity)) {
        throw new IOException("Unexpected Spring fixture artifact drop: " + drop);
      }
    }
  }

  private static void verifySpringSnakeyamlRetained(final String[] arguments) throws IOException {
    if (arguments.length != 2) {
      throw new IllegalArgumentException("Usage: verify-spring-snakeyaml-retained REPORT_JSON");
    }
    final JsonNode report = JSON.readTree(requireAbsolutePath(arguments[1], "REPORT_JSON").toFile());
    final JsonNode trim =
        singleMatching(
            report.path("trimmedArtifacts"),
            value -> value.path("coordinate").asText().startsWith("org.yaml:snakeyaml:jar:"),
            "retained SnakeYAML trim result");
    final String coordinate = trim.path("coordinate").asText();
    final ReportCoordinate resolved = parseCanonicalCoordinate(coordinate);
    boolean rawCandidate = false;
    for (final JsonNode item : report.path("rawDroppedCoordinates")) {
      if (item.isTextual() && coordinate.equals(item.textValue())) {
        rawCandidate = true;
        break;
      }
    }
    boolean effectiveDrop = false;
    for (final JsonNode item : report.path("droppedArtifacts")) {
      if (coordinate.equals(item.path("coordinate").asText())) {
        effectiveDrop = true;
        break;
      }
    }
    if (!rawCandidate || effectiveDrop) {
      throw new IOException("Spring SnakeYAML must remain a raw candidate without an effective drop");
    }

    if (!"compile".equals(resolved.scope())
        || !resolved.classifier().isEmpty()
        || !"elevated_and_trimmed".equals(trim.path("mrjarStatus").asText())) {
      throw new IOException("Retained SnakeYAML must preserve its elevated and trimmed MRJAR status");
    }

    final JsonNode nodes = report.path("mediatedGraph").path("snapshot").path("nodes");
    final JsonNode statuses = report.path("mediatedGraph").path("nodeStatuses");
    if (!nodes.isArray() || !statuses.isArray()) {
      throw new IOException("Spring report is missing the mediated graph needed for retention proof");
    }
    String nodeId = null;
    for (final JsonNode node : nodes) {
      if ("org.yaml".equals(node.path("artifact").path("groupId").asText())
          && "snakeyaml".equals(node.path("artifact").path("artifactId").asText())
          && resolved.version().equals(node.path("artifact").path("version").asText())
          && "compile".equals(node.path("dependency").path("scope").asText())) {
        nodeId = node.path("id").asText();
        break;
      }
    }
    if (nodeId == null) {
      throw new IOException("Spring graph snapshot is missing the SnakeYAML dependency node");
    }
    for (final JsonNode status : statuses) {
      if (nodeId.equals(status.path("nodeId").asText())
          && "RETAINED".equals(status.path("disposition").asText())) {
        return;
      }
    }
    throw new IOException("Spring SnakeYAML must remain retained by graph safety");
  }

  private static void verifyBasicGraphDrop(final String[] arguments) throws IOException {
    if (arguments.length < 2) {
      throw new IllegalArgumentException(
          "Usage: verify-basic-graph-drop REPORT_JSON [EXPECTED_COORDINATES...]");
    }
    final Path reportPath = requireAbsolutePath(arguments[1], "REPORT_JSON");
    final JsonNode report = JSON.readTree(reportPath.toFile());
    final JsonNode drops = report.path("droppedArtifacts");
    final Set<String> actualCoordinates = new HashSet<>();
    for (final JsonNode drop : drops) {
      actualCoordinates.add(drop.path("coordinate").asText(""));
    }
    for (int i = 2; i < arguments.length; i++) {
      if (!actualCoordinates.contains(arguments[i])) {
        throw new IOException(
            "Basic graph report missing expected dropped coordinate "
                + arguments[i]
                + ": "
                + actualCoordinates);
      }
    }
    if (arguments.length > 2 && actualCoordinates.size() != arguments.length - 2) {
      throw new IOException(
          "Basic graph report expected "
              + (arguments.length - 2)
              + " drops, found "
              + actualCoordinates);
    }
  }

  private static void verifyTestViewReport(final String[] arguments) throws IOException {
    if (arguments.length != 3) {
      throw new IllegalArgumentException("Usage: verify-test-view-report PRODUCTION_JSON TEST_JSON");
    }
    final Path productionPath = requireAbsolutePath(arguments[1], "PRODUCTION_JSON");
    final Path testPath = requireAbsolutePath(arguments[2], "TEST_JSON");
    final byte[] productionBytes = Files.readAllBytes(productionPath);
    final JsonNode production = JSON.readTree(productionBytes);
    final JsonNode testView = JSON.readTree(testPath.toFile());
    final String digest;
    try {
      digest = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(productionBytes));
    } catch (final NoSuchAlgorithmException exception) {
      throw new IOException("SHA-256 unavailable for test-view example", exception);
    }
    if (testView.path("schemaVersion").asInt(-1) != 1
        || !"PREPARED".equals(testView.path("status").asText())
        || !digest.equals(testView.path("productionReportSha256").asText())
        || !"io.github.spockz:example-test-view-app:0.1.0-SNAPSHOT"
            .equals(production.path("projectGroupId").asText()
                + ":" + production.path("projectArtifactId").asText()
                + ":" + production.path("projectVersion").asText())
        || !production.path("projectBaseDirectory").asText()
            .equals(testView.path("projectBaseDirectory").asText())
        || !testView.path("conservativeFallbackUsed").asBoolean(false)) {
      throw new IOException("Test-view report does not bind the prepared fallback to production");
    }
    final Set<String> expected =
        Set.of(
            "io/github/spockz/example/testview/library/Builder",
            "io/github/spockz/example/testview/library/Helper",
            "io/github/spockz/example/testview/library/Unused",
            "io/github/spockz/example/testview/marker/Marker");
    final Set<String> observed = new HashSet<>();
    for (final JsonNode addition : testView.path("additions")) {
      for (final JsonNode name : addition.path("classes")) {
        observed.add(name.asText());
      }
    }
    if (!observed.equals(expected)) {
      throw new IOException("Test-view report added classes differ from the example graph: " + observed);
    }
    boolean trimmedInput = false;
    boolean droppedInput = false;
    for (final JsonNode input : testView.path("inputArtifacts")) {
      final String identity = input.path("identity").asText();
      if (identity.contains("artifactId=test-view-library")) {
        trimmedInput = input.path("effectiveJar").asText().endsWith("-trimmed.jar");
      } else if (identity.contains("artifactId=test-only-library")) {
        droppedInput = input.path("effectiveJar").isNull();
      }
    }
    if (!trimmedInput || !droppedInput || !testView.path("additionsJar").asText()
        .endsWith("/elider/test-additions.jar")) {
      throw new IOException("Test-view report did not record both changed dependency providers");
    }
    final JsonNode drops = production.path("droppedArtifacts");
    if (drops.size() != 1 || !drops.get(0).path("coordinate").asText()
        .contains(":test-only-library:")) {
      throw new IOException("Production report did not drop the test-only artifact");
    }
  }

  private static void verifyReactorReports(final String[] arguments) throws IOException {
    if (arguments.length != 4) {
      throw new IllegalArgumentException(
          "Usage: verify-reactor-reports SEQUENTIAL_DIR THREADED_DIR FIXTURE_DIR");
    }
    final Path sequentialDirectory = requireAbsolutePath(arguments[1], "SEQUENTIAL_DIR");
    final Path threadedDirectory = requireAbsolutePath(arguments[2], "THREADED_DIR");
    final Path fixtureDirectory = requireAbsolutePath(arguments[3], "FIXTURE_DIR").toRealPath();
    final Set<Path> reportPaths = new HashSet<>();
    final String[] modules = {"reactor-common", "reactor-service", "reactor-app"};
    for (final String module : modules) {
      final Path expectedBaseDirectory = fixtureDirectory.resolve(module).toRealPath();
      final Path sequentialPath = sequentialDirectory.resolve(module + ".json").toRealPath();
      final Path threadedPath = threadedDirectory.resolve(module + ".json").toRealPath();
      if (!reportPaths.add(sequentialPath) || !reportPaths.add(threadedPath)) {
        throw new IOException("Reactor modules must produce independent report files");
      }
      final JsonNode sequential = readReactorSnapshot(sequentialPath, module, expectedBaseDirectory);
      final JsonNode threaded = readReactorSnapshot(threadedPath, module, expectedBaseDirectory);
      verifyReactorDecisions(sequential, module);
      verifyReactorDecisions(threaded, module);
      if (!stableReactorMetrics(sequential).equals(stableReactorMetrics(threaded))) {
        throw new IOException("Sequential and threaded metrics differ for " + module);
      }
    }
  }

  private static void verifyReactorDecisions(final JsonNode report, final String module)
      throws IOException {
    if (!report.path("droppedArtifacts").isArray() || !report.path("trimmedArtifacts").isArray()) {
      throw new IOException(module + " report is missing artifact decision arrays");
    }
    if ("reactor-common".equals(module)) {
      if (!containsCoordinate(report.path("droppedArtifacts"), "commons-codec:commons-codec:")) {
        throw new IOException("reactor-common report must record the unused Commons Codec drop");
      }
      boolean compressedArtifactTrimmed = false;
      for (final JsonNode artifact : report.path("trimmedArtifacts")) {
        if (artifact.path("coordinate").asText("").startsWith("org.apache.commons:commons-compress:")
            && artifact.path("programClassesPruned").asInt(0) > 0
            && artifact.path("uncompressedProgramClassBytesPruned").asLong(0) > 0) {
          compressedArtifactTrimmed = true;
          break;
        }
      }
      if (!compressedArtifactTrimmed) {
        throw new IOException("reactor-common report must record trimmed Commons Compress classes");
      }
    }
  }

  private static boolean containsCoordinate(final JsonNode artifacts, final String prefix) {
    for (final JsonNode artifact : artifacts) {
      if (artifact.path("coordinate").asText("").startsWith(prefix)) {
        return true;
      }
    }
    return false;
  }

  private static JsonNode readReactorSnapshot(
      final Path reportPath, final String module, final Path expectedBaseDirectory) throws IOException {
    final JsonNode report = JSON.readTree(reportPath.toFile());
    if (report == null || report.path("schemaVersion").asInt(-1) != 1) {
      throw new IOException(module + " report must use schemaVersion 1: " + reportPath);
    }
    if (!"io.github.spockz".equals(report.path("projectGroupId").asText())
        || !module.equals(report.path("projectArtifactId").asText())
        || !"0.1.0-SNAPSHOT".equals(report.path("projectVersion").asText())) {
      throw new IOException(module + " report has an unexpected project GAV: " + reportPath);
    }
    final Path actualBaseDirectory =
        Path.of(report.path("projectBaseDirectory").asText()).toRealPath();
    if (!expectedBaseDirectory.equals(actualBaseDirectory)) {
      throw new IOException(module + " report belongs to " + actualBaseDirectory);
    }
    if (!report.path("mediatedGraph").path("available").asBoolean(false)) {
      throw new IOException(module + " report has no mediated graph");
    }
    return report;
  }

  private static JsonNode stableReactorMetrics(final JsonNode report) throws IOException {
    final ObjectNode stable = JSON.createObjectNode();
    for (final String field :
        List.of(
            "wholeArtifactsDropped",
            "originalJarBytesDropped",
            "droppedProgramClassEntries",
            "droppedProgramClassBytes",
            "programClassesPruned",
            "uncompressedProgramClassBytesPruned")) {
      if (report.path(field).isMissingNode() || !report.path(field).isNumber()) {
        throw new IOException("Reactor report is missing numeric metric " + field);
      }
      stable.set(field, report.path(field));
    }
    stable.set("droppedArtifacts", stableArtifactMetrics(report.path("droppedArtifacts"), true));
    stable.set("trimmedArtifacts", stableArtifactMetrics(report.path("trimmedArtifacts"), false));
    final List<String> rawDrops = new ArrayList<>();
    for (final JsonNode coordinate : report.path("rawDroppedCoordinates")) {
      if (!coordinate.isTextual()) {
        throw new IOException("rawDroppedCoordinates must contain strings");
      }
      rawDrops.add(coordinate.asText());
    }
    rawDrops.sort(Comparator.naturalOrder());
    final ArrayNode rawDropArray = JSON.createArrayNode();
    rawDrops.forEach(rawDropArray::add);
    stable.set("rawDroppedCoordinates", rawDropArray);
    return stable;
  }

  private static ArrayNode stableArtifactMetrics(final JsonNode artifacts, final boolean dropped)
      throws IOException {
    if (!artifacts.isArray()) {
      throw new IOException("Reactor report artifact metrics must be arrays");
    }
    final List<ObjectNode> rows = new ArrayList<>();
    for (final JsonNode artifact : artifacts) {
      final ObjectNode row = JSON.createObjectNode();
      final String[] fields =
          dropped
              ? new String[] {
                "coordinate",
                "originalJarBytes",
                "programClassesRemoved",
                "uncompressedProgramClassBytesRemoved"
              }
              : new String[] {
                "coordinate", "programClassesPruned", "uncompressedProgramClassBytesPruned"
              };
      for (final String field : fields) {
        if (artifact.path(field).isMissingNode()) {
          throw new IOException("Reactor artifact metric is missing " + field);
        }
        row.set(field, artifact.path(field));
      }
      rows.add(row);
    }
    rows.sort(Comparator.comparing(row -> row.path("coordinate").asText()));
    final ArrayNode result = JSON.createArrayNode();
    result.addAll(rows);
    return result;
  }

  private static void verifyCveReport(final String[] arguments) throws IOException {
    if (arguments.length != 4) {
      throw new IllegalArgumentException(
          "Usage: verify-cve-report FIXTURE REPORT_JSON REPORT_OUTPUT");
    }
    final String fixture = arguments[1];
    final Path reportJsonPath = requireAbsolutePath(arguments[2], "REPORT_JSON");
    final Path reportOutputPath = requireAbsolutePath(arguments[3], "REPORT_OUTPUT");

    final JsonNode report = JSON.readTree(reportJsonPath.toFile());
    final String output = Files.readString(reportOutputPath);
    final JsonNode findings = validateGenericFindingReport(report);
    if (!output.contains("[INFO] Vulnerability findings:")) {
      throw new IOException("[" + fixture + "] Report output has no vulnerability findings section");
    }
    if (!output.contains("[INFO] CVE Sources:")) {
      throw new IOException("[" + fixture + "] Report output has no CVE sources section");
    }
    if (findings.isEmpty() && !output.contains("[INFO] Vulnerability findings: none")) {
      throw new IOException("[" + fixture + "] Empty findings must be explicit in report output");
    }

    final List<String> removedIds = new ArrayList<>();
    final List<String> provenIds = new ArrayList<>();
    final List<String> inactiveIds = new ArrayList<>();
    for (final JsonNode finding : findings) {
      final String id = finding.path("vulnerabilityId").asText();
      final String coordinate = renderCandidate(finding.path("candidate"));
      final String line =
          "[INFO]   - "
              + id
              + " "
              + coordinate
              + " ["
              + finding.path("inventoryDisposition").asText()
              + "]";
      final String applicabilityLine =
          "[INFO]     Applicability: " + finding.path("applicability").asText();
      final String outcomeLine =
          "[INFO]     Outcome: "
              + finding.path("outcome").asText()
              + "; "
              + finding.path("detail").asText();
      if (!output.contains(line)
          || !output.contains(applicabilityLine)
          || !output.contains(outcomeLine)) {
        throw new IOException("[" + fixture + "] Missing generic finding details: " + line);
      }
      switch (finding.path("inventoryDisposition").asText()) {
        case "REMOVED" -> removedIds.add(id);
        default -> {}
      }
      switch (finding.path("outcome").asText()) {
        case "DECLARED_CODE_ABSENT" -> provenIds.add(id);
        case "PREREQUISITES_ABSENT" -> {
          inactiveIds.add(id);
          final JsonNode prerequisites = finding.path("effectivePrerequisites");
          if (!prerequisites.isArray() || prerequisites.isEmpty()) {
            throw new IOException("[" + fixture + "] Missing effective prerequisite claims for " + id);
          }
          for (final JsonNode prerequisite : prerequisites) {
            if (prerequisite.path("requiresDependency").asText().isBlank()
                || prerequisite.path("requiresClass").asText().isBlank()) {
              throw new IOException("[" + fixture + "] Malformed effective prerequisite: " + prerequisite);
            }
          }
        }
        default -> {}
      }
    }

    switch (fixture) {
      case "example-basic-app" -> {
        if (!removedIds.contains("CVE-2014-3577") || !provenIds.isEmpty() || !inactiveIds.isEmpty()) {
          throw new IOException("example-basic-app generic finding outcomes changed: " + findings);
        }
        final Path vexPath = reportJsonPath.getParent().resolve("dependency-elider.openvex.json");
        if (Files.exists(vexPath)) {
          throw new IOException("example-basic-app must not emit VEX for a removed component without proof");
        }
      }
      case "example-cve-unused-app" -> {
        if (!provenIds.equals(List.of("CVE-2022-42889"))
            || !inactiveIds.isEmpty()) {
          throw new IOException("example-cve-unused-app generic finding outcomes changed: " + findings);
        }
        final JsonNode removedCommonsLangFinding =
            singleMatching(
                findings,
                value -> "CVE-2025-48924".equals(value.path("vulnerabilityId").asText()),
                "removed Commons Lang CVE finding");
        if (!"org.apache.commons"
                .equals(removedCommonsLangFinding.path("candidate").path("groupId").asText())
            || !"commons-lang3"
                .equals(removedCommonsLangFinding.path("candidate").path("artifactId").asText())
            || !"3.17.0"
                .equals(removedCommonsLangFinding.path("candidate").path("version").asText())
            || !"AFFECTED".equals(removedCommonsLangFinding.path("applicability").asText())
            || !"REMOVED".equals(
                removedCommonsLangFinding.path("inventoryDisposition").asText())
            || !"NO_PROOF".equals(removedCommonsLangFinding.path("outcome").asText())) {
          throw new IOException(
              "Removed Commons Lang CVE must remain affected without a physical absence proof");
        }
      }
      case "example-cve-safe-class-app" -> {
        if (!inactiveIds.equals(List.of("CVE-2025-11226"))
            || !removedIds.isEmpty()
            || !provenIds.isEmpty()) {
          throw new IOException("example-cve-safe-class-app generic finding outcomes changed: " + findings);
        }
      }
      case "example-spring-boot-app" -> {
        for (final String expected : List.of("CVE-2024-50379", "CVE-2026-77310")) {
          singleMatching(
              findings,
              value -> expected.equals(value.path("vulnerabilityId").asText()),
              "real Spring advisory " + expected);
        }
        final JsonNode observedCve =
            singleMatching(
                findings,
                value -> "CVE-2026-68498".equals(value.path("vulnerabilityId").asText())
                    && "com.fasterxml.jackson.core".equals(value.path("candidate").path("groupId").asText()),
                "generic Spring fixture finding");
        if (!"AFFECTED".equals(observedCve.path("applicability").asText())
            || !"NO_PROOF".equals(observedCve.path("outcome").asText())) {
          throw new IOException("Spring fixture finding must remain unverified without physical proof");
        }
        final Path vexPath = reportJsonPath.getParent().resolve("dependency-elider.openvex.json");
        verifySpringLogbackScope(report);
        if (Files.exists(vexPath)) {
          throw new IOException("Spring fixture must not attest findings without verified physical proof");
        }
      }
      default -> {}
    }
  }

  private static String renderCandidate(final JsonNode candidate) {
    final String classifier = candidate.path("classifier").asText();
    return candidate.path("groupId").asText()
        + ":"
        + candidate.path("artifactId").asText()
        + ":"
        + candidate.path("type").asText()
        + (classifier.isEmpty() ? "" : ":" + classifier)
        + ":"
        + candidate.path("version").asText()
        + " ("
        + candidate.path("scope").asText()
        + ")";
  }

  private static void verifyCveSboms(final String[] arguments) throws IOException {
    if (arguments.length != 7) {
      throw new IllegalArgumentException(
          "Usage: verify-cve-sboms FIXTURE BASELINE_SBOM POST_ELISION_SBOM VEX_FILE "
              + "CYCLONEDX_SCHEMA OPENVEX_SCHEMA");
    }
    final String fixture = arguments[1];
    final Path baselinePath = requireAbsolutePath(arguments[2], "BASELINE_SBOM");
    final Path postPath = requireAbsolutePath(arguments[3], "POST_ELISION_SBOM");
    final Path vexPath = requireAbsolutePath(arguments[4], "VEX_FILE");
    final Path cycloneDxSchema = requireAbsolutePath(arguments[5], "CYCLONEDX_SCHEMA");
    final Path openVexSchema = requireAbsolutePath(arguments[6], "OPENVEX_SCHEMA");
    final Path reportPath =
        requireAbsolutePath(
            postPath.getParent().resolve("dependency-elider-report.json").toString(),
            "REPORT_JSON");

    final JsonNode baseline = JSON.readTree(baselinePath.toFile());
    final JsonNode post = JSON.readTree(postPath.toFile());
    final JsonNode report = JSON.readTree(reportPath.toFile());
    validateSchema(postPath, cycloneDxSchema, SpecVersion.VersionFlag.V7);

    final Set<String> before = componentNames(baseline);
    final Set<String> after = componentNames(post);

    validateGenericFindingReport(report);

    if ("example-cve-unused-app".equals(fixture)) {
      if (!before.contains("logback-classic")
          || !before.contains("logback-core")
          || !before.contains("janino")) {
        throw new IOException(
            "baseline inventory must contain Logback and its Janino prerequisite");
      }
      if (!after.contains("logback-classic")
          || !after.contains("logback-core")
          || !after.contains("janino")) {
        throw new IOException(
            "post-elision inventory must retain components whose code was not removed as a whole"
                + " artifact");
      }
      if (!containsCoordinatePrefix(
          report.path("trimmedArtifacts"), "org.codehaus.janino:janino:")) {
        throw new IOException("unused fixture must prove Janino code was trimmed");
      }
      if (!containsCoordinatePrefix(
          report.path("trimmedArtifacts"), "org.apache.commons:commons-text:")) {
        throw new IOException("unused fixture must prove Commons Text code was trimmed");
      }
      if (!Files.exists(vexPath)) {
        throw new IOException(
            "example-cve-unused-app must emit OpenVEX for proven absent Commons Text CVE");
      }
      final JsonNode vexJson = JSON.readTree(vexPath.toFile());
      validateSchema(vexPath, openVexSchema, SpecVersion.VersionFlag.V202012);
      if (!"https://openvex.dev/ns/v0.2.0".equals(vexJson.path("@context").asText())) {
        throw new IOException("OpenVEX context must be https://openvex.dev/ns/v0.2.0");
      }
      final JsonNode statements = vexJson.path("statements");
      if (!statements.isArray() || statements.isEmpty()) {
        throw new IOException("OpenVEX must contain at least one statement");
      }
      boolean foundCommonsTextCve = false;
      for (final JsonNode statement : statements) {
        if ("CVE-2022-42889".equals(statement.path("vulnerability").path("name").asText())
            && "not_affected".equals(statement.path("status").asText())) {
          foundCommonsTextCve = true;
          break;
        }
      }
      if (!foundCommonsTextCve) {
        throw new IOException("OpenVEX missing not_affected statement for CVE-2022-42889");
      }
    } else if ("example-cve-safe-class-app".equals(fixture)
        || "example-spring-boot-app".equals(fixture)) {
      if (!before.contains("logback-classic") || !before.contains("logback-core")) {
        throw new IOException("baseline inventory must contain Logback");
      }
      if (before.contains("janino") || after.contains("janino")) {
        throw new IOException(fixture + " baseline and final inventories must not include Janino");
      }
      if (!after.contains("logback-classic") || !after.contains("logback-core")) {
        throw new IOException(
            "post-elision inventory must retain components whose code was not removed as a whole"
                + " artifact");
      }
      if ("example-spring-boot-app".equals(fixture)) {
        return;
      }
      if (!Files.exists(vexPath)) {
        throw new IOException("inactive precondition CVE must produce OpenVEX");
      }
      final JsonNode vexJson = JSON.readTree(vexPath.toFile());
      validateSchema(vexPath, openVexSchema, SpecVersion.VersionFlag.V202012);
      if (!"https://openvex.dev/ns/v0.2.0".equals(vexJson.path("@context").asText())) {
        throw new IOException("OpenVEX context must be https://openvex.dev/ns/v0.2.0");
      }
      final JsonNode statements = vexJson.path("statements");
      if (!statements.isArray() || statements.isEmpty()) {
        throw new IOException("OpenVEX must contain at least one statement");
      }
      verifySafeClassPrecondition(report, post, vexJson, "1.5.18");
    } else {
      throw new IOException("Unsupported CVE SBOM fixture: " + fixture);
    }
  }

  private static void verifySpringAnalysis(final String[] arguments) throws IOException {
    if (arguments.length != 2) {
      throw new IllegalArgumentException("Usage: verify-spring-analysis ANALYSIS_REPORT");
    }
    final Path reportPath = requireAbsolutePath(arguments[1], "ANALYSIS_REPORT");
    verifySpringLogbackScope(JSON.readTree(reportPath.toFile()));
  }

  private static void verifySpringLogbackScope(final JsonNode report) throws IOException {
    singleMatching(
        report.path("catalogAdoptions"),
        value -> "logback-core-cve-2025-11226".equals(value.path("catalogId").asText()),
        "shared Logback catalog adoption");
    final JsonNode finding =
        singleMatching(
            report.path("genericFindings"),
            value -> "CVE-2025-11226".equals(value.path("vulnerabilityId").asText()),
            "Spring Logback finding outside the catalog's evidence scope");
    if (!"ch.qos.logback".equals(finding.path("candidate").path("groupId").asText())
        || !"logback-core".equals(finding.path("candidate").path("artifactId").asText())
        || !SPRING_LOGBACK_VERSION.equals(finding.path("candidate").path("version").asText())
        || !"NO_AFFECTED_ASSERTION".equals(finding.path("applicability").asText())
        || !"UNRESOLVED".equals(finding.path("outcome").asText())
        || !finding.path("prerequisiteProof").isNull()
        || !finding.path("prerequisitePrediction").isNull()) {
      throw new IOException("Spring Logback is outside the catalog's version scope: " + finding);
    }
  }

  private static void verifySafeClassPrecondition(
      final JsonNode report,
      final JsonNode post,
      final JsonNode vex,
      final String logbackCoreVersion)
      throws IOException {
    final String logbackCorePurl =
        "pkg:maven/ch.qos.logback/logback-core@" + logbackCoreVersion;
    final JsonNode component =
        singleMatching(
            post.path("components"),
            value -> "logback-core".equals(value.path("name").asText()),
            "Logback Core component");
    if (!logbackCorePurl.equals(component.path("purl").asText())
        || !logbackCorePurl.equals(component.path("bom-ref").asText())) {
      throw new IOException("CycloneDX component must identify the exact affected Logback Core");
    }
    final String sha256 = componentSha256(component);
    final JsonNode finding =
        singleMatching(
            report.path("genericFindings"),
            value -> "CVE-2025-11226".equals(value.path("vulnerabilityId").asText()),
            "generic precondition finding");
    if (!"ch.qos.logback".equals(finding.path("candidate").path("groupId").asText())
        || !"logback-core".equals(finding.path("candidate").path("artifactId").asText())
        || !logbackCoreVersion.equals(finding.path("candidate").path("version").asText())
        || !"jar".equals(finding.path("candidate").path("type").asText())
        || !finding.path("candidate").path("classifier").asText().isEmpty()
        || !"AFFECTED".equals(finding.path("applicability").asText())
        || !"PREREQUISITES_ABSENT".equals(finding.path("outcome").asText())) {
      throw new IOException("Inactive finding must target the exact Logback Core coordinate");
    }
    final JsonNode prerequisites = finding.path("effectivePrerequisites");
    if (!prerequisites.isArray() || prerequisites.size() != 1) {
      throw new IOException("Generic precondition finding must retain its atomic prerequisite pair");
    }
    final JsonNode proof = finding.path("prerequisiteProof");
    final JsonNode proofGroups = proof.path("groups");
    if (!proof.isObject()
        || !proof.path("baselineDetail").isNull()
        || !proofGroups.isArray()
        || proofGroups.size() != 1
        || !"ALREADY_ABSENT".equals(proofGroups.get(0).path("attribution").asText())
        || !proofGroups.get(0).path("members").isArray()
        || proofGroups.get(0).path("members").size() != 1
        || !"ALREADY_ABSENT"
            .equals(proofGroups.get(0).path("members").get(0).path("attribution").asText())) {
      throw new IOException(
          "Final prerequisite proof must attribute Janino absence to the complete baseline inventory");
    }
    final JsonNode prerequisite = prerequisites.get(0);
    if (!"org.codehaus.janino:janino".equals(prerequisite.path("requiresDependency").asText())
        || !"org.codehaus.janino.ClassBodyEvaluator".equals(prerequisite.path("requiresClass").asText())) {
      throw new IOException("Generic precondition finding must retain its atomic prerequisite pair");
    }

    final JsonNode vulnerability =
        singleMatching(
            post.path("vulnerabilities"),
            value -> "CVE-2025-11226".equals(value.path("id").asText()),
            "CycloneDX vulnerability");
    final JsonNode analysis = vulnerability.path("analysis");
    if (!"not_affected".equals(analysis.path("state").asText())
        || !"requires_dependency".equals(analysis.path("justification").asText())
        || !analysis.path("detail").asText().contains("org.codehaus.janino.ClassBodyEvaluator")
        || !analysis.path("detail").asText().contains("org.codehaus.janino:janino")
        || !analysis.path("detail").asText().contains("complete declared Maven inventory")
        || !analysis.path("detail").asText().contains("does not cover providers introduced outside")) {
      throw new IOException(
          "CycloneDX precondition evidence must identify the absent Janino class and declared inventory boundary");
    }
    final JsonNode affected = vulnerability.path("affects");
    if (!affected.isArray()
        || affected.size() != 1
        || !logbackCorePurl.equals(affected.get(0).path("ref").asText())) {
      throw new IOException("CycloneDX vulnerability must affect only the exact Logback Core");
    }

    final JsonNode statement =
        singleMatching(
            vex.path("statements"),
            value ->
                "CVE-2025-11226"
                    .equals(value.path("vulnerability").path("name").asText()),
            "OpenVEX statement");
    final String impact = statement.path("impact_statement").asText();
    if (!"not_affected".equals(statement.path("status").asText())
        || statement.has("justification")
        || !impact.contains("org.codehaus.janino:janino")
        || !impact.contains("org.codehaus.janino.ClassBodyEvaluator")
        || !impact.contains("complete declared Maven inventory")
        || !impact.contains("does not cover providers introduced outside")) {
      throw new IOException("OpenVEX statement has invalid precondition evidence");
    }
    final JsonNode products = statement.path("products");
    if (!products.isArray() || products.size() != 1) {
      throw new IOException("OpenVEX statement must have one product binding");
    }
    final JsonNode product = products.get(0);
    if (!product.path("@id").asText().equals(product.path("identifiers").path("purl").asText())) {
      throw new IOException("OpenVEX product identifiers must agree");
    }
    final JsonNode subcomponents = product.path("subcomponents");
    final JsonNode subcomponent =
        singleMatching(
            subcomponents,
            value ->
                logbackCorePurl.equals(value.path("identifiers").path("purl").asText()),
            "OpenVEX affected subcomponent");
    if (subcomponents.size() != 1
        || !logbackCorePurl.equals(subcomponent.path("@id").asText())
        || !sha256.equals(subcomponent.path("hashes").path("sha-256").asText())) {
      throw new IOException("OpenVEX must bind the exact Logback Core component and digest");
    }
  }

  private static JsonNode singleMatching(
      final JsonNode values, final Predicate<JsonNode> predicate, final String description)
      throws IOException {
    if (!values.isArray()) {
      throw new IOException(description + " list is missing");
    }
    JsonNode match = null;
    for (final JsonNode value : values) {
      if (predicate.test(value)) {
        if (match != null) {
          throw new IOException("Multiple matching " + description + " entries");
        }
        match = value;
      }
    }
    if (match == null) {
      throw new IOException("Missing " + description);
    }
    return match;
  }

  private static String componentSha256(final JsonNode component) throws IOException {
    final JsonNode hash =
        singleMatching(
            component.path("hashes"),
            value -> "SHA-256".equals(value.path("alg").asText()),
            "SHA-256 component hash");
    final String digest = hash.path("content").asText();
    if (!digest.matches("[0-9a-f]{64}")) {
      throw new IOException("Logback Core SHA-256 is malformed");
    }
    return digest;
  }

  private static void validateSchema(
      final Path documentPath,
      final Path schemaPath,
      final SpecVersion.VersionFlag version)
      throws IOException {
    final JsonSchema schema =
        JsonSchemaFactory.getInstance(version).getSchema(JSON.readTree(schemaPath.toFile()));
    final Set<ValidationMessage> errors = schema.validate(JSON.readTree(documentPath.toFile()));
    if (!errors.isEmpty()) {
      throw new IOException("Schema validation failed for " + documentPath + ": " + errors);
    }
  }

  private static Set<String> componentNames(final JsonNode bom) {
    final Set<String> names = new HashSet<>();
    for (final JsonNode component : bom.path("components")) {
      final String name = component.path("name").asText("");
      if (!name.isBlank()) {
        names.add(name);
      }
    }
    return names;
  }

  private static boolean containsCoordinatePrefix(final JsonNode array, final String prefix) {
    if (!array.isArray()) {
      return false;
    }
    for (final JsonNode item : array) {
      if (item.path("coordinate").asText("").contains(prefix)) {
        return true;
      }
    }
    return false;
  }
}
