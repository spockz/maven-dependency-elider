// WHY: Provides JDK-based HTTP and JSON checks for the example lifecycle runner.

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.ConnectException;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

public final class ExampleSupport {
  private static final ObjectMapper JSON = new ObjectMapper();

  private ExampleSupport() {}

  public static void main(final String[] arguments) throws Exception {
    if (arguments.length == 0) {
      throw new IllegalArgumentException(
          "Expected run-spring-endpoint, verify-class-report, verify-effective-graph-report, "
              + "verify-cve-report, verify-no-whole-artifact-drops, or verify-basic-graph-drop");
    }
    switch (arguments[0]) {
      case "run-spring-endpoint" -> runSpringEndpoint(arguments);
      case "verify-class-report" -> verifyClassReport(arguments);
      case "verify-effective-graph-report" -> verifyEffectiveGraphReport(arguments);
      case "verify-cve-report" -> verifyCveReport(arguments);
      case "verify-cve-sboms" -> verifyCveSboms(arguments);
      case "verify-no-whole-artifact-drops" -> verifyNoWholeArtifactDrops(arguments);
      case "verify-basic-graph-drop" -> verifyBasicGraphDrop(arguments);
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
    for (int attempt = 1; attempt <= 3; attempt++) {
      final int port;
      try (ServerSocket socket = new ServerSocket(0)) {
        socket.setReuseAddress(true);
        port = socket.getLocalPort();
      }
      final Process process =
          new ProcessBuilder(
                  java.toString(),
                  "-Xlog:class+load=info:file=" + trace,
                  "-Djava.io.tmpdir=" + trace.getParent(),
                  "-jar",
                  jar.toString(),
                  "--server.port=" + port)
              .redirectErrorStream(true)
              .redirectOutput(log.toFile())
              .start();
      try {
        final HttpClient client =
            HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();
        final HttpRequest request =
            HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/api/hello"))
                .timeout(Duration.ofSeconds(2))
                .GET()
                .build();
        final long deadline = System.nanoTime() + Duration.ofSeconds(60).toNanos();
        boolean portCollision = false;
        while (System.nanoTime() < deadline) {
          if (!process.isAlive()) {
            process.waitFor();
            final String logContent = Files.exists(log) ? Files.readString(log) : "";
            if (logContent.contains("was already in use") && attempt < 3) {
              portCollision = true;
              break;
            }
            throw new IOException(
                "Spring Boot exited before serving the endpoint; see " + log);
          }
          try {
            final HttpResponse<String> response =
                client.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200
                || !"{\"message\":\"hello\"}".equals(response.body())) {
              throw new IOException("Unexpected Spring Boot endpoint response: " + response.body());
            }
            verifySpringSbom(client, port, expectedSbom);
            return;
          } catch (final ConnectException exception) {
            TimeUnit.MILLISECONDS.sleep(250);
          } catch (final java.net.http.HttpTimeoutException exception) {
            TimeUnit.MILLISECONDS.sleep(250);
          }
        }
        if (portCollision) {
          TimeUnit.MILLISECONDS.sleep(500);
          continue;
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
    final JsonNode groups = report.path("groups");
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
    if (!report.path("removedCveComponents").isArray()) {
      throw new IOException("Report snapshot missing valid removedCveComponents list");
    }
    if (!report.path("provenAbsentCves").isArray()) {
      throw new IOException("Report snapshot missing valid provenAbsentCves list");
    }
    if (!report.path("inactivePreconditionCves").isArray()) {
      throw new IOException("Report snapshot missing valid inactivePreconditionCves list");
    }
  }

  private static void verifyNoWholeArtifactDrops(final String[] arguments) throws IOException {
    if (arguments.length != 3) {
      throw new IllegalArgumentException("Usage: verify-no-whole-artifact-drops FIXTURE REPORT_JSON");
    }
    final String fixture = arguments[1];
    final Path reportPath = requireAbsolutePath(arguments[2], "REPORT_JSON");
    final JsonNode report = JSON.readTree(reportPath.toFile());
    if (report.path("rawDroppedCoordinates").size() > 0 || report.path("droppedArtifacts").size() > 0) {
      throw new IOException(fixture + " expects no raw or effective whole-artifact drops");
    }
    for (final JsonNode path : report.path("mediatedGraph").path("artifactPaths")) {
      if ("WHOLE_ARTIFACT_DROPPED".equals(path.path("kind").asText(""))) {
        throw new IOException(fixture + " must not report whole-artifact removal paths");
      }
    }
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

    final JsonNode removedCves = report.path("removedCveComponents");
    final JsonNode provenCves = report.path("provenAbsentCves");
    if (!removedCves.isArray()) {
      throw new IOException(
          "[" + fixture + "] dependency-elider-report.json missing valid 'removedCveComponents' array");
    }
    if (!provenCves.isArray()) {
      throw new IOException(
          "[" + fixture + "] dependency-elider-report.json missing valid 'provenAbsentCves' array");
    }

    final Pattern cvePattern = Pattern.compile("^CVE-[0-9]{4}-[0-9]{4,}$");
    final List<String> removedIds = new ArrayList<>();
    for (final JsonNode item : removedCves) {
      final String cveId = item.path("cveId").asText("");
      final String coordinate = item.path("coordinate").asText("");
      if (!cvePattern.matcher(cveId).matches() || coordinate.isBlank()) {
        throw new IOException("[" + fixture + "] Malformed removedCveComponents entry: " + item);
      }
      removedIds.add(cveId);
    }

    final List<String> provenIds = new ArrayList<>();
    for (final JsonNode item : provenCves) {
      final String cveId = item.path("cveId").asText("");
      final String coordinate = item.path("coordinate").asText("");
      if (!cvePattern.matcher(cveId).matches() || coordinate.isBlank()) {
        throw new IOException("[" + fixture + "] Malformed provenAbsentCves entry: " + item);
      }
      provenIds.add(cveId);
    }

    if (!output.contains("[INFO] CVE components removed from inventory:")) {
      throw new IOException(
          "[" + fixture + "] Report output missing 'CVE components removed from inventory:' heading");
    }
    if (!output.contains("[INFO] CVEs with vulnerable code proven absent by trimming:")) {
      throw new IOException(
          "[" + fixture
              + "] Report output missing 'CVEs with vulnerable code proven absent by trimming:' heading");
    }

    if (removedCves.isEmpty()) {
      if (!output.contains(
          "[INFO] CVE components removed from inventory: none matched the available vulnerability"
              + " mappings")) {
        throw new IOException(
            "[" + fixture
                + "] Expected 'none matched the available vulnerability mappings' for removed"
                + " CVEs");
      }
    } else {
      for (final JsonNode item : removedCves) {
        final String line =
            "[INFO]   - " + item.path("cveId").asText() + " " + item.path("coordinate").asText();
        if (!output.contains(line)) {
          throw new IOException(
              "[" + fixture + "] Missing expected removed CVE line in report output: " + line);
        }
      }
    }

    if (provenCves.isEmpty()) {
      if (!output.contains(
          "[INFO] CVEs with vulnerable code proven absent by trimming: none matched the available"
              + " vulnerability mappings")) {
        throw new IOException(
            "[" + fixture
                + "] Expected 'none matched the available vulnerability mappings' for proven"
                + " absent CVEs");
      }
    } else {
      for (final JsonNode item : provenCves) {
        final String line =
            "[INFO]   - " + item.path("cveId").asText() + " " + item.path("coordinate").asText();
        if (!output.contains(line)) {
          throw new IOException(
              "[" + fixture + "] Missing expected proven absent CVE line in report output: " + line);
        }
      }
    }

    // Concrete fixture-specific expected CVE assertions
    switch (fixture) {
      case "example-basic-app" -> {
        if (!removedIds.contains("CVE-2014-3577")) {
          throw new IOException(
              "example-basic-app expected removed CVE-2014-3577, found: " + removedIds);
        }
        if (!provenIds.isEmpty()) {
          throw new IOException(
              "example-basic-app expected 0 proven absent CVEs, found: " + provenIds);
        }
      }
      case "example-cve-unused-app" -> {
        if (!removedIds.isEmpty()) {
          throw new IOException(
              "example-cve-unused-app expected 0 removed CVEs, found: " + removedIds);
        }
        if (!provenIds.contains("CVE-2022-42889")) {
          throw new IOException(
              "example-cve-unused-app expected proven absent CVE-2022-42889, found: " + provenIds);
        }
      }
      case "example-cve-safe-class-app", "example-spring-boot-app" -> {
        if (!removedIds.isEmpty() || !provenIds.isEmpty()) {
          throw new IOException(
              fixture
                  + " expected 0 CVE findings, found removed="
                  + removedIds
                  + ", proven="
                  + provenIds);
        }
      }
      default -> {}
    }
  }

  private static void verifyCveSboms(final String[] arguments) throws IOException {
    if (arguments.length != 5) {
      throw new IllegalArgumentException(
          "Usage: verify-cve-sboms FIXTURE BASELINE_SBOM POST_ELISION_SBOM VEX_FILE");
    }
    final String fixture = arguments[1];
    final Path baselinePath = requireAbsolutePath(arguments[2], "BASELINE_SBOM");
    final Path postPath = requireAbsolutePath(arguments[3], "POST_ELISION_SBOM");
    final Path vexPath = requireAbsolutePath(arguments[4], "VEX_FILE");
    final Path reportPath =
        requireAbsolutePath(
            postPath.getParent().resolve("dependency-elider-report.json").toString(),
            "REPORT_JSON");

    final JsonNode baseline = JSON.readTree(baselinePath.toFile());
    final JsonNode post = JSON.readTree(postPath.toFile());
    final JsonNode report = JSON.readTree(reportPath.toFile());

    final Set<String> before = componentNames(baseline);
    final Set<String> after = componentNames(post);

    if (!report.path("removedCveComponents").isArray()) {
      throw new IOException("report must contain removedCveComponents list");
    }
    if (!report.path("provenAbsentCves").isArray()) {
      throw new IOException("report must contain provenAbsentCves list");
    }
    if (!report.path("inactivePreconditionCves").isArray()) {
      throw new IOException("report must contain inactivePreconditionCves list");
    }

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
    } else {
      if (!before.contains("janino")
          || !before.contains("logback-classic")
          || !before.contains("logback-core")) {
        throw new IOException("baseline inventory must contain Janino and Logback");
      }
      if (!after.contains("janino")
          || !after.contains("logback-classic")
          || !after.contains("logback-core")) {
        throw new IOException(
            "post-elision inventory must retain components whose code was not removed as a whole"
                + " artifact");
      }
      if (!containsCoordinatePrefix(
          report.path("trimmedArtifacts"), "org.codehaus.janino:janino:")) {
        throw new IOException("safe-class fixture must prove Janino code was trimmed");
      }
      if (Files.exists(vexPath)) {
        throw new IOException("unmapped retained Logback CVE must not produce VEX");
      }
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
