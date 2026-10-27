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
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.TimeUnit;

public final class ExampleSupport {
  private static final ObjectMapper JSON = new ObjectMapper();

  private ExampleSupport() {}

  public static void main(final String[] arguments) throws Exception {
    if (arguments.length == 0) {
      throw new IllegalArgumentException("Expected run-spring-endpoint or verify-class-report");
    }
    switch (arguments[0]) {
      case "run-spring-endpoint" -> runSpringEndpoint(arguments);
      case "verify-class-report" -> verifyClassReport(arguments);
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
    final int port;
    try (ServerSocket socket = new ServerSocket(0)) {
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
      while (System.nanoTime() < deadline) {
        if (!process.isAlive()) {
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
}
