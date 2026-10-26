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
    if (arguments.length != 5) {
      throw new IllegalArgumentException(
          "Usage: run-spring-endpoint JAVA JAR TRACE LOG");
    }
    final int port;
    try (ServerSocket socket = new ServerSocket(0)) {
      port = socket.getLocalPort();
    }
    final Process process =
        new ProcessBuilder(
                arguments[1],
                "-Xlog:class+load=info:file=" + arguments[3],
                "-jar",
                arguments[2],
                "--server.port=" + port)
            .redirectErrorStream(true)
            .redirectOutput(Path.of(arguments[4]).toFile())
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
              "Spring Boot exited before serving the endpoint; see " + arguments[4]);
        }
        try {
          final HttpResponse<String> response =
              client.send(request, HttpResponse.BodyHandlers.ofString());
          if (response.statusCode() != 200
              || !"{\"message\":\"hello\"}".equals(response.body())) {
            throw new IOException("Unexpected Spring Boot endpoint response: " + response.body());
          }
          return;
        } catch (final ConnectException exception) {
          TimeUnit.MILLISECONDS.sleep(250);
        } catch (final java.net.http.HttpTimeoutException exception) {
          TimeUnit.MILLISECONDS.sleep(250);
        }
      }
      throw new IOException("Spring Boot did not serve the endpoint; see " + arguments[4]);
    } finally {
      process.destroy();
      if (!process.waitFor(20, TimeUnit.SECONDS)) {
        process.destroyForcibly();
        process.waitFor();
      }
    }
  }

  private static void verifyClassReport(final String[] arguments) throws IOException {
    if (arguments.length != 3) {
      throw new IllegalArgumentException("Usage: verify-class-report REPORT PRODUCTION_OUTPUT");
    }
    final Path reportPath = Path.of(arguments[1]);
    final Path productionOutput = Path.of(arguments[2]).toRealPath();
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
