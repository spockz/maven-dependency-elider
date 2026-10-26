// WHY: Guards the example report verifier against JSON type coercion regressions.

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public final class ExampleSupportContractTest {
  private static final ObjectMapper JSON = new ObjectMapper();

  private ExampleSupportContractTest() {}

  public static void main(final String[] arguments) throws IOException {
    rejectsRelativePath();
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
    } finally {
      Files.deleteIfExists(productionOutput);
    }
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
    return report;
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
