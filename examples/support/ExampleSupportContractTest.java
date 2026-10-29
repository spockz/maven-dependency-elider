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
    } finally {
      Files.deleteIfExists(productionOutput);
    }
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
