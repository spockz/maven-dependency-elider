// WHY: Makes class evidence visible to Maven users without mixing diagnostics into pruning policy.

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import io.github.spockz.elider.engine.ClassUsageReport;
import io.github.spockz.elider.scanner.BytecodeReferenceScan;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** Writes deterministic class-level runtime and static evidence as JSON. */
@SuppressWarnings({"PMD.UseConcurrentHashMap", "PMD.CommentDefaultAccessModifier"})
final class MavenClassUsageReportWriter {
  /** JSON serializer whose report maps preserve the documented field order. */
  private static final ObjectMapper JSON =
      new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

  /** Prevents instances of the stateless JSON report utility. */
  private MavenClassUsageReportWriter() {}

  /** Writes one completed class usage report to the configured output path. */
  static void write(
      final Path output,
      final ClassUsageReport report,
      final Optional<BytecodeReferenceScan> bytecodeScan)
      throws IOException {
    write(output, report, bytecodeScan, null);
  }

  static void write(
      final Path output,
      final ClassUsageReport report,
      final Optional<BytecodeReferenceScan> bytecodeScan,
      final AnalyzePrediction prediction)
      throws IOException {
    write(output, report, bytecodeScan, prediction, null);
  }

  static void write(
      final Path output,
      final ClassUsageReport report,
      final Optional<BytecodeReferenceScan> bytecodeScan,
      final AnalyzePrediction prediction,
      final ExclusionReview exclusionReview)
      throws IOException {
    final Path normalized = output.toAbsolutePath().normalize();
    final Path parent = normalized.getParent();
    if (parent == null) {
      throw new IOException("Class usage report needs a parent directory");
    }
    Files.createDirectories(parent);
    final Path temporary = Files.createTempFile(parent, ".class-usage-", ".json");
    try {
      JSON.writeValue(
          temporary.toFile(), document(report, bytecodeScan, prediction, exclusionReview));
      Files.move(
          temporary,
          normalized,
          StandardCopyOption.ATOMIC_MOVE,
          StandardCopyOption.REPLACE_EXISTING);
    } finally {
      Files.deleteIfExists(temporary);
    }
  }

  private static Map<String, Object> document(
      final ClassUsageReport report,
      final Optional<BytecodeReferenceScan> bytecodeScan,
      final AnalyzePrediction prediction,
      final ExclusionReview exclusionReview) {
    final boolean staticAvailable =
        bytecodeScan.filter(BytecodeReferenceScan::complete).isPresent();
    final Map<String, Object> document = new LinkedHashMap<>();
    document.put("schemaVersion", 1);
    document.put("staticEvidenceAvailable", staticAvailable);
    document.put(
        "productionOutput", bytecodeScan.map(scan -> scan.scope().toString()).orElse(null));
    document.put(
        "classFilesScanned",
        bytecodeScan.map(BytecodeReferenceScan::classFilesScanned).orElse(null));
    final Map<String, Object> groups = new LinkedHashMap<>();
    groups.put(
        "applicationReferenced",
        classNames(staticAvailable, report.applicationBytecodeReferenced()));
    groups.put(
        "runtimeObservedWithoutApplicationReference",
        classNames(staticAvailable, report.runtimeObservedWithoutApplicationReference()));
    groups.put(
        "neitherReferencedNorObserved",
        classNames(staticAvailable, report.neitherReferencedNorObserved()));
    document.put("groups", groups);
    document.put(
        "runtimeObservedClasses",
        report.classes().stream()
            .filter(ClassUsageReport.ClassUsage::runtimeObserved)
            .map(ClassUsageReport.ClassUsage::className)
            .toList());
    document.put(
        "classes", report.classes().stream().map(MavenClassUsageReportWriter::classRow).toList());
    if (prediction != null) {
      document.put("dependencyPrediction", predictionDocument(prediction));
    }
    if (exclusionReview != null) {
      document.put("exclusionReview", exclusionReview);
    }
    return document;
  }

  private static Map<String, Object> predictionDocument(final AnalyzePrediction prediction) {
    final Map<String, Object> document = new LinkedHashMap<>();
    document.put("provenance", prediction.provenance().name());
    document.put("environmentFingerprint", prediction.environmentFingerprint());
    document.put("inventoryFingerprint", prediction.inventoryFingerprint());
    document.put("operationFingerprint", prediction.operationFingerprint());
    document.put(
        "retainedArtifacts",
        prediction.retainedArtifacts().stream().map(Object::toString).toList());
    document.put(
        "wouldElideArtifacts",
        prediction.wouldElideArtifacts().stream().map(Object::toString).toList());
    document.put(
        "plannedClassRemovals",
        prediction.plannedTrims().stream()
            .map(
                planned ->
                    Map.of(
                        "status", "PLANNED_UNVERIFIED",
                        "coordinate", planned.coordinate().toString(),
                        "classes", planned.removedClasses().stream().sorted().toList()))
            .toList());
    if (prediction.banPlan().requested()) {
      document.put("banContextFingerprint", prediction.banPlan().contextFingerprint());
      document.put(
          "banPlan",
          prediction.banPlan().entries().stream()
              .map(
                  entry -> {
                    final Map<String, Object> row = new LinkedHashMap<>();
                    row.put("dependency", entry.dependency().toString());
                    row.put(
                        "status",
                        entry.matched()
                            ? "FORCED_ABSENT_AFTER_RESOLUTION"
                            : "NO_CURRENT_INVENTORY_MATCH");
                    row.put(
                        "matchedArtifacts",
                        entry.artifacts().stream().map(Object::toString).toList());
                    row.put("applied", false);
                    return row;
                  })
              .toList());
    }
    return document;
  }

  private static Map<String, Object> classRow(final ClassUsageReport.ClassUsage usage) {
    final Map<String, Object> row = new LinkedHashMap<>();
    row.put("className", usage.className());
    row.put("category", usage.category().name());
    row.put("runtimeObserved", usage.runtimeObserved());
    row.put(
        "applicationBytecodeReferenced",
        usage.staticEvidenceAvailable() ? usage.applicationBytecodeReferenced() : null);
    row.put("staticEvidenceAvailable", usage.staticEvidenceAvailable());
    return row;
  }

  private static Object classNames(
      final boolean staticAvailable, final List<ClassUsageReport.ClassUsage> classes) {
    return staticAvailable
        ? classes.stream().map(ClassUsageReport.ClassUsage::className).toList()
        : null;
  }
}
