// WHY: Makes class evidence visible to Maven users without mixing diagnostics into pruning policy.

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import io.github.spockz.elider.engine.ClassUsageReport;
import io.github.spockz.elider.scanner.BytecodeReferenceScan;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
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
    final Path normalized = output.toAbsolutePath().normalize();
    final Path parent = normalized.getParent();
    if (parent != null) {
      Files.createDirectories(parent);
    }
    JSON.writeValue(normalized.toFile(), document(report, bytecodeScan));
  }

  private static Map<String, Object> document(
      final ClassUsageReport report, final Optional<BytecodeReferenceScan> bytecodeScan) {
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
