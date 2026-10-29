// WHY: Persists elision metrics atomically and renders them in a later Maven invocation.

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import java.io.File;
import java.io.IOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import org.apache.maven.project.MavenProject;

/** Reads, writes, and renders persisted elision summaries. */
@SuppressWarnings({
  "PMD.CommentDefaultAccessModifier",
  "PMD.CognitiveComplexity",
  "PMD.CyclomaticComplexity",
  "PMD.NPathComplexity"
})
final class MavenElisionReportWriter {
  /** JSON serializer shared by report snapshot reads and writes. */
  private static final ObjectMapper JSON =
      new ObjectMapper()
          .enable(SerializationFeature.INDENT_OUTPUT)
          .enable(com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);

  /** Binary units used for the report's byte totals. */
  private static final String[] BYTE_UNITS = {"B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"};

  /** Bullet prefix for indented report items. */
  private static final String BULLET = "  - ";

  private MavenElisionReportWriter() {}

  static Path outputPath(final File configuredPath, final MavenProject project) {
    if (configuredPath != null) {
      return configuredPath.toPath();
    }
    final String buildDirectory =
        project.getBuild() == null ? null : project.getBuild().getDirectory();
    return buildDirectory == null
        ? Path.of("target", "dependency-elider-report.json")
        : Path.of(buildDirectory, "dependency-elider-report.json");
  }

  static void write(final Path output, final MavenElisionReportSnapshot snapshot)
      throws IOException {
    final Path absolute = output.toAbsolutePath().normalize();
    final Path parent = absolute.getParent();
    if (parent == null) {
      throw new IOException("Elision report path has no parent directory: " + absolute);
    }
    Files.createDirectories(parent);
    final Path temporary = Files.createTempFile(parent, ".elision-report-", ".json.tmp");
    try {
      JSON.writeValue(temporary.toFile(), snapshot);
      try {
        Files.move(
            temporary,
            absolute,
            StandardCopyOption.ATOMIC_MOVE,
            StandardCopyOption.REPLACE_EXISTING);
      } catch (final AtomicMoveNotSupportedException exception) {
        throw new IOException(
            "Filesystem cannot atomically publish elision report: " + absolute, exception);
      }
    } finally {
      Files.deleteIfExists(temporary);
    }
  }

  static MavenElisionReportSnapshot read(final Path input) throws IOException {
    final Path absolute = input.toAbsolutePath().normalize();
    if (!Files.isRegularFile(absolute)) {
      throw new IOException(
          "No successful elision report snapshot exists at "
              + absolute
              + "; run a Maven lifecycle build with dependency elision enabled first");
    }
    final JsonNode payload = JSON.readTree(absolute.toFile());
    MavenElisionReportPayloadValidator.validate(payload);
    final MavenElisionReportSnapshot snapshot =
        JSON.treeToValue(payload, MavenElisionReportSnapshot.class);
    if (snapshot == null) {
      throw new IOException("Elision report snapshot is empty: " + absolute);
    }
    return snapshot;
  }

  static List<String> render(final MavenElisionReportSnapshot snapshot) {
    final List<String> lines = new ArrayList<>();
    lines.add("Dependency Elider report");
    lines.add("Project: " + snapshot.projectGav());
    lines.add("Snapshot: last successful elide run at " + snapshot.generatedAt());
    lines.add("The snapshot does not revalidate changed inputs when this goal runs.");
    lines.add(
        "Whole artifacts dropped: "
            + snapshot.wholeArtifactsDropped()
            + " (original JAR file bytes: "
            + formatBytes(snapshot.originalJarBytesDropped())
            + ")");
    lines.add(
        "Program classes removed with dropped JARs: "
            + snapshot.droppedProgramClassEntries()
            + " (uncompressed .class entry payload bytes: "
            + formatBytes(snapshot.droppedProgramClassBytes())
            + "; excludes module descriptors and archive sanitation metadata)");
    lines.add(
        "Raw trace decision drops before graph safety: " + snapshot.rawDroppedCoordinates().size());
    for (final MavenElisionReportSnapshot.DroppedArtifact artifact : snapshot.droppedArtifacts()) {
      lines.add(
          BULLET
              + artifact.coordinate()
              + ": "
              + formatBytes(artifact.originalJarBytes())
              + " original JAR, "
              + artifact.programClassesRemoved()
              + " class entries, "
              + formatBytes(artifact.uncompressedProgramClassBytesRemoved()));
    }
    lines.add(
        "Program classes pruned from retained JARs: "
            + snapshot.programClassesPruned()
            + " (uncompressed omitted .class payload bytes: "
            + formatBytes(snapshot.uncompressedProgramClassBytesPruned())
            + "; excludes module descriptors and archive metadata)");
    for (final MavenElisionReportSnapshot.TrimmedArtifact artifact : snapshot.trimmedArtifacts()) {
      lines.add(
          BULLET
              + artifact.coordinate()
              + ": "
              + artifact.programClassesPruned()
              + " classes, "
              + formatBytes(artifact.uncompressedProgramClassBytesPruned()));
    }
    if (snapshot.removedCveComponents().isEmpty()) {
      lines.add(
          "Avoided CVEs (dropped artifacts): "
              + "none matched the available vulnerability mappings");
    } else {
      lines.add("Avoided CVEs (dropped artifacts):");
      for (final MavenElisionReportSnapshot.CveFinding finding : snapshot.removedCveComponents()) {
        lines.add(BULLET + finding.cveId() + " " + finding.coordinate());
      }
    }
    if (snapshot.provenAbsentCves().isEmpty()) {
      lines.add(
          "Mitigated CVEs (vulnerable code pruned by trimming): none matched the available"
              + " vulnerability mappings");
    } else {
      lines.add("Mitigated CVEs (vulnerable code pruned by trimming):");
      for (final MavenElisionReportSnapshot.CveFinding finding : snapshot.provenAbsentCves()) {
        lines.add(BULLET + finding.cveId() + " " + finding.coordinate());
      }
    }
    if (snapshot.inactivePreconditionCves().isEmpty()) {
      lines.add(
          "CVEs inactive due to unmet prerequisite dependencies: "
              + "none matched the available vulnerability mappings");
    } else {
      lines.add("CVEs inactive due to unmet prerequisite dependencies:");
      for (final MavenElisionReportSnapshot.CveFinding finding :
          snapshot.inactivePreconditionCves()) {
        lines.add(BULLET + finding.cveId() + " " + finding.coordinate());
      }
    }
    if (snapshot.potentiallyConservativeCves().isEmpty()) {
      lines.add("Potentially conservative CVE exclusions: none detected");
    } else {
      lines.add("Potentially conservative CVE exclusions:");
      for (final MavenElisionReportSnapshot.ConservativeCveFinding finding :
          snapshot.potentiallyConservativeCves()) {
        lines.add(BULLET + finding.cveId() + " " + finding.coordinate());
        lines.add("    Reason: " + finding.reason());
        lines.add(
            "    Actionable POM override to certify if absent classes do not apply to your"
                + " version:");
        for (final String overrideLine : finding.pomOverrideSnippet().split("\n")) {
          lines.add("      " + overrideLine);
        }
      }
    }
    lines.addAll(
        MediatedGraphReportRenderer.render(snapshot.mediatedGraph(), snapshot.projectGav()));
    return List.copyOf(lines);
  }

  static String formatBytes(final long bytes) {
    if (bytes < 0) {
      throw new IllegalArgumentException("bytes must not be negative");
    }
    double amount = bytes;
    int unit = 0;
    while (amount >= 1024.0 && unit < BYTE_UNITS.length - 1) {
      amount /= 1024.0;
      unit++;
    }
    return unit == 0
        ? bytes + " B"
        : String.format(Locale.ROOT, "%.2f %s", amount, BYTE_UNITS[unit]);
  }
}
