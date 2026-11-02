// WHY: Persists elision metrics atomically and renders them in a later Maven invocation.

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import java.io.File;
import java.io.IOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.List;
import org.apache.maven.project.MavenProject;

/** Persists and reads validated elision summaries. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class MavenElisionReportWriter {
  /** Strict serializer shared by report snapshot reads and writes. */
  private static final ObjectMapper JSON =
      new ObjectMapper()
          .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
          .enable(SerializationFeature.INDENT_OUTPUT)
          .enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS)
          .enable(com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);

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
    MavenElisionReportSourceReviewValidator.validate(
        snapshot.sourceReviewFindings(), snapshot.assumeConventionalJavaSourceLayout());
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
    final JsonNode payload;
    try (JsonParser parser = JSON.getFactory().createParser(absolute.toFile())) {
      payload = JSON.readTree(parser);
      if (parser.nextToken() != null) {
        throw new IOException("Trailing data in elision report: " + absolute);
      }
    }
    return decodeSnapshot(payload, absolute);
  }

  private static MavenElisionReportSnapshot decodeSnapshot(
      final JsonNode payload, final Path absolute) throws IOException {
    MavenElisionReportPayloadValidator.validate(payload);
    final MavenElisionReportSnapshot snapshot;
    try {
      snapshot = JSON.treeToValue(payload, MavenElisionReportSnapshot.class);
    } catch (final IllegalArgumentException exception) {
      throw new IOException("Invalid elision report snapshot: " + absolute, exception);
    }
    if (snapshot == null) {
      throw new IOException("Elision report snapshot is empty: " + absolute);
    }
    try {
      MavenElisionReportSourceReviewValidator.validate(
          snapshot.sourceReviewFindings(), snapshot.assumeConventionalJavaSourceLayout());
    } catch (final IllegalArgumentException exception) {
      throw new IOException("Invalid elision report source-review data: " + absolute, exception);
    }
    return snapshot;
  }

  static List<String> render(final MavenElisionReportSnapshot snapshot) {
    return MavenElisionReportRenderer.render(snapshot);
  }

  static String formatBytes(final long bytes) {
    return MavenElisionReportRenderer.formatBytes(bytes);
  }
}
