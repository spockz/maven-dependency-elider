// WHY: Persists test-only observations for replay without reopening dependency archives.

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import io.github.spockz.elider.model.HexDigest;
import java.io.IOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

/** Strict codec for the independent test-view report format. */
@SuppressWarnings({
  "PMD.CommentDefaultAccessModifier",
  "PMD.CommentSize",
  "PMD.TestClassWithoutTestCases"
})
final class TestViewReportWriter {
  /** Rejects duplicate keys during replay and fixes deterministic indentation on write. */
  private static final ObjectMapper JSON =
      new ObjectMapper()
          .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
          .enable(SerializationFeature.INDENT_OUTPUT);

  private TestViewReportWriter() {}

  static void write(final Path output, final TestViewReportSnapshot snapshot) throws IOException {
    final Path absolute = output.toAbsolutePath().normalize();
    final Path parent = absolute.getParent();
    if (parent == null) {
      throw new IOException("Test-view report path has no parent directory: " + absolute);
    }
    Files.createDirectories(parent);
    final Path temporary = Files.createTempFile(parent, ".test-view-report-", ".json.tmp");
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
            "Filesystem cannot atomically publish test-view report: " + absolute, exception);
      }
    } finally {
      Files.deleteIfExists(temporary);
    }
  }

  static TestViewReportSnapshot read(final Path input) throws IOException {
    final Path absolute = input.toAbsolutePath().normalize();
    if (!Files.isRegularFile(absolute)) {
      throw new IOException("No test-view report exists at " + absolute);
    }
    final JsonNode payload;
    try (JsonParser parser = JSON.getFactory().createParser(absolute.toFile())) {
      payload = JSON.readTree(parser);
      if (parser.nextToken() != null) {
        throw new IOException("Trailing data in test-view report: " + absolute);
      }
    }
    try {
      return TestViewReportPayloadValidator.decode(payload);
    } catch (final IllegalArgumentException exception) {
      throw new IOException(
          "Invalid test-view report: " + absolute + ": " + exception.getMessage(), exception);
    }
  }

  static String sha256(final Path path) throws IOException {
    return HexDigest.sha256(path);
  }
}
