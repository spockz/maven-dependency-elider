/* WHY: Validates exact staging files before excluding them from declared resource roots. */

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/** Validates known output stages as generated JSON objects. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class MavenPreconditionStages {
  /** Parses stages before their exact paths are omitted from provider scanning. */
  private static final ObjectMapper JSON = new ObjectMapper();

  private MavenPreconditionStages() {}

  static void validateIfPresent(final List<Path> stages) throws IOException {
    for (final Path stage : stages) {
      if (!MavenPreconditionOutputState.definitelyAbsent(stage)) {
        validateStage(stage);
      }
    }
  }

  static void validateExpected(final List<Path> stages, final List<Path> required)
      throws IOException {
    for (final Path stage : stages) {
      if (required.contains(stage)) {
        validateStage(stage);
      } else if (!MavenPreconditionOutputState.definitelyAbsent(stage)) {
        throw new IOException("Unexpected generated output staging file: " + stage);
      }
    }
  }

  static void validateGenerated(final List<Path> stages) throws IOException {
    for (final Path stage : stages) {
      if (MavenPreconditionOutputState.definitelyAbsent(stage)) {
        throw new IOException("Known generated output staging file is missing: " + stage);
      }
      validateStage(stage);
    }
  }

  private static void validateStage(final Path stage) throws IOException {
    validatePath(stage);
    requireJsonObject(parseJsonObject(stage), stage);
  }

  private static void validatePath(final Path stage) throws IOException {
    if (!Files.isRegularFile(stage)
        || !MavenPreconditionOutputState.canonicalizedPath(stage).equals(stage)) {
      throw new IOException("Known generated output staging file is not canonical: " + stage);
    }
  }

  private static JsonNode parseJsonObject(final Path stage) throws IOException {
    final JsonNode document;
    final boolean hasTrailingData;
    try (JsonParser parser = JSON.getFactory().createParser(stage.toFile())) {
      document = JSON.readTree(parser);
      hasTrailingData = parser.nextToken() != null;
    } catch (final IOException failure) {
      throw new IOException("Known generated output is not valid JSON: " + stage, failure);
    }
    if (hasTrailingData) {
      throw new IOException("Trailing data in known generated output: " + stage);
    }
    return document;
  }

  private static void requireJsonObject(final JsonNode document, final Path stage)
      throws IOException {
    if (document == null || !document.isObject()) {
      throw new IOException("Known generated output is not a JSON object: " + stage);
    }
  }
}
