// WHY: Validates source-review coordinates against the one canonical Maven diagnostic form.

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.spockz.elider.model.ArtifactCoordinate;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

/** Validates exact Maven coordinate text used by persisted source-review rows. */
final class MavenElisionReportSourceCoordinateValidator {
  private MavenElisionReportSourceCoordinateValidator() {}

  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  static void validate(final JsonNode value) throws IOException {
    if (value == null || !value.isTextual()) {
      throw new IOException("Elision report source review coordinate must be canonical Maven text");
    }
    try {
      validate(value.textValue());
    } catch (final IllegalArgumentException exception) {
      throw new IOException(exception.getMessage(), exception);
    }
  }

  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  static void validate(final String text) {
    final ArtifactCoordinate coordinate;
    try {
      coordinate = parseCoordinate(text);
    } catch (final IOException exception) {
      throw new IllegalArgumentException(exception.getMessage(), exception);
    }
    if (!coordinate.toString().equals(text)) {
      throw new IllegalArgumentException(
          "Elision report source review coordinate is not canonical GAVCE text");
    }
  }

  private static ArtifactCoordinate parseCoordinate(final String text) throws IOException {
    final int suffix = coordinateSuffix(text);
    final List<String> parts = coordinateParts(text, suffix);
    if (parts.size() != 4 && parts.size() != 5) {
      throw new IOException("Elision report source review coordinate must be exact GAVCE text");
    }
    validateComponents(parts);
    return toCoordinate(parts, coordinateScope(text, suffix));
  }

  private static int coordinateSuffix(final String text) throws IOException {
    final int suffix = text.lastIndexOf(" (");
    if (suffix <= 0 || !text.endsWith(")")) {
      throw new IOException("Elision report source review coordinate must include its scope");
    }
    return suffix;
  }

  private static List<String> coordinateParts(final String text, final int suffix) {
    return Arrays.asList(text.substring(0, suffix).split(":", -1));
  }

  private static String coordinateScope(final String text, final int suffix) throws IOException {
    final String scope = text.substring(suffix + 2, text.length() - 1);
    if (scope.isBlank() || scope.chars().anyMatch(Character::isWhitespace)) {
      throw new IOException("Elision report source review coordinate has an invalid scope suffix");
    }
    return scope;
  }

  private static void validateComponents(final List<String> parts) throws IOException {
    if (parts.stream().anyMatch(MavenElisionReportSourceCoordinateValidator::isInvalidComponent)) {
      throw new IOException("Elision report source review coordinate has a blank component");
    }
  }

  private static boolean isInvalidComponent(final String part) {
    return part.isBlank() || part.chars().anyMatch(Character::isWhitespace);
  }

  private static ArtifactCoordinate toCoordinate(final List<String> parts, final String scope) {
    final String classifier = parts.size() == 5 ? parts.get(3) : "";
    return new ArtifactCoordinate(
        parts.get(0), parts.get(1), parts.getLast(), parts.get(2), classifier, scope);
  }
}
