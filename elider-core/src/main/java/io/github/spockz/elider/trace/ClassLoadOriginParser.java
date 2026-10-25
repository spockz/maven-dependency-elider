/* WHY: Interprets only exact local archive source tokens so ambiguous class-load records remain
 * class-only evidence. */

package io.github.spockz.elider.trace;

import java.net.URI;
import java.nio.file.Path;
import java.util.Locale;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Extracts an unambiguous local JAR path from one unified-log class-load payload. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class ClassLoadOriginParser {
  /** Matches source field markers even when a field has no value. */
  private static final Pattern SOURCE_FIELD = Pattern.compile("(?:^|\\s)source:");

  /** Prevents construction of the parser utility. */
  private ClassLoadOriginParser() {}

  /** Returns a local absolute JAR path when one supported source is present. */
  static Optional<Path> parseJarPath(final String payload) {
    final Matcher sourceField = SOURCE_FIELD.matcher(payload);
    if (!sourceField.find()) {
      return Optional.empty();
    }
    final int sourceValueStart = sourceField.end();
    if (sourceField.find()) {
      return Optional.empty();
    }
    final String sourceValue = payload.substring(sourceValueStart).trim();
    if (sourceValue.isEmpty() || sourceValue.chars().anyMatch(Character::isWhitespace)) {
      return Optional.empty();
    }
    try {
      return localJarPath(URI.create(sourceValue));
    } catch (final IllegalArgumentException exception) {
      return Optional.empty();
    }
  }

  private static Optional<Path> localJarPath(final URI uri) {
    if (!"file".equalsIgnoreCase(uri.getScheme())
        || !uri.isAbsolute()
        || uri.getRawAuthority() != null
        || uri.getRawQuery() != null
        || uri.getRawFragment() != null) {
      return Optional.empty();
    }
    final Path path = Path.of(uri).normalize();
    final Path fileName = path.getFileName();
    if (!path.isAbsolute()
        || fileName == null
        || !fileName.toString().toLowerCase(Locale.ROOT).endsWith(".jar")) {
      return Optional.empty();
    }
    return Optional.of(path);
  }
}
