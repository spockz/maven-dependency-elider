/* WHY: Converts Native Image resource globs with the JDK21 parser's wildcard grammar. */

package io.github.spockz.elider.plugin;

import java.util.regex.Pattern;

/** Compiles the bounded glob syntax used by Graal resource configuration. */
final class NativeImageGlobPattern {
  /** WHY: The converter quotes all input outside these three wildcard states. */
  private static final int START = 0;

  /** WHY: Single-star wildcards may not cross resource path separators. */
  private static final int STAR = 1;

  /** WHY: Double-star wildcards may cross resource path separators. */
  private static final int DOUBLE_STAR = 2;

  /** WHY: This state makes double-star followed by slash match zero or more segments. */
  private static final int DOUBLE_STAR_SLASH = 3;

  private NativeImageGlobPattern() {
    throw new AssertionError("static Native Image glob compiler");
  }

  /* package */ static Pattern compile(final String glob) {
    return Pattern.compile(toRegex(glob));
  }

  private static String toRegex(final String glob) {
    final String source = glob + '#';
    final StringBuilder regex = new StringBuilder();
    int quoteStart = 0;
    int previous = START;
    for (int index = 0; index < source.length(); index++) {
      final int current = next(previous, source.charAt(index));
      if (previous == START && current != START && quoteStart != index) {
        regex.append(Pattern.quote(source.substring(quoteStart, index)));
      }
      final boolean consecutive = previous == DOUBLE_STAR_SLASH && current != START;
      final boolean wildcardEnd = previous != START && current == START;
      if (wildcardEnd || consecutive) {
        regex.append(wildcardRegex(previous));
        quoteStart = index;
      }
      previous = current;
    }
    final String withoutSentinel = source.substring(0, source.length() - 1);
    if (quoteStart < withoutSentinel.length()) {
      regex.append(Pattern.quote(withoutSentinel.substring(quoteStart)));
    }
    return regex.toString();
  }

  private static int next(final int state, final char character) {
    if (state == START || state == DOUBLE_STAR_SLASH) {
      return character == '*' ? STAR : START;
    }
    if (state == STAR) {
      return character == '*' ? DOUBLE_STAR : START;
    }
    if (state == DOUBLE_STAR) {
      return character == '/' ? DOUBLE_STAR_SLASH : START;
    }
    throw new IllegalArgumentException("Unknown glob state: " + state);
  }

  private static String wildcardRegex(final int state) {
    return switch (state) {
      case STAR -> "[^/]*";
      case DOUBLE_STAR -> ".*";
      case DOUBLE_STAR_SLASH -> "([^/]*(/|$))*";
      default -> "";
    };
  }
}
