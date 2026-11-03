// WHY: Wraps text lines at a fixed column width preserving leading and hanging
// indentation.

package io.github.spockz.elider.plugin;

import java.util.ArrayList;
import java.util.List;

/**
 * Utility for wrapping report text lines at a configurable column width.
 *
 * <p>Preserves indentation and aligns continuation lines under bullet items.
 */
@SuppressWarnings({"PMD.CommentDefaultAccessModifier", "PMD.CyclomaticComplexity"})
final class WordWrapFormatter {
  /** Bullet prefix marker recognized for hanging indent calculation. */
  private static final String BULLET = "  - ";

  /** Subsequent hanging indent when wrapping a bullet item. */
  private static final String BULLET_HANGING_INDENT = "    ";

  private WordWrapFormatter() {
    throw new AssertionError("No instances");
  }

  /**
   * Wraps a line of text if its length exceeds {@code maxWidth}.
   *
   * @param line input line of text
   * @param maxWidth maximum column width before wrapping
   * @return list of wrapped lines
   */
  static List<String> wrap(final String line, final int maxWidth) {
    if (line == null || line.length() <= maxWidth) {
      return line == null ? List.of() : List.of(line);
    }

    final String firstPrefix;
    final String restPrefix;
    final String content;

    if (line.startsWith(BULLET)) {
      firstPrefix = BULLET;
      restPrefix = BULLET_HANGING_INDENT;
      content = line.substring(BULLET.length());
    } else {
      final int indent = leadingSpaces(line);
      firstPrefix = line.substring(0, indent);
      restPrefix = firstPrefix;
      content = line.substring(indent);
    }

    final String[] words = content.split(" ");
    final List<String> lines = new ArrayList<>();
    final StringBuilder currentLine = new StringBuilder(firstPrefix);
    String currentPrefix = firstPrefix;

    for (final String word : words) {
      if (word.isEmpty()) {
        continue;
      }
      if (currentLine.length() == currentPrefix.length()) {
        currentLine.append(word);
      } else if (currentLine.length() + 1 + word.length() <= maxWidth) {
        currentLine.append(' ').append(word);
      } else {
        lines.add(currentLine.toString());
        currentPrefix = restPrefix;
        currentLine.setLength(0);
        currentLine.append(restPrefix).append(word);
      }
    }

    if (currentLine.length() > 0) {
      lines.add(currentLine.toString());
    }

    return List.copyOf(lines);
  }

  private static int leadingSpaces(final String line) {
    int count = 0;
    while (count < line.length() && line.charAt(count) == ' ') {
      count++;
    }
    return count;
  }
}
