/* WHY: Centralizes JVM binary-name validation so trace formats agree on Unicode and hidden
 * classes. */

package io.github.spockz.elider.trace;

/** Validates JVM binary names and identifies hidden classes for trace filtering. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class TraceClassName {
  private TraceClassName() {}

  static boolean isValid(final String name) {
    if (name == null || name.isEmpty()) {
      return false;
    }
    final int marker = hiddenMarker(name);
    if (marker >= 0 && !isHexSuffix(name, marker + 3)) {
      return false;
    }
    final String ordinaryName = marker < 0 ? name : name.substring(0, marker);
    return isValidSegments(ordinaryName);
  }

  private static boolean isValidSegments(final String name) {
    boolean segmentStart = true;
    for (final int codePoint : name.codePoints().toArray()) {
      if (isSeparator(codePoint)) {
        if (segmentStart) {
          return false;
        }
        segmentStart = true;
      } else {
        if (!isIdentifierCodePoint(codePoint, segmentStart)) {
          return false;
        }
        segmentStart = false;
      }
    }
    return !segmentStart;
  }

  private static boolean isSeparator(final int codePoint) {
    return codePoint == '.' || codePoint == '/';
  }

  private static boolean isIdentifierCodePoint(final int codePoint, final boolean segmentStart) {
    return Character.isJavaIdentifierStart(codePoint) && segmentStart
        || Character.isJavaIdentifierPart(codePoint) && !segmentStart;
  }

  static boolean isHidden(final String name) {
    final int marker = hiddenMarker(name);
    return marker >= 0 && isHexSuffix(name, marker + 3) && isValid(name);
  }

  private static int hiddenMarker(final String name) {
    return Math.max(name.lastIndexOf("/0x"), name.lastIndexOf(".0x"));
  }

  private static boolean isHexSuffix(final String name, final int start) {
    if (start >= name.length()) {
      return false;
    }
    for (int index = start; index < name.length(); index++) {
      if (Character.digit(name.charAt(index), 16) < 0) {
        return false;
      }
    }
    return true;
  }
}
