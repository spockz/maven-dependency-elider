/* WHY: Represents class, file, and routine locators in one logical code group. */

package io.github.spockz.elider.model;

import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;

/** One locator without implying attribution or physical verification succeeded. */
public record CodeReference(Kind kind, String value, Set<String> originalValues)
    implements Comparable<CodeReference> {
  /** Kinds of supported code locator. */
  public enum Kind {
    CLASS_NAME,
    SOURCE_FILE,
    ROUTINE
  }

  /** Validates canonical identity and retains original spellings. */
  public CodeReference {
    Objects.requireNonNull(kind, "kind");
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException("value must not be blank");
    }
    if (kind == Kind.SOURCE_FILE) {
      value = normalizePath(value);
    } else {
      value = value.trim();
    }
    Objects.requireNonNull(originalValues, "originalValues");
    final Set<String> originals = new TreeSet<>();
    for (final String original : originalValues) {
      if (original == null || original.isBlank()) {
        throw new IllegalArgumentException("originalValues must contain non-blank values");
      }
      final String normalizedOriginal =
          kind == Kind.SOURCE_FILE ? normalizePath(original) : original.trim();
      if (!value.equals(normalizedOriginal)) {
        throw new IllegalArgumentException(
            "originalValues must normalize to the declared locator identity");
      }
      originals.add(original);
    }
    if (originals.isEmpty()) {
      throw new IllegalArgumentException("originalValues must not be empty");
    }
    originalValues = java.util.Collections.unmodifiableSet(originals);
  }

  /** Creates a reference from one original spelling. */
  public CodeReference(final Kind kind, final String value) {
    this(kind, value, Set.of(value));
  }

  /** Creates a class-name claim. */
  public static CodeReference className(final String value) {
    return new CodeReference(Kind.CLASS_NAME, value);
  }

  /** Creates a source-file claim with normalized separators and syntactic segments. */
  public static CodeReference sourceFile(final String value) {
    return new CodeReference(Kind.SOURCE_FILE, value);
  }

  /** Creates a routine claim, retaining owner and supplied signature text. */
  public static CodeReference routine(final String value) {
    return new CodeReference(Kind.ROUTINE, value);
  }

  /** Combines equivalent normalized locators while retaining all source spellings. */
  public CodeReference withOriginalValues(final Set<String> values) {
    final Set<String> combined = new TreeSet<>(originalValues);
    combined.addAll(values);
    return new CodeReference(kind, value, combined);
  }

  private static String normalizePath(final String path) {
    final String unified = path.replace('\\', '/');
    final boolean absolute = unified.startsWith("/");
    String normalizedPath = String.join("/", normalizeSegments(unified));
    normalizedPath = stripRecognizedSourceRoot(normalizedPath, absolute);
    if (absolute) {
      normalizedPath = "/" + normalizedPath;
    }
    if (normalizedPath.isBlank()) {
      throw new IllegalArgumentException("source-file path must identify a file");
    }
    return normalizedPath;
  }

  private static String stripRecognizedSourceRoot(final String path, final boolean absolute) {
    if (absolute) {
      return path;
    }
    for (final String sourceRoot :
        java.util.List.of(
            "src/main/java/", "src/test/java/", "src/main/kotlin/", "src/test/kotlin/")) {
      if (path.startsWith(sourceRoot)) {
        return path.substring(sourceRoot.length());
      }
    }
    return path;
  }

  private static java.util.Deque<String> normalizeSegments(final String path) {
    final java.util.Deque<String> normalized = new java.util.ArrayDeque<>();
    for (final String segment : path.split("/")) {
      if (segment.isEmpty() || ".".equals(segment)) {
        continue;
      }
      if ("..".equals(segment) && !normalized.isEmpty() && !"..".equals(normalized.getLast())) {
        normalized.removeLast();
      } else {
        normalized.addLast(segment);
      }
    }
    return normalized;
  }

  @Override
  public int compareTo(final CodeReference other) {
    final int kindOrder = kind.compareTo(other.kind);
    if (kindOrder != 0) {
      return kindOrder;
    }
    return value.compareTo(other.value);
  }

  @Override
  public boolean equals(final Object other) {
    return other instanceof CodeReference reference
        && kind == reference.kind
        && value.equals(reference.value);
  }

  @Override
  public int hashCode() {
    return Objects.hash(kind, value);
  }
}
