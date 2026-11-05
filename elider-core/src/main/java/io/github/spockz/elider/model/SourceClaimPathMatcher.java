// WHY: Keeps basename and package-suffix comparisons review-only instead of treating them as proof.

package io.github.spockz.elider.model;

import java.util.ArrayDeque;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/** Applies conservative checks to source-file paths. */
@SuppressWarnings("PMD.GodClass")
public final class SourceClaimPathMatcher {
  /** Java source suffix retained by structured source claims. */
  private static final String JAVA_SUFFIX = ".java";

  /** Relative path parent segment removed during normalization. */
  private static final String PARENT_PATH_SEGMENT = "..";

  /** Source roots accepted when conventional layout is assumed. */
  private static final List<String> CONVENTIONAL_SOURCE_ROOTS =
      List.of("src/main/java/", "src/test/java/", "src/main/kotlin/", "src/test/kotlin/");

  private SourceClaimPathMatcher() {}

  /** Checks whether a claimed path is an admissible relative Java source path. */
  public static boolean isSupportedJavaSourceClaim(final String sourceClaim) {
    return sourceClaim.endsWith(JAVA_SUFFIX)
        && !sourceClaim.contains("://")
        && !sourceClaim.startsWith("/");
  }

  /** Checks whether a binary name denotes a supported top-level class. */
  public static boolean isTopLevelClassName(final String classEntry) {
    return classEntry.matches("[A-Za-z_$][A-Za-z0-9_$]*(\\.[A-Za-z_$][A-Za-z0-9_$]*)+")
        && !classEntry.contains("$")
        && !classEntry.endsWith(".package-info")
        && !classEntry.endsWith(".module-info")
        && !"package-info".equals(classEntry)
        && !"module-info".equals(classEntry);
  }

  /** Returns the final path segment using either slash convention. */
  public static String basename(final String path) {
    final String normalized = path.replace('\\', '/');
    final int separator = normalized.lastIndexOf('/');
    return normalized.substring(separator + 1);
  }

  /** Checks path/package suffix agreement without asserting exact source location. */
  public static boolean hasPackageSuffix(final String sourceClaim, final String classPackage) {
    final String normalized = sourceClaim.replace('\\', '/');
    final int basenameSeparator = normalized.lastIndexOf('/');
    if (basenameSeparator <= 0) {
      return false;
    }
    final String parent = normalized.substring(0, basenameSeparator);
    final String[] pathSegments = parent.split("/");
    final String[] packageSegments = classPackage.split("\\.");
    if (pathSegments.length < packageSegments.length) {
      return false;
    }
    for (final String segment : pathSegments) {
      if (segment.isBlank() || ".".equals(segment) || "..".equals(segment)) {
        return false;
      }
    }
    for (int index = 0; index < packageSegments.length; index++) {
      if (!packageSegments[packageSegments.length - index - 1].equals(
          pathSegments[pathSegments.length - index - 1])) {
        return false;
      }
    }
    return true;
  }

  /** Returns the package portion of a binary class name. */
  public static String classPackage(final String classEntry) {
    final int separator = classEntry.lastIndexOf('.');
    return separator < 0 ? "" : classEntry.substring(0, separator);
  }

  /** Describes the limited package suffix comparison for review-only findings. */
  public static String packageComparison(final String sourceClaim, final String classEntry) {
    return "source path package suffix matches class package "
        + classPackage(classEntry)
        + "; exact source location and sibling class set remain unverified ("
        + sourceClaim
        + ")";
  }

  /** Returns normalized package-relative paths from the claim's original spellings. */
  @SuppressWarnings({"PMD.CognitiveComplexity", "PMD.CyclomaticComplexity"})
  /* default */ static Set<String> packageRelativeSourcePaths(
      final CodeReference reference, final boolean conventionalLayoutAssumed) {
    if (reference.kind() != CodeReference.Kind.SOURCE_FILE) {
      return Set.of();
    }
    final Set<String> paths = new TreeSet<>();
    for (final String original : reference.originalValues()) {
      String path = normalizeRelativePath(original);
      if (path == null || !isSupportedJavaSourceClaim(path)) {
        continue;
      }
      if (hasConventionalSourceRoot(path)) {
        if (!conventionalLayoutAssumed) {
          continue;
        }
        for (final String root : CONVENTIONAL_SOURCE_ROOTS) {
          if (path.startsWith(root)) {
            path = path.substring(root.length());
            break;
          }
        }
      }
      final String[] segments = path.split("/", -1);
      if (hasJavaPackageSegments(segments)) {
        paths.add(path);
      }
    }
    return java.util.Collections.unmodifiableSet(paths);
  }

  /* default */ static boolean containsConventionalSourceRoot(final CodeReference reference) {
    return reference.originalValues().stream()
        .map(SourceClaimPathMatcher::normalizeRelativePath)
        .filter(java.util.Objects::nonNull)
        .anyMatch(SourceClaimPathMatcher::hasConventionalSourceRoot);
  }

  private static boolean hasJavaPackageSegments(final String... segments) {
    if (segments.length < 2 || java.util.Arrays.stream(segments).anyMatch(String::isBlank)) {
      return false;
    }
    for (int index = 0; index < segments.length - 1; index++) {
      if (!isJavaIdentifier(segments[index])) {
        return false;
      }
    }
    return true;
  }

  private static boolean isJavaIdentifier(final String segment) {
    if (segment.isEmpty()) {
      return false;
    }
    int offset = 0;
    final int first = segment.codePointAt(offset);
    if (!Character.isJavaIdentifierStart(first)) {
      return false;
    }
    offset += Character.charCount(first);
    while (offset < segment.length()) {
      final int codePoint = segment.codePointAt(offset);
      if (!Character.isJavaIdentifierPart(codePoint)) {
        return false;
      }
      offset += Character.charCount(codePoint);
    }
    return true;
  }

  private static boolean hasConventionalSourceRoot(final String path) {
    return CONVENTIONAL_SOURCE_ROOTS.stream().anyMatch(path::startsWith);
  }

  private static String normalizeRelativePath(final String original) {
    final String path = original.replace('\\', '/');
    if (path.startsWith("/") || path.contains("://")) {
      return null;
    }
    final java.util.Deque<String> segments = new ArrayDeque<>();
    for (final String segment : path.split("/")) {
      if (segment.isEmpty() || ".".equals(segment)) {
        continue;
      }
      if (segment.isBlank()) {
        return null;
      }
      if (PARENT_PATH_SEGMENT.equals(segment)) {
        if (segments.isEmpty()) {
          return null;
        }
        segments.removeLast();
      } else {
        segments.addLast(segment);
      }
    }
    return String.join("/", segments);
  }
}
