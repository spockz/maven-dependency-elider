// WHY: Keeps basename and package-suffix comparisons review-only instead of treating them as proof.

package io.github.spockz.elider.model;

/** Applies conservative path checks to source-file claims and class-file metadata. */
public final class SourceClaimPathMatcher {
  /** Java source suffix retained by structured source claims. */
  private static final String JAVA_SUFFIX = ".java";

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
}
