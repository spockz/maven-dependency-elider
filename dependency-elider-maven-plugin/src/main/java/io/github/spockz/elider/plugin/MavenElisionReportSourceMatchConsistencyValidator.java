// WHY: Binds saved physical class rows to the source claim that produced each review lead.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.correspondence.SourceClaimPathMatcher;
import java.io.IOException;
import java.util.List;

/** Validates consistency between a physical class match and its saved file claim. */
final class MavenElisionReportSourceMatchConsistencyValidator {
  private MavenElisionReportSourceMatchConsistencyValidator() {}

  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  static void validate(
      final String physicalEntry,
      final int tier,
      final String classEntry,
      final String sourceFile,
      final String programFile,
      final String packageComparison) {
    validatePhysicalClass(physicalEntry, tier, classEntry);
    validateSourceClaim(classEntry, sourceFile, programFile, packageComparison);
  }

  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  static void validateRow(
      final List<String> programFiles,
      final String physicalEntry,
      final int tier,
      final String classEntry,
      final String sourceFile,
      final String programFile,
      final String packageComparison) {
    validate(physicalEntry, tier, classEntry, sourceFile, programFile, packageComparison);
    if (!programFiles.contains(programFile)) {
      throw new IllegalArgumentException(
          "Elision report source match must reference a saved programFiles claim");
    }
  }

  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  static void validateJson(
      final List<String> programFiles,
      final String physicalEntry,
      final int tier,
      final String classEntry,
      final String sourceFile,
      final String programFile,
      final String packageComparison)
      throws IOException {
    try {
      validateRow(
          programFiles,
          physicalEntry,
          tier,
          classEntry,
          sourceFile,
          programFile,
          packageComparison);
    } catch (final IllegalArgumentException exception) {
      throw new IOException(exception.getMessage(), exception);
    }
  }

  private static void validatePhysicalClass(
      final String physicalEntry, final int tier, final String classEntry) {
    final String tierPrefix = tier == 0 ? "" : "META-INF/versions/" + tier + "/";
    if (!hasCanonicalTierPath(physicalEntry, tierPrefix, tier)) {
      throw new IllegalArgumentException(
          "Elision report source match physical entry conflicts with tier");
    }
    final String logicalEntry = physicalEntry.substring(tierPrefix.length());
    final String expectedEntry = classEntry.replace('.', '/') + ".class";
    if (!logicalEntry.equals(expectedEntry)
        || !SourceClaimPathMatcher.isTopLevelClassName(classEntry)) {
      throw new IllegalArgumentException(
          "Elision report source match class conflicts with physical entry");
    }
  }

  private static void validateSourceClaim(
      final String classEntry,
      final String sourceFile,
      final String programFile,
      final String packageComparison) {
    final String classPackage = SourceClaimPathMatcher.classPackage(classEntry);
    if (!sourceClaimMatches(classEntry, classPackage, programFile, sourceFile, packageComparison)) {
      throw new IllegalArgumentException(
          "Elision report source match conflicts with its programFiles claim");
    }
  }

  private static boolean sourceClaimMatches(
      final String classEntry,
      final String classPackage,
      final String programFile,
      final String sourceFile,
      final String packageComparison) {
    return sourceFile.endsWith(".java")
        && !sourceFile.contains("/")
        && !sourceFile.contains("\\")
        && SourceClaimPathMatcher.isSupportedJavaSourceClaim(programFile)
        && SourceClaimPathMatcher.basename(programFile).equals(sourceFile)
        && SourceClaimPathMatcher.hasPackageSuffix(programFile, classPackage)
        && packageComparison.equals(
            SourceClaimPathMatcher.packageComparison(programFile, classEntry));
  }

  private static boolean hasCanonicalTierPath(
      final String physicalEntry, final String tierPrefix, final int tier) {
    return !physicalEntry.startsWith("/")
        && !physicalEntry.contains("\\")
        && physicalEntry.startsWith(tierPrefix)
        && !(tier == 0 && physicalEntry.startsWith("META-INF/versions/"))
        && physicalEntry.endsWith(".class")
        && !hasInvalidPathSegments(physicalEntry.substring(tierPrefix.length()));
  }

  private static boolean hasInvalidPathSegments(final String path) {
    for (final String segment : path.split("/", -1)) {
      if (segment.isBlank() || ".".equals(segment) || "..".equals(segment)) {
        return true;
      }
    }
    return false;
  }
}
