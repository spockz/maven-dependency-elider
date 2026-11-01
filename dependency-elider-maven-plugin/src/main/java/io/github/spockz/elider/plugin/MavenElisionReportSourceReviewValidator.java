// WHY: Keeps saved source-review identity and coherence checks shared across construction and I/O.

package io.github.spockz.elider.plugin;

import java.util.List;

/** Validates typed source-review rows before they enter or leave a report snapshot. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class MavenElisionReportSourceReviewValidator {
  private MavenElisionReportSourceReviewValidator() {}

  static void validate(
      final List<MavenElisionReportSnapshot.SourceReviewFinding> findings,
      final boolean snapshotAssumption) {
    for (final MavenElisionReportSnapshot.SourceReviewFinding finding : findings) {
      validateFinding(finding, snapshotAssumption);
    }
  }

  static void validateFinding(
      final MavenElisionReportSnapshot.SourceReviewFinding finding,
      final boolean snapshotAssumption) {
    validateFinding(
        finding.coordinate(),
        finding.programFiles(),
        finding.matches(),
        finding.conventionalLayoutAssumed(),
        snapshotAssumption);
  }

  static void validateFinding(
      final String coordinate,
      final List<String> programFiles,
      final List<MavenElisionReportSnapshot.SourceReviewMatch> matches,
      final boolean rowAssumption,
      final boolean snapshotAssumption) {
    MavenElisionReportSourceCoordinateValidator.validate(coordinate);
    if (rowAssumption != snapshotAssumption) {
      throw new IllegalArgumentException(
          "Elision report source review assumption must match snapshot flag");
    }
    for (final MavenElisionReportSnapshot.SourceReviewMatch match : matches) {
      MavenElisionReportSourceMatchConsistencyValidator.validateRow(
          programFiles,
          match.physicalJarEntry(),
          match.multiReleaseTier(),
          match.classEntry(),
          match.sourceFileAttribute(),
          match.programFile(),
          match.packagePathComparison());
    }
  }

  static void validateMatch(
      final String programFile,
      final String physicalJarEntry,
      final int multiReleaseTier,
      final String classEntry,
      final String sourceFileAttribute,
      final String packagePathComparison) {
    MavenElisionReportSourceMatchConsistencyValidator.validate(
        physicalJarEntry,
        multiReleaseTier,
        classEntry,
        sourceFileAttribute,
        programFile,
        packagePathComparison);
  }
}
