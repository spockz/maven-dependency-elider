// WHY: Renders advisory associations separately from findings that carry proof classifications.

package io.github.spockz.elider.plugin;

import java.util.ArrayList;
import java.util.List;

/** Formats report-only package and heuristic advisory rows. */
final class MavenElisionReportAdvisoryRenderer {
  /** Report bullet formatting. */
  private static final String BULLET = "  - ";

  /** Explicit text for absent optional review data. */
  private static final String NONE = "none";

  private MavenElisionReportAdvisoryRenderer() {}

  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  static List<String> render(final MavenElisionReportSnapshot.AdvisoryReview review) {
    if (review.packageAdvisories().isEmpty() && review.heuristicAdvisories().isEmpty()) {
      return List.of();
    }
    final List<String> lines = new ArrayList<>();
    lines.add("Advisory associations (review only; inventory disposition is not impact proof):");
    review.packageAdvisories().forEach(finding -> renderPackage(finding, lines));
    review.heuristicAdvisories().forEach(finding -> renderHeuristic(finding, lines));
    return List.copyOf(lines);
  }

  private static void renderPackage(
      final MavenElisionReportSnapshot.PackageAdvisoryFinding finding, final List<String> lines) {
    lines.add(
        BULLET
            + finding.osvId()
            + " "
            + finding.coordinate()
            + " ["
            + finding.inventoryDisposition()
            + "]");
    lines.add("    Origin: OSV " + finding.ecosystem() + " / " + finding.packageName());
    lines.add("    Aliases: " + (finding.aliases().isEmpty() ? NONE : finding.aliases()));
    lines.add(
        "    Affected-version applicability: "
            + finding.applicability()
            + " ("
            + finding.applicabilityRationale()
            + ")");
    if (!finding.affectedVersions().isEmpty()) {
      lines.add("    OSV versions: " + finding.affectedVersions());
    }
    if (!finding.ranges().isEmpty()) {
      lines.add("    OSV ranges: " + finding.ranges());
    }
  }

  private static void renderHeuristic(
      final MavenElisionReportSnapshot.HeuristicAdvisoryFinding finding, final List<String> lines) {
    lines.add(
        BULLET
            + finding.osvId()
            + (finding.cveId() == null ? "" : " / " + finding.cveId())
            + " "
            + finding.coordinate()
            + " ["
            + finding.inventoryDisposition()
            + "]");
    lines.add(
        "    Heuristic origin: "
            + finding.origin()
            + " / "
            + finding.sourceRecordId()
            + " ("
            + finding.confidence()
            + ")");
    lines.add(
        "    Affected-version applicability: "
            + finding.applicability()
            + " ("
            + finding.applicabilityRationale()
            + ")");
    lines.add(
        "    Heuristic candidate scope: "
            + finding.versionRangeSpec()
            + " (not used as raw OSV applicability)");
    lines.add("    Source URL: " + (finding.sourceUrl() == null ? NONE : finding.sourceUrl()));
    lines.add("    Candidate classes: " + finding.candidateClasses());
    lines.add("    Candidate dependencies: " + finding.candidateDependencies());
    lines.add(
        "    Verify the source claim and exact original artifact before adding an exact POM"
            + " mapping; candidates do not establish a complete class set.");
  }
}
