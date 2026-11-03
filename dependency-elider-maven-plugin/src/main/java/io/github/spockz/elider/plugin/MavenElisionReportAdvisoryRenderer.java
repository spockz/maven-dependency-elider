// WHY: Renders advisory associations separately from findings that carry proof classifications.

package io.github.spockz.elider.plugin;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

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
    if (!review.heuristicAdvisories().isEmpty()) {
      addWrapped(
          lines,
          "    Heuristic candidates are review leads; they do not establish a complete affected"
              + " class set.");
      addWrapped(
          lines,
          "    Add a POM mapping with HIGH only after verifying the source applies to the exact"
              + " artifact version and the listed classes form the complete affected set.");
      addWrapped(
          lines,
          "    The elider still checks the original and trimmed artifacts before publishing VEX."
              + " Keep unverified candidates review-only.");
    }
    if (hasRemovedAdvisory(review)) {
      addWrapped(
          lines,
          "    REMOVED means excluded from this project's subsequent classpaths; the cached JAR "
              + "is not deleted.");
    }
    final Set<String> heuristicAdvisoryKeys =
        review.heuristicAdvisories().stream()
            .map(h -> h.osvId() + ":" + h.coordinate())
            .collect(Collectors.toSet());
    review.packageAdvisories().stream()
        .filter(pkg -> !heuristicAdvisoryKeys.contains(pkg.osvId() + ":" + pkg.coordinate()))
        .forEach(finding -> renderPackage(finding, lines));
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
      lines.add(
          "    OSV ranges: "
              + finding.ranges().stream()
                  .map(MavenElisionReportAdvisoryRenderer::renderRange)
                  .collect(Collectors.joining(" | ")));
    }
  }

  private static boolean hasRemovedAdvisory(
      final MavenElisionReportSnapshot.AdvisoryReview review) {
    return review.packageAdvisories().stream()
            .anyMatch(
                finding ->
                    finding.inventoryDisposition()
                        == MavenVulnerabilityAssessment.InventoryDisposition.REMOVED)
        || review.heuristicAdvisories().stream()
            .anyMatch(
                finding ->
                    finding.inventoryDisposition()
                        == MavenVulnerabilityAssessment.InventoryDisposition.REMOVED);
  }

  private static String renderRange(final MavenElisionReportSnapshot.AffectedRange range) {
    final String repository = range.repo() == null ? "" : " for " + range.repo();
    final String events =
        range.events().stream()
            .map(MavenElisionReportAdvisoryRenderer::renderEvents)
            .collect(Collectors.joining("; "));
    return range.type()
        + " range"
        + repository
        + ": "
        + (events.isEmpty() ? "no boundary events" : events);
  }

  private static String renderEvents(final Map<String, String> event) {
    return event.entrySet().stream()
        .map(MavenElisionReportAdvisoryRenderer::renderEvent)
        .collect(Collectors.joining(", "));
  }

  private static String renderEvent(final Map.Entry<String, String> event) {
    return switch (event.getKey()) {
      case "introduced" -> "introduced at " + event.getValue();
      case "fixed" -> "fixed at " + event.getValue();
      case "last_affected" -> "last affected at " + event.getValue();
      case "limit" -> "limit at " + event.getValue();
      default -> event.getKey() + " = " + event.getValue();
    };
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
    final List<String> mappingSnippet = MavenHeuristicPomMappingSnippet.render(finding);
    if (!mappingSnippet.isEmpty()) {
      lines.add("    POM mapping template for this candidate:");
      for (final String snippetLine : mappingSnippet) {
        lines.add("      " + snippetLine);
      }
    }
  }

  private static void addWrapped(final List<String> lines, final String text) {
    lines.addAll(WordWrapFormatter.wrap(text, 80));
  }
}
