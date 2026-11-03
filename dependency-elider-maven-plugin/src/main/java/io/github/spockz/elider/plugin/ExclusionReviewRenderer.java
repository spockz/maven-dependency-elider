// WHY: Explains repeated Maven exclusions as review findings without implying equivalent edits.

package io.github.spockz.elider.plugin;

import java.util.ArrayList;
import java.util.List;

/** Renders only saved review findings. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class ExclusionReviewRenderer {
  /** Indentation for report sections. */
  private static final String SECTION_INDENT = "  ";

  /** Indentation for report rows. */
  private static final String ITEM_INDENT = "    ";

  /** Indentation for row details. */
  private static final String DETAIL_INDENT = "      ";

  /** Indentation for exclusion origins. */
  private static final String EXCLUSION_INDENT = "        ";

  /** Saved state for declarations whose source provenance could not be established. */
  private static final String UNKNOWN_ORIGIN = "UNKNOWN";

  private ExclusionReviewRenderer() {}

  static List<String> render(final ExclusionReview review) {
    final List<String> lines = new ArrayList<>();
    if (!review.available()) {
      addWrapped(lines, SECTION_INDENT + "Exclusion review unavailable: " + review.unavailableReason());
      return List.copyOf(lines);
    }
    lines.add(SECTION_INDENT + "Repeated POM exclusions (advisory only):");
    appendCandidates(review.candidates(), lines);
    appendManagement(review.management(), lines);
    appendDiagnostics(review, lines);
    if (!review.candidates().isEmpty()) {
      addWrapped(
          lines,
          SECTION_INDENT
              + "Next step: review each listed dependency path and origin. If you want a reviewed"
              + " transitive component removed from this project's output, set"
              + " -Delide.banishedDependencies=<groupId>:<artifactId> and rerun"
              + " the Maven lifecycle, then inspect the applied-ban result. This does not edit"
              + " POM exclusions; a global ban can also remove content needed by downstream"
              + " consumers.");
    }
    addWrapped(
        lines,
        SECTION_INDENT
            + "Review only: Maven path exclusions change dependency collection and mediation; "
            + "a global ban changes this project's output and may remove content needed by "
            + "downstream consumers.");
    return List.copyOf(lines);
  }

  private static void appendCandidates(
      final List<ExclusionReview.Candidate> candidates, final List<String> lines) {
    if (candidates.isEmpty()) {
      lines.add(ITEM_INDENT + "none found across effective dependency paths");
    }
    for (final ExclusionReview.Candidate candidate : candidates) {
      lines.add(
          ITEM_INDENT
              + candidate.coordinate().groupId()
              + ":"
              + candidate.coordinate().artifactId()
              + " appears on "
              + candidate.count()
              + " effective dependency paths");
      for (final ExclusionRecommendations.Observation observation : candidate.declarations()) {
        final ExclusionRecommendations.Reference ref = observation.declaration();
        lines.add(
            DETAIL_INDENT
                + ref.groupId()
                + ":"
                + ref.artifactId()
                + ":"
                + ref.type()
                + ":"
                + ref.classifier()
                + " [row "
                + ref.ordinal()
                + ", "
                + origin(ref.origin())
                + "]");
        observation
            .exclusionOrigins()
            .forEach(value -> lines.add(EXCLUSION_INDENT + "exclusion origin: " + origin(value)));
      }
    }
  }

  private static void appendManagement(
      final List<ExclusionRecommendations.Declaration> management, final List<String> lines) {
    if (management.isEmpty()) {
      return;
    }
    lines.add(
        SECTION_INDENT
            + "Noncontributing dependency-management exclusions: "
            + management.size()
            + " row(s)");
    for (final ExclusionRecommendations.Declaration declaration : management) {
      final ExclusionRecommendations.Reference ref = declaration.reference();
      for (final ExclusionRecommendations.Exclusion exclusion : declaration.exclusions()) {
        lines.add(
            ITEM_INDENT
                + ref.groupId()
                + ":"
                + ref.artifactId()
                + ":"
                + ref.type()
                + ":"
                + ref.classifier()
                + " excludes "
                + exclusion.coordinate().groupId()
                + ":"
                + exclusion.coordinate().artifactId()
                + " [declaration "
                + origin(ref.origin())
                + "; exclusion "
                + origin(exclusion.origin())
                + "]");
      }
    }
  }

  private static void appendDiagnostics(final ExclusionReview review, final List<String> lines) {
    final List<String> diagnostics =
        ExclusionProvenancePayload.decode(review.snapshot()).diagnostics();
    final List<String> originDiagnostics =
        diagnostics.stream()
            .filter(value -> value.startsWith("Incomplete or ambiguous provenance"))
            .toList();
    final List<String> captureDiagnostics =
        diagnostics.stream()
            .filter(value -> !value.startsWith("Incomplete or ambiguous provenance"))
            .toList();
    if (!originDiagnostics.isEmpty()) {
      addWrapped(
          lines,
          SECTION_INDENT
              + "Exclusion provenance incomplete for "
              + originDiagnostics.size()
              + " dependency or exclusion origins. Maven supplied no source location/identity or"
              + " the location matched zero or multiple original POM rows. This advisory review"
              + " does not affect elision.");
      originDiagnostics.stream()
          .distinct()
          .limit(3)
          .map(ExclusionReviewRenderer::diagnostic)
          .forEach(value -> addWrapped(lines, ITEM_INDENT + value));
    }
    if (!captureDiagnostics.isEmpty()) {
      addWrapped(
          lines,
          SECTION_INDENT
              + "Exclusion capture warnings: "
              + captureDiagnostics.size()
              + " issue(s)");
      captureDiagnostics.stream()
          .distinct()
          .limit(3)
          .forEach(value -> addWrapped(lines, ITEM_INDENT + value));
    }
    if (!diagnostics.isEmpty()) {
      addWrapped(
          lines,
          SECTION_INDENT
              + "Full evidence is in the JSON snapshot fields"
              + " exclusionReview.snapshot.dependencies and exclusionReview.snapshot.diagnostics.");
    }
  }

  private static void addWrapped(final List<String> lines, final String text) {
    lines.addAll(WordWrapFormatter.wrap(text, 80));
  }

  private static String origin(final ExclusionRecommendations.Origin origin) {
    if (UNKNOWN_ORIGIN.equals(origin.kind())) {
      if (origin.line() < 1 || origin.column() < 1) {
        return "UNKNOWN provenance (source location unavailable)";
      }
      final String source = origin.source().isBlank() ? origin.modelId() : origin.source();
      return "UNKNOWN provenance at "
          + (source.isBlank() ? "line " + origin.line() : source + ":" + origin.line())
          + (source.isBlank() ? ", column " : ":")
          + origin.column();
    }
    return origin.kind()
        + " "
        + origin.modelId()
        + ":"
        + origin.line()
        + ":"
        + origin.column()
        + (origin.source().isEmpty() ? "" : " source " + origin.source())
        + (origin.profileId().isEmpty() ? "" : " profile " + origin.profileId());
  }

  private static String diagnostic(final String value) {
    if (value.startsWith("Incomplete or ambiguous provenance at :")) {
      return "Incomplete or ambiguous provenance: Maven supplied no source model identity or"
          + " usable source location for this effective POM element.";
    }
    return value;
  }
}
