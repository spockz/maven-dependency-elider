// WHY: Explains repeated Maven exclusions as review findings without implying equivalent edits.

package io.github.spockz.elider.plugin;

import java.util.ArrayList;
import java.util.List;

/** Renders only saved review findings. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class ExclusionReviewRenderer {
  private ExclusionReviewRenderer() {}

  static List<String> render(final ExclusionReview review) {
    final List<String> lines = new ArrayList<>();
    if (!review.available()) {
      lines.add("  Exclusion review unavailable: " + review.unavailableReason());
      return List.copyOf(lines);
    }
    lines.add("  Repeated POM exclusions (advisory only):");
    for (final ExclusionReview.Candidate candidate : review.candidates()) {
      lines.add(
          "    "
              + candidate.coordinate().groupId()
              + ":"
              + candidate.coordinate().artifactId()
              + " appears on "
              + candidate.count()
              + " effective dependency paths");
      for (final ExclusionRecommendations.Observation observation : candidate.declarations()) {
        final ExclusionRecommendations.Reference ref = observation.declaration();
        lines.add(
            "      "
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
            .forEach(value -> lines.add("        exclusion origin: " + origin(value)));
      }
    }
    if (!review.management().isEmpty()) {
      lines.add(
          "  Noncontributing dependency-management exclusions: "
              + review.management().size()
              + " row(s)");
      for (final ExclusionRecommendations.Declaration declaration : review.management()) {
        final ExclusionRecommendations.Reference ref = declaration.reference();
        for (final ExclusionRecommendations.Exclusion exclusion : declaration.exclusions()) {
          lines.add(
              "    "
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
    final List<String> diagnostics =
        ExclusionProvenancePayload.decode(review.snapshot()).diagnostics();
    if (!diagnostics.isEmpty()) {
      lines.add(
          "  Exclusion provenance incomplete: "
              + diagnostics.size()
              + " issue(s); full details are saved in the report");
      diagnostics.stream().distinct().limit(3).forEach(value -> lines.add("    " + value));
    }
    lines.add(
        "  Review only: Maven path exclusions affect dependency collection and mediation; "
            + "a global post-resolution ban affects project output and may remove content "
            + "needed by consumers.");
    return List.copyOf(lines);
  }

  private static String origin(final ExclusionRecommendations.Origin origin) {
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
}
