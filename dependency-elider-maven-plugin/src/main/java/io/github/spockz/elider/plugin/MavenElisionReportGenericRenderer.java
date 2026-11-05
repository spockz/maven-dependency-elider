/* WHY: Presents saved generic decisions without re-running source or artifact analysis. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.CodeAttributionResolver;
import io.github.spockz.elider.model.VulnerabilityFindingContribution;
import java.util.ArrayList;
import java.util.List;
import java.util.TreeSet;

/** Renders captured findings and independent source health. */
final class MavenElisionReportGenericRenderer {
  private MavenElisionReportGenericRenderer() {}

  /* package */ static List<String> render(
      final List<GenericFindingAssessment> findings,
      final List<FindingSourceObservation> observations) {
    final List<String> lines = new ArrayList<>();
    lines.add("Vulnerability findings: " + (findings.isEmpty() ? "none" : findings.size()));
    for (final GenericFindingAssessment finding : findings) {
      lines.add(
          "  - "
              + finding.vulnerabilityId()
              + " "
              + finding.candidate()
              + " ["
              + finding.inventoryDisposition()
              + "]");
      lines.add("    Aliases: " + new TreeSet<>(finding.aliases()));
      lines.add(
          "    Applicability: "
              + finding.applicability()
              + "; intent: "
              + finding.intent().map(Enum::name).orElse("UNRESOLVED"));
      lines.add("    Outcome: " + finding.outcome() + "; " + finding.detail());
      lines.add(
          "    Code group: "
              + finding.codeGroupStatus()
              + "; prerequisite group: "
              + finding.prerequisiteGroupStatus());
      for (final CodeAttributionResolver.DeclarationResult declaration :
          finding.codeAttribution()) {
        lines.add(
            "    Declared code: "
                + declaration.claim().reference().originalValues()
                + " "
                + declaration.status()
                + "; classes: "
                + declaration.classFamily()
                + "; reasons: "
                + declaration.reasons());
      }
      lines.add("    Heuristic leads: " + finding.heuristicLeads());
      lines.add("    Effective prerequisites: " + finding.effectivePrerequisites());
      lines.add("    Unresolved coverage: " + finding.unresolvedVersionClaims());
      lines.add("    Overridden fields: " + new TreeSet<>(finding.overriddenFields()));
      lines.add("    Enriched fields: " + new TreeSet<>(finding.enrichedFields()));
      for (final VulnerabilityFindingContribution contribution : finding.contributions()) {
        lines.add(
            "    Source: "
                + contribution.provenance()
                + "; records: "
                + contribution.sourceProvenance());
        lines.add("      Coverage: " + contribution.versionClaims());
        lines.add(
            "      Original code: "
                + contribution.codeGroup()
                + "; prerequisites: "
                + contribution.prerequisiteGroup());
        lines.add(
            "      Priority: " + contribution.priority() + "; intent: " + contribution.intent());
      }
    }
    lines.add("Source observations: " + (observations.isEmpty() ? "none" : observations.size()));
    for (final FindingSourceObservation observation : observations) {
      lines.add(
          "  - "
              + observation.source().map(Enum::name).orElse("CACHE")
              + " "
              + observation.status()
              + "; revision: "
              + observation.revision()
              + "; last success: "
              + observation.lastSuccessfulSync()
              + "; contributions: "
              + observation.contributionCount());
      if (observation.diagnostic() != null) {
        lines.add("    " + observation.diagnostic());
      }
      for (final String diagnostic : observation.observationDiagnostics()) {
        lines.add("    " + diagnostic);
      }
    }
    return List.copyOf(lines);
  }
}
