/* WHY: Presents saved generic decisions without re-running source or artifact analysis. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.AdvisoryProvenance;
import io.github.spockz.elider.model.CodeAttributionResolver;
import io.github.spockz.elider.model.EvidenceOrigin;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/** Renders captured findings and independent source health. */
final class MavenElisionReportGenericRenderer {
  private MavenElisionReportGenericRenderer() {}

  /* package */ static List<String> render(
      final List<GenericFindingAssessment> findings,
      final List<FindingSourceObservation> observations) {
    return render(findings, observations, false);
  }

  /* package */ static List<String> render(
      final List<GenericFindingAssessment> findings,
      final List<FindingSourceObservation> observations,
      final boolean predicted) {
    final List<String> lines = new ArrayList<>();
    if (predicted) {
      lines.add("Analysis only: no trim proof or published changes");
    }
    lines.add("Vulnerability findings: " + (findings.isEmpty() ? "none" : findings.size()));
    for (final GenericFindingAssessment finding : findings) {
      appendFinding(lines, finding, predicted);
    }
    appendObservations(lines, observations);
    return List.copyOf(lines);
  }

  private static void appendFinding(
      final List<String> lines, final GenericFindingAssessment finding, final boolean predicted) {
    lines.add(
        "  - "
            + finding.vulnerabilityId()
            + " "
            + finding.candidate()
            + " ["
            + disposition(finding, predicted)
            + "]");
    if (finding.aliases().stream().anyMatch(alias -> !alias.equals(finding.vulnerabilityId()))) {
      lines.add("    Aliases: " + new TreeSet<>(finding.aliases()));
    }
    lines.add(
        "    Applicability: "
            + finding.applicability()
            + "; intent: "
            + finding.intent().map(Enum::name).orElse("UNRESOLVED"));
    lines.add("    Outcome: " + outcome(finding, predicted) + "; " + finding.detail());
    for (final CodeAttributionResolver.DeclarationResult declaration : finding.codeAttribution()) {
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
    appendFindingDetails(lines, finding);
  }

  private static void appendFindingDetails(
      final List<String> lines, final GenericFindingAssessment finding) {
    if (!finding.heuristicLeads().isEmpty()) {
      final Set<String> leads = new TreeSet<>();
      finding.heuristicLeads().forEach(lead -> leads.addAll(lead.originalValues()));
      lines.add("    Heuristic leads: " + leads);
    }
    if (!finding.effectivePrerequisites().isEmpty()) {
      lines.add(
          "    Effective prerequisites: "
              + finding.effectivePrerequisites().stream()
                  .map(claim -> claim.requiresDependency() + " / " + claim.requiresClass())
                  .toList());
    }
    finding
        .prerequisiteProofEvidence()
        .ifPresent(evidence -> MavenElisionReportPrerequisiteProofRenderer.append(lines, evidence));
    if (!finding.unresolvedVersionClaims().isEmpty()) {
      lines.add(
          "    Unresolved coverage: "
              + finding.unresolvedVersionClaims().stream()
                  .map(claim -> claim.rawPredicate() + ": " + claim.diagnostic())
                  .toList());
    }
    if (!finding.overriddenFields().isEmpty()) {
      lines.add("    Overridden fields: " + new TreeSet<>(finding.overriddenFields()));
    }
    if (!finding.enrichedFields().isEmpty()) {
      lines.add("    Enriched fields: " + new TreeSet<>(finding.enrichedFields()));
    }
    final Set<String> sources = sources(finding);
    if (!sources.isEmpty()) {
      lines.add("    Sources: " + sources);
    }
  }

  private static Set<String> sources(final GenericFindingAssessment finding) {
    final Set<String> sources = new TreeSet<>();
    finding
        .contributions()
        .forEach(
            contribution -> {
              sources.add(source(contribution.provenance()));
              contribution.sourceProvenance().stream()
                  .map(AdvisoryProvenance::origin)
                  .filter(MavenElisionReportGenericRenderer::isSource)
                  .map(Enum::name)
                  .forEach(sources::add);
            });
    return sources;
  }

  private static void appendObservations(
      final List<String> lines, final List<FindingSourceObservation> observations) {
    lines.add(observations.isEmpty() ? "CVE Sources: none" : "CVE Sources:");
    for (final FindingSourceObservation observation : observations) {
      lines.add(
          "  - "
              + observation.source().map(Enum::name).orElse("CACHE")
              + " "
              + observation.status());
      if (observation.diagnostic() != null) {
        lines.add("    " + observation.diagnostic());
      }
      if (!observation.observationDiagnostics().isEmpty()) {
        lines.add("    Source diagnostics are in the JSON snapshot");
      }
    }
  }

  private static String source(final String provenance) {
    final int separator = provenance.indexOf(':');
    final String prefix = separator < 0 ? provenance : provenance.substring(0, separator);
    return switch (prefix.toLowerCase(java.util.Locale.ROOT)) {
      case "osv" -> "OSV";
      case "snyk" -> "SNYK";
      case "cve-list" -> "CVE_LIST";
      case "catalog" -> "CATALOG";
      case "effective-project-pom" -> "POM";
      default -> prefix;
    };
  }

  private static boolean isSource(final EvidenceOrigin origin) {
    return switch (origin) {
      case POM, CATALOG, OSV, SNYK, CVE_LIST -> true;
      case DESCRIPTION, REFERENCE_URL -> false;
    };
  }

  private static String outcome(final GenericFindingAssessment finding, final boolean predicted) {
    return predicted
            && (finding.outcome() == GenericFindingAssessment.Outcome.DECLARED_CODE_ABSENT
                || finding.outcome() == GenericFindingAssessment.Outcome.PREREQUISITES_ABSENT)
        ? "UNVERIFIED"
        : finding.outcome().name();
  }

  private static String disposition(
      final GenericFindingAssessment finding, final boolean predicted) {
    return predicted
            && finding.inventoryDisposition()
                == MavenVulnerabilityAssessment.InventoryDisposition.REMOVED
        ? "WOULD_REMOVE"
        : finding.inventoryDisposition().name();
  }
}
