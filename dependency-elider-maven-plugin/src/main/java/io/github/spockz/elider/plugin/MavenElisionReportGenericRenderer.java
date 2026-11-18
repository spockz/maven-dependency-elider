/* WHY: Presents saved generic decisions without re-running source or artifact analysis. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.applicability.CodeAttributionResolver;
import io.github.spockz.elider.model.AdvisoryProvenance;
import io.github.spockz.elider.model.EvidenceOrigin;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/** Renders captured findings and independent source health. */
final class MavenElisionReportGenericRenderer {
  /** Maps normalized provenance prefixes to display source labels. */
  private static final Map<String, String> SOURCE_NAMES =
      Map.of(
          "osv",
          "OSV",
          "snyk",
          "SNYK",
          "cve-list",
          "CVE_LIST",
          "catalog",
          "CATALOG",
          "effective-project-pom",
          "POM");

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
    final String disposition =
        predicted
                && finding.inventoryDisposition()
                    == MavenVulnerabilityAssessment.InventoryDisposition.REMOVED
            ? "WOULD_REMOVE"
            : finding.inventoryDisposition().name();
    final String outcome =
        predicted
                && (finding.outcome() == GenericFindingAssessment.Outcome.DECLARED_CODE_ABSENT
                    || finding.outcome() == GenericFindingAssessment.Outcome.PREREQUISITES_ABSENT)
            ? "UNVERIFIED"
            : finding.outcome().name();
    lines.add(
        "  - " + finding.vulnerabilityId() + " " + finding.candidate() + " [" + disposition + "]");
    if (finding.aliases().stream().anyMatch(alias -> !alias.equals(finding.vulnerabilityId()))) {
      lines.add("    Aliases: " + new TreeSet<>(finding.aliases()));
    }
    lines.add(
        "    Applicability: "
            + finding.applicability()
            + "; intent: "
            + finding.intent().map(Enum::name).orElse("UNRESOLVED"));
    lines.add("    Outcome: " + outcome + "; " + finding.detail());
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
        .ifPresent(evidence -> appendPrerequisiteProof(lines, evidence));
    finding
        .prerequisitePrediction()
        .ifPresent(prediction -> appendPrerequisitePrediction(lines, prediction));
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
                  .filter(
                      origin ->
                          origin != EvidenceOrigin.DESCRIPTION
                              && origin != EvidenceOrigin.REFERENCE_URL)
                  .map(Enum::name)
                  .forEach(sources::add);
            });
    return sources;
  }

  private static void appendObservations(
      final List<String> lines, final List<FindingSourceObservation> observations) {
    final boolean hasStale =
        observations.stream()
            .anyMatch(observation -> observation.status() == FindingSourceObservation.Status.STALE);
    final boolean hasError =
        observations.stream()
            .anyMatch(observation -> observation.status() == FindingSourceObservation.Status.ERROR);
    if (hasStale) {
      lines.add("CVE Freshness: STALE (refresh failed; using last-good snapshots)");
    } else if (hasError) {
      lines.add("CVE Freshness: ERROR (refresh failed without complete last-good snapshots)");
    }
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
    return SOURCE_NAMES.getOrDefault(prefix.toLowerCase(Locale.ROOT), prefix);
  }

  private static void appendPrerequisitePrediction(
      final List<String> lines, final PrerequisitePrediction prediction) {
    lines.add("    Planned prerequisite forecast (not verified against output bytes):");
    for (final PrerequisitePrediction.GroupForecast group : prediction.groups()) {
      lines.add("      " + group.group().operator() + " disarmed=" + group.disarmed());
      for (final PrerequisitePrediction.MemberForecast member : group.members()) {
        lines.add(
            "        "
                + member.claim().requiresDependency()
                + " / "
                + member.claim().requiresClass()
                + ": "
                + member.state()
                + " ("
                + member.reason()
                + ")");
      }
    }
    if (prediction.detail() != null) {
      lines.add("      Forecast detail: " + prediction.detail());
    }
  }

  private static void appendPrerequisiteProof(
      final List<String> lines, final PrerequisiteProofEvidence evidence) {
    lines.add(
        "    Prerequisite proof evidence: final inventory " + evidence.finalInventoryFingerprint());
    if (evidence.baselineDetail() != null) {
      lines.add("      Baseline attribution: " + evidence.baselineDetail());
    }
    for (final PrerequisiteProofEvidence.GroupEvidence group : evidence.groups()) {
      lines.add("      " + group.group().operator() + " group attribution: " + group.attribution());
      for (final PrerequisiteProofEvidence.MemberEvidence member : group.members()) {
        lines.add(
            "        "
                + member.claim().requiresDependency()
                + " / "
                + member.claim().requiresClass()
                + "="
                + member.state()
                + " ("
                + member.attribution()
                + ")");
        for (final PrerequisiteProofEvidence.ProviderEvidence provider : member.providers()) {
          lines.add(
              "          Provider "
                  + (provider.coordinate() == null ? provider.kind() : provider.coordinate())
                  + ": "
                  + provider.attribution()
                  + "; baseline="
                  + provider.baselinePath()
                  + "; final="
                  + provider.finalPath());
        }
      }
    }
  }
}
