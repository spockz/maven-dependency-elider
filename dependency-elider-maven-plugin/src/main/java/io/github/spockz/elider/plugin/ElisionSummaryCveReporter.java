// WHY: Displays captured vulnerability decisions without assigning authority to a source.

package io.github.spockz.elider.plugin;

import java.util.List;
import org.apache.maven.plugin.logging.Log;

/** Emits the vulnerability portion of the Maven analysis summary. */
@SuppressWarnings("PMD.GuardLogStatement") // The public entry point guards the logging level.
final class ElisionSummaryCveReporter {
  private ElisionSummaryCveReporter() {
    throw new AssertionError("No instances");
  }

  /* default */ static void report(
      final Log log,
      final MavenVulnerabilityAssessment.Result assessment,
      final boolean predicted) {
    if (assessment == null || !log.isInfoEnabled()) {
      return;
    }
    reportFindings(log, assessment.genericFindings(), predicted);
    reportSources(log, assessment.sourceObservations());
  }

  private static void reportFindings(
      final Log log, final List<GenericFindingAssessment> findings, final boolean predicted) {
    if (findings.isEmpty()) {
      log.info("  Vulnerability findings: none");
      return;
    }
    log.info(
        predicted
            ? "  Vulnerability findings (analysis only; no trim proof):"
            : "  Vulnerability findings:");
    for (final GenericFindingAssessment finding : findings) {
      final String outcome = predicted ? "UNVERIFIED" : finding.outcome().name();
      log.info(
          "    "
              + finding.vulnerabilityId()
              + " "
              + finding.candidate().toId()
              + ": "
              + finding.applicability()
              + "; "
              + outcome
              + "; "
              + finding.inventoryDisposition());
      if (!predicted) {
        log.info("      " + finding.detail());
      }
    }
  }

  private static void reportSources(
      final Log log, final List<FindingSourceObservation> observations) {
    if (observations.isEmpty()) {
      log.info("  Vulnerability sources: none observed");
      return;
    }
    log.info("  Vulnerability sources:");
    for (final FindingSourceObservation observation : observations) {
      log.info(
          "    "
              + observation.source().map(Enum::name).orElse("CACHE")
              + ": "
              + observation.status()
              + (observation.diagnostic() == null ? "" : "; " + observation.diagnostic()));
      for (final String diagnostic : observation.observationDiagnostics()) {
        log.info("      " + diagnostic);
      }
    }
  }
}
