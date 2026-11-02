// WHY: Keeps advisory and mitigation log rows separate from artifact summary formatting.

package io.github.spockz.elider.plugin;

import java.util.List;
import org.apache.maven.plugin.logging.Log;

/** Emits the vulnerability portion of the Maven analysis summary. */
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
    final String removedHeading =
        predicted
            ? "  Advisories associated with components that would be removed: "
            : "  Advisories associated with removed components: ";
    final String provenHeading =
        predicted
            ? "  Mitigated CVEs (vulnerable code that would be pruned by trimming): "
            : "  Mitigated CVEs (vulnerable code pruned by trimming): ";
    final String inactiveHeading =
        predicted
            ? "  CVEs that would be inactive due to unmet prerequisite dependencies: "
            : "  CVEs inactive due to unmet prerequisite dependencies: ";
    final String noVerifiedEvidence = predicted ? "none verified by published trim evidence" : null;
    final String noOmissionProof = predicted ? "no published omission proof" : null;
    final String noPreconditionProof = predicted ? "no precondition proof available" : null;
    reportFindings(log, removedHeading, assessment.removedComponents(), noVerifiedEvidence);
    reportFindings(log, provenHeading, assessment.provenVulnerableCodeAbsent(), noOmissionProof);
    reportFindings(
        log, inactiveHeading, assessment.inactiveDueToMissingPrerequisites(), noPreconditionProof);
    reportConservativeDrops(log, assessment.potentiallyConservativeCves(), predicted);
  }

  private static void reportConservativeDrops(
      final Log log,
      final List<MavenVulnerabilityAssessment.ConservativeFinding> findings,
      final boolean predicted) {
    if (!log.isInfoEnabled()) {
      return;
    }
    final String heading =
        predicted
            ? "  Vulnerability mappings that remain unverified by the in-memory Analyze prediction:"
            : "  CVEs excluded due to conservative multi-symbol checks:";
    if (findings.isEmpty()) {
      log.info(heading + " none detected");
      return;
    }
    log.info(heading);
    for (final MavenVulnerabilityAssessment.ConservativeFinding finding : findings) {
      log.info("    " + finding.cveId() + " " + finding.coordinate().toId());
      log.info("      Reason: " + finding.reason());
      log.info(
          "      Actionable POM override to certify if absent classes do not apply to your"
              + " version:");
      for (final String line : finding.pomOverrideSnippet().split("\n")) {
        log.info("        " + line);
      }
    }
  }

  private static void reportFindings(
      final Log log,
      final String heading,
      final List<MavenVulnerabilityAssessment.Finding> findings,
      final String predictedEmptyMessage) {
    if (!log.isInfoEnabled()) {
      return;
    }
    if (findings.isEmpty()) {
      log.info(
          heading
              + (predictedEmptyMessage == null
                  ? "none matched the available vulnerability mappings"
                  : predictedEmptyMessage));
      return;
    }
    log.info(heading);
    findings.forEach(
        finding -> log.info("    " + finding.cveId() + " " + finding.coordinate().toId()));
  }
}
