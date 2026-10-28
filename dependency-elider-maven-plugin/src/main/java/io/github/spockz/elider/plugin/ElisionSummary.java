// WHY: Distinguishes nonmutating elision predictions from applied artifact and trim results.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ElisionDecision;
import java.io.IOException;
import java.util.Locale;
import org.apache.maven.plugin.logging.Log;

/** Emits Maven summaries for predicted and applied elision results. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class ElisionSummary {
  /** Prevents instances of this static-only writer. */
  private ElisionSummary() {
    throw new AssertionError("No instances");
  }

  /** Prints whole-artifact counts and explicitly marks unsupported stages. */
  static void report(final Log log, final ElisionDecision decision, final int inputCount) {
    report(log, decision, inputCount, (MavenVulnerabilityAssessment.Result) null);
  }

  static void report(
      final Log log,
      final ElisionDecision decision,
      final int inputCount,
      final MavenElisionReportSnapshot reportSnapshot) {
    report(log, decision, inputCount, reportSnapshot, null);
  }

  static void report(
      final Log log,
      final ElisionDecision decision,
      final int inputCount,
      final MavenVulnerabilityAssessment.Result vulnerabilityAssessment) {
    report(log, decision, inputCount, null, vulnerabilityAssessment);
  }

  private static void report(
      final Log log,
      final ElisionDecision decision,
      final int inputCount,
      final MavenElisionReportSnapshot reportSnapshot,
      final MavenVulnerabilityAssessment.Result vulnerabilityAssessment) {
    if (!log.isInfoEnabled()) {
      return;
    }
    reportHeader(log, decision, inputCount);
    reportDroppedClassMetrics(log, reportSnapshot);
    log.info("  Classes removed: 0 / N/A (N/A; stage not run)");
    log.info("  Methods removed: 0 / N/A (N/A; stage not run)");
    log.info("  Fields removed: 0 / N/A (N/A; stage not run)");
    log.info("  JAR trim cache: unavailable (trim stage not run)");
    reportCves(log, vulnerabilityAssessment, false);
  }

  /** Reports artifacts this nonmutating analysis predicts would be elided. */
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  static void reportAnalysis(final Log log, final MavenElisionService.Analysis analysis)
      throws IOException {
    reportAnalysis(log, analysis, null, false);
  }

  static void reportAnalysis(
      final Log log,
      final MavenElisionService.Analysis analysis,
      final MavenVulnerabilityAssessment.Result vulnerabilityAssessment,
      final boolean trimJars)
      throws IOException {
    if (!log.isInfoEnabled()) {
      return;
    }
    final MavenElisionReportSnapshot.DroppedArtifactSummary droppedArtifacts =
        MavenElisionReportSnapshot.droppedArtifactSummary(analysis);
    final int inputCount = analysis.resolvedSnapshots().size();
    final int elidedCount = droppedArtifacts.artifacts().size();
    final String percentage =
        inputCount == 0
            ? "N/A"
            : String.format(Locale.ROOT, "%.1f%%", elidedCount * 100.0 / inputCount);
    log.info("Dependency Elider analysis summary");
    log.info(
        "  Artifacts that would be elided by this analysis: "
            + elidedCount
            + " / "
            + inputCount
            + " ("
            + percentage
            + ")");
    log.info(
        "  Estimated original JAR bytes for those artifacts: "
            + MavenElisionReportWriter.formatBytes(droppedArtifacts.originalJarBytes())
            + " (sum of original on-disk input JAR sizes; final package delta may differ)");
    log.info(
        "  Program class entries in JARs that would be dropped: "
            + droppedArtifacts.programClassesRemoved()
            + " (uncompressed .class entry payload bytes: "
            + MavenElisionReportWriter.formatBytes(
                droppedArtifacts.uncompressedProgramClassBytesRemoved())
            + "; excludes module descriptors and archive sanitation metadata)");
    reportTrimCache(log, analysis, trimJars);
    reportCves(log, vulnerabilityAssessment, true);
  }

  /** Prints measured class payload metrics when retained JAR trimming ran. */
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  static void reportTrimmed(
      final Log log,
      final MavenElisionService.Analysis analysis,
      final MavenElisionReportSnapshot reportSnapshot,
      final MavenVulnerabilityAssessment.Result vulnerabilityAssessment) {
    if (!log.isInfoEnabled()) {
      return;
    }
    reportHeader(log, analysis.decision(), analysis.resolvedSnapshots().size());
    log.info(
        "  Program classes removed: "
            + reportSnapshot.programClassesPruned()
            + " (uncompressed omitted .class entry payload bytes: "
            + MavenElisionReportWriter.formatBytes(
                reportSnapshot.uncompressedProgramClassBytesPruned())
            + "; excludes module descriptors and archive sanitation metadata)");
    log.info("  Methods removed: 0 / N/A (N/A; stage not run)");
    log.info("  Fields removed: 0 / N/A (N/A; stage not run)");
    reportTrimCache(log, analysis, true);
    reportCves(log, vulnerabilityAssessment, false);
  }

  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  static void reportTrimmed(
      final Log log,
      final ElisionDecision decision,
      final int inputCount,
      final MavenElisionReportSnapshot reportSnapshot) {
    if (!log.isInfoEnabled()) {
      return;
    }
    reportHeader(log, decision, inputCount);
    reportDroppedClassMetrics(log, reportSnapshot);
    log.info(
        "  Program classes pruned from retained JARs: "
            + reportSnapshot.programClassesPruned()
            + " (uncompressed omitted .class entry payload bytes: "
            + MavenElisionReportWriter.formatBytes(
                reportSnapshot.uncompressedProgramClassBytesPruned())
            + "; excludes module descriptors and archive sanitation metadata)");
    log.info("  Methods removed: 0 / N/A (N/A; stage not run)");
    log.info("  Fields removed: 0 / N/A (N/A; stage not run)");
    log.info("  JAR trim cache: unavailable");
  }

  private static void reportTrimCache(
      final Log log, final MavenElisionService.Analysis analysis, final boolean trimJars) {
    if (!log.isInfoEnabled()) {
      return;
    }
    if (!trimJars) {
      log.info("  JAR trim cache: unavailable (trim stage not run)");
      return;
    }
    final String cacheMessage =
        "  JAR trim cache: "
            + analysis.trimCacheHits()
            + " validated hit(s), "
            + analysis.trimAnalysisRuns()
            + " analysis run(s)";
    log.info(
        analysis.trimCacheHits() == 0
            ? cacheMessage
            : cacheMessage
                + "; maximum validated hit "
                + analysis.maximumTrimCacheHitNanos() / 1_000_000.0
                + " ms");
  }

  private static void reportCves(
      final Log log,
      final MavenVulnerabilityAssessment.Result assessment,
      final boolean predicted) {
    if (assessment == null) {
      return;
    }
    final String removedHeading =
        predicted
            ? "  CVE components that would be removed from inventory: "
            : "  CVE components removed from inventory: ";
    final String provenHeading =
        predicted
            ? "  CVEs whose vulnerable code would be proven absent by trimming: "
            : "  CVEs with vulnerable code proven absent by trimming: ";
    reportFindings(log, removedHeading, assessment.removedComponents());
    reportFindings(log, provenHeading, assessment.provenVulnerableCodeAbsent());
  }

  private static void reportFindings(
      final Log log,
      final String heading,
      final java.util.List<MavenVulnerabilityAssessment.Finding> findings) {
    if (!log.isInfoEnabled()) {
      return;
    }
    if (findings.isEmpty()) {
      log.info(heading + "none matched the available vulnerability mappings");
      return;
    }
    log.info(heading);
    findings.forEach(
        finding -> log.info("    " + finding.cveId() + " " + finding.coordinate().toId()));
  }

  private static void reportHeader(
      final Log log, final ElisionDecision decision, final int inputCount) {
    final int removed = decision.elidedArtifacts().size();
    final String percentage =
        inputCount == 0
            ? "N/A"
            : String.format(Locale.ROOT, "%.1f%%", removed * 100.0 / inputCount);
    if (log.isInfoEnabled()) {
      log.info("Dependency Elider summary");
      log.info("  Whole artifacts: " + removed + " / " + inputCount + " (" + percentage + ")");
    }
  }

  private static void reportDroppedClassMetrics(
      final Log log, final MavenElisionReportSnapshot reportSnapshot) {
    if (reportSnapshot == null) {
      return;
    }
    log.info(
        "  Program classes removed with dropped JARs: "
            + reportSnapshot.droppedProgramClassEntries()
            + " (uncompressed .class entry payload bytes: "
            + MavenElisionReportWriter.formatBytes(reportSnapshot.droppedProgramClassBytes())
            + "; excludes module descriptors and archive sanitation metadata)");
  }
}
