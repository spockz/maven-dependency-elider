// WHY: Distinguishes nonmutating elision predictions from applied artifact and trim results.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ElisionDecision;
import java.io.IOException;
import java.util.Locale;
import org.apache.maven.plugin.logging.Log;

/** Emits Maven summaries for predicted and applied elision results. */
final class ElisionSummary {
  /** Prevents instances of this static-only writer. */
  private ElisionSummary() {
    throw new AssertionError("No instances");
  }

  /** Prints whole-artifact counts and explicitly marks unsupported stages. */
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  static void report(
      final Log log,
      final ElisionDecision decision,
      final int inputCount,
      final MavenElisionReportSnapshot reportSnapshot) {
    if (!log.isInfoEnabled()) {
      return;
    }
    reportHeader(log, decision, inputCount);
    reportDroppedClassMetrics(log, reportSnapshot);
    log.info("  Classes removed: 0 / N/A (N/A; stage not run)");
    log.info("  Methods removed: 0 / N/A (N/A; stage not run)");
    log.info("  Fields removed: 0 / N/A (N/A; stage not run)");
    log.info("  Cache: unavailable");
  }

  /** Reports artifacts this nonmutating analysis predicts would be elided. */
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  static void reportAnalysis(final Log log, final MavenElisionService.Analysis analysis)
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
    log.info("  Cache: unavailable");
  }

  /** Prints measured class payload metrics when retained JAR trimming ran. */
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
    log.info("  Cache: unavailable");
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
    if (log.isInfoEnabled()) {
      log.info(
          "  Program classes removed with dropped JARs: "
              + reportSnapshot.droppedProgramClassEntries()
              + " (uncompressed .class entry payload bytes: "
              + MavenElisionReportWriter.formatBytes(reportSnapshot.droppedProgramClassBytes())
              + "; excludes module descriptors and archive sanitation metadata)");
    }
  }
}
