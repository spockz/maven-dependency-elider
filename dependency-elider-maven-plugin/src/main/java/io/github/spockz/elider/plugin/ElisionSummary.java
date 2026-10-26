// WHY: Reports whole-artifact decisions and the trim metrics available from each Maven goal.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ElisionDecision;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.util.List;
import java.util.Locale;
import org.apache.maven.plugin.logging.Log;

/** Emits Maven summaries for whole-artifact decisions and available trim metrics. */
final class ElisionSummary {
  /** Prevents instances of this static-only writer. */
  private ElisionSummary() {
    throw new AssertionError("No instances");
  }

  /** Prints whole-artifact counts and explicitly marks unsupported stages. */
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  static void report(final Log log, final ElisionDecision decision, final int inputCount) {
    if (!log.isInfoEnabled()) {
      return;
    }
    reportHeader(log, decision, inputCount);
    log.info("  Classes removed: 0 / N/A (N/A; stage not run)");
    log.info("  Methods removed: 0 / N/A (N/A; stage not run)");
    log.info("  Fields removed: 0 / N/A (N/A; stage not run)");
    log.info("  Cache: unavailable");
  }

  /** Prints measured class payload metrics when retained JAR trimming ran. */
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  static void reportTrimmed(
      final Log log,
      final ElisionDecision decision,
      final int inputCount,
      final List<ArtifactTrimRecord> trimRecords) {
    if (!log.isInfoEnabled()) {
      return;
    }
    reportHeader(log, decision, inputCount);
    final TrimTotals totals = totalTrimmedClasses(trimRecords);
    log.info(
        "  Program classes removed: "
            + totals.classes()
            + " (uncompressed omitted .class entry payload bytes: "
            + MavenElisionReportWriter.formatBytes(totals.classBytes())
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

  private static TrimTotals totalTrimmedClasses(final List<ArtifactTrimRecord> trimRecords) {
    int classes = 0;
    long classBytes = 0;
    for (final ArtifactTrimRecord record : trimRecords) {
      classes = Math.addExact(classes, record.totalClasses() - record.retainedClasses());
      classBytes = Math.addExact(classBytes, record.prunedClassBytes());
    }
    return new TrimTotals(classes, classBytes);
  }

  private record TrimTotals(int classes, long classBytes) {}
}
