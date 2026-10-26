// WHY: Distinguishes nonmutating elision predictions from applied artifact and trim results.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ElisionDecision;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
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

  /** Reports artifacts this nonmutating analysis predicts would be elided. */
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  static void reportAnalysis(
      final Log log,
      final ElisionDecision decision,
      final List<MavenElisionService.ArtifactSnapshot> resolvedSnapshots)
      throws IOException {
    if (!log.isInfoEnabled()) {
      return;
    }
    final int inputCount = resolvedSnapshots.size();
    final int elidedCount = decision.elidedArtifacts().size();
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
            + MavenElisionReportWriter.formatBytes(
                originalBytesForElisions(decision, resolvedSnapshots))
            + " (sum of original on-disk input JAR sizes; final package delta may differ)");
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
    log.info(
        "  Program classes removed: "
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

  private static long originalBytesForElisions(
      final ElisionDecision decision,
      final List<MavenElisionService.ArtifactSnapshot> resolvedSnapshots)
      throws IOException {
    long total = 0;
    for (final ArtifactCoordinate coordinate : decision.elidedArtifacts()) {
      final MavenElisionService.ArtifactSnapshot snapshot =
          findSnapshot(coordinate, resolvedSnapshots);
      if (snapshot == null) {
        throw missingInput(coordinate);
      }
      final Path path = snapshot.filePath();
      if (path == null || !Files.isRegularFile(path)) {
        throw missingJar(coordinate);
      }
      total = checkedByteTotal(total, Files.size(path));
    }
    return total;
  }

  private static MavenElisionService.ArtifactSnapshot findSnapshot(
      final ArtifactCoordinate coordinate,
      final List<MavenElisionService.ArtifactSnapshot> resolvedSnapshots) {
    for (final MavenElisionService.ArtifactSnapshot snapshot : resolvedSnapshots) {
      if (snapshot.coordinate().equals(coordinate)) {
        return snapshot;
      }
    }
    return null;
  }

  private static IOException missingInput(final ArtifactCoordinate coordinate) {
    return new IOException("Elided artifact is missing from input: " + coordinate);
  }

  private static IOException missingJar(final ArtifactCoordinate coordinate) {
    return new IOException("Elided artifact has no regular original JAR file: " + coordinate);
  }

  private static long checkedByteTotal(final long current, final long additional) {
    try {
      return Math.addExact(current, additional);
    } catch (final ArithmeticException exception) {
      throw new IllegalArgumentException("Original JAR byte total overflowed", exception);
    }
  }
}
