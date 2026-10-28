// WHY: Keeps diagnostics outside publication.

package io.github.spockz.elider.plugin;

import org.apache.maven.plugin.logging.Log;

/** Emits goal completion and unchanged-artifact diagnostics. */
final class MavenElisionOutputLogger {
  private MavenElisionOutputLogger() {
    throw new AssertionError("No instances");
  }

  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  static void completion(
      final MavenElisionOutputPublisher.Request request,
      final MavenElisionReportSnapshot reportSnapshot) {
    final MavenElisionService.Analysis analysis = request.analysis();
    final Log log = request.log();
    if (log.isInfoEnabled() && request.files().trimJars() && analysis.trimCacheHits() > 0) {
      final double milliseconds = analysis.maximumTrimCacheHitNanos() / 1_000_000.0;
      log.info(
          "  JAR trim cache: "
              + analysis.trimCacheHits()
              + " hit(s), maximum validated hit "
              + milliseconds
              + " ms (target < 1.5 ms)");
    }
    if (request.files().trimJars()) {
      ElisionSummary.reportTrimmed(
          log, analysis.effectiveDecision(), analysis.resolvedSnapshots().size(), reportSnapshot);
    } else {
      ElisionSummary.report(
          log, analysis.effectiveDecision(), analysis.resolvedSnapshots().size(), reportSnapshot);
    }
    if (log.isInfoEnabled()) {
      log.info(
          "  Class usage report: "
              + request.files().classUsage().toPath().toAbsolutePath().normalize());
    }
  }

  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  static void passThroughWarnings(final Log log, final MavenElisionService.Analysis analysis) {
    analysis
        .multiReleasePassthroughArtifacts()
        .forEach(
            coordinate ->
                log.warn(
                    "Keeping multi-release dependency unchanged with Java "
                        + Runtime.version().feature()
                        + " effective classes for closure; unchanged external links are tolerated: "
                        + coordinate));
    analysis
        .moduleInfoPassthroughArtifacts()
        .forEach(
            coordinate ->
                log.warn(
                    "Keeping root-module-info dependency unchanged; "
                        + "its class-only projection covers "
                        + "classpath closure, not module-path closure: "
                        + coordinate));
    analysis
        .configuredPassThroughArtifacts()
        .forEach(
            coordinate ->
                log.warn(
                    "Keeping configured dependency unchanged; "
                        + "external links from unchanged classes "
                        + "are tolerated: "
                        + coordinate));
  }
}
