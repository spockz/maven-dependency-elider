// WHY: Keeps diagnostics outside publication.

package io.github.spockz.elider.plugin;

import java.io.IOException;
import org.apache.maven.plugin.logging.Log;

/** Emits goal completion and unchanged-artifact diagnostics. */
final class MavenElisionOutputLogger {
  private MavenElisionOutputLogger() {
    throw new AssertionError("No instances");
  }

  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  static void completion(
      final MavenElisionOutputPublisher.Request request,
      final MavenVulnerabilityAssessment.Result assessment,
      final ExclusionReview exclusionReview)
      throws IOException {
    final MavenElisionReportSnapshot reportSnapshot =
        MavenElisionReportSnapshot.from(request.project(), request.analysis(), assessment)
            .withExclusionReview(exclusionReview);
    final ElisionAnalysisModel.Analysis analysis = request.analysis();
    final Log log = request.log();
    dynamicRootWarnings(log, analysis.evidence());
    if (log.isInfoEnabled()) {
      if (request.files().trimJars()) {
        final String message =
            "  JAR trim cache: "
                + analysis.trimResult().cacheHits()
                + " validated hit(s), "
                + analysis.trimResult().analysisRuns()
                + " analysis run(s)";
        log.info(
            analysis.trimResult().cacheHits() == 0
                ? message
                : message
                    + "; maximum validated hit "
                    + analysis.trimResult().maximumCacheHitNanos() / 1_000_000.0
                    + " ms");
      } else {
        log.info("  JAR trim cache: unavailable (trim stage not run)");
      }
    }
    final String fallback = analysis.evidence().sourceAttributionFallback();
    if (fallback != null && log.isWarnEnabled()) {
      log.warn(
          "Post-compile source attribution used conservative fallback; all compile-visible "
              + "artifacts and indexed classes were retained: "
              + fallback);
    }
    if (log.isInfoEnabled()) {
      MavenElisionReportWriter.render(reportSnapshot).forEach(log::info);
      log.info(
          "  Class usage report: "
              + request.files().classUsage().toPath().toAbsolutePath().normalize());
    }
  }

  /* package */ static void dynamicRootWarnings(
      final Log log, final ElisionAnalysisModel.AnalysisEvidence evidence) {
    if (log.isWarnEnabled()) {
      evidence.unresolvedDynamicRootDiagnostics().forEach(log::warn);
    }
  }

  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  static void passThroughWarnings(final Log log, final ElisionAnalysisModel.Analysis analysis) {
    analysis
        .trimResult()
        .multiReleasePassthroughArtifacts()
        .forEach(
            coordinate ->
                log.warn(
                    "Keeping multi-release dependency unchanged with Java "
                        + Runtime.version().feature()
                        + " effective classes for closure; unchanged external links are tolerated: "
                        + coordinate));
    analysis
        .trimResult()
        .moduleInfoPassthroughArtifacts()
        .forEach(
            coordinate ->
                log.warn(
                    "Keeping root-module-info dependency unchanged; "
                        + "its class-only projection covers "
                        + "classpath closure, not module-path closure: "
                        + coordinate));
    analysis
        .trimResult()
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
