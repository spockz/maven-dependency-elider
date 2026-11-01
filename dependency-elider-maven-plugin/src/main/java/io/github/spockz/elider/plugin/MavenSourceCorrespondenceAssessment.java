// WHY: Keeps source reproduction results separate from proof admission and classification.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.OsvAdvisoryRecord;
import io.github.spockz.elider.model.StructuredSourceClassEvidence;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.project.MavenProject;

/** Collects exact, raw-applicable structured claim correspondence results. */
final class MavenSourceCorrespondenceAssessment {
  /** Maven context for exact source lookup. */
  private final MavenProject project;

  /** Original session is copied before Maven resolves the source classifier. */
  private final MavenSession session;

  /** Resolver is absent for assessment paths without exact source lookup. */
  private final Optional<MavenSourceClassifierResolver> resolver;

  /** Path-root translation is a user assumption, never a completeness signal. */
  private final boolean conventionalLayoutAssumed;

  /** Memoized compiler image identity. */
  private Optional<SourceJdkIdentity.Resolution> sourceJdkIdentity = Optional.empty();

  private MavenSourceCorrespondenceAssessment(
      final MavenProject project,
      final MavenSession session,
      final Optional<MavenSourceClassifierResolver> resolver,
      final boolean conventionalLayoutAssumed) {
    this.project = project;
    this.session = session;
    this.resolver = Objects.requireNonNull(resolver, "resolver");
    this.conventionalLayoutAssumed = conventionalLayoutAssumed;
  }

  /* default */ static MavenSourceCorrespondenceAssessment unavailable(
      final boolean conventionalLayoutAssumed) {
    return new MavenSourceCorrespondenceAssessment(
        null, null, Optional.empty(), conventionalLayoutAssumed);
  }

  /* default */ static MavenSourceCorrespondenceAssessment configured(
      final MavenProject project,
      final MavenSession session,
      final Optional<MavenSourceClassifierResolver> resolver,
      final boolean conventionalLayoutAssumed) {
    return new MavenSourceCorrespondenceAssessment(
        project, session, resolver, conventionalLayoutAssumed);
  }

  /* default */ boolean canResolve() {
    return resolver.isPresent() && project != null && session != null;
  }

  /* default */ List<SourceBuildCorrespondence> evaluate(
      final ArtifactCoordinate candidate,
      final List<OsvAdvisoryRecord> records,
      final List<MavenVulnerabilityAssessment.MatchedAdvisoryEvidence> matched,
      final List<ElisionAnalysisModel.ArtifactSnapshot> artifacts) {
    final List<MavenVulnerabilityAssessment.MatchedAdvisoryEvidence> structuredClaims =
        matched.stream()
            .filter(item -> item.evidence() instanceof StructuredSourceClassEvidence)
            .toList();
    if (structuredClaims.isEmpty()) {
      return List.of();
    }
    final MavenSourceCorrespondenceClaimEvaluator evaluator =
        new MavenSourceCorrespondenceClaimEvaluator(
            candidate,
            records,
            artifacts,
            project,
            session,
            resolver,
            conventionalLayoutAssumed,
            currentJdkIdentity());
    final List<SourceBuildCorrespondence> results = new ArrayList<>();
    for (final MavenVulnerabilityAssessment.MatchedAdvisoryEvidence item : structuredClaims) {
      final StructuredSourceClassEvidence evidence =
          (StructuredSourceClassEvidence) item.evidence();
      evaluator.evaluate(item, evidence).ifPresent(results::add);
    }
    return List.copyOf(results);
  }

  private SourceJdkIdentity.Resolution currentJdkIdentity() {
    if (sourceJdkIdentity.isEmpty()) {
      final SourceJdkIdentity.Resolution current =
          canResolve()
              ? SourceJdkIdentity.current()
              : SourceJdkIdentity.Resolution.unavailable(
                  "Maven source artifact resolver is unavailable");
      sourceJdkIdentity = Optional.of(current);
    }
    return sourceJdkIdentity.orElseThrow();
  }
}
