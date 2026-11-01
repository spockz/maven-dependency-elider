// WHY: Resolves and reproduces one identity-bound source claim with dual applicability.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.OsvAdvisoryRecord;
import io.github.spockz.elider.model.StructuredSourceClassEvidence;
import java.io.IOException;
import java.util.List;
import java.util.Optional;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.project.MavenProject;

/** Evaluates a structured source claim for one exact Maven candidate. */
final class MavenSourceCorrespondenceClaimEvaluator {
  /** Exactly one original archive must match the assessed coordinate. */
  private static final int ONE_MATCH = 1;

  /** Exact Maven component whose source correspondence is being checked. */
  private final ArtifactCoordinate candidate;

  /** Record set used to require one unambiguous OSV owner. */
  private final List<OsvAdvisoryRecord> records;

  /** Original analysis artifacts used to bind the exact GAVCE archive. */
  private final List<ElisionAnalysisModel.ArtifactSnapshot> artifacts;

  /** Maven context used only to resolve the source classifier. */
  private final MavenProject project;

  /** Session holding Maven's configured artifact resolver and repositories. */
  private final MavenSession session;

  /** Absent when source correspondence is disabled for this invocation. */
  private final Optional<MavenSourceClassifierResolver> resolver;

  /** Shared compiler identity for this assessment. */
  private final SourceJdkIdentity.Resolution sourceJdkIdentity;

  /** Enables only the documented source-root translation. */
  private final boolean conventionalLayoutAssumed;

  /** Lazily resolved once so several claims share the same classifier lookup. */
  private Optional<MavenSourceClassifierResolver.ResolvedSourceArtifact> sourceArtifact =
      Optional.empty();

  /** Captures resolution failure for a diagnosed review-only abstention. */
  private IOException resolutionFailure;

  /** Prevents repeated resolver calls after either success or failure. */
  private boolean resolutionAttempted;

  /* default */ MavenSourceCorrespondenceClaimEvaluator(
      final ArtifactCoordinate candidate,
      final List<OsvAdvisoryRecord> records,
      final List<ElisionAnalysisModel.ArtifactSnapshot> artifacts,
      final MavenProject project,
      final MavenSession session,
      final Optional<MavenSourceClassifierResolver> resolver,
      final boolean conventionalLayoutAssumed,
      final SourceJdkIdentity.Resolution sourceJdkIdentity) {
    this.candidate = candidate;
    this.records = List.copyOf(records);
    this.artifacts = List.copyOf(artifacts);
    this.project = project;
    this.session = session;
    this.resolver = resolver;
    this.conventionalLayoutAssumed = conventionalLayoutAssumed;
    this.sourceJdkIdentity = sourceJdkIdentity;
  }

  /* default */ Optional<SourceBuildCorrespondence> evaluate(
      final MavenVulnerabilityAssessment.MatchedAdvisoryEvidence item,
      final StructuredSourceClassEvidence evidence) {
    final Optional<OsvAdvisoryRecord> owner = uniqueOwner(item.osvId());
    if (owner.isEmpty() || !isApplicable(owner.orElseThrow(), evidence)) {
      return Optional.empty();
    }
    if (evidence.programFiles().isEmpty() && evidence.programRoutines().isEmpty()) {
      return abstained(item, evidence, "Structured source claim has no files or routines");
    }
    return evaluateExactCandidate(item, evidence);
  }

  private Optional<SourceBuildCorrespondence> evaluateExactCandidate(
      final MavenVulnerabilityAssessment.MatchedAdvisoryEvidence item,
      final StructuredSourceClassEvidence evidence) {
    final List<ElisionAnalysisModel.ArtifactSnapshot> snapshots = candidateSnapshots();
    if (snapshots.size() != ONE_MATCH || resolver.isEmpty()) {
      return abstained(item, evidence, snapshotFailureReason(snapshots.size()));
    }
    if (sourceJdkIdentity.identity().isEmpty()) {
      return abstained(item, evidence, sourceJdkIdentity.refusal().orElseThrow());
    }
    resolveSourceArtifact();
    if (resolutionFailure != null) {
      return abstained(item, evidence, resolutionFailure.getMessage());
    }
    return reproduce(item, evidence, sourceArtifact.orElseThrow(), snapshots.getFirst().filePath());
  }

  private String snapshotFailureReason(final int snapshotCount) {
    if (snapshotCount != ONE_MATCH) {
      return "Exact original artifact file is missing or ambiguous";
    }
    return "Maven source artifact resolver is unavailable";
  }

  private Optional<OsvAdvisoryRecord> uniqueOwner(final String osvId) {
    final List<OsvAdvisoryRecord> matches =
        records.stream().filter(record -> record.osvId().equals(osvId)).toList();
    return matches.size() == 1 ? Optional.of(matches.getFirst()) : Optional.empty();
  }

  private boolean isApplicable(
      final OsvAdvisoryRecord owner, final StructuredSourceClassEvidence evidence) {
    return MavenVulnerabilitySourceReview.matchesReviewClaim(owner, evidence, candidate)
        && CorroboratedSourceCandidateMatcher.isApplicable(owner, evidence, candidate);
  }

  private List<ElisionAnalysisModel.ArtifactSnapshot> candidateSnapshots() {
    return artifacts.stream().filter(value -> exactGavce(value.coordinate(), candidate)).toList();
  }

  private void resolveSourceArtifact() {
    if (resolutionAttempted) {
      return;
    }
    resolutionAttempted = true;
    try {
      sourceArtifact = Optional.of(resolver.orElseThrow().resolve(candidate, project, session));
    } catch (final IOException failure) {
      resolutionFailure = failure;
    }
  }

  private Optional<SourceBuildCorrespondence> reproduce(
      final MavenVulnerabilityAssessment.MatchedAdvisoryEvidence item,
      final StructuredSourceClassEvidence evidence,
      final MavenSourceClassifierResolver.ResolvedSourceArtifact sources,
      final java.nio.file.Path originalJar) {
    final SourceArtifactReproducer.Outcome outcome =
        SourceArtifactReproducer.reproduce(
            candidate,
            sources,
            originalJar,
            evidence.programFiles().stream().sorted().toList(),
            evidence.programRoutines().stream().sorted().toList(),
            conventionalLayoutAssumed,
            sourceJdkIdentity.identity().orElseThrow());
    return toCorrespondence(item, evidence, outcome);
  }

  private Optional<SourceBuildCorrespondence> toCorrespondence(
      final MavenVulnerabilityAssessment.MatchedAdvisoryEvidence item,
      final StructuredSourceClassEvidence evidence,
      final SourceArtifactReproducer.Outcome outcome) {
    if (outcome instanceof SourceArtifactReproducer.Abstained failure) {
      return abstained(item, evidence, failure.rationale());
    }
    final SourceArtifactReproducer.Reproduced reproduced =
        (SourceArtifactReproducer.Reproduced) outcome;
    return Optional.of(
        new SourceBuildCorrespondence.Matched(
            candidate,
            item.osvId(),
            evidence.scope().cveId(),
            evidence.provenance().sourceRecordSha256(),
            evidence.cnaAffectedEntryIdentity(),
            reproduced.sourcesCoordinate().toId(),
            reproduced.sourceRepositoryId(),
            reproduced.originalArchiveSha256(),
            reproduced.sourcesArchiveSha256(),
            reproduced.compilerIdentity(),
            reproduced.compilerOptions(),
            reproduced.mappedClaims(),
            reproduced.originalClassInventory(),
            reproduced.sourceUnits()));
  }

  private Optional<SourceBuildCorrespondence> abstained(
      final MavenVulnerabilityAssessment.MatchedAdvisoryEvidence item,
      final StructuredSourceClassEvidence evidence,
      final String rationale) {
    return Optional.of(
        new SourceBuildCorrespondence.Abstained(
            item.coordinate(),
            item.osvId(),
            evidence.scope().cveId(),
            evidence.provenance().sourceRecordSha256(),
            evidence.cnaAffectedEntryIdentity(),
            rationale == null || rationale.isBlank()
                ? "Source correspondence is unavailable"
                : rationale));
  }

  private static boolean exactGavce(final ArtifactCoordinate left, final ArtifactCoordinate right) {
    return left.groupId().equals(right.groupId())
        && left.artifactId().equals(right.artifactId())
        && left.version().equals(right.version())
        && left.type().equals(right.type())
        && left.classifier().equals(right.classifier());
  }
}
