// WHY: Builds report-only advisory findings from matched evidence and raw OSV owner claims.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.HeuristicCandidateEvidence;
import io.github.spockz.elider.model.OsvAdvisoryRecord;
import io.github.spockz.elider.model.OsvAffectedPackage;
import io.github.spockz.elider.model.PackageAdvisoryEvidence;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

/** Creates advisory rows outside proof and classification capability. */
final class MavenAdvisoryFindingFactory {
  /** Diagnostic used when raw owner package scope cannot be uniquely selected. */
  private static final String AMBIGUOUS_OWNER = "Owning OSV package scope is missing or ambiguous";

  /** One uniquely matching raw package claim is required for applicability. */
  private static final int SINGLE_MATCH = 1;

  private MavenAdvisoryFindingFactory() {}

  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  static Optional<MavenVulnerabilityAssessment.HeuristicAdvisoryFinding> heuristicFinding(
      final MavenVulnerabilityAssessment.MatchedAdvisoryEvidence matched,
      final MavenVulnerabilityAssessment.InventoryDisposition disposition,
      final List<OsvAdvisoryRecord> records) {
    if (!(matched.evidence() instanceof HeuristicCandidateEvidence evidence)) {
      return Optional.empty();
    }
    final OsvPackageApplicability.Result applicability =
        heuristicPackageApplicability(matched.osvId(), evidence, matched.coordinate(), records);
    return Optional.of(
        new MavenVulnerabilityAssessment.HeuristicAdvisoryFinding(
            matched.osvId(),
            matched.aliases(),
            evidence.scope().cveId(),
            matched.coordinate(),
            evidence.scope().ecosystem(),
            evidence.scope().packageName(),
            evidence.scope().versionRangeSpec(),
            applicability.status(),
            applicability.rationale(),
            disposition,
            evidence.provenance().origin(),
            evidence.provenance().sourceRecordId(),
            evidence.provenance().sourceUrl() == null
                ? null
                : evidence.provenance().sourceUrl().toString(),
            evidence.provenance().sourceRecordSha256(),
            evidence.confidenceLabel(),
            evidence.candidateClasses(),
            evidence.candidateDependencies()));
  }

  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  static MavenVulnerabilityAssessment.InventoryDisposition inventoryDisposition(
      final ArtifactCoordinate candidate,
      final Collection<ArtifactCoordinate> removedArtifacts,
      final Collection<ArtifactCoordinate> retainedArtifacts,
      final List<ArtifactTrimRecord> trimRecords) {
    return inventoryDisposition(
        candidate, removedArtifacts, retainedArtifacts, trimRecords, java.util.Set.of());
  }

  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  static MavenVulnerabilityAssessment.InventoryDisposition inventoryDisposition(
      final ArtifactCoordinate candidate,
      final Collection<ArtifactCoordinate> removedArtifacts,
      final Collection<ArtifactCoordinate> retainedArtifacts,
      final List<ArtifactTrimRecord> trimRecords,
      final Collection<ArtifactCoordinate> plannedUnverifiedCandidates) {
    if (removedArtifacts.stream().anyMatch(value -> sameGavce(value, candidate))) {
      return MavenVulnerabilityAssessment.InventoryDisposition.REMOVED;
    }
    if (trimRecords.stream().anyMatch(value -> sameGavce(value.coordinate(), candidate))) {
      return MavenVulnerabilityAssessment.InventoryDisposition.RETAINED_AND_TRIMMED;
    }
    if (retainedArtifacts.stream().anyMatch(value -> sameGavce(value, candidate))) {
      return MavenVulnerabilityAssessment.InventoryDisposition.RETAINED_UNCHANGED;
    }
    if (plannedUnverifiedCandidates.stream().anyMatch(value -> sameGavce(value, candidate))) {
      return MavenVulnerabilityAssessment.InventoryDisposition.PLANNED_UNVERIFIED;
    }
    throw new IllegalArgumentException(
        "Matched advisory candidate is absent from the analyzed inventory: " + candidate);
  }

  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  static String packageSourceDigest(
      final OsvAdvisoryRecord record, final OsvAffectedPackage affectedPackage) {
    return record.evidence().stream()
        .filter(PackageAdvisoryEvidence.class::isInstance)
        .map(PackageAdvisoryEvidence.class::cast)
        .filter(
            evidence ->
                evidence.scope().packageName().equals(affectedPackage.packageName())
                    && evidence.scope().ecosystem().equals(affectedPackage.ecosystem()))
        .map(evidence -> evidence.provenance().sourceRecordSha256())
        .filter(java.util.Objects::nonNull)
        .findFirst()
        .orElse(null);
  }

  private static OsvPackageApplicability.Result heuristicPackageApplicability(
      final String osvId,
      final HeuristicCandidateEvidence evidence,
      final ArtifactCoordinate candidate,
      final List<OsvAdvisoryRecord> records) {
    final List<OsvAffectedPackage> packages =
        records.stream()
            .filter(record -> record.osvId().equals(osvId))
            .flatMap(record -> record.affectedPackages().stream())
            .filter(
                affectedPackage ->
                    affectedPackage.ecosystem().equals(evidence.scope().ecosystem())
                        && affectedPackage.packageName().equals(evidence.scope().packageName())
                        && matchesPackageCoordinate(affectedPackage, candidate))
            .toList();
    if (packages.size() != SINGLE_MATCH) {
      return new OsvPackageApplicability.Result(
          OsvPackageApplicability.Status.UNRESOLVED, AMBIGUOUS_OWNER);
    }
    return OsvPackageApplicability.evaluate(packages.getFirst(), candidate.version());
  }

  private static boolean matchesPackageCoordinate(
      final OsvAffectedPackage affectedPackage, final ArtifactCoordinate candidate) {
    final ArtifactCoordinate source = affectedPackage.coordinate();
    return source.groupId().equals(candidate.groupId())
        && source.artifactId().equals(candidate.artifactId())
        && source.type().equals(candidate.type())
        && source.classifier().equals(candidate.classifier())
        && (source.version() == null || source.version().equals(candidate.version()));
  }

  private static boolean sameGavce(final ArtifactCoordinate left, final ArtifactCoordinate right) {
    return left.groupId().equals(right.groupId())
        && left.artifactId().equals(right.artifactId())
        && left.version().equals(right.version())
        && left.type().equals(right.type())
        && left.classifier().equals(right.classifier());
  }
}
