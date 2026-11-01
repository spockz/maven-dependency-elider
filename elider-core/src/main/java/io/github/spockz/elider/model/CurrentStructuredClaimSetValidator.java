/* WHY: Checks a proof candidate against competing CVE owners in the current index. */

package io.github.spockz.elider.model;

import io.github.spockz.elider.scanner.VulnerabilityCacheEnvelope;
import java.io.IOException;
import java.util.List;
import java.util.Locale;

/** Rejects current-index ambiguity across OSV records that own the same CVE. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class CurrentStructuredClaimSetValidator {
  /** Exactly one package owner and structured claim may match. */
  private static final int ONE_MATCH = 1;

  private CurrentStructuredClaimSetValidator() {}

  static void requireUnique(
      final VulnerabilityCacheEnvelope envelope,
      final OsvAdvisoryRecord requestOwner,
      final StructuredSourceClassEvidence requestEvidence,
      final ArtifactCoordinate candidate,
      final OsvAffectedPackage requestPackage)
      throws IOException {
    final String cveId = requestEvidence.scope().cveId();
    final List<OsvAdvisoryRecord> cveOwners =
        envelope.records().stream()
            .filter(record -> record.osvId().equals(cveId) || record.aliases().contains(cveId))
            .toList();
    final List<PackageOwner> packageOwners =
        cveOwners.stream()
            .flatMap(
                owner ->
                    owner.affectedPackages().stream()
                        .filter(
                            item ->
                                isExactMavenPackage(
                                    item,
                                    requestEvidence.scope().ecosystem(),
                                    requestEvidence.scope().packageName(),
                                    candidate))
                        .map(item -> new PackageOwner(owner, item)))
            .toList();
    final List<StructuredOwner> structuredOwners =
        cveOwners.stream()
            .flatMap(
                owner ->
                    owner.evidence().stream()
                        .filter(StructuredSourceClassEvidence.class::isInstance)
                        .map(StructuredSourceClassEvidence.class::cast)
                        .filter(item -> isExactStructuredClaim(item, cveId, candidate))
                        .map(item -> new StructuredOwner(owner, item)))
            .toList();
    if (packageOwners.size() != ONE_MATCH
        || !packageOwners.getFirst().owner().equals(requestOwner)
        || !packageOwners.getFirst().affectedPackage().equals(requestPackage)
        || structuredOwners.size() != ONE_MATCH
        || !structuredOwners.getFirst().owner().equals(requestOwner)
        || !structuredOwners.getFirst().evidence().equals(requestEvidence)) {
      throw new IOException(
          "Current index has competing CVE owner claims for this Maven candidate");
    }
  }

  static boolean isMaven(final String ecosystem) {
    return "Maven".equalsIgnoreCase(ecosystem)
        || ecosystem.toLowerCase(Locale.ROOT).startsWith("maven:");
  }

  private static boolean isExactMavenPackage(
      final OsvAffectedPackage affectedPackage,
      final String ecosystem,
      final String packageName,
      final ArtifactCoordinate candidate) {
    return isMaven(affectedPackage.ecosystem())
        && affectedPackage.ecosystem().equalsIgnoreCase(ecosystem)
        && affectedPackage.packageName().equals(packageName)
        && affectedPackage.packageName().equals(candidate.groupId() + ":" + candidate.artifactId())
        && "jar".equals(candidate.type())
        && candidate.classifier().isEmpty();
  }

  private static boolean isExactStructuredClaim(
      final StructuredSourceClassEvidence evidence,
      final String cveId,
      final ArtifactCoordinate candidate) {
    final ArtifactCoordinate scope = evidence.scope().affectedCoordinate();
    return evidence.provenance().origin() == EvidenceOrigin.CVE_LIST
        && cveId.equals(evidence.scope().cveId())
        && cveId.equals(evidence.provenance().sourceRecordId())
        && scope.groupId().equals(candidate.groupId())
        && scope.artifactId().equals(candidate.artifactId())
        && scope.type().equals(candidate.type())
        && scope.classifier().equals(candidate.classifier())
        && (scope.version() == null || scope.version().equals(candidate.version()));
  }

  private record PackageOwner(OsvAdvisoryRecord owner, OsvAffectedPackage affectedPackage) {}

  private record StructuredOwner(OsvAdvisoryRecord owner, StructuredSourceClassEvidence evidence) {}
}
