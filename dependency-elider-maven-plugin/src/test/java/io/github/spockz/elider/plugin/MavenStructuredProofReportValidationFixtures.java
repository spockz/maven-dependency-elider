// WHY: Builds isolated typed and serialized proof payload mutations for report validation tests.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.StructuredProofProvenance;
import java.util.ArrayList;
import java.util.List;

/** Small report mutation helpers shared by structured proof persistence tests. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class MavenStructuredProofReportValidationFixtures {
  private MavenStructuredProofReportValidationFixtures() {}

  /** Creates a typed proof row with a changed saved layout flag. */
  static MavenElisionReportSnapshot.VerifiedStructuredProofFinding withLayoutAssumption(
      final MavenElisionReportSnapshot.VerifiedStructuredProofFinding proof,
      final boolean layoutAssumed) {
    final StructuredProofProvenance provenance = proof.provenance();
    return new MavenElisionReportSnapshot.VerifiedStructuredProofFinding(
        proof.cveId(),
        proof.coordinate(),
        proof.originalSha256(),
        proof.trimmedSha256(),
        copyProvenance(provenance, provenance.rawScopeEvidence(), layoutAssumed));
  }

  /** Creates a typed proof row with a changed original archive digest. */
  static MavenElisionReportSnapshot.VerifiedStructuredProofFinding withOriginalDigest(
      final MavenElisionReportSnapshot.VerifiedStructuredProofFinding proof,
      final String originalDigest) {
    return new MavenElisionReportSnapshot.VerifiedStructuredProofFinding(
        proof.cveId(),
        proof.coordinate(),
        originalDigest,
        proof.trimmedSha256(),
        proof.provenance());
  }

  /** Creates the same GAVCE proof with a different Maven scope suffix. */
  static MavenElisionReportSnapshot.VerifiedStructuredProofFinding withProofRuntimeScope(
      final MavenElisionReportSnapshot.VerifiedStructuredProofFinding proof) {
    final ArtifactCoordinate coordinate =
        MavenElisionReportSourceCoordinateValidator.parseCanonical(proof.coordinate());
    final ArtifactCoordinate runtimeCoordinate =
        new ArtifactCoordinate(
            coordinate.groupId(),
            coordinate.artifactId(),
            coordinate.version(),
            coordinate.type(),
            coordinate.classifier(),
            "runtime");
    return new MavenElisionReportSnapshot.VerifiedStructuredProofFinding(
        proof.cveId(),
        runtimeCoordinate.toString(),
        proof.originalSha256(),
        proof.trimmedSha256(),
        proof.provenance());
  }

  /** Creates a typed proof row with a changed OSV package name. */
  static MavenElisionReportSnapshot.VerifiedStructuredProofFinding withRawPackageName(
      final MavenElisionReportSnapshot.VerifiedStructuredProofFinding proof,
      final String packageName) {
    final StructuredProofProvenance provenance = proof.provenance();
    final StructuredProofProvenance.RawScopeEvidence rawScope = provenance.rawScopeEvidence();
    final StructuredProofProvenance.RawScopeEvidence changedScope =
        new StructuredProofProvenance.RawScopeEvidence(
            rawScope.osvModified(),
            rawScope.osvEcosystem(),
            packageName,
            rawScope.osvVersions(),
            rawScope.osvRanges(),
            rawScope.cveState(),
            rawScope.cnaDefaultStatus(),
            rawScope.cnaVersions(),
            rawScope.osvStatus(),
            rawScope.cnaStatus(),
            rawScope.osvRationale(),
            rawScope.cnaRationale());
    return new MavenElisionReportSnapshot.VerifiedStructuredProofFinding(
        proof.cveId(),
        proof.coordinate(),
        proof.originalSha256(),
        proof.trimmedSha256(),
        copyProvenance(provenance, changedScope, provenance.conventionalLayoutAssumed()));
  }

  /** Builds a source review row from a live matched source claim. */
  static MavenElisionReportSnapshot.SourceReviewFinding sourceReviewFinding(
      final MavenVulnerabilityAssessment.MatchedSourceClaim claim) {
    return new MavenElisionReportSnapshot.SourceReviewFinding(
        claim.osvId(),
        claim.cveId(),
        claim.coordinate().toString(),
        claim.sourceRecordSha256(),
        claim.cnaAffectedEntryIdentity(),
        claim.affectedProductIdentity(),
        claim.programFiles(),
        claim.programRoutines(),
        claim.conventionalLayoutAssumed(),
        claim.matches().stream().map(MavenElisionReportSnapshot.SourceReviewMatch::from).toList(),
        claim.applicability(),
        claim.applicabilityRationale(),
        claim.unresolvedRationale());
  }

  /** Creates a source-review finding with another scope but identical GAVCE claims. */
  static MavenElisionReportSnapshot.SourceReviewFinding withReviewRuntimeScope(
      final MavenElisionReportSnapshot.SourceReviewFinding finding) {
    final ArtifactCoordinate coordinate =
        MavenElisionReportSourceCoordinateValidator.parseCanonical(finding.coordinate());
    final ArtifactCoordinate runtimeCoordinate =
        new ArtifactCoordinate(
            coordinate.groupId(),
            coordinate.artifactId(),
            coordinate.version(),
            coordinate.type(),
            coordinate.classifier(),
            "runtime");
    return new MavenElisionReportSnapshot.SourceReviewFinding(
        finding.osvId(),
        finding.cveId(),
        runtimeCoordinate.toString(),
        finding.sourceRecordSha256(),
        finding.cnaAffectedEntryIdentity(),
        finding.affectedProductIdentity(),
        finding.programFiles(),
        finding.programRoutines(),
        finding.conventionalLayoutAssumed(),
        finding.matches(),
        finding.applicability(),
        finding.applicabilityRationale(),
        finding.unresolvedRationale());
  }

  /** Adds one unverified routine claim while preserving a row's verified claims. */
  static MavenElisionReportSnapshot.SourceReviewFinding withUnresolvedRoutine(
      final MavenElisionReportSnapshot.SourceReviewFinding finding) {
    final List<String> routines = new ArrayList<>(finding.programRoutines());
    routines.add("parseUnverified");
    return new MavenElisionReportSnapshot.SourceReviewFinding(
        finding.osvId(),
        finding.cveId(),
        finding.coordinate(),
        finding.sourceRecordSha256(),
        finding.cnaAffectedEntryIdentity(),
        finding.affectedProductIdentity(),
        finding.programFiles(),
        routines,
        finding.conventionalLayoutAssumed(),
        finding.matches(),
        finding.applicability(),
        finding.applicabilityRationale(),
        finding.unresolvedRationale());
  }

  private static StructuredProofProvenance copyProvenance(
      final StructuredProofProvenance provenance,
      final StructuredProofProvenance.RawScopeEvidence rawScope,
      final boolean layoutAssumed) {
    return new StructuredProofProvenance(
        provenance.osvId(),
        provenance.cveSourceSha256(),
        provenance.cnaAffectedEntryIdentity(),
        provenance.affectedProductIdentity(),
        provenance.osvSourceAuthority(),
        provenance.sourcesCoordinate(),
        provenance.sourcesArchiveSha256(),
        provenance.sourceRepositoryProvenance(),
        provenance.compilerIdentity(),
        provenance.compilerOptions(),
        layoutAssumed,
        rawScope,
        provenance.claimAttributions());
  }
}
