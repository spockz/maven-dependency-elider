/* WHY: Converts exact source-file matches into review leads without granting proof authority. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.CorroboratedSourceClassCandidate;
import io.github.spockz.elider.model.CveAffectedEntryContext;
import io.github.spockz.elider.model.MavenPackageIdentity;
import io.github.spockz.elider.model.OsvAdvisoryRecord;
import io.github.spockz.elider.model.OsvAffectedPackage;
import io.github.spockz.elider.model.StructuredSourceClassEvidence;
import io.github.spockz.elider.scanner.JarSourceFileIndex;
import java.util.List;
import java.util.Objects;

/** Builds review candidates from exact source and version matches. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class CorroboratedSourceCandidateMatcher {
  /** Exact identity admission requires one matching entry. */
  private static final int ONE_MATCH = 1;

  private CorroboratedSourceCandidateMatcher() {}

  static boolean hasApplicableClaims(
      final List<OsvAdvisoryRecord> records, final ArtifactCoordinate candidate) {
    return records.stream()
        .anyMatch(
            record ->
                record.evidence().stream()
                    .filter(StructuredSourceClassEvidence.class::isInstance)
                    .map(StructuredSourceClassEvidence.class::cast)
                    .filter(evidence -> !evidence.programFiles().isEmpty())
                    .anyMatch(evidence -> applicableEntry(record, evidence, candidate) != null));
  }

  static boolean isApplicable(
      final OsvAdvisoryRecord record,
      final StructuredSourceClassEvidence evidence,
      final ArtifactCoordinate candidate) {
    return applicableEntry(record, evidence, candidate) != null;
  }

  static List<CorroboratedSourceClassCandidate> candidates(
      final OsvAdvisoryRecord record,
      final StructuredSourceClassEvidence evidence,
      final ArtifactCoordinate matchedCoordinate,
      final JarSourceFileIndex sourceIndex,
      final boolean conventionalLayoutAssumed) {
    Objects.requireNonNull(record, "record");
    Objects.requireNonNull(evidence, "evidence");
    Objects.requireNonNull(matchedCoordinate, "matchedCoordinate");
    Objects.requireNonNull(sourceIndex, "sourceIndex");
    final CveAffectedEntryContext entry = applicableEntry(record, evidence, matchedCoordinate);
    if (entry == null) {
      return List.of();
    }

    return CorroboratedSourceClassCandidateFactory.candidates(
        evidence, entry, matchedCoordinate, sourceIndex, conventionalLayoutAssumed);
  }

  private static CveAffectedEntryContext applicableEntry(
      final OsvAdvisoryRecord record,
      final StructuredSourceClassEvidence evidence,
      final ArtifactCoordinate candidate) {
    if (!matchesOsvScope(evidence, candidate) || !entryMetadataMatches(record, evidence)) {
      return null;
    }
    final CveAffectedEntryContext entry = selectApplicableEntry(record, evidence, candidate);
    if (entry == null
        || !entry.programFiles().equals(evidence.programFiles())
        || !entry.programRoutines().equals(evidence.programRoutines())) {
      return null;
    }
    final List<OsvAffectedPackage> packages =
        record.affectedPackages().stream()
            .filter(affectedPackage -> matchesOsvPackage(affectedPackage, candidate))
            .toList();
    if (!hasExactlyOneAffectedPackage(packages, entry, candidate)) {
      return null;
    }
    return entry;
  }

  private static CveAffectedEntryContext selectApplicableEntry(
      final OsvAdvisoryRecord record,
      final StructuredSourceClassEvidence evidence,
      final ArtifactCoordinate candidate) {
    final List<CveAffectedEntryContext> applicableEntries =
        record.cnaAffectedEntries().stream()
            .filter(entry -> MavenPackageIdentity.matchesCnaArtifact(entry, candidate))
            .filter(
                entry ->
                    entry
                        .sourceRecord()
                        .authorizesStructuredClaims(
                            evidence.scope().cveId(), record.osvId(), record.aliases()))
            .toList();
    if (applicableEntries.size() != ONE_MATCH) {
      return null;
    }
    final List<CveAffectedEntryContext> matchingEntries =
        record.cnaAffectedEntries().stream()
            .filter(entry -> entry.entryIdentity().equals(evidence.cnaAffectedEntryIdentity()))
            .toList();
    final CveAffectedEntryContext entry =
        matchingEntries.size() == ONE_MATCH ? matchingEntries.getFirst() : null;
    return entry != null && entry.equals(applicableEntries.getFirst()) ? entry : null;
  }

  private static boolean hasExactlyOneAffectedPackage(
      final List<OsvAffectedPackage> packages,
      final CveAffectedEntryContext entry,
      final ArtifactCoordinate candidate) {
    return packages.size() == ONE_MATCH
        && MavenRawScopeApplicability.evaluateStructured(
                    packages.getFirst(), entry, candidate.version())
                .status()
            == MavenRawScopeApplicability.Status.AFFECTED;
  }

  private static boolean entryMetadataMatches(
      final OsvAdvisoryRecord record, final StructuredSourceClassEvidence evidence) {
    return record.cnaAffectedEntries().stream()
        .filter(entry -> entry.entryIdentity().equals(evidence.cnaAffectedEntryIdentity()))
        .filter(
            entry ->
                entry
                    .sourceRecord()
                    .authorizesStructuredClaims(
                        evidence.scope().cveId(), record.osvId(), record.aliases()))
        .anyMatch(
            entry ->
                entry
                    .sourceRecord()
                    .sourceRecordSha256()
                    .equals(evidence.provenance().sourceRecordSha256()));
  }

  private static boolean matchesOsvPackage(
      final OsvAffectedPackage affectedPackage, final ArtifactCoordinate candidate) {
    final ArtifactCoordinate packageCoordinate = affectedPackage.coordinate();
    return "maven".equalsIgnoreCase(affectedPackage.ecosystem())
        && affectedPackage.packageName().equals(candidate.groupId() + ":" + candidate.artifactId())
        && packageCoordinate.groupId().equals(candidate.groupId())
        && packageCoordinate.artifactId().equals(candidate.artifactId())
        && packageCoordinate.type().equals(candidate.type())
        && packageCoordinate.classifier().equals(candidate.classifier());
  }

  private static boolean matchesOsvScope(
      final StructuredSourceClassEvidence evidence, final ArtifactCoordinate candidate) {
    final ArtifactCoordinate affected = evidence.scope().affectedCoordinate();
    return affected.groupId().equals(candidate.groupId())
        && affected.artifactId().equals(candidate.artifactId())
        && affected.type().equals(candidate.type())
        && affected.classifier().equals(candidate.classifier())
        && (affected.version() == null || affected.version().equals(candidate.version()));
  }
}
