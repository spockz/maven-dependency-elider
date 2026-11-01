/* WHY: Converts exact source-file matches into review leads without granting proof authority. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.CorroboratedSourceClassCandidate;
import io.github.spockz.elider.model.CveAffectedEntryContext;
import io.github.spockz.elider.model.OsvAdvisoryRecord;
import io.github.spockz.elider.model.StructuredSourceClassEvidence;
import io.github.spockz.elider.scanner.JarSourceFileIndex;
import io.github.spockz.elider.scanner.JarSourceFileIndex.ClassSourceFile;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/** Builds review candidates from exact source and version matches. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class CorroboratedSourceCandidateMatcher {
  /** Maven package URL scheme used to reject display-name-only attribution. */
  private static final String MAVEN_PACKAGE_PREFIX = "pkg:maven/";

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

    final List<CorroboratedSourceClassCandidate> result = new ArrayList<>();
    for (final String sourceClaim : evidence.programFiles()) {
      result.addAll(
          candidatesForSourceClaim(
              sourceClaim,
              entry,
              evidence,
              matchedCoordinate,
              sourceIndex,
              conventionalLayoutAssumed));
    }
    return List.copyOf(result);
  }

  private static List<CorroboratedSourceClassCandidate> candidatesForSourceClaim(
      final String sourceClaim,
      final CveAffectedEntryContext entry,
      final StructuredSourceClassEvidence evidence,
      final ArtifactCoordinate matchedCoordinate,
      final JarSourceFileIndex sourceIndex,
      final boolean conventionalLayoutAssumed) {
    if (!SourceClaimPathMatcher.isSupportedJavaSourceClaim(sourceClaim)) {
      return List.of();
    }
    final String sourceBasename = SourceClaimPathMatcher.basename(sourceClaim);
    final List<CorroboratedSourceClassCandidate> result = new ArrayList<>();
    for (final ClassSourceFile classFile : sourceIndex.classFiles()) {
      if (matchesSourceClaim(classFile, sourceClaim, sourceBasename)) {
        result.add(
            candidate(
                sourceClaim,
                entry,
                evidence,
                matchedCoordinate,
                sourceIndex,
                classFile,
                conventionalLayoutAssumed));
      }
    }
    return result;
  }

  private static boolean matchesSourceClaim(
      final ClassSourceFile classFile, final String sourceClaim, final String sourceBasename) {
    if (classFile.sourceFile() == null
        || !classFile.sourceFile().equals(sourceBasename)
        || !SourceClaimPathMatcher.isTopLevelClassName(classFile.classEntry())) {
      return false;
    }
    final String classPackage = SourceClaimPathMatcher.classPackage(classFile.classEntry());
    return !classPackage.isBlank()
        && SourceClaimPathMatcher.hasPackageSuffix(sourceClaim, classPackage);
  }

  private static CorroboratedSourceClassCandidate candidate(
      final String sourceClaim,
      final CveAffectedEntryContext entry,
      final StructuredSourceClassEvidence evidence,
      final ArtifactCoordinate matchedCoordinate,
      final JarSourceFileIndex sourceIndex,
      final ClassSourceFile classFile,
      final boolean conventionalLayoutAssumed) {
    return new CorroboratedSourceClassCandidate(
        evidence.scope(),
        evidence.provenance(),
        entry.entryIdentity(),
        matchedCoordinate,
        sourceIndex.archiveSha256(),
        classFile.physicalJarEntry(),
        classFile.multiReleaseTier(),
        evidence.affectedProductIdentity(),
        sourceClaim,
        classFile.classEntry(),
        classFile.sourceFile(),
        SourceClaimPathMatcher.packageComparison(sourceClaim, classFile.classEntry()),
        conventionalLayoutAssumed,
        CorroboratedSourceClassCandidate.MappingStatus.INCOMPLETE_REVIEW_ONLY);
  }

  private static CveAffectedEntryContext applicableEntry(
      final OsvAdvisoryRecord record,
      final StructuredSourceClassEvidence evidence,
      final ArtifactCoordinate candidate) {
    if (!matchesOsvScope(evidence, candidate)
        || !MavenVersionRangeMatcher.includes(
            evidence.scope().versionRangeSpec(), candidate.version())) {
      return null;
    }
    final CveAffectedEntryContext entry = matchingEntry(record, evidence);
    if (entry == null
        || !matchesExactPackage(entry, candidate)
        || !hasExactAffectedVersion(entry, candidate.version())
        || !entry.programFiles().equals(evidence.programFiles())
        || !entry.programRoutines().equals(evidence.programRoutines())) {
      return null;
    }
    return entry;
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

  private static CveAffectedEntryContext matchingEntry(
      final OsvAdvisoryRecord record, final StructuredSourceClassEvidence evidence) {
    final List<CveAffectedEntryContext> matches =
        record.cnaAffectedEntries().stream()
            .filter(entry -> entry.entryIdentity().equals(evidence.cnaAffectedEntryIdentity()))
            .toList();
    return matches.size() == 1 ? matches.getFirst() : null;
  }

  private static boolean matchesExactPackage(
      final CveAffectedEntryContext entry, final ArtifactCoordinate candidate) {
    return (MAVEN_PACKAGE_PREFIX + candidate.groupId() + "/" + candidate.artifactId())
        .equals(entry.packageUrl());
  }

  private static boolean hasExactAffectedVersion(
      final CveAffectedEntryContext entry, final String version) {
    return entry.hasUnambiguousExactAffectedVersion(version);
  }
}
