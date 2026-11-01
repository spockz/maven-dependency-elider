/* WHY: Builds review candidates only after the matcher binds an exact CNA entry. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.CorroboratedSourceClassCandidate;
import io.github.spockz.elider.model.CveAffectedEntryContext;
import io.github.spockz.elider.model.StructuredSourceClassEvidence;
import io.github.spockz.elider.scanner.JarSourceFileIndex;
import io.github.spockz.elider.scanner.JarSourceFileIndex.ClassSourceFile;
import java.util.ArrayList;
import java.util.List;

/** Creates incomplete source matches for later human review. */
final class CorroboratedSourceClassCandidateFactory {
  private CorroboratedSourceClassCandidateFactory() {}

  /* package */ static List<CorroboratedSourceClassCandidate> candidates(
      final StructuredSourceClassEvidence evidence,
      final CveAffectedEntryContext entry,
      final ArtifactCoordinate matchedCoordinate,
      final JarSourceFileIndex sourceIndex,
      final boolean conventionalLayoutAssumed) {
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
}
