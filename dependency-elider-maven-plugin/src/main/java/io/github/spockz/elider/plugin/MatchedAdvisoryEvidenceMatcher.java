// WHY: Separates advisory review matching and live SourceFile corroboration from proof assessment.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.AdvisoryEvidence;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.CorroboratedSourceClassCandidate;
import io.github.spockz.elider.model.OsvAdvisoryRecord;
import io.github.spockz.elider.model.StructuredSourceClassEvidence;
import io.github.spockz.elider.scanner.JarSourceFileIndex;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.apache.maven.plugin.logging.Log;

/** Matches cached advisory claims and recomputes artifact-bound review candidates. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class MatchedAdvisoryEvidenceMatcher {
  /** Restricts source-attribute inspection to exact Maven JAR snapshots. */
  private static final String JAR_SUFFIX = ".jar";

  /** Immutable advisory records loaded through the validated cache boundary. */
  private final List<OsvAdvisoryRecord> records;

  /** Original artifact snapshots from the current analysis. */
  private final List<ElisionAnalysisModel.ArtifactSnapshot> artifacts;

  /** Logger for best-effort source review diagnostics. */
  private final Log log;

  /** Saved assumption for this assessment; it does not affect candidate selection. */
  private final boolean conventionalLayoutAssumed;

  /** Reuses each immutable archive index during one assessment. */
  @SuppressWarnings("PMD.UseConcurrentHashMap") // This state is confined to one assessment call.
  private final Map<Path, JarSourceFileIndex> sourceIndexes = new HashMap<>();

  MatchedAdvisoryEvidenceMatcher(
      final List<OsvAdvisoryRecord> records,
      final List<ElisionAnalysisModel.ArtifactSnapshot> artifacts,
      final Log log,
      final boolean conventionalLayoutAssumed) {
    this.records = List.copyOf(records);
    this.artifacts = List.copyOf(artifacts);
    this.log = log;
    this.conventionalLayoutAssumed = conventionalLayoutAssumed;
  }

  List<MavenVulnerabilityAssessment.MatchedAdvisoryEvidence> matching(
      final ArtifactCoordinate candidate) {
    final List<MavenVulnerabilityAssessment.MatchedAdvisoryEvidence> matched = new ArrayList<>();
    for (final OsvAdvisoryRecord record : records) {
      for (final AdvisoryEvidence evidence : record.evidence()) {
        if (evidence instanceof CorroboratedSourceClassCandidate) {
          continue;
        }
        if (applies(evidence, candidate)) {
          matched.add(
              new MavenVulnerabilityAssessment.MatchedAdvisoryEvidence(
                  record.osvId(), record.aliases(), evidence));
        }
      }
    }
    addCurrentCorroboration(candidate, matched);
    return List.copyOf(matched);
  }

  private void addCurrentCorroboration(
      final ArtifactCoordinate candidate,
      final List<MavenVulnerabilityAssessment.MatchedAdvisoryEvidence> matched) {
    if (!CorroboratedSourceCandidateMatcher.hasApplicableClaims(records, candidate)) {
      return;
    }
    final List<ElisionAnalysisModel.ArtifactSnapshot> snapshots =
        artifacts.stream().filter(value -> sameGavce(value.coordinate(), candidate)).toList();
    if (snapshots.size() != 1 || snapshots.getFirst().filePath() == null) {
      return;
    }
    final Path archivePath = snapshots.getFirst().filePath().toAbsolutePath().normalize();
    final Path fileName = archivePath.getFileName();
    if (fileName == null || !fileName.toString().toLowerCase(Locale.ROOT).endsWith(JAR_SUFFIX)) {
      return;
    }
    final JarSourceFileIndex sourceIndex = sourceIndex(archivePath);
    if (sourceIndex == null) {
      return;
    }
    addCandidates(candidate, sourceIndex, matched);
  }

  private JarSourceFileIndex sourceIndex(final Path archivePath) {
    JarSourceFileIndex index = sourceIndexes.get(archivePath);
    if (index != null) {
      return index;
    }
    try {
      index = JarSourceFileIndex.read(archivePath);
    } catch (final IOException failure) {
      if (log.isWarnEnabled()) {
        log.warn("Could not corroborate source-file claims in " + archivePath, failure);
      }
      return null;
    }
    sourceIndexes.put(archivePath, index);
    return index;
  }

  private void addCandidates(
      final ArtifactCoordinate candidate,
      final JarSourceFileIndex sourceIndex,
      final List<MavenVulnerabilityAssessment.MatchedAdvisoryEvidence> matched) {
    for (final OsvAdvisoryRecord record : records) {
      for (final AdvisoryEvidence evidence : record.evidence()) {
        if (evidence instanceof StructuredSourceClassEvidence structured) {
          CorroboratedSourceCandidateMatcher.candidates(
                  record, structured, candidate, sourceIndex, conventionalLayoutAssumed)
              .forEach(
                  corroborated ->
                      matched.add(
                          new MavenVulnerabilityAssessment.MatchedAdvisoryEvidence(
                              record.osvId(), record.aliases(), corroborated)));
        }
      }
    }
  }

  private static boolean applies(
      final AdvisoryEvidence evidence, final ArtifactCoordinate candidate) {
    final ArtifactCoordinate affected = evidence.scope().affectedCoordinate();
    return affected.groupId().equals(candidate.groupId())
        && affected.artifactId().equals(candidate.artifactId())
        && affected.type().equals(candidate.type())
        && affected.classifier().equals(candidate.classifier())
        && MavenVersionRangeMatcher.includes(
            evidence.scope().versionRangeSpec(), candidate.version());
  }

  private static boolean sameGavce(final ArtifactCoordinate left, final ArtifactCoordinate right) {
    return left.groupId().equals(right.groupId())
        && left.artifactId().equals(right.artifactId())
        && left.version().equals(right.version())
        && left.type().equals(right.type())
        && left.classifier().equals(right.classifier());
  }
}
