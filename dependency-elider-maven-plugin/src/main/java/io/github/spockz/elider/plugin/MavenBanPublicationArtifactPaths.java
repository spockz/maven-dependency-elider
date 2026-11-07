// WHY: Keeps staged, captured, and live artifact path checks together at the pre-report boundary.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.trimmer.ArtifactDigests;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.IOException;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.apache.maven.artifact.Artifact;

@SuppressWarnings({"PMD.CommentRequired", "PMD.UseConcurrentHashMap"})
final class MavenBanPublicationArtifactPaths {
  private MavenBanPublicationArtifactPaths() {}

  /* package */ static void verify(
      final MavenArtifactViewBinding binding,
      final ElisionAnalysisModel.ApplyPlan applyPlan,
      final List<ArtifactTrimRecord> records)
      throws IOException {
    final Map<ArtifactIdentity, ArtifactTrimRecord> trims = trimRecords(records);
    final Set<ArtifactIdentity> matchedResolved = verifyResolvedPaths(binding, applyPlan, trims);
    verifyDirectPaths(binding, applyPlan, trims);
    rejectUnmatchedRecords(trims.keySet(), matchedResolved);
  }

  private static Map<ArtifactIdentity, ArtifactTrimRecord> trimRecords(
      final List<ArtifactTrimRecord> records) throws IOException {
    final Map<ArtifactIdentity, ArtifactTrimRecord> trims = new HashMap<>();
    for (final ArtifactTrimRecord record : records) {
      final ArtifactIdentity identity = ArtifactIdentity.of(record.coordinate());
      if (trims.putIfAbsent(identity, record) != null) {
        throw new IOException("Ban output has duplicate trim records for " + identity);
      }
      if (!record.trimmedSha256().equals(ArtifactDigests.read(record.trimmedPath()).sha256())) {
        throw new IOException(
            "Trimmed output bytes changed before ban publication: " + record.coordinate());
      }
    }
    return trims;
  }

  private static Set<ArtifactIdentity> verifyResolvedPaths(
      final MavenArtifactViewBinding binding,
      final ElisionAnalysisModel.ApplyPlan applyPlan,
      final Map<ArtifactIdentity, ArtifactTrimRecord> trims)
      throws IOException {
    final Set<ArtifactIdentity> matchedResolved = new HashSet<>();
    for (final Artifact artifact : applyPlan.resolvedArtifacts()) {
      final ArtifactCoordinate coordinate = MavenArtifactInventory.toCoordinate(artifact);
      final ArtifactIdentity identity = ArtifactIdentity.of(coordinate);
      final ElisionAnalysisModel.ArtifactSnapshot source =
          capturedSource(binding.liveViews().resolvedSnapshots(), identity, "Final", coordinate);
      final ArtifactTrimRecord trim = trims.get(identity);
      verifyCurrentPath(artifact, source, trim, identity);
      if (trim != null) {
        matchedResolved.add(identity);
      }
    }
    return matchedResolved;
  }

  private static void verifyDirectPaths(
      final MavenArtifactViewBinding binding,
      final ElisionAnalysisModel.ApplyPlan applyPlan,
      final Map<ArtifactIdentity, ArtifactTrimRecord> trims)
      throws IOException {
    for (final Artifact artifact : applyPlan.directArtifacts()) {
      final ArtifactIdentity identity =
          ArtifactIdentity.of(MavenArtifactInventory.toCoordinate(artifact));
      final ArtifactTrimRecord trim = trims.get(identity);
      if (trim != null) {
        final ElisionAnalysisModel.ArtifactSnapshot source =
            capturedSource(binding.liveViews().directSnapshots(), identity, "Direct", null);
        verifyCurrentPath(artifact, source, trim, identity);
      }
    }
  }

  private static ElisionAnalysisModel.ArtifactSnapshot capturedSource(
      final List<ElisionAnalysisModel.ArtifactSnapshot> snapshots,
      final ArtifactIdentity identity,
      final String view,
      final ArtifactCoordinate coordinate)
      throws IOException {
    for (final ElisionAnalysisModel.ArtifactSnapshot snapshot : snapshots) {
      if (ArtifactIdentity.of(snapshot.coordinate()).equals(identity)) {
        return snapshot;
      }
    }
    throw new IOException(
        view + " artifact has no captured input: " + (coordinate == null ? identity : coordinate));
  }

  private static void verifyCurrentPath(
      final Artifact artifact,
      final ElisionAnalysisModel.ArtifactSnapshot source,
      final ArtifactTrimRecord trim,
      final ArtifactIdentity identity)
      throws IOException {
    final Path expected = trim == null ? source.filePath() : trim.originalPath();
    final Path actual = MavenArtifactInventory.normalizedPath(artifact);
    if (!Objects.equals(expected, actual)
        || (trim != null && !Objects.equals(source.filePath(), trim.originalPath()))) {
      throw new IOException("Artifact path changed before applying trim: " + identity);
    }
  }

  private static void rejectUnmatchedRecords(
      final Set<ArtifactIdentity> trims, final Set<ArtifactIdentity> matchedResolved)
      throws IOException {
    if (matchedResolved.containsAll(trims)) {
      return;
    }
    final Set<ArtifactIdentity> missing = new HashSet<>(trims);
    missing.removeAll(matchedResolved);
    throw new IOException("Trim records have no resolved Maven artifacts: " + missing);
  }

  private record ArtifactIdentity(
      String groupId, String artifactId, String version, String type, String classifier) {
    private static ArtifactIdentity of(final ArtifactCoordinate coordinate) {
      return new ArtifactIdentity(
          coordinate.groupId(),
          coordinate.artifactId(),
          coordinate.version(),
          coordinate.type(),
          coordinate.classifier());
    }
  }
}
