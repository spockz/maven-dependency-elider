// WHY: Rechecks captured and staged bytes before the resolver plan commits.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.trimmer.ArtifactDigests;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.apache.maven.artifact.Artifact;

/** Verifies final artifact paths and digests against the prepared output plan. */
final class MavenBanFinalOutputVerifier {
  private MavenBanFinalOutputVerifier() {}

  /* package */ static void verify(
      final MavenArtifactViewBinding binding,
      final ElisionAnalysisModel.ApplyPlan applyPlan,
      final List<ArtifactTrimRecord> records)
      throws IOException {
    binding.verifyOriginalInputsFresh();
    final Map<ArtifactIdentity, ArtifactTrimRecord> trims = trimsByIdentity(records);
    for (final Artifact artifact : applyPlan.resolvedArtifacts()) {
      verifyFinalArtifact(binding, artifact, trims);
    }
  }

  private static Map<ArtifactIdentity, ArtifactTrimRecord> trimsByIdentity(
      final List<ArtifactTrimRecord> records) throws IOException {
    final Map<ArtifactIdentity, ArtifactTrimRecord> trims = new ConcurrentHashMap<>();
    for (final ArtifactTrimRecord record : records) {
      final ArtifactIdentity identity = ArtifactIdentity.of(record.coordinate());
      if (trims.putIfAbsent(identity, record) != null) {
        throw new IOException("Ban output has duplicate trim records for " + identity);
      }
    }
    return trims;
  }

  private static void verifyFinalArtifact(
      final MavenArtifactViewBinding binding,
      final Artifact artifact,
      final Map<ArtifactIdentity, ArtifactTrimRecord> trims)
      throws IOException {
    final ArtifactCoordinate coordinate = MavenArtifactInventory.toCoordinate(artifact);
    final ElisionAnalysisModel.ArtifactSnapshot source = sourceFor(binding, coordinate);
    final ArtifactTrimRecord trim = trims.get(ArtifactIdentity.of(coordinate));
    verifyFinalPath(coordinate, artifact, trim == null ? source.filePath() : trim.trimmedPath());
    verifyTrimDigest(coordinate, trim);
  }

  private static void verifyFinalPath(
      final ArtifactCoordinate coordinate, final Artifact artifact, final Path expectedPath)
      throws IOException {
    if (expectedPath == null) {
      if (artifact.getFile() != null) {
        throw pathMismatch(coordinate);
      }
      return;
    }
    if (!expectedPath.equals(finalPath(artifact))) {
      throw pathMismatch(coordinate);
    }
  }

  private static void verifyTrimDigest(
      final ArtifactCoordinate coordinate, final ArtifactTrimRecord trim) throws IOException {
    if (trim != null
        && !trim.trimmedSha256().equals(ArtifactDigests.read(trim.trimmedPath()).sha256())) {
      throw new IOException("Trimmed output bytes changed before ban publication: " + coordinate);
    }
  }

  private static ElisionAnalysisModel.ArtifactSnapshot sourceFor(
      final MavenArtifactViewBinding binding, final ArtifactCoordinate coordinate)
      throws IOException {
    return binding.liveViews().resolvedSnapshots().stream()
        .filter(snapshot -> snapshot.coordinate().equals(coordinate))
        .findFirst()
        .orElseThrow(() -> new IOException("Final artifact has no captured input: " + coordinate));
  }

  private static Path finalPath(final Artifact artifact) {
    return MavenArtifactInventory.normalizedPath(artifact);
  }

  private static IOException pathMismatch(final ArtifactCoordinate coordinate) {
    return new IOException("Final artifact path differs from its verified output: " + coordinate);
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
