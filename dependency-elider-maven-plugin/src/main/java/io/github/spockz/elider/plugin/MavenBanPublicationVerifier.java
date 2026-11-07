// WHY: Checks final Maven views before delegating graph and output proofs ahead of plan commit.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.plugin.MojoFailureException;

/** Verifies final ban absence in the live views and staged output. */
final class MavenBanPublicationVerifier {
  private MavenBanPublicationVerifier() {}

  /* package */ static void verify(
      final MavenBanPlan banPlan,
      final MavenArtifactViewBinding binding,
      final ElisionAnalysisModel.ApplyPlan applyPlan,
      final ElisionAnalysisModel.Analysis analysis)
      throws IOException, MojoFailureException {
    banPlan.verifyAuditBytesFresh();
    verifyPlannedViews(banPlan, applyPlan, analysis);
    MavenBanPublicationGraphVerifier.verify(banPlan, binding, analysis.graphProjection());
    MavenBanFinalOutputVerifier.verify(binding, applyPlan, analysis.trimResult().records());
    MavenBanRetainedProviderClosure.verify(
        analysis.banPlan(),
        new ArrayList<>(applyPlan.resolvedArtifacts()),
        analysis.trimResult().records(),
        analysis);
  }

  private static void verifyPlannedViews(
      final MavenBanPlan banPlan,
      final ElisionAnalysisModel.ApplyPlan applyPlan,
      final ElisionAnalysisModel.Analysis analysis)
      throws MojoFailureException {
    final List<Artifact> resolved = new ArrayList<>(applyPlan.resolvedArtifacts());
    final List<Artifact> direct = new ArrayList<>(applyPlan.directArtifacts());
    rejectBanArtifacts(banPlan, resolved, "final resolved view");
    rejectBanArtifacts(banPlan, direct, "final direct view");
    rejectBanTrimRecords(banPlan, analysis.trimResult().records());
  }

  private static void rejectBanArtifacts(
      final MavenBanPlan banPlan, final List<Artifact> artifacts, final String location)
      throws MojoFailureException {
    for (final Artifact artifact : artifacts) {
      rejectBan(banPlan, artifact, location);
    }
  }

  private static void rejectBanTrimRecords(
      final MavenBanPlan banPlan, final List<ArtifactTrimRecord> records)
      throws MojoFailureException {
    for (final ArtifactTrimRecord record : records) {
      for (final MavenBanPlan.Entry entry : banPlan.entries()) {
        if (sameDependencyIdentity(entry.dependency(), record.coordinate())) {
          throw MavenBanClassProviderClosure.conflict(
              record.coordinate(), "requested dependency is present in trim output membership");
        }
      }
    }
  }

  private static void rejectBan(
      final MavenBanPlan banPlan, final Artifact artifact, final String location)
      throws MojoFailureException {
    final ArtifactCoordinate coordinate = MavenArtifactInventory.toCoordinate(artifact);
    for (final MavenBanPlan.Entry entry : banPlan.entries()) {
      if (sameDependencyIdentity(entry.dependency(), coordinate)) {
        throw MavenBanClassProviderClosure.conflict(
            coordinate, "requested dependency is present in " + location);
      }
    }
  }

  private static boolean sameDependencyIdentity(
      final BanishedDependency dependency, final ArtifactCoordinate coordinate) {
    return dependency.groupId().equals(coordinate.groupId())
        && dependency.artifactId().equals(coordinate.artifactId());
  }
}
