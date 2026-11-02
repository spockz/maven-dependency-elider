// WHY: Checks final Maven views before delegating graph and output proofs ahead of plan commit.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.project.MavenProject;

/** Verifies final ban absence in the live views and staged output. */
final class MavenBanPublicationVerifier {
  private MavenBanPublicationVerifier() {}

  /* package */ static void verify(
      final MavenBanPlan banPlan,
      final MavenArtifactViewBinding binding,
      final MavenProject project,
      final ElisionAnalysisModel.ApplyPlan applyPlan,
      final ElisionAnalysisModel.Analysis analysis)
      throws IOException, MojoFailureException {
    banPlan.verifyAuditBytesFresh();
    verifyFinalViews(banPlan, project, applyPlan, analysis);
    MavenBanPublicationGraphVerifier.verify(banPlan, binding, analysis.graphProjection());
    MavenBanFinalOutputVerifier.verify(binding, applyPlan, analysis.trimResult().records());
    MavenBanRetainedProviderClosure.verify(banPlan, project, analysis);
  }

  private static void verifyFinalViews(
      final MavenBanPlan banPlan,
      final MavenProject project,
      final ElisionAnalysisModel.ApplyPlan applyPlan,
      final ElisionAnalysisModel.Analysis analysis)
      throws MojoFailureException {
    final List<Artifact> resolved = new ArrayList<>(project.getArtifacts());
    final boolean directPresent = project.getDependencyArtifacts() != null;
    final List<Artifact> direct =
        directPresent ? new ArrayList<>(project.getDependencyArtifacts()) : List.of();
    if (directPresent != applyPlan.directArtifactsPresent()) {
      throw new MojoFailureException(
          "Final Maven direct view presence differs from the apply plan");
    }
    requireSameReferences("resolved", resolved, applyPlan.resolvedArtifacts());
    requireSameReferences("direct", direct, applyPlan.directArtifacts());
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

  private static void requireSameReferences(
      final String viewName, final List<Artifact> actual, final Set<Artifact> expected)
      throws MojoFailureException {
    final Set<Artifact> actualReferences =
        java.util.Collections.newSetFromMap(new java.util.IdentityHashMap<>());
    actualReferences.addAll(actual);
    final Set<Artifact> expectedReferences =
        java.util.Collections.newSetFromMap(new java.util.IdentityHashMap<>());
    expectedReferences.addAll(expected);
    if (actual.size() != expected.size() || !actualReferences.equals(expectedReferences)) {
      throw new MojoFailureException(
          "Final Maven " + viewName + " view differs from the apply plan");
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
