// WHY: Rejects references to classes from removed providers because same-name classes may differ.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.project.MavenProject;

/** Shares provider resolution across both ban checks. */
final class MavenBanClassProviderClosure {
  /** The minimum count that represents a unique provider. */
  private static final int ONE_PROVIDER = 1;

  private MavenBanClassProviderClosure() {}

  /* package */ static void verifyPublication(
      final MavenBanPlan banPlan,
      final MavenArtifactViewBinding binding,
      final ElisionAnalysisModel.ApplyPlan applyPlan,
      final ElisionAnalysisModel.Analysis analysis,
      final MavenProject project,
      final MavenSession session)
      throws IOException, MojoFailureException {
    banPlan.verifyContext(binding.resolutionContext());
    binding.verifyFresh(project);
    banPlan.verifyAuditFresh(project, session);
    verifyPlannedMembership(banPlan, applyPlan, analysis.trimResult().records());
    ResolverArtifactGraphProjection.verifyBanPublication(
        banPlan, binding, analysis.graphProjection());
    MavenBanPublicationArtifactPaths.verify(binding, applyPlan, analysis.trimResult().records());
    MavenBanFinalBytecodeClosure.verify(
        analysis.banPlan(),
        new ArrayList<>(applyPlan.resolvedArtifacts()),
        analysis.trimResult().records(),
        analysis);
  }

  private static void verifyPlannedMembership(
      final MavenBanPlan banPlan,
      final ElisionAnalysisModel.ApplyPlan applyPlan,
      final List<ArtifactTrimRecord> records)
      throws MojoFailureException {
    rejectBanArtifacts(
        banPlan, new ArrayList<>(applyPlan.resolvedArtifacts()), "final resolved view");
    rejectBanArtifacts(banPlan, new ArrayList<>(applyPlan.directArtifacts()), "final direct view");
    for (final ArtifactTrimRecord record : records) {
      for (final MavenBanPlan.Entry entry : banPlan.entries()) {
        if (sameDependencyIdentity(entry.dependency(), record.coordinate())) {
          throw conflict(
              record.coordinate(), "requested dependency is present in trim output membership");
        }
      }
    }
  }

  private static void rejectBanArtifacts(
      final MavenBanPlan banPlan, final List<Artifact> artifacts, final String location)
      throws MojoFailureException {
    for (final Artifact artifact : artifacts) {
      final ArtifactCoordinate coordinate = MavenArtifactInventory.toCoordinate(artifact);
      for (final MavenBanPlan.Entry entry : banPlan.entries()) {
        if (sameDependencyIdentity(entry.dependency(), coordinate)) {
          throw conflict(coordinate, "requested dependency is present in " + location);
        }
      }
    }
  }

  private static boolean sameDependencyIdentity(
      final BanishedDependency dependency, final ArtifactCoordinate coordinate) {
    return dependency.groupId().equals(coordinate.groupId())
        && dependency.artifactId().equals(coordinate.artifactId());
  }

  /* package */ static void verifyReference(
      final String className,
      final String location,
      final Map<String, List<ArtifactCoordinate>> absentOwners,
      final Map<String, List<ArtifactCoordinate>> effectiveOwners,
      final Set<ArtifactCoordinate> retainedArtifacts,
      final Set<String> effectiveProjectClasses)
      throws MojoFailureException {
    final List<ArtifactCoordinate> absent = absentOwners.getOrDefault(className, List.of());
    if (absent.isEmpty()) {
      return;
    }
    final List<ArtifactCoordinate> retained =
        effectiveOwners.getOrDefault(className, List.of()).stream()
            .filter(retainedArtifacts::contains)
            .toList();
    final int effectiveProviderCount =
        retained.size() + (effectiveProjectClasses.contains(className) ? 1 : 0);
    final String reason;
    if (effectiveProviderCount == ONE_PROVIDER) {
      reason =
          location
              + " references class "
              + className
              + " also supplied by a forced-absent artifact; same-name providers are not proven "
              + "equivalent";
    } else if (effectiveProviderCount > ONE_PROVIDER || absent.size() > ONE_PROVIDER) {
      reason =
          "class " + className + " has ambiguous retained and removed providers during " + location;
    } else {
      reason = location + " has no retained provider for class " + className;
    }
    throw conflict(absent.getFirst(), reason);
  }

  /* package */ static MojoFailureException conflict(
      final ArtifactCoordinate coordinate, final String reason) {
    return new MojoFailureException(
        "elide.banishedDependencies conflicts with " + coordinate + ": " + reason);
  }
}
