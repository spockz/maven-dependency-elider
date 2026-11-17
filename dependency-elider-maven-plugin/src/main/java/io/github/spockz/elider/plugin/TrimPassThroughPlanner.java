/* WHY: Keeps skip-coordinate validation and unsupported archive policy
 * identical for analysis and publication. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.MultiReleaseClassInventory;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/** Applies the same unsupported-archive policy to analysis and publication. */
final class TrimPassThroughPlanner {
  /** Production scopes eligible for candidate trimming. */
  /* package */ static final Set<String> TRIMMABLE_SCOPES = Set.of("compile", "runtime");

  private TrimPassThroughPlanner() {}

  /* package */ static List<ElisionAnalysisModel.ArtifactSnapshot> retainedAnalysisLibraries(
      final TrimRequest request) {
    return request.candidates().stream()
        .filter(snapshot -> MavenDependencyTrimmer.JAR_TYPE.equals(snapshot.coordinate().type()))
        .filter(
            snapshot ->
                MavenDependencyTrimmer.ANALYSIS_LIBRARY_SCOPES.contains(
                    snapshot.coordinate().scope()))
        .filter(snapshot -> request.retainedCoordinates().contains(snapshot.coordinate()))
        .toList();
  }

  /* package */ static boolean unchangedScope(final ArtifactCoordinate coordinate) {
    return MavenDependencyTrimmer.ANALYSIS_LIBRARY_SCOPES.contains(coordinate.scope())
        && !TRIMMABLE_SCOPES.contains(coordinate.scope());
  }

  /* package */ static TrimPassThroughPlan passThroughPlan(final TrimRequest request)
      throws IOException {
    final List<ElisionAnalysisModel.ArtifactSnapshot> retainedLibraries =
        request.candidates().stream()
            .filter(
                snapshot ->
                    MavenDependencyTrimmer.JAR_TYPE.equals(snapshot.coordinate().type())
                        && TRIMMABLE_SCOPES.contains(snapshot.coordinate().scope())
                        && request.retainedCoordinates().contains(snapshot.coordinate()))
            .toList();
    final ArchivePolicies policies = archivePolicies(request, retainedLibraries);
    final List<ElisionAnalysisModel.ArtifactSnapshot> multiRelease = policies.multiRelease();
    final List<ElisionAnalysisModel.ArtifactSnapshot> moduleInfo = policies.moduleInfo();
    final List<ElisionAnalysisModel.ArtifactSnapshot> configured =
        new ArrayList<>(
            parsePassThroughArtifacts(
                request.policy().explicitPassThroughCoordinates(), retainedLibraries));
    final Set<String> configuredIdentities = identities(configured);
    DuplicateClasses.retainedOwners(request, retainedLibraries).stream()
        .filter(snapshot -> !configuredIdentities.contains(artifactIdentity(snapshot.coordinate())))
        .forEach(configured::add);
    final Set<String> multiReleaseIdentities = identities(multiRelease);
    final Set<String> moduleInfoIdentities = identities(moduleInfo);
    final List<ElisionAnalysisModel.ArtifactSnapshot> configuredOnly =
        configured.stream()
            .filter(
                snapshot ->
                    !multiReleaseIdentities.contains(artifactIdentity(snapshot.coordinate()))
                        && !moduleInfoIdentities.contains(artifactIdentity(snapshot.coordinate())))
            .toList();
    final Set<String> skippedIdentities = new LinkedHashSet<>(multiReleaseIdentities);
    skippedIdentities.addAll(moduleInfoIdentities);
    skippedIdentities.addAll(identities(configured));
    final List<ElisionAnalysisModel.ArtifactSnapshot> retained =
        retainedLibraries.stream()
            .filter(
                snapshot -> !skippedIdentities.contains(artifactIdentity(snapshot.coordinate())))
            .toList();
    return new TrimPassThroughPlan(
        retainedLibraries,
        retained,
        multiReleaseIdentities,
        moduleInfoIdentities,
        skippedIdentities,
        multiRelease.stream().map(ElisionAnalysisModel.ArtifactSnapshot::coordinate).toList(),
        moduleInfo.stream().map(ElisionAnalysisModel.ArtifactSnapshot::coordinate).toList(),
        configuredOnly.stream().map(ElisionAnalysisModel.ArtifactSnapshot::coordinate).toList());
  }

  private static ArchivePolicies archivePolicies(
      final TrimRequest request,
      final List<ElisionAnalysisModel.ArtifactSnapshot> retainedLibraries)
      throws IOException {
    final List<ElisionAnalysisModel.ArtifactSnapshot> multiRelease = new ArrayList<>();
    final List<ElisionAnalysisModel.ArtifactSnapshot> moduleInfo = new ArrayList<>();
    final MrjarStrategy strategy = MrjarStrategy.parse(request.policy().mrjarStrategy());
    for (final ElisionAnalysisModel.ArtifactSnapshot snapshot : retainedLibraries) {
      if (strategy == MrjarStrategy.PASS_THROUGH
          && MultiReleaseClassInventory.hasUnsupportedVersionedClasses(snapshot.filePath())) {
        multiRelease.add(snapshot);
      }
      if (MultiReleaseLibraryProjection.hasRootModuleDescriptor(snapshot.filePath())) {
        if (request.policy().failOnUnsupportedModuleInfo()) {
          throw new IOException(
              "Unsupported root module descriptor in retained classpath JAR: "
                  + snapshot.coordinate());
        }
        if (strategy != MrjarStrategy.CLASSPATH_ONLY) {
          moduleInfo.add(snapshot);
        }
      }
    }
    return new ArchivePolicies(multiRelease, moduleInfo);
  }

  /** Archive policy groups retain the original candidate encounter order. */
  private record ArchivePolicies(
      List<ElisionAnalysisModel.ArtifactSnapshot> multiRelease,
      List<ElisionAnalysisModel.ArtifactSnapshot> moduleInfo) {}

  /* package */ static String artifactIdentity(final ArtifactCoordinate coordinate) {
    return MavenArtifactIdentity.from(coordinate).format();
  }

  /* package */ static Set<String> identities(
      final List<ElisionAnalysisModel.ArtifactSnapshot> snapshots) {
    return snapshots.stream()
        .map(snapshot -> artifactIdentity(snapshot.coordinate()))
        .collect(java.util.stream.Collectors.toCollection(LinkedHashSet::new));
  }

  /* package */ static List<ElisionAnalysisModel.ArtifactSnapshot> parsePassThroughArtifacts(
      final List<String> requested,
      final List<ElisionAnalysisModel.ArtifactSnapshot> retainedLibraries)
      throws IOException {
    final Set<String> requestedIdentities = new LinkedHashSet<>();
    for (final String raw : requested) {
      final MavenArtifactIdentity coordinate;
      try {
        coordinate = MavenArtifactIdentity.parsePassThrough(raw);
      } catch (final IllegalArgumentException exception) {
        throw new IOException(exception.getMessage(), exception);
      }
      final List<ElisionAnalysisModel.ArtifactSnapshot> matches =
          retainedLibraries.stream()
              .filter(snapshot -> coordinate.matches(snapshot.coordinate()))
              .toList();
      if (matches.isEmpty()) {
        throw new IOException(
            "elide.trimSkipArtifacts coordinate is not a retained compile/runtime JAR: " + raw);
      }
      matches.stream()
          .map(snapshot -> artifactIdentity(snapshot.coordinate()))
          .forEach(requestedIdentities::add);
    }
    return retainedLibraries.stream()
        .filter(snapshot -> requestedIdentities.contains(artifactIdentity(snapshot.coordinate())))
        .toList();
  }
}
