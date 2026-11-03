/* WHY: Keeps skip-coordinate validation and unsupported archive policy
 * identical for analysis and publication. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
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

  /* package */ static boolean passThroughCoordinate(
      final TrimRequest request, final ElisionAnalysisModel.ArtifactSnapshot snapshot)
      throws IOException {
    final boolean multiRelease =
        MultiReleaseClassInventory.hasUnsupportedVersionedClasses(snapshot.filePath());
    final boolean moduleInfo =
        MultiReleaseLibraryProjection.hasRootModuleDescriptor(snapshot.filePath());
    if (!request.retainedCoordinates().contains(snapshot.coordinate())) {
      return multiRelease || moduleInfo;
    }
    if (moduleInfo && request.policy().failOnUnsupportedModuleInfo()) {
      throw new IOException(
          "Unsupported root module descriptor in retained classpath JAR: " + snapshot.coordinate());
    }
    final MrjarStrategy strategy = MrjarStrategy.parse(request.policy().mrjarStrategy());
    final boolean modulePassThrough = moduleInfo && strategy != MrjarStrategy.CLASSPATH_ONLY;
    final boolean multiReleasePassThrough =
        switch (strategy) {
          case PASS_THROUGH -> multiRelease;
          case VERTICAL_SHADING, CLASSPATH_ONLY -> false;
        };
    return modulePassThrough || multiReleasePassThrough;
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
        parsePassThroughArtifacts(
            request.policy().explicitPassThroughCoordinates(), retainedLibraries);
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
      if (MultiReleaseClassInventory.hasUnsupportedVersionedClasses(snapshot.filePath())
          && strategy == MrjarStrategy.PASS_THROUGH) {
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
    return coordinate.groupId()
        + ":"
        + coordinate.artifactId()
        + ":"
        + coordinate.version()
        + ":"
        + coordinate.type()
        + ":"
        + coordinate.classifier();
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
      final RequestedCoordinate coordinate = requestedCoordinate(raw);
      final List<ElisionAnalysisModel.ArtifactSnapshot> matches =
          retainedLibraries.stream().filter(coordinate::matches).toList();
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

  private static RequestedCoordinate requestedCoordinate(final String raw) throws IOException {
    final String[] parts = requestedParts(raw);
    final String type =
        parts.length > 3 && !parts[3].isBlank() ? parts[3] : MavenDependencyTrimmer.JAR_TYPE;
    final String classifier = parts.length > 4 ? parts[4] : "";
    return new RequestedCoordinate(parts[0], parts[1], parts[2], type, classifier);
  }

  private static String[] requestedParts(final String raw) throws IOException {
    if (raw == null || raw.isBlank()) {
      throw new IOException("elide.trimSkipArtifacts must not contain blank coordinates");
    }
    final String[] parts = raw.trim().split(":", -1);
    if (!validCoordinateParts(parts)) {
      throw new IOException(
          "Invalid elide.trimSkipArtifacts coordinate; expected "
              + "group:artifact:version[:type[:classifier]]: "
              + raw);
    }
    return parts;
  }

  private static boolean validCoordinateParts(final String... parts) {
    if (parts.length < 3 || parts.length > 5) {
      return false;
    }
    return !parts[0].isBlank() && !parts[1].isBlank() && !parts[2].isBlank();
  }

  /** Scope-independent coordinates match only the supplied retained inventory. */
  private record RequestedCoordinate(
      String groupId, String artifactId, String version, String type, String classifier) {
    private boolean matches(final ElisionAnalysisModel.ArtifactSnapshot snapshot) {
      final ArtifactCoordinate coordinate = snapshot.coordinate();
      return coordinate.groupId().equals(groupId)
          && coordinate.artifactId().equals(artifactId)
          && coordinate.version().equals(version)
          && coordinate.type().equals(type)
          && coordinate.classifier().equals(classifier);
    }
  }
}
