// WHY: Keeps declaration conflicts distinct from the resolver's direct artifact view.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.ArtifactSnapshot;
import java.util.List;
import org.apache.maven.model.Dependency;
import org.apache.maven.plugin.MojoFailureException;

/** Rejects configured bans that match current first-level inputs. */
final class BanishedDependencyDirectMatchPolicy {
  private BanishedDependencyDirectMatchPolicy() {}

  /* package */ static void reject(
      final BanishedDependency request,
      final List<Dependency> firstLevelDependencies,
      final List<ArtifactSnapshot> directSnapshots)
      throws MojoFailureException {
    if (matchesFirstLevelDependency(request, firstLevelDependencies)) {
      throw new MojoFailureException(
          "elide.banishedDependencies cannot match a direct first-level dependency: " + request);
    }
    if (directSnapshots.stream().anyMatch(snapshot -> matches(request, snapshot.coordinate()))) {
      throw new MojoFailureException(
          "elide.banishedDependencies cannot match a direct artifact-view member: " + request);
    }
  }

  private static boolean matchesFirstLevelDependency(
      final BanishedDependency request, final List<Dependency> firstLevelDependencies) {
    return firstLevelDependencies != null
        && firstLevelDependencies.stream()
            .anyMatch(
                dependency ->
                    request.groupId().equals(dependency.getGroupId())
                        && request.artifactId().equals(dependency.getArtifactId()));
  }

  private static boolean matches(
      final BanishedDependency request, final ArtifactCoordinate coordinate) {
    return request.groupId().equals(coordinate.groupId())
        && request.artifactId().equals(coordinate.artifactId());
  }
}
