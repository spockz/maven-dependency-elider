// WHY: Resolves references against retained providers before blaming removed artifacts.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.maven.plugin.MojoFailureException;

/** Shares provider resolution across both ban checks. */
final class MavenBanClassProviderClosure {
  /** The minimum count that represents a unique provider. */
  private static final int ONE_PROVIDER = 1;

  private MavenBanClassProviderClosure() {}

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
    if (effectiveProviderCount == ONE_PROVIDER) {
      return;
    }
    final String reason;
    if (effectiveProviderCount > ONE_PROVIDER || absent.size() > ONE_PROVIDER) {
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
