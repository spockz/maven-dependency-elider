// WHY: Resolves configured retention and pass-through coordinates for raw
// artifact pruning.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.engine.PruneConfig;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ElisionDecision;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.ArtifactSnapshot;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import org.apache.maven.plugin.MojoFailureException;

/** Resolves retained and pass-through coordinates for artifact pruning. */
final class ElisionArtifactPolicy {
  /** Scopes eligible for whole-artifact elision. */
  private static final Set<String> ELIGIBLE_SCOPES = Set.of("compile", "runtime");

  /** Archive type accepted by the trimming policy. */
  private static final String JAR_TYPE = "jar";

  private ElisionArtifactPolicy() {}

  /* package */ static PruneConfig config(
      final List<String> retainedArtifacts, final Set<ArtifactCoordinate> keepArtifacts)
      throws MojoFailureException {
    final Set<ArtifactCoordinate> retained = parseRetentionCoordinates(retainedArtifacts);
    return new PruneConfig(Set.of(), keepArtifacts, ELIGIBLE_SCOPES, retained);
  }

  /* package */ static Set<ArtifactCoordinate> parseRetentionCoordinates(
      final List<String> retainedArtifacts) throws MojoFailureException {
    return BanishedDependencyPolicy.parseRetentionCoordinates(retainedArtifacts);
  }

  /* package */ static Set<ArtifactCoordinate> parsePassThroughCoordinates(
      final List<String> requested, final List<ArtifactSnapshot> snapshots)
      throws MojoFailureException {
    final Set<ArtifactCoordinate> result = new LinkedHashSet<>();
    if (requested == null) {
      return result;
    }
    for (final String raw : requested) {
      final MavenArtifactIdentity requestedCoordinate = passThroughCoordinate(raw);
      final List<ArtifactSnapshot> matches = matchingSnapshots(requestedCoordinate, snapshots);
      if (matches.isEmpty()) {
        throw new MojoFailureException(
            "elide.trimSkipArtifacts coordinate is not a resolved compile/runtime JAR: " + raw);
      }
      matches.stream().map(ArtifactSnapshot::coordinate).forEach(result::add);
    }
    return result;
  }

  /* package */ static ElisionDecision retainNonJarArtifacts(
      final ElisionDecision jarDecision, final List<ArtifactSnapshot> snapshots) {
    final Set<ArtifactCoordinate> retained = new HashSet<>(jarDecision.retainedArtifacts());
    for (final ArtifactSnapshot snapshot : snapshots) {
      if (!JAR_TYPE.equals(snapshot.coordinate().type()) && snapshot.filePath() != null) {
        retained.add(snapshot.coordinate());
      }
    }
    return new ElisionDecision(
        retained,
        jarDecision.elidedArtifacts(),
        jarDecision.retainedClassesPerArtifact(),
        jarDecision.unusedClassesPerArtifact(),
        jarDecision.elapsedNanos());
  }

  private static MavenArtifactIdentity passThroughCoordinate(final String raw)
      throws MojoFailureException {
    final MavenArtifactIdentity identity;
    try {
      identity = MavenArtifactIdentity.parsePassThrough(raw);
    } catch (final IllegalArgumentException exception) {
      throw new MojoFailureException(exception.getMessage(), exception);
    }
    if (!JAR_TYPE.equals(identity.type())) {
      throw new MojoFailureException("elide.trimSkipArtifacts supports JAR artifacts only: " + raw);
    }
    return identity;
  }

  private static List<ArtifactSnapshot> matchingSnapshots(
      final MavenArtifactIdentity requested, final List<ArtifactSnapshot> snapshots) {
    return snapshots.stream()
        .filter(
            snapshot ->
                requested.matches(snapshot.coordinate())
                    && ELIGIBLE_SCOPES.contains(snapshot.coordinate().scope())
                    && snapshot.filePath() != null)
        .toList();
  }
}
