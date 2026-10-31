// WHY: Resolves configured exclusions and pass-through coordinates for raw
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

/** Resolves exclusions and pass-through coordinates for artifact pruning. */
final class ElisionArtifactPolicy {
  /** Scopes eligible for whole-artifact elision. */
  private static final Set<String> ELIGIBLE_SCOPES = Set.of("compile", "runtime");

  /** Archive type accepted by the trimming policy. */
  private static final String JAR_TYPE = "jar";

  private ElisionArtifactPolicy() {}

  /* package */ static PruneConfig config(
      final List<String> excludedArtifacts, final Set<ArtifactCoordinate> keepArtifacts)
      throws MojoFailureException {
    final Set<ArtifactCoordinate> exclusions = new LinkedHashSet<>();
    if (excludedArtifacts != null) {
      for (final String text : excludedArtifacts) {
        exclusions.add(parseExclusion(text));
      }
    }
    return new PruneConfig(Set.of(), keepArtifacts, ELIGIBLE_SCOPES, exclusions);
  }

  /* package */ static Set<ArtifactCoordinate> parsePassThroughCoordinates(
      final List<String> requested, final List<ArtifactSnapshot> snapshots)
      throws MojoFailureException {
    final Set<ArtifactCoordinate> result = new LinkedHashSet<>();
    if (requested == null) {
      return result;
    }
    for (final String raw : requested) {
      final PassThroughCoordinate requestedCoordinate = passThroughCoordinate(raw);
      final List<ArtifactSnapshot> matches =
          snapshots.stream().filter(requestedCoordinate::matches).toList();
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

  private static PassThroughCoordinate passThroughCoordinate(final String raw)
      throws MojoFailureException {
    final String[] parts = passThroughPieces(raw);
    final String type = optionalPiece(parts, 3, JAR_TYPE);
    if (!JAR_TYPE.equals(type)) {
      throw new MojoFailureException("elide.trimSkipArtifacts supports JAR artifacts only: " + raw);
    }
    return new PassThroughCoordinate(
        parts[0], parts[1], parts[2], type, optionalPiece(parts, 4, ""));
  }

  private static String[] passThroughPieces(final String raw) throws MojoFailureException {
    if (raw == null || raw.isBlank()) {
      throw new MojoFailureException("elide.trimSkipArtifacts must not contain blank coordinates");
    }
    final String[] parts = raw.trim().split(":", -1);
    if (!validPassThroughPieces(parts)) {
      throw new MojoFailureException(
          "Invalid elide.trimSkipArtifacts coordinate; expected "
              + "group:artifact:version[:type[:classifier]]: "
              + raw);
    }
    return parts;
  }

  private static boolean validPassThroughPieces(final String... parts) {
    if (parts.length < 3 || parts.length > 5) {
      return false;
    }
    return !parts[0].isBlank() && !parts[1].isBlank() && !parts[2].isBlank();
  }

  private record PassThroughCoordinate(
      String groupId, String artifactId, String version, String type, String classifier) {
    private boolean matches(final ArtifactSnapshot snapshot) {
      final ArtifactCoordinate coordinate = snapshot.coordinate();
      return coordinate.groupId().equals(groupId)
          && coordinate.artifactId().equals(artifactId)
          && coordinate.version().equals(version)
          && coordinate.type().equals(type)
          && coordinate.classifier().equals(classifier)
          && ELIGIBLE_SCOPES.contains(coordinate.scope())
          && snapshot.filePath() != null;
    }
  }

  private static ArtifactCoordinate parseExclusion(final String text) throws MojoFailureException {
    final String[] pieces = text.split(":", -1);
    if (pieces.length < 2 || pieces.length > 5 || pieces[0].isBlank() || pieces[1].isBlank()) {
      throw new MojoFailureException(
          "Invalid elide.excludedArtifacts coordinate '"
              + text
              + "'; expected groupId:artifactId[:version[:type[:classifier]]]");
    }
    final String version = optionalPiece(pieces, 2, null);
    final String type = optionalPiece(pieces, 3, JAR_TYPE);
    final String classifier = optionalPiece(pieces, 4, "");
    return new ArtifactCoordinate(pieces[0], pieces[1], version, type, classifier, "compile");
  }

  private static String optionalPiece(
      final String[] pieces, final int index, final String defaultValue) {
    return pieces.length > index && !pieces[index].isBlank() ? pieces[index] : defaultValue;
  }
}
