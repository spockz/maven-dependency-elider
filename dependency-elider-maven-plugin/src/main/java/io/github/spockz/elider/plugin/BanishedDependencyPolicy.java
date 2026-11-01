// WHY: Keeps ban matching separate from retention coordinate grammar.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.ArtifactSnapshot;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import org.apache.maven.model.Dependency;
import org.apache.maven.plugin.MojoFailureException;

/** Normalizes and evaluates explicit dependency bans against one inventory. */
final class BanishedDependencyPolicy {
  /** Supported Maven dependency scopes for ban matching. */
  private static final Set<String> SUPPORTED_SCOPES = Set.of("compile", "runtime");

  /** Supported Maven artifact type for ban matching. */
  private static final String SUPPORTED_TYPE = "jar";

  private BanishedDependencyPolicy() {}

  /* package */ static List<BanishedDependency> normalize(final List<String> configured)
      throws MojoFailureException {
    final Set<BanishedDependency> normalized = new TreeSet<>();
    if (configured == null) {
      return List.of();
    }
    for (final String raw : configured) {
      try {
        normalized.add(BanishedDependency.parse(raw));
      } catch (final IllegalArgumentException exception) {
        throw invalidConfiguration(raw, exception);
      }
    }
    return List.copyOf(normalized);
  }

  /* package */ static Resolution resolve(
      final List<String> retainedArtifacts,
      final List<String> banishedDependencies,
      final List<Dependency> firstLevelDependencies,
      final List<String> trimSkipArtifacts,
      final List<ArtifactSnapshot> resolvedSnapshots,
      final List<ArtifactSnapshot> directSnapshots)
      throws MojoFailureException {
    final List<BanishedDependency> requests = normalize(banishedDependencies);
    if (requests.isEmpty()) {
      return new Resolution(List.of());
    }
    validateRetentionConflicts(requests, retainedArtifacts);
    validatePassThroughConflicts(requests, trimSkipArtifacts);

    final List<Match> matches = new ArrayList<>();
    for (final BanishedDependency request : requests) {
      BanishedDependencyDirectMatchPolicy.reject(request, firstLevelDependencies, directSnapshots);
      final List<ArtifactSnapshot> resolvedMatches = matching(request, resolvedSnapshots);
      for (final ArtifactSnapshot snapshot : resolvedMatches) {
        validateSupportedMatch(request, snapshot);
      }
      matches.add(new Match(request, resolvedMatches));
    }
    return new Resolution(matches);
  }

  private static List<ArtifactSnapshot> matching(
      final BanishedDependency request, final List<ArtifactSnapshot> snapshots) {
    return snapshots.stream()
        .filter(snapshot -> request.equals(identityOf(snapshot.coordinate())))
        .sorted(Comparator.comparing(snapshot -> snapshot.coordinate().toString()))
        .toList();
  }

  private static void validateSupportedMatch(
      final BanishedDependency request, final ArtifactSnapshot snapshot)
      throws MojoFailureException {
    final ArtifactCoordinate coordinate = snapshot.coordinate();
    if (!SUPPORTED_SCOPES.contains(coordinate.scope())
        || !SUPPORTED_TYPE.equals(coordinate.type())
        || snapshot.filePath() == null) {
      throw new MojoFailureException(
          "elide.banishedDependencies matches an unsupported resolved artifact for "
              + request
              + ": "
              + coordinate
              + " (supported scope/type: compile/runtime JAR)");
    }
  }

  private static BanishedDependency identityOf(final ArtifactCoordinate coordinate) {
    return new BanishedDependency(coordinate.groupId(), coordinate.artifactId());
  }

  private static void validateRetentionConflicts(
      final List<BanishedDependency> requests, final List<String> retainedArtifacts)
      throws MojoFailureException {
    final Set<BanishedDependency> retainedIdentities = new LinkedHashSet<>();
    for (final ArtifactCoordinate coordinate :
        ElisionArtifactPolicy.parseRetentionCoordinates(retainedArtifacts)) {
      retainedIdentities.add(identityOf(coordinate));
    }
    for (final BanishedDependency request : requests) {
      if (retainedIdentities.contains(request)) {
        throw new MojoFailureException(
            "elide.banishedDependencies conflicts with elide.retainedArtifacts for " + request);
      }
    }
  }

  private static void validatePassThroughConflicts(
      final List<BanishedDependency> requests, final List<String> trimSkipArtifacts)
      throws MojoFailureException {
    final Set<String> trimSkipIdentities = new LinkedHashSet<>();
    for (final String configured :
        trimSkipArtifacts == null ? List.<String>of() : trimSkipArtifacts) {
      final String identity = passThroughIdentity(configured);
      if (identity != null) {
        trimSkipIdentities.add(identity);
      }
    }
    for (final BanishedDependency request : requests) {
      if (trimSkipIdentities.contains(request.toString())) {
        throw new MojoFailureException(
            "elide.banishedDependencies conflicts with matching elide.trimSkipArtifacts entry for "
                + request);
      }
    }
  }

  private static String passThroughIdentity(final String configured) {
    if (configured == null) {
      return null;
    }
    final String[] parts = configured.trim().split(":", -1);
    if (parts.length < 2 || parts[0].isBlank() || parts[1].isBlank()) {
      return null;
    }
    return parts[0].trim() + ":" + parts[1].trim();
  }

  private static MojoFailureException invalidConfiguration(
      final String raw, final IllegalArgumentException cause) {
    return new MojoFailureException(
        "Invalid elide.banishedDependencies coordinate '"
            + raw
            + "'; expected exact groupId:artifactId without wildcards ("
            + cause.getMessage()
            + ")",
        cause);
  }

  /* default */ record Resolution(List<Match> matches) {
    /* default */ Resolution {
      matches = List.copyOf(matches);
    }

    /* default */ List<BanishedDependency> requested() {
      return matches.stream().map(Match::dependency).toList();
    }

    /* default */ List<BanishedDependency> noCurrentInventoryMatch() {
      return matches.stream().filter(match -> !match.matched()).map(Match::dependency).toList();
    }
  }

  /* default */ record Match(BanishedDependency dependency, List<ArtifactSnapshot> artifacts) {
    /* default */ Match {
      artifacts = List.copyOf(artifacts);
    }

    /* default */ boolean matched() {
      return !artifacts.isEmpty();
    }
  }
}
