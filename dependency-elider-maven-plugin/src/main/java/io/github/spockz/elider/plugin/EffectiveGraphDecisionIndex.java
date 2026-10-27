// WHY: Normalizes raw decisions by resolver identity while preserving scope ambiguity.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ElisionDecision;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/** Normalizes artifact identities for one raw analyzer decision. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class EffectiveGraphDecisionIndex {
  private EffectiveGraphDecisionIndex() {
    throw new AssertionError("No instances");
  }

  /** Classification of one resolver artifact identity in the raw decision. */
  enum DecisionOutcome {
    RETAINED,
    ELIDED,
    AMBIGUOUS
  }

  /** Artifact identity plus its path-specific effective scope. */
  record DecisionKey(Gavce identity, String scope) {
    static DecisionKey of(final ArtifactCoordinate coordinate) {
      return new DecisionKey(Gavce.of(coordinate), coordinate.scope());
    }

    static DecisionKey of(final Map<?, ?> artifact, final String scope) {
      final Gavce identity = gavce(artifact);
      return identity == null ? null : new DecisionKey(identity, scope);
    }
  }

  /** Conflict family independent of version. */
  record Family(String groupId, String artifactId, String extension, String classifier) {}

  /** Resolver artifact identity with normalized extension and classifier. */
  record Gavce(
      String groupId, String artifactId, String version, String extension, String classifier) {
    static Gavce of(final ArtifactCoordinate coordinate) {
      return new Gavce(
          coordinate.groupId(),
          coordinate.artifactId(),
          coordinate.version(),
          coordinate.type(),
          coordinate.classifier());
    }

    Family family() {
      return new Family(groupId, artifactId, extension, classifier);
    }
  }

  static Gavce gavce(final Map<String, Object> node) {
    return gavce(node.get(ResolverArtifactGraphSnapshotSchema.ARTIFACT));
  }

  static Gavce gavce(final Object value) {
    if (!(value instanceof Map<?, ?> artifact)) {
      return null;
    }
    final String groupId = stringOrNull(artifact.get(ResolverArtifactGraphSnapshotSchema.GROUP_ID));
    final String artifactId =
        stringOrNull(artifact.get(ResolverArtifactGraphSnapshotSchema.ARTIFACT_ID));
    final String version = stringOrNull(artifact.get(ResolverArtifactGraphSnapshotSchema.VERSION));
    final String extension =
        stringOrNull(artifact.get(ResolverArtifactGraphSnapshotSchema.EXTENSION));
    final String classifier =
        stringOrNull(artifact.get(ResolverArtifactGraphSnapshotSchema.CLASSIFIER));
    if (groupId == null || artifactId == null || version == null || extension == null) {
      return null;
    }
    return new Gavce(groupId, artifactId, version, extension, classifier == null ? "" : classifier);
  }

  private static String stringOrNull(final Object value) {
    return value instanceof String text ? text : null;
  }

  /** Indexed decisions and their path-scope ambiguity. */
  static final class DecisionIndex {
    /** Raw artifact outcome by normalized resolver identity. */
    private final Map<Gavce, DecisionOutcome> outcomesByIdentity;

    /** First coordinate retained for reporting each identity. */
    private final Map<Gavce, ArtifactCoordinate> coordinatesByIdentity;

    /** Identities with incompatible raw outcomes or path scopes. */
    private final Set<Gavce> ambiguousIdentities;

    private DecisionIndex(
        final Map<Gavce, DecisionOutcome> outcomesByIdentity,
        final Map<Gavce, ArtifactCoordinate> coordinatesByIdentity,
        final Set<Gavce> ambiguousIdentities) {
      this.outcomesByIdentity = outcomesByIdentity;
      this.coordinatesByIdentity = coordinatesByIdentity;
      this.ambiguousIdentities = ambiguousIdentities;
    }

    @SuppressWarnings("PMD.UseConcurrentHashMap")
    static DecisionIndex of(final ElisionDecision decision) {
      final Map<Gavce, DecisionOutcome> outcomes = new LinkedHashMap<>();
      final Map<Gavce, ArtifactCoordinate> coordinates = new LinkedHashMap<>();
      final Set<Gavce> ambiguous = new LinkedHashSet<>();
      add(decision.retainedArtifacts(), DecisionOutcome.RETAINED, outcomes, coordinates, ambiguous);
      add(decision.elidedArtifacts(), DecisionOutcome.ELIDED, outcomes, coordinates, ambiguous);
      return new DecisionIndex(outcomes, coordinates, ambiguous);
    }

    private static void add(
        final Set<ArtifactCoordinate> values,
        final DecisionOutcome outcome,
        final Map<Gavce, DecisionOutcome> outcomes,
        final Map<Gavce, ArtifactCoordinate> coordinates,
        final Set<Gavce> ambiguous) {
      for (final ArtifactCoordinate coordinate : values) {
        final Gavce identity = Gavce.of(coordinate);
        final DecisionOutcome previous = outcomes.putIfAbsent(identity, outcome);
        if (previous != null && previous != outcome) {
          outcomes.put(identity, DecisionOutcome.AMBIGUOUS);
          ambiguous.add(identity);
        }
        final ArtifactCoordinate previousCoordinate = coordinates.putIfAbsent(identity, coordinate);
        if (previousCoordinate != null && !previousCoordinate.equals(coordinate)) {
          ambiguous.add(identity);
          outcomes.put(identity, DecisionOutcome.AMBIGUOUS);
        }
      }
    }

    Map<Gavce, DecisionOutcome> outcomes() {
      return outcomesByIdentity;
    }

    Set<Gavce> ambiguous() {
      return ambiguousIdentities;
    }

    boolean isElided(final Gavce identity) {
      return outcomesByIdentity.get(identity) == DecisionOutcome.ELIDED;
    }

    ArtifactCoordinate coordinate(final Gavce identity) {
      return coordinatesByIdentity.get(identity);
    }

    Set<ArtifactCoordinate> coordinates(final Set<Gavce> identities, final boolean onlyElided) {
      final Set<ArtifactCoordinate> result = new LinkedHashSet<>();
      identities.stream()
          .sorted(Comparator.comparing(Object::toString))
          .forEach(
              identity -> {
                if (!onlyElided || isElided(identity)) {
                  final ArtifactCoordinate coordinate = coordinate(identity);
                  if (coordinate != null) {
                    result.add(coordinate);
                  }
                }
              });
      return EffectiveGraphPolicy.immutableSorted(result);
    }
  }
}
