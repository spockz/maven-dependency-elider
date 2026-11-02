// WHY: Groups frozen effective exclusion paths without treating observations as POM edits.

package io.github.spockz.elider.plugin;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

/** Deterministic advisory findings from a detached declaration snapshot. */
@SuppressWarnings({
  "PMD.CommentDefaultAccessModifier",
  "PMD.UseConcurrentHashMap",
  "PMD.AvoidInstantiatingObjectsInLoops"
})
final class ExclusionRecommendations {
  private ExclusionRecommendations() {}

  static Result collect(final Snapshot snapshot) {
    Objects.requireNonNull(snapshot, "snapshot");
    final Map<Coordinate, List<Observation>> paths = new TreeMap<>();
    for (final Declaration declaration : snapshot.dependencies()) {
      final Map<Coordinate, List<Origin>> exclusions = new LinkedHashMap<>();
      for (final Exclusion exclusion : declaration.exclusions()) {
        if (exclusion.coordinate().isExact()) {
          exclusions
              .computeIfAbsent(exclusion.coordinate(), ignored -> new ArrayList<>())
              .add(exclusion.origin());
        }
      }
      exclusions.forEach(
          (coordinate, origins) ->
              paths
                  .computeIfAbsent(coordinate, ignored -> new ArrayList<>())
                  .add(
                      new Observation(
                          declaration.reference(), origins.stream().distinct().toList())));
    }
    final List<Candidate> candidates =
        paths.entrySet().stream()
            .filter(entry -> entry.getValue().size() >= 2)
            .map(entry -> new Candidate(entry.getKey(), entry.getValue()))
            .toList();
    final List<Origin> contributing =
        snapshot.dependencies().stream()
            .flatMap(declaration -> declaration.exclusions().stream())
            .map(Exclusion::origin)
            .filter(origin -> !"UNKNOWN".equals(origin.kind()))
            .toList();
    final List<Declaration> management =
        snapshot.management().stream()
            .map(
                declaration ->
                    new Declaration(
                        declaration.reference(),
                        declaration.exclusions().stream()
                            .filter(
                                exclusion ->
                                    !"UNKNOWN".equals(exclusion.origin().kind())
                                        && !contributing.contains(exclusion.origin()))
                            .toList()))
            .filter(declaration -> !declaration.exclusions().isEmpty())
            .toList();
    return new Result(candidates, management, snapshot.diagnostics());
  }

  record Coordinate(String groupId, String artifactId) implements Comparable<Coordinate> {
    Coordinate {
      Objects.requireNonNull(groupId, "groupId");
      Objects.requireNonNull(artifactId, "artifactId");
    }

    boolean isExact() {
      return !groupId.isBlank()
          && !artifactId.isBlank()
          && !groupId.contains("*")
          && !artifactId.contains("*");
    }

    @Override
    public int compareTo(final Coordinate other) {
      final int group = groupId.compareTo(other.groupId);
      return group == 0 ? artifactId.compareTo(other.artifactId) : group;
    }
  }

  record Origin(
      String kind, String modelId, String source, int line, int column, String profileId) {
    Origin {
      Objects.requireNonNull(kind, "kind");
      Objects.requireNonNull(modelId, "modelId");
      Objects.requireNonNull(source, "source");
      Objects.requireNonNull(profileId, "profileId");
    }
  }

  record Reference(
      int ordinal,
      String groupId,
      String artifactId,
      String type,
      String classifier,
      Origin origin) {
    Reference {
      Objects.requireNonNull(groupId, "groupId");
      Objects.requireNonNull(artifactId, "artifactId");
      Objects.requireNonNull(type, "type");
      Objects.requireNonNull(classifier, "classifier");
      Objects.requireNonNull(origin, "origin");
    }
  }

  record Exclusion(Coordinate coordinate, Origin origin) {
    Exclusion {
      Objects.requireNonNull(coordinate, "coordinate");
      Objects.requireNonNull(origin, "origin");
    }
  }

  record Declaration(Reference reference, List<Exclusion> exclusions) {
    Declaration {
      Objects.requireNonNull(reference, "reference");
      exclusions = List.copyOf(exclusions);
    }
  }

  record Snapshot(
      List<Declaration> dependencies, List<Declaration> management, List<String> diagnostics) {
    Snapshot {
      dependencies = List.copyOf(dependencies);
      management = List.copyOf(management);
      diagnostics = List.copyOf(diagnostics);
    }
  }

  record Observation(Reference declaration, List<Origin> exclusionOrigins) {
    Observation {
      Objects.requireNonNull(declaration, "declaration");
      exclusionOrigins = List.copyOf(exclusionOrigins);
    }
  }

  record Candidate(Coordinate coordinate, List<Observation> declarations) {
    Candidate {
      declarations =
          declarations.stream()
              .sorted(
                  java.util.Comparator.comparingInt(
                      observation -> observation.declaration().ordinal()))
              .toList();
    }

    int count() {
      return declarations.size();
    }
  }

  record Result(
      List<Candidate> candidates, List<Declaration> management, List<String> diagnostics) {
    Result {
      candidates = List.copyOf(candidates);
      management = List.copyOf(management);
      diagnostics = List.copyOf(diagnostics);
    }
  }
}
