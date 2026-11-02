// WHY: Freezes source locations before lifecycle exclusion injection changes the effective model.

package io.github.spockz.elider.plugin;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.maven.model.Dependency;
import org.apache.maven.model.Exclusion;
import org.apache.maven.model.InputLocation;
import org.apache.maven.model.InputSource;
import org.apache.maven.model.Model;
import org.apache.maven.model.Profile;
import org.apache.maven.project.MavenProject;

/** Captures effective rows without counting lookup models as additional paths. */
@SuppressWarnings({
  "PMD.CommentDefaultAccessModifier",
  "PMD.AvoidInstantiatingObjectsInLoops",
  "PMD.UseConcurrentHashMap"
})
final class ExclusionProvenanceCapture {
  private ExclusionProvenanceCapture() {}

  static ExclusionRecommendations.Snapshot capture(final MavenProject project) {
    final List<String> diagnostics = new ArrayList<>();
    final Map<LocationKey, List<Match>> index = sourceIndex(project);
    for (MavenProject current = project; current != null; current = current.getParent()) {
      if (current.getOriginalModel() == null
          || current.getOriginalModel().getLocation("") == null) {
        diagnostics.add("Original model locations are unavailable");
      }
      if (current.getOriginalModel() != null
          && current.getOriginalModel().getParent() != null
          && current.getParent() == null) {
        diagnostics.add("Parent original model is unavailable");
      }
    }
    final List<ExclusionRecommendations.Declaration> dependencies =
        declarations(project, project.getDependencies(), index, diagnostics);
    final List<Dependency> managed =
        project.getDependencyManagement() == null
            ? List.of()
            : project.getDependencyManagement().getDependencies();
    final List<ExclusionRecommendations.Declaration> management =
        declarations(project, managed, index, diagnostics);
    return new ExclusionRecommendations.Snapshot(dependencies, management, diagnostics);
  }

  private static List<ExclusionRecommendations.Declaration> declarations(
      final MavenProject project,
      final List<Dependency> dependencies,
      final Map<LocationKey, List<Match>> index,
      final List<String> diagnostics) {
    final List<ExclusionRecommendations.Declaration> result = new ArrayList<>();
    for (int ordinal = 0; ordinal < dependencies.size(); ordinal++) {
      final Dependency dependency = dependencies.get(ordinal);
      final ExclusionRecommendations.Origin origin =
          origin(project, dependency.getLocation(""), index, diagnostics);
      final ExclusionRecommendations.Reference reference =
          new ExclusionRecommendations.Reference(
              ordinal,
              value(dependency.getGroupId()),
              value(dependency.getArtifactId()),
              value(dependency.getType()),
              value(dependency.getClassifier()),
              origin);
      final List<ExclusionRecommendations.Exclusion> exclusions = new ArrayList<>();
      for (final Exclusion exclusion : dependency.getExclusions()) {
        exclusions.add(
            new ExclusionRecommendations.Exclusion(
                new ExclusionRecommendations.Coordinate(
                    value(exclusion.getGroupId()), value(exclusion.getArtifactId())),
                origin(project, exclusion.getLocation(""), index, diagnostics)));
      }
      result.add(new ExclusionRecommendations.Declaration(reference, exclusions));
    }
    return List.copyOf(result);
  }

  @SuppressWarnings({"PMD.CyclomaticComplexity", "PMD.NPathComplexity"})
  private static ExclusionRecommendations.Origin origin(
      final MavenProject project,
      final InputLocation location,
      final Map<LocationKey, List<Match>> index,
      final List<String> diagnostics) {
    final InputSource source = location == null ? null : location.getSource();
    final String modelId = source == null ? "" : value(source.getModelId());
    final String path = source == null ? "" : value(source.getLocation());
    final int line = location == null ? -1 : location.getLineNumber();
    final int column = location == null ? -1 : location.getColumnNumber();
    final List<Match> matches =
        index.getOrDefault(new LocationKey(modelId, path, line, column), List.of()).stream()
            .filter(
                match ->
                    match.profile().isEmpty()
                        || project
                            .getInjectedProfileIds()
                            .getOrDefault(modelId, List.of())
                            .contains(match.profile()))
            .toList();
    final String kind;
    final String profile;
    if (matches.size() != 1 || modelId.isEmpty() || line < 1 || column < 1) {
      kind = "UNKNOWN";
      profile = "";
      diagnostics.add(
          "Incomplete or ambiguous provenance at " + modelId + ":" + line + ":" + column);
    } else {
      final Match match = matches.getFirst();
      final boolean local =
          modelId.equals(
              project.getGroupId() + ":" + project.getArtifactId() + ":" + project.getVersion());
      kind = (local ? "LOCAL" : "INHERITED") + (match.management() ? "_MANAGEMENT" : "");
      profile = match.profile();
    }
    return new ExclusionRecommendations.Origin(kind, modelId, path, line, column, profile);
  }

  private static Map<LocationKey, List<Match>> sourceIndex(final MavenProject project) {
    final Map<LocationKey, List<Match>> result = new HashMap<>();
    for (MavenProject current = project; current != null; current = current.getParent()) {
      final Model original = current.getOriginalModel();
      if (original == null) {
        continue;
      }
      addMatches(result, original.getDependencies(), false, "");
      if (original.getDependencyManagement() != null) {
        addMatches(result, original.getDependencyManagement().getDependencies(), true, "");
      }
      for (final Profile profile : original.getProfiles()) {
        addMatches(result, profile.getDependencies(), false, profile.getId());
        if (profile.getDependencyManagement() != null) {
          addMatches(
              result, profile.getDependencyManagement().getDependencies(), true, profile.getId());
        }
      }
    }
    return result;
  }

  private static void addMatches(
      final Map<LocationKey, List<Match>> result,
      final List<Dependency> dependencies,
      final boolean management,
      final String profile) {
    for (final Dependency dependency : dependencies) {
      addMatch(result, dependency.getLocation(""), management, profile);
      for (final Exclusion exclusion : dependency.getExclusions()) {
        addMatch(result, exclusion.getLocation(""), management, profile);
      }
    }
  }

  private record Match(boolean management, String profile) {}

  private record LocationKey(String modelId, String path, int line, int column) {}

  private static void addMatch(
      final Map<LocationKey, List<Match>> index,
      final InputLocation location,
      final boolean management,
      final String profile) {
    if (location != null && location.getSource() != null) {
      final LocationKey key =
          new LocationKey(
              value(location.getSource().getModelId()),
              value(location.getSource().getLocation()),
              location.getLineNumber(),
              location.getColumnNumber());
      index.computeIfAbsent(key, ignored -> new ArrayList<>()).add(new Match(management, profile));
    }
  }

  private static String value(final String value) {
    return value == null ? "" : value;
  }
}
