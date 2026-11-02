// WHY: Freezes source locations before lifecycle exclusion injection changes the effective model.

package io.github.spockz.elider.plugin;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
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
    final Map<String, List<String>> activeProfiles = activeProfiles(project, diagnostics);
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
        declarations(activeProfiles, project.getDependencies(), index, diagnostics, "dependency");
    final List<Dependency> managed =
        project.getDependencyManagement() == null
            ? List.of()
            : project.getDependencyManagement().getDependencies();
    final List<ExclusionRecommendations.Declaration> management =
        declarations(activeProfiles, managed, index, diagnostics, "dependency-management");
    return new ExclusionRecommendations.Snapshot(
        dependencies, management, activeProfiles, diagnostics);
  }

  private static Map<String, List<String>> activeProfiles(
      final MavenProject project, final List<String> diagnostics) {
    final Map<String, List<String>> result = new TreeMap<>();
    project
        .getInjectedProfileIds()
        .forEach(
            (model, profiles) -> {
              if (profiles == null || profiles.isEmpty()) {
                return;
              }
              if (model == null
                  || model.isBlank()
                  || profiles.stream()
                      .anyMatch(id -> id == null || id.isBlank() || !id.equals(id.trim()))) {
                diagnostics.add("Active profile identities are unavailable");
                return;
              }
              result.put(model, profiles.stream().distinct().sorted().toList());
            });
    return result;
  }

  private static List<ExclusionRecommendations.Declaration> declarations(
      final Map<String, List<String>> activeProfiles,
      final List<Dependency> dependencies,
      final Map<LocationKey, List<Match>> index,
      final List<String> diagnostics,
      final String section) {
    final List<ExclusionRecommendations.Declaration> result = new ArrayList<>();
    for (int ordinal = 0; ordinal < dependencies.size(); ordinal++) {
      final Dependency dependency = dependencies.get(ordinal);
      final String dependencyIdentity =
          value(dependency.getGroupId()) + ":" + value(dependency.getArtifactId());
      final String rowDescription = section + " row " + ordinal + " (" + dependencyIdentity + ")";
      final ExclusionRecommendations.Origin origin =
          origin(activeProfiles, dependency.getLocation(""), index, diagnostics, rowDescription);
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
        final String exclusionIdentity =
            value(exclusion.getGroupId()) + ":" + value(exclusion.getArtifactId());
        exclusions.add(
            new ExclusionRecommendations.Exclusion(
                new ExclusionRecommendations.Coordinate(
                    value(exclusion.getGroupId()), value(exclusion.getArtifactId())),
                origin(
                    activeProfiles,
                    exclusion.getLocation(""),
                    index,
                    diagnostics,
                    "exclusion " + exclusionIdentity + " on " + rowDescription)));
      }
      result.add(new ExclusionRecommendations.Declaration(reference, exclusions));
    }
    return List.copyOf(result);
  }

  @SuppressWarnings({"PMD.CyclomaticComplexity", "PMD.NPathComplexity", "PMD.CognitiveComplexity"})
  private static ExclusionRecommendations.Origin origin(
      final Map<String, List<String>> activeProfiles,
      final InputLocation location,
      final Map<LocationKey, List<Match>> index,
      final List<String> diagnostics,
      final String rowDescription) {
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
                        || activeProfiles
                            .getOrDefault(modelId, List.of())
                            .contains(match.profile()))
            .toList();
    final String kind;
    final String profile;
    if (location == null || source == null || modelId.isEmpty() || line < 1 || column < 1) {
      kind = "UNKNOWN";
      profile = "";
      diagnostics.add(incompleteLocationDiagnostic(rowDescription, modelId, line, column));
    } else if (matches.size() != 1) {
      kind = "UNKNOWN";
      profile = "";
      diagnostics.add(
          "Incomplete or ambiguous provenance at "
              + modelId
              + ":"
              + line
              + ":"
              + column
              + ": "
              + (matches.isEmpty() ? "no original POM row matches " : "multiple POM rows match ")
              + rowDescription
              + (matches.size() > 1 ? " (" + matches.size() + " matches)" : ""));
    } else {
      final Match match = matches.getFirst();
      kind =
          (match.local() ? "LOCAL" : "INHERITED")
              + (match.profile().isEmpty() ? "" : "_PROFILE")
              + (match.management() ? "_MANAGEMENT" : "");
      profile = match.profile();
    }
    return new ExclusionRecommendations.Origin(kind, modelId, path, line, column, profile);
  }

  private static String incompleteLocationDiagnostic(
      final String rowDescription, final String modelId, final int line, final int column) {
    if (line < 1 || column < 1) {
      return "Incomplete or ambiguous provenance: Maven did not provide a source location for "
          + rowDescription
          + (modelId.isBlank() ? "" : " in model " + modelId);
    }
    return "Incomplete or ambiguous provenance: Maven did not provide a source identity for "
        + rowDescription
        + " at line "
        + line
        + ", column "
        + column;
  }

  // WHY: Locality depends on project identity, not coordinate equality.
  @SuppressWarnings("PMD.CompareObjectsWithEquals")
  private static Map<LocationKey, List<Match>> sourceIndex(final MavenProject project) {
    final Map<LocationKey, List<Match>> result = new HashMap<>();
    for (MavenProject current = project; current != null; current = current.getParent()) {
      final Model original = current.getOriginalModel();
      if (original == null) {
        continue;
      }
      final boolean local = current == project;
      addMatches(result, original.getDependencies(), local, false, "");
      if (original.getDependencyManagement() != null) {
        addMatches(result, original.getDependencyManagement().getDependencies(), local, true, "");
      }
      for (final Profile profile : original.getProfiles()) {
        if (profile.getId() == null || profile.getId().isBlank()) {
          continue;
        }
        addMatches(result, profile.getDependencies(), local, false, profile.getId());
        if (profile.getDependencyManagement() != null) {
          addMatches(
              result,
              profile.getDependencyManagement().getDependencies(),
              local,
              true,
              profile.getId());
        }
      }
    }
    return result;
  }

  private static void addMatches(
      final Map<LocationKey, List<Match>> result,
      final List<Dependency> dependencies,
      final boolean local,
      final boolean management,
      final String profile) {
    for (final Dependency dependency : dependencies) {
      addMatch(result, dependency.getLocation(""), local, management, profile);
      for (final Exclusion exclusion : dependency.getExclusions()) {
        addMatch(result, exclusion.getLocation(""), local, management, profile);
      }
    }
  }

  private record Match(boolean local, boolean management, String profile) {}

  private record LocationKey(String modelId, String path, int line, int column) {}

  private static void addMatch(
      final Map<LocationKey, List<Match>> index,
      final InputLocation location,
      final boolean local,
      final boolean management,
      final String profile) {
    if (location != null && location.getSource() != null) {
      final LocationKey key =
          new LocationKey(
              value(location.getSource().getModelId()),
              value(location.getSource().getLocation()),
              location.getLineNumber(),
              location.getColumnNumber());
      index
          .computeIfAbsent(key, ignored -> new ArrayList<>())
          .add(new Match(local, management, profile));
    }
  }

  private static String value(final String value) {
    return value == null ? "" : value;
  }
}
