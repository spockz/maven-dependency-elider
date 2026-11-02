// WHY: Keeps the frozen provenance snapshot portable across Maven extension class realms.

package io.github.spockz.elider.plugin;

import java.util.List;
import java.util.Map;
import java.util.Set;

/** Strict JDK-only encoding for exclusion provenance. */
@SuppressWarnings({
  "PMD.TooManyMethods",
  "PMD.CommentDefaultAccessModifier",
  "PMD.AvoidDuplicateLiterals",
  "PMD.UseExplicitTypes"
})
final class ExclusionProvenancePayload {
  private ExclusionProvenancePayload() {}

  static Map<String, Object> encode(final ExclusionRecommendations.Snapshot snapshot) {
    return Map.of(
        "dependencies",
        snapshot.dependencies().stream()
            .map(ExclusionProvenancePayload::encodeDeclaration)
            .toList(),
        "management",
        snapshot.management().stream().map(ExclusionProvenancePayload::encodeDeclaration).toList(),
        "diagnostics",
        snapshot.diagnostics());
  }

  private static Map<String, Object> encodeDeclaration(
      final ExclusionRecommendations.Declaration declaration) {
    final var ref = declaration.reference();
    return Map.of(
        "ordinal",
        ref.ordinal(),
        "groupId",
        ref.groupId(),
        "artifactId",
        ref.artifactId(),
        "type",
        ref.type(),
        "classifier",
        ref.classifier(),
        "origin",
        encodeOrigin(ref.origin()),
        "exclusions",
        declaration.exclusions().stream()
            .map(
                exclusion ->
                    Map.of(
                        "groupId",
                        exclusion.coordinate().groupId(),
                        "artifactId",
                        exclusion.coordinate().artifactId(),
                        "origin",
                        encodeOrigin(exclusion.origin())))
            .toList());
  }

  private static Map<String, Object> encodeOrigin(final ExclusionRecommendations.Origin origin) {
    return Map.of(
        "kind",
        origin.kind(),
        "modelId",
        origin.modelId(),
        "source",
        origin.source(),
        "line",
        origin.line(),
        "column",
        origin.column(),
        "profileId",
        origin.profileId());
  }

  static ExclusionRecommendations.Snapshot decode(final Object value) {
    final Map<?, ?> map = fields(value, Set.of("dependencies", "management", "diagnostics"));
    return new ExclusionRecommendations.Snapshot(
        declarations(map.get("dependencies")),
        declarations(map.get("management")),
        list(map.get("diagnostics")).stream().map(ExclusionProvenancePayload::string).toList());
  }

  private static List<ExclusionRecommendations.Declaration> declarations(final Object value) {
    return list(value).stream().map(ExclusionProvenancePayload::declaration).toList();
  }

  private static ExclusionRecommendations.Declaration declaration(final Object value) {
    final Map<?, ?> map =
        fields(
            value,
            Set.of(
                "ordinal", "groupId", "artifactId", "type", "classifier", "origin", "exclusions"));
    final int ordinal = integer(map.get("ordinal"));
    if (ordinal < 0) {
      throw invalid();
    }
    final var reference =
        new ExclusionRecommendations.Reference(
            ordinal,
            string(map.get("groupId")),
            string(map.get("artifactId")),
            string(map.get("type")),
            string(map.get("classifier")),
            origin(map.get("origin")));
    final var exclusions =
        list(map.get("exclusions")).stream()
            .map(
                item -> {
                  final Map<?, ?> exclusion =
                      fields(item, Set.of("groupId", "artifactId", "origin"));
                  return new ExclusionRecommendations.Exclusion(
                      new ExclusionRecommendations.Coordinate(
                          string(exclusion.get("groupId")), string(exclusion.get("artifactId"))),
                      origin(exclusion.get("origin")));
                })
            .toList();
    return new ExclusionRecommendations.Declaration(reference, exclusions);
  }

  private static ExclusionRecommendations.Origin origin(final Object value) {
    final Map<?, ?> map =
        fields(value, Set.of("kind", "modelId", "source", "line", "column", "profileId"));
    final String kind = string(map.get("kind"));
    if (!Set.of("UNKNOWN", "LOCAL", "INHERITED", "LOCAL_MANAGEMENT", "INHERITED_MANAGEMENT")
        .contains(kind)) {
      throw invalid();
    }
    return new ExclusionRecommendations.Origin(
        kind,
        string(map.get("modelId")),
        string(map.get("source")),
        integer(map.get("line")),
        integer(map.get("column")),
        string(map.get("profileId")));
  }

  private static Map<?, ?> fields(final Object value, final Set<String> keys) {
    if (!(value instanceof Map<?, ?> map) || !map.keySet().equals(keys)) {
      throw invalid();
    }
    return map;
  }

  private static List<?> list(final Object value) {
    if (!(value instanceof List<?> list)) {
      throw invalid();
    }
    return list;
  }

  private static String string(final Object value) {
    if (!(value instanceof String string)) {
      throw invalid();
    }
    return string;
  }

  private static int integer(final Object value) {
    if (!(value instanceof Integer number)) {
      throw invalid();
    }
    return number;
  }

  private static IllegalStateException invalid() {
    return new IllegalStateException("Invalid exclusion provenance payload");
  }
}
