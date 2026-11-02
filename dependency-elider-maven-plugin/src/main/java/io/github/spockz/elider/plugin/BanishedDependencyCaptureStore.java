// WHY: Stores detached original Maven declarations safely across extension class realms.

package io.github.spockz.elider.plugin;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/** Immutable schema-one session payload for original declarations. */
@SuppressWarnings({
  "PMD.CommentDefaultAccessModifier",
  "PMD.CommentRequired",
  "PMD.UseConcurrentHashMap"
})
record BanishedDependencyCaptureStore(
    Map<BanishedDependencyOriginalModel.ProjectIdentity, BanishedDependencyOriginalModel>
        projects) {
  private static final int SCHEMA_VERSION = 1;
  private static final String SCHEMA_FIELD = "schemaVersion";
  private static final String PROJECTS_FIELD = "projects";
  private static final String PROJECT_FIELD = "project";
  private static final String EXECUTIONS_FIELD = "executions";
  private static final String BANS_FIELD = "banishedDependencies";
  private static final String EFFECTIVE_DEPENDENCIES_FIELD = "effectiveDependencies";
  private static final String ORIGINAL_DEPENDENCIES_FIELD = "originalDependencies";
  private static final String EFFECTIVE_MANAGEMENT_FIELD = "effectiveManagement";
  private static final String ORIGINAL_MANAGEMENT_FIELD = "originalManagement";
  private static final String SOURCE_FINGERPRINT_FIELD = "sourceFingerprint";
  private static final String EXCLUSION_PROVENANCE_FIELD = "exclusionProvenance";
  private static final String EXECUTION_ID_FIELD = "id";
  private static final String PHASE_FIELD = "phase";
  private static final String SHORT_BANS_FIELD = "bans";
  private static final String PROVENANCE_FIELD = "provenance";
  private static final String ORDINAL_FIELD = "ordinal";
  private static final String GROUP_ID_FIELD = "groupId";
  private static final String ARTIFACT_ID_FIELD = "artifactId";
  private static final String VERSION_FIELD = "version";
  private static final String TYPE_FIELD = "type";
  private static final String CLASSIFIER_FIELD = "classifier";
  private static final String SCOPE_FIELD = "scope";
  private static final String OPTIONAL_FIELD = "optional";
  private static final String SYSTEM_PATH_FIELD = "systemPath";
  private static final String EXCLUSIONS_FIELD = "exclusions";
  private static final int PROJECT_IDENTITY_FIELD_COUNT = 4;
  private static final Set<String> ROOT_FIELDS = Set.of(SCHEMA_FIELD, PROJECTS_FIELD);
  private static final Set<String> PROJECT_FIELDS =
      Set.of(
          PROJECT_FIELD,
          EXECUTIONS_FIELD,
          BANS_FIELD,
          EFFECTIVE_DEPENDENCIES_FIELD,
          ORIGINAL_DEPENDENCIES_FIELD,
          EFFECTIVE_MANAGEMENT_FIELD,
          ORIGINAL_MANAGEMENT_FIELD,
          EXCLUSION_PROVENANCE_FIELD,
          SOURCE_FINGERPRINT_FIELD);
  private static final String GOAL_FIELD = "goal";
  private static final String PLUGIN_VERSION_FIELD = "pluginVersion";
  private static final String SOURCE_FIELD = "source";
  private static final Set<String> EXECUTION_FIELDS =
      Set.of(
          EXECUTION_ID_FIELD,
          GOAL_FIELD,
          PLUGIN_VERSION_FIELD,
          PHASE_FIELD,
          SOURCE_FIELD,
          SHORT_BANS_FIELD);
  private static final Set<String> DEPENDENCY_FIELDS =
      Set.of(
          PROVENANCE_FIELD,
          ORDINAL_FIELD,
          GROUP_ID_FIELD,
          ARTIFACT_ID_FIELD,
          VERSION_FIELD,
          TYPE_FIELD,
          CLASSIFIER_FIELD,
          SCOPE_FIELD,
          OPTIONAL_FIELD,
          SYSTEM_PATH_FIELD,
          EXCLUSIONS_FIELD);
  private static final Set<String> EXCLUSION_FIELDS = Set.of(GROUP_ID_FIELD, ARTIFACT_ID_FIELD);

  BanishedDependencyCaptureStore {
    Objects.requireNonNull(projects, "projects");
    projects = Collections.unmodifiableMap(new LinkedHashMap<>(projects));
  }

  static BanishedDependencyCaptureStore empty() {
    return new BanishedDependencyCaptureStore(Map.of());
  }

  static BanishedDependencyCaptureStore fromPayload(final Object payload) {
    if (payload == null) {
      return empty();
    }
    final Map<?, ?> root = requireMap(payload, "capture store");
    if (!root.keySet().equals(ROOT_FIELDS)) {
      throw invalid("capture store fields do not match schema");
    }
    if (!Integer.valueOf(SCHEMA_VERSION).equals(root.get(SCHEMA_FIELD))) {
      throw invalid("unsupported capture store schema");
    }
    return new BanishedDependencyCaptureStore(decodeProjects(root.get(PROJECTS_FIELD)));
  }

  private static Map<
          BanishedDependencyOriginalModel.ProjectIdentity, BanishedDependencyOriginalModel>
      decodeProjects(final Object value) {
    final Map<?, ?> encodedProjects = requireMap(value, PROJECTS_FIELD);
    final Map<BanishedDependencyOriginalModel.ProjectIdentity, BanishedDependencyOriginalModel>
        decoded = new LinkedHashMap<>();
    for (final Map.Entry<?, ?> entry : encodedProjects.entrySet()) {
      final String key = requireString(entry.getKey(), "project key");
      final BanishedDependencyOriginalModel model = decodeModel(entry.getValue());
      if (!projectKey(model.project()).equals(key)) {
        throw invalid("project key does not match captured identity");
      }
      if (decoded.put(model.project(), model) != null) {
        throw invalid("duplicate captured project");
      }
    }
    return decoded;
  }

  BanishedDependencyCaptureStore withModel(final BanishedDependencyOriginalModel model) {
    Objects.requireNonNull(model, "model");
    final Map<BanishedDependencyOriginalModel.ProjectIdentity, BanishedDependencyOriginalModel>
        updated = new LinkedHashMap<>(projects);
    updated.put(model.project(), model);
    return new BanishedDependencyCaptureStore(updated);
  }

  BanishedDependencyOriginalModel find(
      final BanishedDependencyOriginalModel.ProjectIdentity project) {
    return projects.get(Objects.requireNonNull(project, "project"));
  }

  Map<String, Object> toPayload() {
    final Map<String, Object> encodedProjects = new LinkedHashMap<>();
    projects
        .values()
        .forEach(model -> encodedProjects.put(projectKey(model.project()), encodeModel(model)));
    final Map<String, Object> root = new LinkedHashMap<>();
    root.put(SCHEMA_FIELD, SCHEMA_VERSION);
    root.put(PROJECTS_FIELD, Collections.unmodifiableMap(encodedProjects));
    return Collections.unmodifiableMap(root);
  }

  static String projectKey(final BanishedDependencyOriginalModel.ProjectIdentity project) {
    return encodeTuple(
        List.of(project.basedir(), project.groupId(), project.artifactId(), project.version()));
  }

  private static Map<String, Object> encodeModel(final BanishedDependencyOriginalModel model) {
    final Map<String, Object> encoded = new LinkedHashMap<>();
    encoded.put(
        PROJECT_FIELD,
        List.of(
            model.project().basedir(),
            model.project().groupId(),
            model.project().artifactId(),
            model.project().version()));
    encoded.put(
        EXECUTIONS_FIELD,
        model.executions().stream()
            .map(
                execution ->
                    Map.of(
                        EXECUTION_ID_FIELD, execution.executionId(),
                        GOAL_FIELD, execution.goal(),
                        PLUGIN_VERSION_FIELD, execution.pluginVersion(),
                        PHASE_FIELD, execution.phase(),
                        SOURCE_FIELD, execution.source(),
                        SHORT_BANS_FIELD, execution.bans()))
            .toList());
    encoded.put(BANS_FIELD, model.banishedDependencies());
    encoded.put(EFFECTIVE_DEPENDENCIES_FIELD, encodeDependencies(model.effectiveDependencies()));
    encoded.put(ORIGINAL_DEPENDENCIES_FIELD, encodeDependencies(model.originalDependencies()));
    encoded.put(EFFECTIVE_MANAGEMENT_FIELD, encodeDependencies(model.effectiveManagement()));
    encoded.put(ORIGINAL_MANAGEMENT_FIELD, encodeDependencies(model.originalManagement()));
    encoded.put(
        EXCLUSION_PROVENANCE_FIELD, ExclusionProvenancePayload.encode(model.exclusionProvenance()));
    encoded.put(SOURCE_FINGERPRINT_FIELD, model.sourceFingerprint());
    return Collections.unmodifiableMap(encoded);
  }

  private static List<Map<String, Object>> encodeDependencies(
      final List<BanishedDependencyOriginalModel.DependencyEntry> dependencies) {
    return dependencies.stream().map(BanishedDependencyCaptureStore::encodeDependency).toList();
  }

  private static Map<String, Object> encodeDependency(
      final BanishedDependencyOriginalModel.DependencyEntry dependency) {
    final List<Map<String, String>> exclusions =
        dependency.exclusions().stream()
            .map(
                exclusion ->
                    Map.of(
                        GROUP_ID_FIELD,
                        exclusion.groupId(),
                        ARTIFACT_ID_FIELD,
                        exclusion.artifactId()))
            .toList();
    final Map<String, Object> encoded = new LinkedHashMap<>();
    encoded.put(PROVENANCE_FIELD, dependency.provenance());
    encoded.put(ORDINAL_FIELD, dependency.ordinal());
    encoded.put(GROUP_ID_FIELD, dependency.groupId());
    encoded.put(ARTIFACT_ID_FIELD, dependency.artifactId());
    encoded.put(VERSION_FIELD, dependency.version());
    encoded.put(TYPE_FIELD, dependency.type());
    encoded.put(CLASSIFIER_FIELD, dependency.classifier());
    encoded.put(SCOPE_FIELD, dependency.scope());
    encoded.put(OPTIONAL_FIELD, dependency.optional());
    encoded.put(SYSTEM_PATH_FIELD, dependency.systemPath());
    encoded.put(EXCLUSIONS_FIELD, exclusions);
    return Collections.unmodifiableMap(encoded);
  }

  private static BanishedDependencyOriginalModel decodeModel(final Object value) {
    final Map<?, ?> encoded = requireMap(value, "captured project");
    if (!encoded.keySet().equals(PROJECT_FIELDS)) {
      throw invalid("captured project fields do not match schema");
    }
    final List<?> projectValues = requireList(encoded.get(PROJECT_FIELD), PROJECT_FIELD);
    if (projectValues.size() != PROJECT_IDENTITY_FIELD_COUNT) {
      throw invalid("project identity must contain four fields");
    }
    final BanishedDependencyOriginalModel.ProjectIdentity project =
        new BanishedDependencyOriginalModel.ProjectIdentity(
            requireString(projectValues.get(0), "project basedir"),
            requireString(projectValues.get(1), "project groupId"),
            requireString(projectValues.get(2), "project artifactId"),
            requireString(projectValues.get(3), "project version"));
    final List<BanishedDependencyOriginalModel.ExecutionPolicy> executions =
        decodeExecutions(encoded.get(EXECUTIONS_FIELD));
    final List<String> bans = decodeStrings(encoded.get(BANS_FIELD), BANS_FIELD);
    final BanishedDependencyOriginalModel model =
        new BanishedDependencyOriginalModel(
            project,
            executions,
            bans,
            decodeDependencies(encoded.get(EFFECTIVE_DEPENDENCIES_FIELD)),
            decodeDependencies(encoded.get(ORIGINAL_DEPENDENCIES_FIELD)),
            decodeDependencies(encoded.get(EFFECTIVE_MANAGEMENT_FIELD)),
            decodeDependencies(encoded.get(ORIGINAL_MANAGEMENT_FIELD)),
            ExclusionProvenancePayload.decode(encoded.get(EXCLUSION_PROVENANCE_FIELD)),
            requireString(encoded.get(SOURCE_FINGERPRINT_FIELD), SOURCE_FINGERPRINT_FIELD));
    validateProvenanceRows(
        model.effectiveDependencies(), model.exclusionProvenance().dependencies());
    validateProvenanceRows(model.effectiveManagement(), model.exclusionProvenance().management());
    if (!model.hasValidSourceFingerprint()) {
      throw invalid("captured source fingerprint does not match its values");
    }
    return model;
  }

  @SuppressWarnings({"PMD.CyclomaticComplexity", "PMD.UseExplicitTypes"})
  private static void validateProvenanceRows(
      final List<BanishedDependencyOriginalModel.DependencyEntry> entries,
      final List<ExclusionRecommendations.Declaration> declarations) {
    if (entries.size() != declarations.size()) {
      throw invalid("provenance row count does not match declarations");
    }
    for (int index = 0; index < entries.size(); index++) {
      final var entry = entries.get(index);
      final var declaration = declarations.get(index);
      final var reference = declaration.reference();
      if (reference.ordinal() != index
          || !reference.groupId().equals(entry.groupId())
          || !reference.artifactId().equals(entry.artifactId())
          || !reference.type().equals(entry.type())
          || !reference.classifier().equals(entry.classifier())
          || declaration.exclusions().size() != entry.exclusions().size()) {
        throw invalid("provenance row does not match declaration");
      }
      for (int exclusionIndex = 0; exclusionIndex < entry.exclusions().size(); exclusionIndex++) {
        final var expected = entry.exclusions().get(exclusionIndex);
        final var actual = declaration.exclusions().get(exclusionIndex).coordinate();
        if (!actual.groupId().equals(expected.groupId())
            || !actual.artifactId().equals(expected.artifactId())) {
          throw invalid("provenance exclusion does not match declaration");
        }
      }
    }
  }

  private static List<BanishedDependencyOriginalModel.ExecutionPolicy> decodeExecutions(
      final Object value) {
    final List<?> rows = requireList(value, EXECUTIONS_FIELD);
    final List<BanishedDependencyOriginalModel.ExecutionPolicy> decoded = new ArrayList<>();
    for (final Object row : rows) {
      final Map<?, ?> fields = requireMap(row, "execution policy");
      if (!fields.keySet().equals(EXECUTION_FIELDS)) {
        throw invalid("execution fields do not match schema");
      }
      decoded.add(
          new BanishedDependencyOriginalModel.ExecutionPolicy(
              requireString(fields.get(EXECUTION_ID_FIELD), "execution id"),
              requireString(fields.get(GOAL_FIELD), "execution goal"),
              requireString(fields.get(PLUGIN_VERSION_FIELD), "plugin version"),
              requireString(fields.get(PHASE_FIELD), "execution phase"),
              requireString(fields.get(SOURCE_FIELD), "execution source"),
              decodeStrings(fields.get(SHORT_BANS_FIELD), "execution bans")));
    }
    return List.copyOf(decoded);
  }

  private static List<BanishedDependencyOriginalModel.DependencyEntry> decodeDependencies(
      final Object value) {
    final List<?> rows = requireList(value, "dependency declarations");
    final List<BanishedDependencyOriginalModel.DependencyEntry> decoded = new ArrayList<>();
    for (final Object row : rows) {
      final Map<?, ?> fields = requireMap(row, "dependency declaration");
      if (!fields.keySet().equals(DEPENDENCY_FIELDS)) {
        throw invalid("dependency declaration fields do not match schema");
      }
      final Object ordinalValue = fields.get(ORDINAL_FIELD);
      if (!(ordinalValue instanceof Integer ordinal) || ordinal < 0) {
        throw invalid("dependency ordinal must be a non-negative integer");
      }
      decoded.add(
          new BanishedDependencyOriginalModel.DependencyEntry(
              requireString(fields.get(PROVENANCE_FIELD), "dependency provenance"),
              ordinal,
              requireString(fields.get(GROUP_ID_FIELD), "dependency groupId"),
              requireString(fields.get(ARTIFACT_ID_FIELD), "dependency artifactId"),
              requireString(fields.get(VERSION_FIELD), "dependency version"),
              requireString(fields.get(TYPE_FIELD), "dependency type"),
              requireString(fields.get(CLASSIFIER_FIELD), "dependency classifier"),
              requireString(fields.get(SCOPE_FIELD), "dependency scope"),
              requireString(fields.get(OPTIONAL_FIELD), "dependency optional"),
              requireString(fields.get(SYSTEM_PATH_FIELD), "dependency systemPath"),
              decodeExclusions(fields.get("exclusions"))));
    }
    return List.copyOf(decoded);
  }

  private static List<BanishedDependencyOriginalModel.ExclusionEntry> decodeExclusions(
      final Object value) {
    final List<?> rows = requireList(value, "exclusions");
    final List<BanishedDependencyOriginalModel.ExclusionEntry> decoded = new ArrayList<>();
    for (final Object row : rows) {
      final Map<?, ?> fields = requireMap(row, "exclusion");
      if (!fields.keySet().equals(EXCLUSION_FIELDS)) {
        throw invalid("exclusion fields do not match schema");
      }
      decoded.add(
          new BanishedDependencyOriginalModel.ExclusionEntry(
              requireString(fields.get(GROUP_ID_FIELD), "exclusion groupId"),
              requireString(fields.get(ARTIFACT_ID_FIELD), "exclusion artifactId")));
    }
    return List.copyOf(decoded);
  }

  private static List<String> decodeStrings(final Object value, final String name) {
    final List<?> raw = requireList(value, name);
    return raw.stream().map(item -> requireString(item, name + " entry")).toList();
  }

  private static Map<?, ?> requireMap(final Object value, final String name) {
    if (value instanceof Map<?, ?> map) {
      return map;
    }
    throw invalid(name + " must be a map");
  }

  private static List<?> requireList(final Object value, final String name) {
    if (value instanceof List<?> list) {
      return list;
    }
    throw invalid(name + " must be a list");
  }

  private static String requireString(final Object value, final String name) {
    if (value instanceof String string) {
      return string;
    }
    throw invalid(name + " must be a string");
  }

  private static String encodeTuple(final List<String> values) {
    return values.stream()
        .map(
            value ->
                Base64.getUrlEncoder()
                    .withoutPadding()
                    .encodeToString(value.getBytes(StandardCharsets.UTF_8)))
        .collect(java.util.stream.Collectors.joining("."));
  }

  private static IllegalStateException invalid(final String message) {
    return new IllegalStateException("Invalid ban exclusion capture payload: " + message);
  }
}
