/* WHY: Rejects malformed or proof-laundering persisted advisory documents. */

package io.github.spockz.elider.scanner;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.spockz.elider.model.AdvisoryEvidence;
import io.github.spockz.elider.model.AdvisoryProvenance;
import io.github.spockz.elider.model.AdvisoryScope;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.CorroboratedSourceClassCandidate;
import io.github.spockz.elider.model.EvidenceOrigin;
import io.github.spockz.elider.model.HeuristicCandidateEvidence;
import io.github.spockz.elider.model.PackageAdvisoryEvidence;
import io.github.spockz.elider.model.StructuredSourceClassEvidence;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;

/** Strict v1 reader for review-only advisory evidence. */
@SuppressWarnings({
  "PMD.GodClass",
  "PMD.TooManyMethods",
  "PMD.CyclomaticComplexity",
  "PMD.AvoidDuplicateLiterals"
})
public final class AdvisoryEvidenceReader {
  /** Root fields allowed by schema version one. */
  private static final Set<String> ROOT_FIELDS = Set.of("schemaVersion", "evidence");

  /** Scope fields required for every evidence item. */
  private static final Set<String> SCOPE_FIELDS =
      Set.of("cveId", "affectedCoordinate", "versionRangeSpec");

  /** Complete Maven coordinate fields persisted by the codec. */
  private static final Set<String> COORDINATE_FIELDS =
      Set.of("groupId", "artifactId", "version", "type", "classifier", "scope");

  /** Provenance fields required by each cacheable variant. */
  private static final Set<String> PROVENANCE_FIELDS =
      Set.of("origin", "sourceRecordId", "sourceUrl", "sourceRecordSha256");

  /** JSON mapper used by this strict reader. */
  private final ObjectMapper mapper;

  /** Creates a reader that rejects duplicate JSON object keys. */
  public AdvisoryEvidenceReader() {
    this(new ObjectMapper().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION));
  }

  /** Creates a reader using a mapper that still rejects duplicate keys. */
  public AdvisoryEvidenceReader(final ObjectMapper mapper) {
    this.mapper = Objects.requireNonNull(mapper, "mapper");
  }

  /** Reads schema version one and only the four cacheable advisory-source variants. */
  public List<AdvisoryEvidence> read(final InputStream input) throws IOException {
    Objects.requireNonNull(input, "input");
    final JsonNode root;
    try (JsonParser parser = mapper.getFactory().createParser(input)) {
      parser.enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
      root = mapper.readTree(parser);
      if (parser.nextToken() != null) {
        throw new IOException("Advisory evidence document contains trailing JSON content");
      }
    }
    requireObject(root, "advisory evidence document");
    requireFields(root, ROOT_FIELDS, "advisory evidence document");
    if (!root.path("schemaVersion").isIntegralNumber()
        || !root.path("schemaVersion").canConvertToInt()
        || root.path("schemaVersion").intValue() != 1) {
      throw new IOException("Unsupported advisory evidence schemaVersion");
    }
    final JsonNode items = root.get("evidence");
    if (items == null || !items.isArray()) {
      throw new IOException("evidence must be an array");
    }
    final List<AdvisoryEvidence> result = new ArrayList<>();
    for (final JsonNode item : items) {
      result.add(readEvidence(item));
    }
    return List.copyOf(result);
  }

  private AdvisoryEvidence readEvidence(final JsonNode node) throws IOException {
    requireObject(node, "evidence item");
    final String kind = requiredText(node, "kind");
    try {
      return switch (kind) {
        case "structured-source-class" -> readStructured(node);
        case "corroborated-source-class-candidate" -> readCorroborated(node);
        case "heuristic-candidate" -> readHeuristic(node);
        case "package-advisory" -> readPackage(node);
        case "explicit-class-mapping", "explicit-prerequisite" ->
            throw new IOException(
                "Owner proof evidence cannot be loaded from an advisory document");
        default -> throw new IOException("Unknown advisory evidence discriminator: " + kind);
      };
    } catch (final IllegalArgumentException exception) {
      throw new IOException("Invalid " + kind + " evidence: " + exception.getMessage(), exception);
    }
  }

  private StructuredSourceClassEvidence readStructured(final JsonNode node) throws IOException {
    requireFields(
        node,
        Set.of(
            "kind",
            "scope",
            "provenance",
            "affectedProductIdentity",
            "programFiles",
            "programRoutines",
            "fileClassAttribution",
            "routineClassAttribution"),
        "structured-source-class evidence");
    return new StructuredSourceClassEvidence(
        readScope(node.get("scope")),
        readProvenance(node.get("provenance")),
        requiredText(node, "affectedProductIdentity"),
        readStringSet(node.get("programFiles"), "programFiles"),
        readStringSet(node.get("programRoutines"), "programRoutines"),
        readAttribution(node.get("fileClassAttribution"), "fileClassAttribution"),
        readAttribution(node.get("routineClassAttribution"), "routineClassAttribution"));
  }

  private CorroboratedSourceClassCandidate readCorroborated(final JsonNode node)
      throws IOException {
    requireFields(
        node,
        Set.of(
            "kind",
            "scope",
            "provenance",
            "affectedProductIdentity",
            "programFile",
            "classEntry",
            "sourceFileAttribute",
            "packagePathComparison",
            "conventionalLayoutAssumed",
            "mappingStatus"),
        "corroborated source candidate");
    return new CorroboratedSourceClassCandidate(
        readScope(node.get("scope")),
        readProvenance(node.get("provenance")),
        requiredText(node, "affectedProductIdentity"),
        requiredText(node, "programFile"),
        requiredText(node, "classEntry"),
        optionalText(node, "sourceFileAttribute"),
        requiredText(node, "packagePathComparison"),
        requiredBoolean(node, "conventionalLayoutAssumed"),
        CorroboratedSourceClassCandidate.MappingStatus.valueOf(
            requiredText(node, "mappingStatus")));
  }

  private HeuristicCandidateEvidence readHeuristic(final JsonNode node) throws IOException {
    requireFields(
        node,
        Set.of("kind", "scope", "provenance", "candidateClasses", "candidateDependencies"),
        "heuristic candidate");
    return new HeuristicCandidateEvidence(
        readScope(node.get("scope")),
        readProvenance(node.get("provenance")),
        readStringSet(node.get("candidateClasses"), "candidateClasses"),
        readStringSet(node.get("candidateDependencies"), "candidateDependencies"));
  }

  private PackageAdvisoryEvidence readPackage(final JsonNode node) throws IOException {
    requireFields(node, Set.of("kind", "scope", "provenance"), "package advisory");
    return new PackageAdvisoryEvidence(
        readScope(node.get("scope")), readProvenance(node.get("provenance")));
  }

  private AdvisoryScope readScope(final JsonNode node) throws IOException {
    requireObject(node, "scope");
    requireFields(node, SCOPE_FIELDS, "scope");
    final JsonNode coordinate = node.get("affectedCoordinate");
    requireObject(coordinate, "affectedCoordinate");
    requireFields(coordinate, COORDINATE_FIELDS, "affectedCoordinate");
    return new AdvisoryScope(
        requiredText(node, "cveId"),
        new ArtifactCoordinate(
            requiredText(coordinate, "groupId"),
            requiredText(coordinate, "artifactId"),
            optionalText(coordinate, "version"),
            requiredText(coordinate, "type"),
            requiredTextAllowBlank(coordinate, "classifier"),
            requiredText(coordinate, "scope")),
        requiredText(node, "versionRangeSpec"));
  }

  private AdvisoryProvenance readProvenance(final JsonNode node) throws IOException {
    requireObject(node, "provenance");
    requireFields(node, PROVENANCE_FIELDS, "provenance");
    final String sourceUrl = optionalText(node, "sourceUrl");
    return new AdvisoryProvenance(
        EvidenceOrigin.valueOf(requiredText(node, "origin")),
        requiredText(node, "sourceRecordId"),
        sourceUrl == null ? null : URI.create(sourceUrl),
        optionalText(node, "sourceRecordSha256"));
  }

  private static Set<String> readStringSet(final JsonNode node, final String field)
      throws IOException {
    if (node == null || !node.isArray()) {
      throw new IOException(field + " must be an array");
    }
    final Set<String> values = new TreeSet<>();
    for (final JsonNode value : node) {
      if (!value.isTextual() || !values.add(value.textValue())) {
        throw new IOException(field + " must contain unique strings");
      }
    }
    return Set.copyOf(values);
  }

  @SuppressWarnings("PMD.UseConcurrentHashMap")
  private static Map<String, Set<String>> readAttribution(final JsonNode node, final String field)
      throws IOException {
    if (node == null || !node.isObject()) {
      throw new IOException(field + " must be an object");
    }
    final Map<String, Set<String>> result = new LinkedHashMap<>();
    final Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
    while (fields.hasNext()) {
      final Map.Entry<String, JsonNode> entry = fields.next();
      if (result.putIfAbsent(entry.getKey(), readStringSet(entry.getValue(), field)) != null) {
        throw new IOException(field + " contains duplicate source keys");
      }
    }
    return Map.copyOf(result);
  }

  private static String requiredText(final JsonNode node, final String field) throws IOException {
    final JsonNode value = node == null ? null : node.get(field);
    if (value == null || !value.isTextual() || value.textValue().isBlank()) {
      throw new IOException(field + " must be a non-empty string");
    }
    return value.textValue();
  }

  private static String optionalText(final JsonNode node, final String field) throws IOException {
    final JsonNode value = node == null ? null : node.get(field);
    if (value == null || value.isNull()) {
      return null;
    }
    if (!value.isTextual()) {
      throw new IOException(field + " must be a string or null");
    }
    return value.textValue();
  }

  private static String requiredTextAllowBlank(final JsonNode node, final String field)
      throws IOException {
    final JsonNode value = node == null ? null : node.get(field);
    if (value == null || !value.isTextual()) {
      throw new IOException(field + " must be a string");
    }
    return value.textValue();
  }

  private static boolean requiredBoolean(final JsonNode node, final String field)
      throws IOException {
    final JsonNode value = node.get(field);
    if (value == null || !value.isBoolean()) {
      throw new IOException(field + " must be a boolean");
    }
    return value.booleanValue();
  }

  private static void requireObject(final JsonNode node, final String name) throws IOException {
    if (node == null || !node.isObject()) {
      throw new IOException(name + " must be an object");
    }
  }

  private static void requireFields(
      final JsonNode node, final Set<String> allowed, final String name) throws IOException {
    final Iterator<String> fields = node.fieldNames();
    final Set<String> present = new HashSet<>();
    while (fields.hasNext()) {
      final String field = fields.next();
      if (!allowed.contains(field)) {
        throw new IOException(name + " contains unknown field: " + field);
      }
      present.add(field);
    }
    if (!present.containsAll(allowed)) {
      final Set<String> missing = new HashSet<>(allowed);
      missing.removeAll(present);
      throw new IOException(name + " is missing required fields: " + missing);
    }
  }
}
