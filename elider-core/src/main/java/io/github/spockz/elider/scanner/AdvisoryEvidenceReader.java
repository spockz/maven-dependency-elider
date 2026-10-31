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
import io.github.spockz.elider.model.CveAffectedEntryContext;
import io.github.spockz.elider.model.CveVersionClaim;
import io.github.spockz.elider.model.EvidenceOrigin;
import io.github.spockz.elider.model.HeuristicCandidateEvidence;
import io.github.spockz.elider.model.OsvAdvisoryRecord;
import io.github.spockz.elider.model.OsvAffectedPackage;
import io.github.spockz.elider.model.OsvAffectedRange;
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
  "PMD.AvoidDuplicateLiterals",
  "PMD.CouplingBetweenObjects",
  "PMD.AvoidInstantiatingObjectsInLoops",
  "PMD.UseConcurrentHashMap"
})
public final class AdvisoryEvidenceReader {
  /** Root fields allowed by schema version one. */
  private static final Set<String> ROOT_FIELDS = Set.of("schemaVersion", "records");

  /** Scope fields required for every evidence item. */
  private static final Set<String> SCOPE_FIELDS =
      Set.of("cveId", "affectedCoordinate", "versionRangeSpec", "ecosystem", "packageName");

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

  /** Reads schema version one and only cacheable advisory-source variants. */
  public List<OsvAdvisoryRecord> read(final InputStream input) throws IOException {
    Objects.requireNonNull(input, "input");
    final JsonNode root;
    try (JsonParser parser = mapper.getFactory().createParser(input)) {
      parser.enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
      root = mapper.readTree(parser);
      if (parser.nextToken() != null) {
        throw new IOException("Advisory evidence document contains trailing JSON content");
      }
    }
    return readTree(root);
  }

  /** Validates and decodes an already parsed advisory document tree. */
  public List<OsvAdvisoryRecord> readTree(final JsonNode root) throws IOException {
    requireObject(root, "advisory evidence document");
    requireFields(root, ROOT_FIELDS, "advisory evidence document");
    if (!root.path("schemaVersion").isIntegralNumber()
        || !root.path("schemaVersion").canConvertToInt()
        || root.path("schemaVersion").intValue() != 1) {
      throw new IOException("Unsupported advisory evidence schemaVersion");
    }
    final JsonNode items = root.get("records");
    if (items == null || !items.isArray()) {
      throw new IOException("records must be an array");
    }
    final List<OsvAdvisoryRecord> result = new ArrayList<>();
    final Set<String> recordIds = new HashSet<>();
    for (final JsonNode item : items) {
      final OsvAdvisoryRecord record;
      try {
        record = readRecord(item);
      } catch (final IllegalArgumentException exception) {
        throw new IOException("Invalid OSV record: " + exception.getMessage(), exception);
      }
      if (!recordIds.add(record.osvId())) {
        throw new IOException("Duplicate OSV record ID: " + record.osvId());
      }
      result.add(record);
    }
    return List.copyOf(result);
  }

  private OsvAdvisoryRecord readRecord(final JsonNode node) throws IOException {
    requireObject(node, "OSV record");
    requireFields(
        node,
        Set.of("osvId", "aliases", "affectedPackages", "cnaAffectedEntries", "evidence"),
        "OSV record");
    final List<AdvisoryEvidence> evidence = new ArrayList<>();
    final JsonNode evidenceNodes = node.get("evidence");
    if (!evidenceNodes.isArray()) {
      throw new IOException("record evidence must be an array");
    }
    for (final JsonNode item : evidenceNodes) {
      evidence.add(readEvidence(item));
    }
    final List<CveAffectedEntryContext> cnaEntries = new ArrayList<>();
    final JsonNode cnaNodes = node.get("cnaAffectedEntries");
    if (!cnaNodes.isArray()) {
      throw new IOException("cnaAffectedEntries must be an array");
    }
    for (final JsonNode entry : cnaNodes) {
      cnaEntries.add(readCnaEntry(entry));
    }
    final List<OsvAffectedPackage> affectedPackages = new ArrayList<>();
    final JsonNode packageNodes = node.get("affectedPackages");
    if (!packageNodes.isArray()) {
      throw new IOException("affectedPackages must be an array");
    }
    for (final JsonNode affectedPackage : packageNodes) {
      affectedPackages.add(readAffectedPackage(affectedPackage));
    }
    try {
      return new OsvAdvisoryRecord(
          requiredText(node, "osvId"),
          readStringSet(node.get("aliases"), "aliases"),
          affectedPackages,
          cnaEntries,
          evidence);
    } catch (final IllegalArgumentException exception) {
      throw new IOException("Invalid OSV record: " + exception.getMessage(), exception);
    }
  }

  private OsvAffectedPackage readAffectedPackage(final JsonNode node) throws IOException {
    requireObject(node, "affected package");
    requireFields(
        node,
        Set.of("ecosystem", "packageName", "coordinate", "versions", "ranges"),
        "affected package");
    final JsonNode coordinate = node.get("coordinate");
    requireObject(coordinate, "affected package coordinate");
    requireFields(coordinate, COORDINATE_FIELDS, "affected package coordinate");
    final List<String> versions = readListOfText(node.get("versions"), "versions");
    final JsonNode rangesNode = node.get("ranges");
    if (!rangesNode.isArray()) {
      throw new IOException("ranges must be an array");
    }
    final List<OsvAffectedRange> ranges = new ArrayList<>();
    for (final JsonNode rangeNode : rangesNode) {
      requireObject(rangeNode, "OSV range");
      requireFields(rangeNode, Set.of("type", "repo", "events"), "OSV range");
      final JsonNode eventsNode = rangeNode.get("events");
      if (!eventsNode.isArray()) {
        throw new IOException("range events must be an array");
      }
      final List<Map<String, String>> events = new ArrayList<>();
      for (final JsonNode eventNode : eventsNode) {
        requireObject(eventNode, "OSV range event");
        final Map<String, String> values = new LinkedHashMap<>();
        final Iterator<Map.Entry<String, JsonNode>> fields = eventNode.fields();
        while (fields.hasNext()) {
          final Map.Entry<String, JsonNode> field = fields.next();
          if (!field.getValue().isTextual()
              || values.putIfAbsent(field.getKey(), field.getValue().textValue()) != null) {
            throw new IOException("OSV range event fields must be unique strings");
          }
        }
        events.add(values);
      }
      ranges.add(
          new OsvAffectedRange(
              requiredText(rangeNode, "type"), optionalText(rangeNode, "repo"), events));
    }
    return new OsvAffectedPackage(
        requiredText(node, "ecosystem"),
        requiredText(node, "packageName"),
        new ArtifactCoordinate(
            requiredText(coordinate, "groupId"),
            requiredText(coordinate, "artifactId"),
            optionalText(coordinate, "version"),
            requiredText(coordinate, "type"),
            requiredTextAllowBlank(coordinate, "classifier"),
            requiredText(coordinate, "scope")),
        versions,
        ranges);
  }

  private static List<String> readListOfText(final JsonNode node, final String field)
      throws IOException {
    if (node == null || !node.isArray()) {
      throw new IOException(field + " must be an array");
    }
    final List<String> values = new ArrayList<>();
    for (final JsonNode value : node) {
      if (!value.isTextual() || value.textValue().isBlank()) {
        throw new IOException(field + " must contain non-blank strings");
      }
      values.add(value.textValue());
    }
    return List.copyOf(values);
  }

  private CveAffectedEntryContext readCnaEntry(final JsonNode node) throws IOException {
    requireObject(node, "CNA affected entry");
    requireFields(
        node,
        Set.of(
            "entryIdentity",
            "vendor",
            "product",
            "packageUrl",
            "collectionUrl",
            "defaultStatus",
            "versions",
            "programFiles",
            "programRoutines"),
        "CNA affected entry");
    final List<CveVersionClaim> versions = readCnaVersions(node.get("versions"));
    return new CveAffectedEntryContext(
        requiredText(node, "entryIdentity"),
        optionalText(node, "vendor"),
        requiredText(node, "product"),
        optionalText(node, "packageUrl"),
        optionalText(node, "collectionUrl"),
        optionalText(node, "defaultStatus"),
        versions,
        Set.copyOf(readStringSet(node.get("programFiles"), "programFiles")),
        Set.copyOf(readStringSet(node.get("programRoutines"), "programRoutines")));
  }

  private List<CveVersionClaim> readCnaVersions(final JsonNode versionNodes) throws IOException {
    if (versionNodes == null || !versionNodes.isArray()) {
      throw new IOException("CNA versions must be an array");
    }
    final List<CveVersionClaim> versions = new ArrayList<>();
    for (final JsonNode version : versionNodes) {
      versions.add(readCnaVersion(version));
    }
    return List.copyOf(versions);
  }

  private CveVersionClaim readCnaVersion(final JsonNode version) throws IOException {
    requireObject(version, "CNA version");
    requireFields(
        version,
        Set.of("version", "status", "versionType", "lessThan", "lessThanOrEqual", "changes"),
        "CNA version");
    return new CveVersionClaim(
        requiredText(version, "version"),
        requiredText(version, "status"),
        optionalText(version, "versionType"),
        optionalText(version, "lessThan"),
        optionalText(version, "lessThanOrEqual"),
        readCnaChanges(version.get("changes")));
  }

  private List<Map<String, String>> readCnaChanges(final JsonNode changeNodes) throws IOException {
    if (changeNodes == null) {
      return List.of();
    }
    if (!changeNodes.isArray()) {
      throw new IOException("CNA version changes must be an array");
    }
    final List<Map<String, String>> changes = new ArrayList<>();
    for (final JsonNode change : changeNodes) {
      requireObject(change, "CNA version change");
      changes.add(readCnaChange(change));
    }
    return List.copyOf(changes);
  }

  private Map<String, String> readCnaChange(final JsonNode change) throws IOException {
    final Map<String, String> fields = new LinkedHashMap<>();
    final Iterator<Map.Entry<String, JsonNode>> changeFields = change.fields();
    while (changeFields.hasNext()) {
      final Map.Entry<String, JsonNode> field = changeFields.next();
      if (!field.getValue().isTextual()) {
        throw new IOException("CNA version change fields must be strings");
      }
      fields.put(field.getKey(), field.getValue().textValue());
    }
    return Map.copyOf(fields);
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
            "cnaAffectedEntryIdentity",
            "affectedProductIdentity",
            "programFiles",
            "programRoutines",
            "fileClassAttribution",
            "routineClassAttribution"),
        "structured-source-class evidence");
    return new StructuredSourceClassEvidence(
        readScope(node.get("scope")),
        readProvenance(node.get("provenance")),
        requiredText(node, "cnaAffectedEntryIdentity"),
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
            "cnaAffectedEntryIdentity",
            "artifactCoordinate",
            "originalArchiveSha256",
            "physicalJarEntry",
            "multiReleaseTier",
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
        requiredText(node, "cnaAffectedEntryIdentity"),
        readCoordinate(node.get("artifactCoordinate"), "artifactCoordinate"),
        requiredText(node, "originalArchiveSha256"),
        requiredText(node, "physicalJarEntry"),
        requiredInteger(node, "multiReleaseTier"),
        requiredText(node, "affectedProductIdentity"),
        requiredText(node, "programFile"),
        requiredText(node, "classEntry"),
        requiredText(node, "sourceFileAttribute"),
        requiredText(node, "packagePathComparison"),
        requiredBoolean(node, "conventionalLayoutAssumed"),
        CorroboratedSourceClassCandidate.MappingStatus.valueOf(
            requiredText(node, "mappingStatus")));
  }

  private static ArtifactCoordinate readCoordinate(final JsonNode node, final String context)
      throws IOException {
    requireObject(node, context);
    requireFields(node, COORDINATE_FIELDS, context);
    return new ArtifactCoordinate(
        requiredText(node, "groupId"),
        requiredText(node, "artifactId"),
        optionalText(node, "version"),
        requiredText(node, "type"),
        requiredTextAllowBlank(node, "classifier"),
        requiredText(node, "scope"));
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
        optionalText(node, "cveId"),
        new ArtifactCoordinate(
            requiredText(coordinate, "groupId"),
            requiredText(coordinate, "artifactId"),
            optionalText(coordinate, "version"),
            requiredText(coordinate, "type"),
            requiredTextAllowBlank(coordinate, "classifier"),
            requiredText(coordinate, "scope")),
        requiredText(node, "versionRangeSpec"),
        requiredText(node, "ecosystem"),
        requiredText(node, "packageName"));
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

  private static int requiredInteger(final JsonNode node, final String field) throws IOException {
    final JsonNode value = node.get(field);
    if (value == null || !value.isIntegralNumber() || !value.canConvertToInt()) {
      throw new IOException(field + " must be an integer");
    }
    return value.intValue();
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
