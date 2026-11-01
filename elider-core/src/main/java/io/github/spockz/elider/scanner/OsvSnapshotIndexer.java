/* WHY: Preserves OSV-owned Maven scopes and separate review-only source evidence. */

package io.github.spockz.elider.scanner;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.spockz.elider.model.AdvisoryProvenance;
import io.github.spockz.elider.model.AdvisoryScope;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.CveAffectedEntryContext;
import io.github.spockz.elider.model.CveSourceRecordMetadata;
import io.github.spockz.elider.model.CveVersionClaim;
import io.github.spockz.elider.model.EvidenceOrigin;
import io.github.spockz.elider.model.HeuristicCandidateEvidence;
import io.github.spockz.elider.model.MavenPackageIdentity;
import io.github.spockz.elider.model.OsvAdvisoryRecord;
import io.github.spockz.elider.model.OsvAffectedPackage;
import io.github.spockz.elider.model.OsvAffectedRange;
import io.github.spockz.elider.model.PackageAdvisoryEvidence;
import io.github.spockz.elider.model.StructuredSourceClassEvidence;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/** Indexes OSV Maven advisories and retains source-attribution candidates for review. */
@SuppressWarnings({
  "PMD.TooManyMethods",
  "PMD.CyclomaticComplexity",
  "PMD.GodClass",
  "PMD.ExcessiveImports",
  "PMD.CouplingBetweenObjects",
  "PMD.CognitiveComplexity",
  "PMD.AvoidLiteralsInIfCondition",
  "PMD.AvoidDeeplyNestedIfStmts",
  "PMD.AssignmentInOperand",
  "PMD.UseConcurrentHashMap",
  "PMD.ShortVariable",
  "PMD.CommentRequired",
  "PMD.CommentSize",
  "PMD.AvoidInstantiatingObjectsInLoops"
})
public final class OsvSnapshotIndexer {
  private static final String CONTAINERS_FIELD = "containers";
  private static final String NAME_FIELD = "name";
  private static final String VERSIONS_FIELD = "versions";
  private static final String WITHDRAWN_FIELD = "withdrawn";
  private static final Pattern CVE_PATTERN = Pattern.compile("^CVE-[0-9]{4}-[0-9]{4,}$");
  private static final Pattern FQCN_PATTERN =
      Pattern.compile("\\b([a-z][a-z0-9_]*(\\.[a-z0-9_]+)+\\.[A-Z][a-zA-Z0-9_]*)\\b");
  private static final Pattern STRICT_FQCN =
      Pattern.compile("^[a-z][a-z0-9_]*(\\.[a-z0-9_]+)*\\.[A-Z][a-zA-Z0-9_]*$");
  private static final Pattern COMMIT_PATH_PATTERN =
      Pattern.compile(
          "(?:src/(?:main|test)/java/)?"
              + "([a-z][a-z0-9_]*(?:/[a-z0-9_]+)+/[A-Z][a-zA-Z0-9_]*)\\.java");

  private final ObjectMapper mapper;

  /** Creates an indexer using a default Jackson object mapper. */
  public OsvSnapshotIndexer() {
    this(new ObjectMapper());
  }

  /** Creates an indexer using the supplied Jackson object mapper. */
  public OsvSnapshotIndexer(final ObjectMapper mapper) {
    this.mapper = Objects.requireNonNull(mapper, "mapper");
  }

  /**
   * Reads an OSV advisory ZIP stream and builds OSV-owned evidence groups.
   *
   * @param zipStream the raw input stream of all.zip
   * @param cveListGitDir optional local checkout of CVEList v5 (nullable)
   * @return list of typed records preserving each OSV owner
   * @throws IOException if reading the zip stream fails
   */
  public List<OsvAdvisoryRecord> indexZip(final InputStream zipStream, final Path cveListGitDir)
      throws IOException {
    Objects.requireNonNull(zipStream, "zipStream");
    final List<OsvAdvisoryRecord> records = new ArrayList<>();
    final Set<String> seen = new HashSet<>();
    try (ZipInputStream zis = new ZipInputStream(zipStream)) {
      ZipEntry entry;
      while ((entry = zis.getNextEntry()) != null) {
        if (!entry.isDirectory() && entry.getName().toLowerCase(Locale.ROOT).endsWith(".json")) {
          final byte[] bytes = zis.readAllBytes();
          final JsonNode root = readSingleJsonDocument(bytes, "OSV record");
          if (!root.isObject()) {
            throw new IOException("OSV record in " + entry.getName() + " must be a JSON object");
          }
          final JsonNode idNode = root.get("id");
          if (idNode == null || !idNode.isTextual() || idNode.textValue().isBlank()) {
            throw new IOException("OSV record in " + entry.getName() + " has no ID");
          }
          final String recordId = idNode.textValue();
          if (!seen.add(recordId)) {
            throw new IOException("Duplicate OSV record ID: " + recordId);
          }
          final OsvAdvisoryRecord record;
          try {
            record = parseAdvisory(root, cveListGitDir, bytes);
          } catch (final IllegalArgumentException exception) {
            throw new IOException("Invalid OSV record in " + entry.getName(), exception);
          }
          if (record != null) {
            records.add(record);
          }
        }
        zis.closeEntry();
      }
    }
    return List.copyOf(records);
  }

  /** Strictly indexes one fetched OSV record; an empty result denotes an explicit withdrawal. */
  public IndexedOsvRecord indexRecord(
      final byte[] bytes, final Path cveListGitDir, final String expectedId) throws IOException {
    final JsonNode root = readSingleJsonDocument(bytes, "OSV record");
    if (!root.isObject()) {
      throw new IOException("OSV record must be a JSON object");
    }
    final JsonNode id = root.get("id");
    if (id == null || !id.isTextual() || !expectedId.equals(id.textValue())) {
      throw new IOException("Fetched OSV record ID does not match modified index");
    }
    try {
      final String modified = requiredSourceText(root, "modified");
      final OsvAdvisoryRecord record = parseAdvisory(root, cveListGitDir, bytes);
      return new IndexedOsvRecord(expectedId, modified, Optional.ofNullable(record));
    } catch (final IllegalArgumentException exception) {
      throw new IOException("Invalid OSV record " + root.path("id").asText(""), exception);
    }
  }

  /** Retains source revision metadata when a fetched record has no active advisory. */
  public record IndexedOsvRecord(
      String osvId, String modified, Optional<OsvAdvisoryRecord> advisory) {
    /** Validates the source owner/revision pair and any active advisory projection. */
    public IndexedOsvRecord {
      if (osvId == null || osvId.isBlank()) {
        throw new IllegalArgumentException("osvId must not be blank");
      }
      if (modified == null || modified.isBlank()) {
        throw new IllegalArgumentException("modified must not be blank");
      }
      try {
        Instant.parse(modified);
      } catch (final java.time.format.DateTimeParseException exception) {
        throw new IllegalArgumentException("modified must be an RFC 3339 timestamp", exception);
      }
      Objects.requireNonNull(advisory, "advisory");
      advisory.ifPresent(
          record -> {
            if (!osvId.equals(record.osvId()) || !modified.equals(record.modified())) {
              throw new IllegalArgumentException(
                  "advisory identity and revision must match source");
            }
          });
    }
  }

  /** Parses one OSV record, retaining its identity even when no CVE alias exists. */
  public OsvAdvisoryRecord parseAdvisory(
      final JsonNode root, final Path cveListGitDir, final byte[] sourceBytes) {
    if (root == null || !root.isObject()) {
      throw new IllegalArgumentException("OSV record must be a JSON object");
    }
    final JsonNode idNode = root.get("id");
    if (idNode == null || !idNode.isTextual() || idNode.textValue().isBlank()) {
      throw new IllegalArgumentException("OSV record ID must be a non-blank string");
    }
    final String osvId = idNode.textValue();
    final String modified = requiredSourceText(root, "modified");
    try {
      Instant.parse(modified);
    } catch (final java.time.format.DateTimeParseException exception) {
      throw new IllegalArgumentException("modified must be an RFC 3339 timestamp", exception);
    }
    if (root.has(WITHDRAWN_FIELD)) {
      if (!root.path(WITHDRAWN_FIELD).isTextual()
          || root.path(WITHDRAWN_FIELD).asText().isBlank()) {
        throw new IllegalArgumentException(WITHDRAWN_FIELD + " must be a non-blank timestamp");
      }
      try {
        Instant.parse(root.path(WITHDRAWN_FIELD).textValue());
      } catch (final java.time.format.DateTimeParseException exception) {
        throw new IllegalArgumentException(
            WITHDRAWN_FIELD + " must be an RFC 3339 UTC timestamp", exception);
      }
      return null;
    }
    final Set<String> aliases = new TreeSet<>();
    final JsonNode aliasNodes = root.get("aliases");
    if (aliasNodes != null) {
      if (!aliasNodes.isArray()) {
        throw new IllegalArgumentException("aliases must be an array");
      }
      for (final JsonNode alias : aliasNodes) {
        if (!alias.isTextual() || alias.textValue().isBlank()) {
          throw new IllegalArgumentException("aliases must contain non-blank strings");
        }
        aliases.add(alias.textValue());
      }
    }
    final String cveId = resolveCveId(root);
    final String osvDigest = sha256(sourceBytes);
    final List<OsvAffectedPackage> affectedPackages = new ArrayList<>();
    final List<io.github.spockz.elider.model.AdvisoryEvidence> evidence = new ArrayList<>();
    final List<AdvisoryScope> scopes =
        readAffectedEntries(root, cveId, osvId, osvDigest, affectedPackages, evidence);
    final List<CveAffectedEntryContext> cnaEntries = new ArrayList<>();
    final String cvePath = locateCveRecord(cveListGitDir, cveId);
    if (cvePath != null) {
      final Path path = Path.of(cvePath);
      try {
        final byte[] cveBytes = Files.readAllBytes(path);
        final JsonNode cveRoot = readSingleJsonDocument(cveBytes, "CVE source record");
        if (!cveRoot.isObject()) {
          throw new IllegalArgumentException("CVE source record must be a JSON object");
        }
        validateCveSourceShape(cveRoot);
        final String cveDigest = sha256(cveBytes);
        final CveSourceRecordMetadata sourceMetadata = readCveSourceMetadata(cveRoot, cveDigest);
        final JsonNode affected = cveRoot.path(CONTAINERS_FIELD).path("cna").path("affected");
        if (affected.isArray()) {
          for (int index = 0; index < affected.size(); index++) {
            final JsonNode entry = affected.get(index);
            final CveAffectedEntryContext context = readCnaContext(entry, index, sourceMetadata);
            cnaEntries.add(context);
            for (final AdvisoryScope scope : scopes) {
              if (sourceMetadata.authorizesStructuredClaims(cveId, osvId, aliases)
                  && matchesCnaProduct(context, scope)) {
                addStructuredEvidence(
                    entry, context.entryIdentity(), scope, cveId, cveDigest, evidence);
              }
            }
          }
        }
        if (sourceMetadata.authorizesStructuredClaims(cveId, osvId, aliases)) {
          addCveTextEvidence(cveRoot, scopes, cveId, cveDigest, evidence);
        }
      } catch (final IOException exception) {
        throw new IllegalArgumentException("Could not read CVE source record " + cveId, exception);
      }
    }
    return new OsvAdvisoryRecord(osvId, modified, aliases, affectedPackages, cnaEntries, evidence);
  }

  private static List<AdvisoryScope> readAffectedEntries(
      final JsonNode root,
      final String cveId,
      final String osvId,
      final String digest,
      final List<OsvAffectedPackage> affectedPackages,
      final List<io.github.spockz.elider.model.AdvisoryEvidence> evidence) {
    final JsonNode affectedArray = root.get("affected");
    if (affectedArray == null || !affectedArray.isArray()) {
      throw new IllegalArgumentException("affected must be an array");
    }
    final List<AdvisoryScope> scopes = new ArrayList<>();
    for (final JsonNode affected : affectedArray) {
      final OsvAffectedPackage affectedPackage = readAffectedPackage(affected);
      if (affectedPackage != null) {
        affectedPackages.add(affectedPackage);
      }
      final AdvisoryScope scope = cveId == null ? null : readOsvScope(affected, cveId);
      if (scope != null) {
        scopes.add(scope);
        evidence.add(
            new PackageAdvisoryEvidence(
                scope, new AdvisoryProvenance(EvidenceOrigin.OSV, osvId, null, digest)));
        addTextEvidence(root, scope, osvId, digest, evidence);
        addReferenceEvidence(root.path("references"), scope, osvId, digest, evidence);
      }
    }
    return scopes;
  }

  private JsonNode readSingleJsonDocument(final byte[] bytes, final String description)
      throws IOException {
    try (JsonParser parser = mapper.getFactory().createParser(bytes)) {
      parser.enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
      final JsonNode root = mapper.readTree(parser);
      if (root == null || parser.nextToken() != null) {
        throw new IOException(description + " must contain exactly one JSON document");
      }
      return root;
    }
  }

  private static OsvAffectedPackage readAffectedPackage(final JsonNode affected) {
    if (!affected.isObject()) {
      throw new IllegalArgumentException("affected entries must be objects");
    }
    final JsonNode pkg = affected.get("package");
    if (pkg == null || !pkg.isObject()) {
      throw new IllegalArgumentException("affected package must be an object");
    }
    final String ecosystem = requiredSourceText(pkg, "ecosystem");
    final String packageName = requiredSourceText(pkg, NAME_FIELD);
    final JsonNode versionsNode = affected.get(VERSIONS_FIELD);
    final JsonNode rangesNode = affected.get("ranges");
    final List<String> versions = readSourceVersions(versionsNode);
    final List<OsvAffectedRange> ranges = readSourceRanges(rangesNode);
    if (!isMavenEcosystem(ecosystem)) {
      return null;
    }
    final int colon = packageName.indexOf(':');
    if (colon <= 0
        || colon == packageName.length() - 1
        || packageName.indexOf(':', colon + 1) >= 0) {
      throw new IllegalArgumentException("Maven package name must be groupId:artifactId");
    }
    if (versions.isEmpty() && ranges.isEmpty()) {
      throw new IllegalArgumentException("Maven affected package must declare versions or ranges");
    }
    return new OsvAffectedPackage(
        ecosystem,
        packageName,
        ArtifactCoordinate.of(
            packageName.substring(0, colon), packageName.substring(colon + 1), null),
        versions,
        ranges);
  }

  private static List<String> readSourceVersions(final JsonNode versionsNode) {
    if (versionsNode == null) {
      return List.of();
    }
    if (!versionsNode.isArray()) {
      throw new IllegalArgumentException("affected versions must be an array");
    }
    final List<String> versions = new ArrayList<>();
    for (final JsonNode version : versionsNode) {
      if (!version.isTextual() || version.textValue().isBlank()) {
        throw new IllegalArgumentException("affected versions must contain non-blank strings");
      }
      versions.add(version.textValue());
    }
    return List.copyOf(versions);
  }

  private static List<OsvAffectedRange> readSourceRanges(final JsonNode rangesNode) {
    if (rangesNode == null) {
      return List.of();
    }
    if (!rangesNode.isArray()) {
      throw new IllegalArgumentException("affected ranges must be an array");
    }
    final List<OsvAffectedRange> ranges = new ArrayList<>();
    for (final JsonNode range : rangesNode) {
      if (!range.isObject()) {
        throw new IllegalArgumentException("OSV ranges must be objects");
      }
      final String type = requiredSourceText(range, "type");
      final JsonNode repoNode = range.get("repo");
      final String repo;
      if (repoNode == null || repoNode.isNull()) {
        repo = null;
      } else if (repoNode.isTextual()) {
        repo = repoNode.textValue();
      } else {
        throw new IllegalArgumentException("OSV range repo must be a string or null");
      }
      final JsonNode eventsNode = range.get("events");
      if (eventsNode == null || !eventsNode.isArray() || eventsNode.isEmpty()) {
        throw new IllegalArgumentException("OSV range events must be a non-empty array");
      }
      final List<Map<String, String>> events = new ArrayList<>();
      for (final JsonNode event : eventsNode) {
        if (!event.isObject() || event.isEmpty()) {
          throw new IllegalArgumentException("OSV range events must be non-empty objects");
        }
        final Map<String, String> values = new LinkedHashMap<>();
        event
            .fields()
            .forEachRemaining(
                field -> {
                  if (!field.getValue().isTextual() || field.getValue().textValue().isBlank()) {
                    throw new IllegalArgumentException(
                        "OSV range event values must be non-blank strings");
                  }
                  values.put(field.getKey(), field.getValue().textValue());
                });
        events.add(values);
      }
      ranges.add(new OsvAffectedRange(type, repo, events));
    }
    return List.copyOf(ranges);
  }

  private static String requiredSourceText(final JsonNode node, final String field) {
    final JsonNode value = node.get(field);
    if (value == null || !value.isTextual() || value.textValue().isBlank()) {
      throw new IllegalArgumentException(field + " must be a non-blank string");
    }
    return value.textValue();
  }

  private static AdvisoryScope readOsvScope(final JsonNode affected, final String cveId) {
    final JsonNode pkg = affected.path("package");
    final String ecosystem = pkg.path("ecosystem").asText("");
    if (!isMavenEcosystem(ecosystem)) {
      return null;
    }
    final String name = pkg.path(NAME_FIELD).asText("");
    final int colon = name.indexOf(':');
    if (colon <= 0 || colon == name.length() - 1) {
      return null;
    }
    final String groupId = name.substring(0, colon);
    final String artifactId = name.substring(colon + 1);
    final String versionRangeSpec = resolveVersionRange(affected);
    if (versionRangeSpec == null) {
      return null;
    }
    return new AdvisoryScope(
        cveId, ArtifactCoordinate.of(groupId, artifactId, null), versionRangeSpec, ecosystem, name);
  }

  private static void addTextEvidence(
      final JsonNode root,
      final AdvisoryScope scope,
      final String osvId,
      final String digest,
      final List<io.github.spockz.elider.model.AdvisoryEvidence> evidence) {
    for (final String field : List.of("summary", "details")) {
      final String text = root.path(field).asText("");
      if (!text.isBlank()) {
        final Set<String> classes = new TreeSet<>();
        extractClassesFromText(
            text,
            scope.affectedCoordinate().groupId(),
            scope.affectedCoordinate().artifactId(),
            classes);
        evidence.add(
            new HeuristicCandidateEvidence(
                scope,
                new AdvisoryProvenance(
                    EvidenceOrigin.DESCRIPTION, osvId + "#" + field, null, digest),
                classes,
                Set.of(scope.packageName())));
      }
    }
  }

  private static void addReferenceEvidence(
      final JsonNode references,
      final AdvisoryScope scope,
      final String osvId,
      final String digest,
      final List<io.github.spockz.elider.model.AdvisoryEvidence> evidence) {
    if (!references.isArray()) {
      return;
    }
    for (int index = 0; index < references.size(); index++) {
      final String value = references.get(index).path("url").asText("");
      try {
        final URI url = URI.create(value);
        if (!url.isAbsolute()
            || !("http".equalsIgnoreCase(url.getScheme())
                || "https".equalsIgnoreCase(url.getScheme()))) {
          continue;
        }
        final Set<String> classes = new TreeSet<>();
        extractClassesFromCommitUrl(
            value,
            scope.affectedCoordinate().groupId(),
            scope.affectedCoordinate().artifactId(),
            classes);
        evidence.add(
            new HeuristicCandidateEvidence(
                scope,
                new AdvisoryProvenance(
                    EvidenceOrigin.REFERENCE_URL, osvId + "#reference:" + index, url, digest),
                classes,
                Set.of(scope.packageName())));
      } catch (final IllegalArgumentException ignored) {
        // Invalid reference URLs are omitted instead of being attached as provenance.
      }
    }
  }

  private static void addCveTextEvidence(
      final JsonNode root,
      final List<AdvisoryScope> scopes,
      final String cveId,
      final String digest,
      final List<io.github.spockz.elider.model.AdvisoryEvidence> evidence) {
    final JsonNode cna = root.path(CONTAINERS_FIELD).path("cna");
    final JsonNode descriptions = cna.path("descriptions");
    if (descriptions.isArray()) {
      for (int index = 0; index < descriptions.size(); index++) {
        final String text = descriptions.get(index).path("value").asText("");
        addCveCandidateText(text, cveId + "#description:" + index, null, scopes, digest, evidence);
      }
    }
    final JsonNode references = cna.path("references");
    if (references.isArray()) {
      for (int index = 0; index < references.size(); index++) {
        final String value = references.get(index).path("url").asText("");
        try {
          final URI url = URI.create(value);
          if (url.isAbsolute()
              && ("http".equalsIgnoreCase(url.getScheme())
                  || "https".equalsIgnoreCase(url.getScheme()))) {
            addCveCandidateText("", cveId + "#reference:" + index, url, scopes, digest, evidence);
          }
        } catch (final IllegalArgumentException ignored) {
          // Invalid reference URLs are not evidence provenance.
        }
      }
    }
  }

  private static void addCveCandidateText(
      final String text,
      final String sourceId,
      final URI sourceUrl,
      final List<AdvisoryScope> scopes,
      final String digest,
      final List<io.github.spockz.elider.model.AdvisoryEvidence> evidence) {
    for (final AdvisoryScope scope : scopes) {
      final Set<String> classes = new TreeSet<>();
      extractClassesFromText(
          text,
          scope.affectedCoordinate().groupId(),
          scope.affectedCoordinate().artifactId(),
          classes);
      if (sourceUrl != null) {
        extractClassesFromCommitUrl(
            sourceUrl.toString(),
            scope.affectedCoordinate().groupId(),
            scope.affectedCoordinate().artifactId(),
            classes);
      }
      evidence.add(
          new HeuristicCandidateEvidence(
              scope,
              new AdvisoryProvenance(
                  sourceUrl == null ? EvidenceOrigin.DESCRIPTION : EvidenceOrigin.REFERENCE_URL,
                  sourceId,
                  sourceUrl,
                  digest),
              classes,
              Set.of(scope.packageName())));
    }
  }

  private static CveAffectedEntryContext readCnaContext(
      final JsonNode entry, final int index, final CveSourceRecordMetadata sourceRecord) {
    final String product = entry.path("product").textValue();
    final List<CveVersionClaim> versions = new ArrayList<>();
    final JsonNode versionsNode = entry.path(VERSIONS_FIELD);
    if (versionsNode.isArray()) {
      for (final JsonNode version : versionsNode) {
        final String value = version.path("version").asText("");
        final String status = version.path("status").asText("");
        final String versionType = version.path("versionType").asText(null);
        if (!value.isBlank() && !status.isBlank()) {
          versions.add(
              new CveVersionClaim(
                  value,
                  status,
                  versionType,
                  optionalText(version, "lessThan"),
                  optionalText(version, "lessThanOrEqual"),
                  readVersionChanges(version.path("changes"))));
        }
      }
    }
    return new CveAffectedEntryContext(
        "containers.cna.affected[" + index + "]",
        sourceRecord,
        entry.path("vendor").asText(null),
        product,
        entry.path("packageURL").asText(null),
        entry.path("collectionURL").asText(null),
        entry.path("packageName").asText(null),
        optionalText(entry, "defaultStatus"),
        versions,
        readTextArray(entry.path("programFiles")),
        readRoutineNames(entry.path("programRoutines")));
  }

  private static void validateCveSourceShape(final JsonNode root) {
    final JsonNode containers = optionalObject(root, CONTAINERS_FIELD, CONTAINERS_FIELD);
    if (containers == null) {
      return;
    }
    final JsonNode cna = optionalObject(containers, "cna", "containers.cna");
    if (cna == null) {
      return;
    }
    final JsonNode affected = optionalArray(cna, "affected", "containers.cna.affected");
    if (affected == null) {
      return;
    }
    for (int index = 0; index < affected.size(); index++) {
      validateCnaAffectedEntry(affected.get(index), index);
    }
  }

  private static void validateCnaAffectedEntry(final JsonNode entry, final int index) {
    final String context = "containers.cna.affected[" + index + "]";
    if (!entry.isObject()) {
      throw new IllegalArgumentException(context + " must be an object");
    }
    requiredCnaText(entry, "product", context);
    for (final String field :
        List.of("vendor", "packageURL", "collectionURL", "packageName", "defaultStatus")) {
      optionalCnaText(entry, field, context);
    }
    final JsonNode versions = optionalArray(entry, VERSIONS_FIELD, context + ".versions");
    if (versions != null) {
      for (int versionIndex = 0; versionIndex < versions.size(); versionIndex++) {
        validateCnaVersion(versions.get(versionIndex), context + ".versions[" + versionIndex + "]");
      }
    }
    validateCnaStringArray(entry, "programFiles", context);
    validateCnaRoutines(entry, context);
  }

  private static void validateCnaVersion(final JsonNode version, final String context) {
    if (!version.isObject()) {
      throw new IllegalArgumentException(context + " must be an object");
    }
    requiredCnaText(version, "version", context);
    requiredCnaText(version, "status", context);
    for (final String field : List.of("versionType", "lessThan", "lessThanOrEqual")) {
      optionalCnaText(version, field, context);
    }
    final JsonNode changes = optionalArray(version, "changes", context + ".changes");
    if (changes == null) {
      return;
    }
    for (int changeIndex = 0; changeIndex < changes.size(); changeIndex++) {
      final JsonNode change = changes.get(changeIndex);
      if (!change.isObject()) {
        throw new IllegalArgumentException(context + ".changes entries must be objects");
      }
      change
          .fields()
          .forEachRemaining(
              field -> {
                if (!field.getValue().isTextual()) {
                  throw new IllegalArgumentException(context + ".changes values must be strings");
                }
              });
    }
  }

  private static void validateCnaStringArray(
      final JsonNode entry, final String field, final String context) {
    final JsonNode values = optionalArray(entry, field, context + "." + field);
    if (values == null) {
      return;
    }
    for (final JsonNode value : values) {
      if (!value.isTextual() || value.textValue().isBlank()) {
        throw new IllegalArgumentException(context + "." + field + " must contain strings");
      }
    }
  }

  private static void validateCnaRoutines(final JsonNode entry, final String context) {
    final JsonNode routines = optionalArray(entry, "programRoutines", context + ".programRoutines");
    if (routines == null) {
      return;
    }
    for (final JsonNode routine : routines) {
      if (routine.isTextual()) {
        if (routine.textValue().isBlank()) {
          throw new IllegalArgumentException(context + ".programRoutines must contain names");
        }
      } else if (routine.isObject()) {
        requiredCnaText(routine, NAME_FIELD, context + ".programRoutines entry");
      } else {
        throw new IllegalArgumentException(context + ".programRoutines entries must be names");
      }
    }
  }

  private static JsonNode optionalObject(
      final JsonNode parent, final String field, final String context) {
    final JsonNode value = parent.get(field);
    if (value == null) {
      return null;
    }
    if (!value.isObject()) {
      throw new IllegalArgumentException(context + " must be an object");
    }
    return value;
  }

  private static JsonNode optionalArray(
      final JsonNode parent, final String field, final String context) {
    final JsonNode value = parent.get(field);
    if (value == null) {
      return null;
    }
    if (!value.isArray()) {
      throw new IllegalArgumentException(context + " must be an array");
    }
    return value;
  }

  private static void requiredCnaText(
      final JsonNode parent, final String field, final String context) {
    final JsonNode value = parent.get(field);
    if (value == null || !value.isTextual() || value.textValue().isBlank()) {
      throw new IllegalArgumentException(context + "." + field + " must be a non-blank string");
    }
  }

  private static void optionalCnaText(
      final JsonNode parent, final String field, final String context) {
    final JsonNode value = parent.get(field);
    if (value != null && !value.isNull() && !value.isTextual()) {
      throw new IllegalArgumentException(context + "." + field + " must be a string or null");
    }
  }

  private static boolean matchesCnaProduct(
      final CveAffectedEntryContext entry, final AdvisoryScope scope) {
    return MavenPackageIdentity.matchesCnaScope(entry, scope.affectedCoordinate());
  }

  private static CveSourceRecordMetadata readCveSourceMetadata(
      final JsonNode root, final String sourceRecordSha256) {
    final JsonNode metadata = root.get("cveMetadata");
    if (metadata == null) {
      return new CveSourceRecordMetadata(
          false, false, false, null, false, null, sourceRecordSha256);
    }
    if (!metadata.isObject()) {
      if (!metadata.isNull()) {
        return new CveSourceRecordMetadata(
            true, false, false, null, false, null, sourceRecordSha256);
      }
      return new CveSourceRecordMetadata(true, false, false, null, false, null, sourceRecordSha256);
    }
    final JsonNode cveIdNode = metadata.get("cveId");
    final JsonNode stateNode = metadata.get("state");
    if (isInvalidNullableSourceText(cveIdNode) || isInvalidNullableSourceText(stateNode)) {
      throw new IllegalArgumentException("cveMetadata.cveId and state must be text or null");
    }
    return new CveSourceRecordMetadata(
        true,
        true,
        cveIdNode != null,
        cveIdNode == null || cveIdNode.isNull() ? null : cveIdNode.textValue(),
        stateNode != null,
        stateNode == null || stateNode.isNull() ? null : stateNode.textValue(),
        sourceRecordSha256);
  }

  private static boolean isInvalidNullableSourceText(final JsonNode value) {
    return value != null && !value.isNull() && !value.isTextual();
  }

  private static void addStructuredEvidence(
      final JsonNode entry,
      final String entryIdentity,
      final AdvisoryScope scope,
      final String cveId,
      final String cveDigest,
      final List<io.github.spockz.elider.model.AdvisoryEvidence> evidence) {
    final Set<String> files = readTextArray(entry.path("programFiles"));
    final Set<String> routines = readRoutineNames(entry.path("programRoutines"));
    if (files.isEmpty() && routines.isEmpty()) {
      return;
    }
    final Map<String, Set<String>> fileClasses = new LinkedHashMap<>();
    for (final String file : files) {
      fileClasses.put(file, classesForProgramFile(file, scope));
    }
    final Map<String, Set<String>> routineClasses = new LinkedHashMap<>();
    routines.forEach(routine -> routineClasses.put(routine, Set.of()));
    final String product = entry.path("product").asText("unknown");
    evidence.add(
        new StructuredSourceClassEvidence(
            scope,
            new AdvisoryProvenance(EvidenceOrigin.CVE_LIST, cveId, null, cveDigest),
            entryIdentity,
            entry.path("vendor").asText("") + ":" + product,
            files,
            routines,
            fileClasses,
            routineClasses));
  }

  private static Set<String> classesForProgramFile(final String file, final AdvisoryScope scope) {
    final Set<String> classes = new TreeSet<>();
    extractClassesFromCommitUrl(
        file,
        scope.affectedCoordinate().groupId(),
        scope.affectedCoordinate().artifactId(),
        classes);
    return Set.copyOf(classes);
  }

  private static Set<String> readTextArray(final JsonNode node) {
    if (!node.isArray()) {
      return Set.of();
    }
    final Set<String> values = new TreeSet<>();
    node.forEach(
        value -> {
          if (value.isTextual() && !value.textValue().isBlank()) {
            values.add(value.textValue());
          }
        });
    return Set.copyOf(values);
  }

  private static Set<String> readRoutineNames(final JsonNode node) {
    if (!node.isArray()) {
      return Set.of();
    }
    final Set<String> values = new TreeSet<>();
    for (final JsonNode value : node) {
      final JsonNode name = value.isObject() ? value.path(NAME_FIELD) : value;
      if (name.isTextual() && !name.textValue().isBlank()) {
        values.add(name.textValue());
      }
    }
    return Set.copyOf(values);
  }

  private static List<Map<String, String>> readVersionChanges(final JsonNode node) {
    if (!node.isArray()) {
      return List.of();
    }
    final List<Map<String, String>> changes = new ArrayList<>();
    for (final JsonNode change : node) {
      if (!change.isObject()) {
        continue;
      }
      final Map<String, String> fields = new LinkedHashMap<>();
      change
          .fields()
          .forEachRemaining(
              field -> {
                if (field.getValue().isTextual()) {
                  fields.put(field.getKey(), field.getValue().textValue());
                }
              });
      if (!fields.isEmpty()) {
        changes.add(fields);
      }
    }
    return List.copyOf(changes);
  }

  private static String optionalText(final JsonNode node, final String field) {
    final JsonNode value = node.get(field);
    return value != null && value.isTextual() ? value.textValue() : null;
  }

  private static String locateCveRecord(final Path gitDir, final String cveId) {
    if (gitDir == null || cveId == null || !Files.isDirectory(gitDir)) {
      return null;
    }
    final String[] parts = cveId.split("-");
    if (parts.length < 3) {
      return null;
    }
    final String thousandPrefix =
        parts[2].length() > 3 ? parts[2].substring(0, parts[2].length() - 3) + "xxx" : "0xxx";
    final Path path =
        gitDir.resolve("cves").resolve(parts[1]).resolve(thousandPrefix).resolve(cveId + ".json");
    return Files.isRegularFile(path) ? path.toString() : null;
  }

  private static String sha256(final byte[] bytes) {
    try {
      final byte[] digest = MessageDigest.getInstance("SHA-256").digest(bytes);
      final StringBuilder result = new StringBuilder(digest.length * 2);
      for (final byte value : digest) {
        result.append(String.format(Locale.ROOT, "%02x", value));
      }
      return result.toString();
    } catch (final NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is unavailable", exception);
    }
  }

  private static boolean isMavenEcosystem(final String ecosystem) {
    return "Maven".equalsIgnoreCase(ecosystem)
        || ecosystem.toLowerCase(Locale.ROOT).startsWith("maven:");
  }

  private static String resolveCveId(final JsonNode root) {
    final String id = root.path("id").asText("");
    if (CVE_PATTERN.matcher(id).matches()) {
      return id;
    }
    final JsonNode aliases = root.path("aliases");
    if (aliases.isArray()) {
      for (final JsonNode alias : aliases) {
        final String text = alias.asText("");
        if (CVE_PATTERN.matcher(text).matches()) {
          return text;
        }
      }
    }
    return null;
  }

  private static String resolveVersionRange(final JsonNode affected) {
    final JsonNode ranges = affected.path("ranges");
    if (ranges.isArray()) {
      for (final JsonNode range : ranges) {
        if ("ECOSYSTEM".equalsIgnoreCase(range.path("type").asText(""))) {
          final String spec = rangeFromEvents(range.path("events"));
          if (spec != null) {
            return spec;
          }
        }
      }
    }
    final JsonNode versions = affected.path(VERSIONS_FIELD);
    if (versions.isArray() && !versions.isEmpty()) {
      if (versions.size() == 1) {
        return "[" + versions.get(0).asText() + "]";
      }
      return "["
          + versions.get(0).asText()
          + ","
          + versions.get(versions.size() - 1).asText()
          + "]";
    }
    return null;
  }

  private static String rangeFromEvents(final JsonNode events) {
    if (!events.isArray()) {
      return null;
    }
    String introduced = null;
    String fixed = null;
    String lastAffected = null;
    for (final JsonNode event : events) {
      if (event.hasNonNull("introduced")) {
        introduced = event.path("introduced").asText();
      }
      if (event.hasNonNull("fixed")) {
        fixed = event.path("fixed").asText();
      }
      if (event.hasNonNull("last_affected")) {
        lastAffected = event.path("last_affected").asText();
      }
    }
    if (fixed != null) {
      if (introduced == null || "0".equals(introduced)) {
        return "(," + fixed + ")";
      }
      return "[" + introduced + "," + fixed + ")";
    }
    if (lastAffected != null) {
      if (introduced == null || "0".equals(introduced)) {
        return "(," + lastAffected + "]";
      }
      return "[" + introduced + "," + lastAffected + "]";
    }
    if (introduced != null && !"0".equals(introduced)) {
      return "[" + introduced + ",)";
    }
    return null;
  }

  private static void extractClassesFromText(
      final String text, final String groupId, final String artifactId, final Set<String> classes) {
    final Matcher matcher = FQCN_PATTERN.matcher(text);
    while (matcher.find()) {
      final String candidate = matcher.group(1);
      if (isRelevantClass(candidate, groupId, artifactId)) {
        classes.add(candidate);
      }
    }
  }

  private static void extractClassesFromCommitUrl(
      final String url, final String groupId, final String artifactId, final Set<String> classes) {
    final Matcher matcher = COMMIT_PATH_PATTERN.matcher(url);
    while (matcher.find()) {
      final String path = matcher.group(1);
      final String candidate = path.replace('/', '.');
      if (isRelevantClass(candidate, groupId, artifactId)) {
        classes.add(candidate);
      }
    }
  }

  private static boolean isRelevantClass(
      final String className, final String groupId, final String artifactId) {
    if (className == null
        || className.indexOf('$') >= 0
        || !STRICT_FQCN.matcher(className).matches()
        || className.endsWith(".Test")
        || className.endsWith(".Tests")) {
      return false;
    }
    final String[] groupSegments = groupId.split("\\.");
    if (groupSegments.length >= 2) {
      final String rootGroup = groupSegments[0] + "." + groupSegments[1];
      if (className.startsWith(rootGroup)) {
        return true;
      }
    }
    final String cleanedArtifact = artifactId.replaceAll("[^a-zA-Z0-9]", ".");
    return className.startsWith(cleanedArtifact) || className.startsWith(groupId);
  }
}
