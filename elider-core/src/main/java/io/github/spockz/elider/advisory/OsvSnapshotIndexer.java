/* WHY: Preserves OSV-owned Maven scopes and separate review-only source evidence. */

package io.github.spockz.elider.advisory;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.spockz.elider.model.AdvisoryProvenance;
import io.github.spockz.elider.model.AdvisoryScope;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.EvidenceOrigin;
import io.github.spockz.elider.model.HeuristicCandidateEvidence;
import io.github.spockz.elider.model.MavenVersionRangeMatcher;
import io.github.spockz.elider.model.OsvAdvisoryRecord;
import io.github.spockz.elider.model.OsvAffectedPackage;
import io.github.spockz.elider.model.OsvAffectedRange;
import io.github.spockz.elider.model.PackageAdvisoryEvidence;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
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
import org.apache.maven.artifact.versioning.ComparableVersion;

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
  "PMD.CommentRequired",
  "PMD.CommentSize",
  "PMD.AvoidInstantiatingObjectsInLoops",
  "PMD.CommentDefaultAccessModifier"
})
public final class OsvSnapshotIndexer {
  private static final String OSV_RECORD = "OSV record";
  private static final String MODIFIED_FIELD = "modified";
  private static final String NAME_FIELD = "name";
  private static final String VERSIONS_FIELD = "versions";
  private static final String WITHDRAWN_FIELD = "withdrawn";
  private static final Pattern RECORD_ID_PATTERN = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]*");
  private static final Pattern CVE_PATTERN = Pattern.compile("^CVE-[0-9]{4}-[0-9]{4,}$");
  private static final Pattern FQCN_PATTERN =
      Pattern.compile("\\b([a-z][a-z0-9_]*(\\.[a-z0-9_]+)+\\.[A-Z][a-zA-Z0-9_]*)\\b");
  private static final Pattern STRICT_FQCN =
      Pattern.compile("^[a-z][a-z0-9_]*(\\.[a-z0-9_]+)*\\.[A-Z][a-zA-Z0-9_]*$");
  private static final Pattern COMMIT_PATH_PATTERN =
      Pattern.compile(
          "(?:src/(?:main|test)/java/)?"
              + "([a-z][a-z0-9_]*(?:/[a-z0-9_]+)+/[A-Z][a-zA-Z0-9_]*)\\.java");

  private static final ObjectMapper DEFAULT_MAPPER = new ObjectMapper();

  private final ObjectMapper mapper;

  /** Creates an indexer using a default Jackson object mapper. */
  public OsvSnapshotIndexer() {
    this(DEFAULT_MAPPER);
  }

  /** Creates an indexer using the supplied Jackson object mapper. */
  public OsvSnapshotIndexer(final ObjectMapper mapper) {
    this.mapper = Objects.requireNonNull(mapper, "mapper");
  }

  /** Indexes independently readable OSV records, retaining diagnostics for skipped entries. */
  @SuppressWarnings("PMD.ExceptionAsFlowControl") // Invalid records are isolated at this boundary.
  public PartialIndex indexZipIsolated(final InputStream zipStream) throws IOException {
    Objects.requireNonNull(zipStream, "zipStream");
    final Map<String, OsvAdvisoryRecord> records = new LinkedHashMap<>();
    final Set<String> seen = new HashSet<>();
    final Set<String> ambiguous = new HashSet<>();
    final Map<String, AcceptedSource> accepted = new java.util.HashMap<>();
    final Map<String, String> withdrawnRevisions = new java.util.HashMap<>();
    final List<String> skipped = new ArrayList<>();
    try (ZipInputStream zip = new ZipInputStream(zipStream)) {
      ZipEntry entry;
      while ((entry = zip.getNextEntry()) != null) {
        if (!entry.isDirectory() && entry.getName().toLowerCase(Locale.ROOT).endsWith(".json")) {
          final byte[] bytes = zip.readAllBytes();
          final String locator = entry.getName();
          String recordId = null;
          String sourceDigest = null;
          try {
            final JsonNode root = readSingleJsonDocument(bytes, OSV_RECORD);
            if (!root.isObject()
                || !root.path("id").isTextual()
                || root.path("id").textValue().isBlank()) {
              throw new IllegalArgumentException("OSV record has no valid ID");
            }
            recordId = root.path("id").textValue();
            if (!RECORD_ID_PATTERN.matcher(recordId).matches()) {
              throw new IllegalArgumentException("OSV record ID has invalid characters");
            }
            if (!seen.add(recordId)) {
              records.remove(recordId);
              withdrawnRevisions.remove(recordId);
              final AcceptedSource original = accepted.remove(recordId);
              if (original != null) {
                skipped.add(
                    formatSkippedRecord(
                        original.locator(),
                        original.sha256(),
                        "Duplicate OSV record ID: " + recordId));
              }
              ambiguous.add(recordId);
              throw new IllegalArgumentException("Duplicate OSV record ID: " + recordId);
            }
            sourceDigest = sha256(bytes);
            final OsvAdvisoryRecord record = parseAdvisory(root, sourceDigest, skipped, locator);
            if (record != null && !ambiguous.contains(recordId)) {
              records.put(recordId, record);
            }
            if (record == null) {
              withdrawnRevisions.put(recordId, root.path(MODIFIED_FIELD).textValue());
            }
            accepted.put(recordId, new AcceptedSource(locator, sourceDigest));
          } catch (final IOException | IllegalArgumentException failure) {
            if (recordId != null) {
              records.remove(recordId);
              withdrawnRevisions.remove(recordId);
              ambiguous.add(recordId);
            }
            final String digest = sourceDigest != null ? sourceDigest : sha256(bytes);
            skipped.add(formatSkippedRecord(locator, digest, failure.getMessage()));
          }
        }
        zip.closeEntry();
      }
    }
    return new PartialIndex(
        List.copyOf(records.values()),
        List.copyOf(skipped),
        skipped.size(),
        ambiguous,
        withdrawnRevisions);
  }

  /** Stable diagnostic includes the skipped bytes so repairs change source identity. */
  static String skippedRecord(final String locator, final byte[] bytes, final String reason)
      throws IOException {
    return formatSkippedRecord(locator, sha256(bytes), reason);
  }

  private static String formatSkippedRecord(
      final String locator, final String digest, final String reason) {
    return locator + " sha256=" + digest + ": " + Objects.toString(reason, "invalid OSV record");
  }

  private record AcceptedSource(String locator, String sha256) {}

  /** Valid records and malformed record diagnostics from one source observation. */
  public record PartialIndex(
      List<OsvAdvisoryRecord> records,
      List<String> skippedRows,
      int skippedCount,
      Set<String> quarantinedIds,
      Map<String, String> withdrawnRevisions) {
    /** Creates a result with one diagnostic per skipped row. */
    public PartialIndex(final List<OsvAdvisoryRecord> records, final List<String> skippedRows) {
      this(records, skippedRows, skippedRows.size(), Set.of(), Map.of());
    }

    /** Freezes result data and validates the skipped count. */
    public PartialIndex {
      records = List.copyOf(records);
      quarantinedIds = Set.copyOf(quarantinedIds);
      withdrawnRevisions = Map.copyOf(withdrawnRevisions);
      skippedRows = List.copyOf(boundSkippedRows(skippedRows));
      if (skippedCount < skippedRows.size() || skippedCount < 0) {
        throw new IllegalArgumentException("Invalid skipped record count");
      }
    }
  }

  static List<String> boundSkippedRows(final List<String> rows) {
    final int limit = 128;
    if (rows.size() <= limit) {
      return List.copyOf(rows);
    }
    final List<String> bounded = new ArrayList<>(rows.subList(0, limit - 1));
    final String overflow = String.join("\n", rows.subList(limit - 1, rows.size()));
    bounded.add(
        "Additional skipped OSV records; sha256="
            + sha256(overflow.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
    return List.copyOf(bounded);
  }

  /** Strictly indexes one fetched OSV record; an empty result denotes an explicit withdrawal. */
  public IndexedOsvRecord indexRecord(final byte[] bytes, final String expectedId)
      throws IOException {
    final JsonNode root = readSingleJsonDocument(bytes, OSV_RECORD);
    if (!root.isObject()) {
      throw new IOException("OSV record must be a JSON object");
    }
    final JsonNode idNode = root.get("id");
    if (idNode == null || !idNode.isTextual() || !expectedId.equals(idNode.textValue())) {
      throw new IOException("Fetched OSV record ID does not match modified index");
    }
    try {
      final String modified = requiredSourceText(root, MODIFIED_FIELD);
      final OsvAdvisoryRecord record = parseAdvisory(root, sha256(bytes), null, null);
      return new IndexedOsvRecord(expectedId, modified, Optional.ofNullable(record));
    } catch (final IllegalArgumentException exception) {
      throw new IOException("Invalid OSV record " + root.path("id").asText(""), exception);
    }
  }

  /** Parses a changed owner while isolating malformed affected entries. */
  PartialRecord indexRecordIsolated(final byte[] bytes, final String expectedId)
      throws IOException {
    final JsonNode root = readSingleJsonDocument(bytes, OSV_RECORD);
    if (!root.isObject()
        || !root.path("id").isTextual()
        || !expectedId.equals(root.path("id").textValue())) {
      throw new IOException("Fetched OSV record ID does not match modified index");
    }
    final List<String> skipped = new ArrayList<>();
    try {
      final String modified = requiredSourceText(root, MODIFIED_FIELD);
      final OsvAdvisoryRecord record = parseAdvisory(root, sha256(bytes), skipped, expectedId);
      return new PartialRecord(
          new IndexedOsvRecord(expectedId, modified, Optional.ofNullable(record)), skipped);
    } catch (final IllegalArgumentException exception) {
      throw new IOException("Invalid OSV record " + expectedId, exception);
    }
  }

  record PartialRecord(IndexedOsvRecord record, List<String> skippedRows) {
    PartialRecord {
      skippedRows = List.copyOf(skippedRows);
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

  private OsvAdvisoryRecord parseAdvisory(
      final JsonNode root,
      final String osvDigest,
      final List<String> skipped,
      final String locator) {
    if (root == null || !root.isObject()) {
      throw new IllegalArgumentException("OSV record must be a JSON object");
    }
    final JsonNode idNode = root.get("id");
    if (idNode == null || !idNode.isTextual() || idNode.textValue().isBlank()) {
      throw new IllegalArgumentException("OSV record ID must be a non-blank string");
    }
    final String osvId = idNode.textValue();
    final String modified = requiredSourceText(root, MODIFIED_FIELD);
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
    final List<OsvAffectedPackage> affectedPackages = new ArrayList<>();
    final List<io.github.spockz.elider.model.AdvisoryEvidence> evidence = new ArrayList<>();
    readAffectedEntries(
        root, cveId, osvId, osvDigest, affectedPackages, evidence, skipped, locator);
    return new OsvAdvisoryRecord(osvId, modified, aliases, affectedPackages, evidence);
  }

  private static List<AdvisoryScope> readAffectedEntries(
      final JsonNode root,
      final String cveId,
      final String osvId,
      final String digest,
      final List<OsvAffectedPackage> affectedPackages,
      final List<io.github.spockz.elider.model.AdvisoryEvidence> evidence,
      final List<String> skipped,
      final String locator) {
    final JsonNode affectedArray = root.get("affected");
    if (affectedArray == null || !affectedArray.isArray()) {
      throw new IllegalArgumentException("affected must be an array");
    }
    final List<AdvisoryScope> scopes = new ArrayList<>();
    for (int index = 0; index < affectedArray.size(); index++) {
      final JsonNode affected = affectedArray.get(index);
      final List<io.github.spockz.elider.model.AdvisoryEvidence> stagedEvidence = new ArrayList<>();
      try {
        final OsvAffectedPackage affectedPackage = readAffectedPackage(affected);
        final AdvisoryScope scope = cveId == null ? null : readOsvScope(affected, cveId);
        if (scope != null) {
          stagedEvidence.add(
              new PackageAdvisoryEvidence(
                  scope, new AdvisoryProvenance(EvidenceOrigin.OSV, osvId, null, digest)));
          addTextEvidence(root, scope, osvId, digest, stagedEvidence);
          addReferenceEvidence(root.path("references"), scope, osvId, digest, stagedEvidence);
        }
        if (affectedPackage != null) {
          affectedPackages.add(affectedPackage);
        }
        if (scope != null) {
          scopes.add(scope);
        }
        evidence.addAll(stagedEvidence);
      } catch (final IllegalArgumentException failure) {
        if (skipped == null) {
          throw failure;
        }
        skipped.add(
            locator + "#affected[" + index + "] sha256=" + digest + ": " + failure.getMessage());
      }
    }
    return scopes;
  }

  /** Shares strict JSON parsing with the live CVE source reader. */
  JsonNode readSingleJsonDocument(final byte[] bytes, final String description) throws IOException {
    return FindingJsonFields.readSingleJsonDocument(mapper, bytes, description);
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
    try {
      MavenVersionRangeMatcher.validate(versionRangeSpec);
    } catch (final IllegalArgumentException ignored) {
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

  private static String sha256(final byte[] bytes) {
    return io.github.spockz.elider.model.ArtifactDigests.sha256Hex(bytes);
  }

  private static boolean isMavenEcosystem(final String ecosystem) {
    return ecosystem != null
        && ("maven".equalsIgnoreCase(ecosystem)
            || ecosystem.toLowerCase(Locale.ROOT).startsWith("maven:"));
  }

  private static String resolveCveId(final JsonNode root) {
    final String recordId = root.path("id").asText("");
    if (CVE_PATTERN.matcher(recordId).matches()) {
      return recordId;
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
      final List<String> sortedVersions = new ArrayList<>();
      for (final JsonNode v : versions) {
        if (v.isTextual() && !v.textValue().isBlank()) {
          sortedVersions.add(v.textValue());
        }
      }
      if (!sortedVersions.isEmpty()) {
        sortedVersions.sort(
            (v1, v2) -> new ComparableVersion(v1).compareTo(new ComparableVersion(v2)));
        if (sortedVersions.size() == 1) {
          return "[" + sortedVersions.getFirst() + "]";
        }
        return "[" + sortedVersions.getFirst() + "," + sortedVersions.getLast() + "]";
      }
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
