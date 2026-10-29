/* WHY: Indexes OSV Maven advisories and extracts verified class symbols. */

package io.github.spockz.elider.scanner;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.VulnerabilitySymbolMapping;
import io.github.spockz.elider.model.VulnerabilitySymbolMapping.ConfidenceLevel;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/** Indexes OSV Maven advisories and correlates class symbols. */
@SuppressWarnings({
  "PMD.TooManyMethods",
  "PMD.CyclomaticComplexity",
  "PMD.GodClass",
  "PMD.CognitiveComplexity",
  "PMD.AvoidLiteralsInIfCondition",
  "PMD.AvoidDeeplyNestedIfStmts",
  "PMD.AssignmentInOperand",
  "PMD.ShortVariable",
  "PMD.CommentRequired",
  "PMD.AvoidDuplicateLiterals",
  "PMD.NPathComplexity",
  "PMD.CommentSize",
  "PMD.AvoidInstantiatingObjectsInLoops"
})
public final class OsvSnapshotIndexer {
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
   * Reads an OSV advisory ZIP stream and builds vulnerability mappings.
   *
   * @param zipStream the raw input stream of all.zip
   * @param cveListGitDir optional local checkout of CVEList v5 (nullable)
   * @return list of extracted vulnerability mappings with proven class symbols
   * @throws IOException if reading the zip stream fails
   */
  public List<VulnerabilitySymbolMapping> indexZip(
      final InputStream zipStream, final Path cveListGitDir) throws IOException {
    Objects.requireNonNull(zipStream, "zipStream");
    final List<VulnerabilitySymbolMapping> mappings = new ArrayList<>();
    final Set<String> seen = new LinkedHashSet<>();
    try (ZipInputStream zis = new ZipInputStream(zipStream)) {
      ZipEntry entry;
      while ((entry = zis.getNextEntry()) != null) {
        if (!entry.isDirectory() && entry.getName().toLowerCase(Locale.ROOT).endsWith(".json")) {
          final byte[] bytes = zis.readAllBytes();
          final JsonNode root = mapper.readTree(bytes);
          for (final VulnerabilitySymbolMapping mapping : parseAdvisories(root, cveListGitDir)) {
            final String key = mapping.cveId() + "\u0000" + mapping.affectedCoordinate().toId();
            if (seen.add(key)) {
              mappings.add(mapping);
            }
          }
        }
        zis.closeEntry();
      }
    }
    return Collections.unmodifiableList(mappings);
  }

  /** Parses all applicable Maven mappings for a single OSV advisory JSON record. */
  public List<VulnerabilitySymbolMapping> parseAdvisories(
      final JsonNode root, final Path cveListGitDir) {
    if (root == null || !root.isObject() || root.hasNonNull("withdrawn")) {
      return List.of();
    }
    final String cveId = resolveCveId(root);
    if (cveId == null) {
      return List.of();
    }
    final JsonNode affectedArray = root.path("affected");
    if (!affectedArray.isArray()) {
      return List.of();
    }
    final List<VulnerabilitySymbolMapping> result = new ArrayList<>();
    for (final JsonNode affected : affectedArray) {
      parseAffectedItem(root, affected, cveId, cveListGitDir).ifPresent(result::add);
    }
    return result;
  }

  private Optional<VulnerabilitySymbolMapping> parseAffectedItem(
      final JsonNode root, final JsonNode affected, final String cveId, final Path cveListGitDir) {
    final JsonNode pkg = affected.path("package");
    final String ecosystem = pkg.path("ecosystem").asText("");
    if (!isMavenEcosystem(ecosystem)) {
      return Optional.empty();
    }
    final String name = pkg.path("name").asText("");
    final int colon = name.indexOf(':');
    if (colon <= 0 || colon == name.length() - 1) {
      return Optional.empty();
    }
    final String groupId = name.substring(0, colon);
    final String artifactId = name.substring(colon + 1);
    final String versionRangeSpec = resolveVersionRange(affected);
    if (versionRangeSpec == null) {
      return Optional.empty();
    }
    final Set<String> classes =
        extractVulnerableClasses(root, groupId, artifactId, cveId, cveListGitDir);
    if (classes.isEmpty()) {
      return Optional.empty();
    }
    final URI sourceUrl = resolveSourceUrl(root, cveId, groupId, artifactId);
    final ArtifactCoordinate coordinate = ArtifactCoordinate.of(groupId, artifactId, null);
    try {
      return Optional.of(
          new VulnerabilitySymbolMapping(
              cveId, coordinate, versionRangeSpec, classes, sourceUrl, ConfidenceLevel.HIGH));
    } catch (final IllegalArgumentException ignored) {
      return Optional.empty();
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
    final JsonNode versions = affected.path("versions");
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

  private Set<String> extractVulnerableClasses(
      final JsonNode root,
      final String groupId,
      final String artifactId,
      final String cveId,
      final Path cveListGitDir) {
    final Set<String> classes = new TreeSet<>();
    final String text = root.path("summary").asText("") + " " + root.path("details").asText("");
    extractClassesFromText(text, groupId, artifactId, classes);

    final JsonNode references = root.path("references");
    if (references.isArray()) {
      for (final JsonNode ref : references) {
        final String url = ref.path("url").asText("");
        extractClassesFromCommitUrl(url, groupId, artifactId, classes);
      }
    }

    if (cveListGitDir != null && Files.isDirectory(cveListGitDir)) {
      enrichFromCveListV5(cveListGitDir, cveId, groupId, artifactId, classes);
    }
    return classes;
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

  private void enrichFromCveListV5(
      final Path gitDir,
      final String cveId,
      final String groupId,
      final String artifactId,
      final Set<String> classes) {
    final String[] parts = cveId.split("-");
    if (parts.length < 3) {
      return;
    }
    final String year = parts[1];
    final String number = parts[2];
    final String thousandPrefix =
        number.length() > 3 ? number.substring(0, number.length() - 3) + "xxx" : "0xxx";
    final Path recordPath =
        gitDir.resolve("cves").resolve(year).resolve(thousandPrefix).resolve(cveId + ".json");
    if (!Files.isRegularFile(recordPath)) {
      return;
    }
    try {
      final JsonNode cveRoot = mapper.readTree(recordPath.toFile());
      final JsonNode cna = cveRoot.path("containers").path("cna");
      final JsonNode descriptions = cna.path("descriptions");
      if (descriptions.isArray()) {
        for (final JsonNode desc : descriptions) {
          extractClassesFromText(desc.path("value").asText(""), groupId, artifactId, classes);
        }
      }
      final JsonNode affectedArray = cna.path("affected");
      if (affectedArray.isArray()) {
        for (final JsonNode aff : affectedArray) {
          final JsonNode programFiles = aff.path("programFiles");
          if (programFiles.isArray()) {
            for (final JsonNode pf : programFiles) {
              extractClassesFromCommitUrl(pf.asText(""), groupId, artifactId, classes);
            }
          }
        }
      }
    } catch (final IOException ignored) {
      // Best-effort enrichment; parsing failure does not abort indexing.
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

  private static URI resolveSourceUrl(
      final JsonNode root, final String cveId, final String groupId, final String artifactId) {
    final JsonNode references = root.path("references");
    if (references.isArray()) {
      // 1. Prioritize commit diff or pull request URLs that explicitly touch relevant source
      // classes
      for (final JsonNode ref : references) {
        final String url = ref.path("url").asText("");
        if ((url.startsWith("https://") || url.startsWith("http://"))
            && (url.contains("/commit/") || url.contains("/pull/"))) {
          final Set<String> probe = new TreeSet<>();
          extractClassesFromCommitUrl(url, groupId, artifactId, probe);
          if (!probe.isEmpty()) {
            try {
              return URI.create(url);
            } catch (final IllegalArgumentException ignored) {
              // Fall back below
            }
          }
        }
      }
      // 2. Secondary preference: any commit or pull request URL
      for (final JsonNode ref : references) {
        final String url = ref.path("url").asText("");
        if ((url.startsWith("https://") || url.startsWith("http://"))
            && (url.contains("/commit/") || url.contains("/pull/"))) {
          try {
            return URI.create(url);
          } catch (final IllegalArgumentException ignored) {
            // Fall back below
          }
        }
      }
      // 3. Fallback: standard advisory or reference URLs
      for (final JsonNode ref : references) {
        final String url = ref.path("url").asText("");
        if (url.startsWith("https://")
            && (url.contains("nvd.nist.gov") || url.contains("security/advisories"))) {
          try {
            return URI.create(url);
          } catch (final IllegalArgumentException ignored) {
            // Fall back below
          }
        }
      }
      for (final JsonNode ref : references) {
        final String url = ref.path("url").asText("");
        if (url.startsWith("https://") || url.startsWith("http://")) {
          try {
            return URI.create(url);
          } catch (final IllegalArgumentException ignored) {
            // Fall back below
          }
        }
      }
    }
    return URI.create("https://osv.dev/vulnerability/" + root.path("id").asText(cveId));
  }
}
