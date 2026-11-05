/* WHY: Reconciles current CVE List assertions once per checkout scan, independently of OSV. */

package io.github.spockz.elider.scanner;

import io.github.spockz.elider.model.VulnerabilityFindingContribution;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/** Builds one generic finding snapshot from the current CVE List v5 checkout. */
@SuppressWarnings("PMD.TooManyMethods") // Canonical path checks remain local to indexing.
public final class CveListFindingIndexer {
  /** Accepted CVE identifiers for canonical source-record paths. */
  private static final Pattern CVE_ID = Pattern.compile("CVE-[0-9]{4}-[0-9]{4,}");

  /** CVE lifecycle state whose affected entries can be indexed. */
  private static final String PUBLISHED_STATE = "PUBLISHED";

  /** Adapter that converts one parsed CVE record into generic contributions. */
  private final CveVulnerabilityFindingAdapter adapter;

  /** Creates an indexer using the production CVE source adapter. */
  public CveListFindingIndexer() {
    this(new CveVulnerabilityFindingAdapter());
  }

  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  CveListFindingIndexer(final CveVulnerabilityFindingAdapter adapter) {
    this.adapter = Objects.requireNonNull(adapter, "adapter");
  }

  /** Scans and indexes every JSON record in the checkout's CVE directory. */
  public IndexResult index(final Path checkoutRoot) throws IOException {
    Objects.requireNonNull(checkoutRoot, "checkoutRoot");
    final Path cvesRoot = checkoutRoot.resolve("cves");
    if (!Files.isDirectory(cvesRoot)) {
      throw new IOException("CVE List checkout has no cves directory: " + checkoutRoot);
    }
    final List<Path> records;
    try (Stream<Path> paths = Files.walk(cvesRoot)) {
      records =
          paths
              .filter(Files::isRegularFile)
              .filter(CveListFindingIndexer::isJson)
              .sorted()
              .toList();
    }
    return indexPaths(checkoutRoot, records.stream().map(checkoutRoot::relativize).toList());
  }

  /** Indexes only the selected canonical CVE record paths from one Git observation. */
  public IndexResult indexPaths(final Path checkoutRoot, final Collection<Path> relativePaths)
      throws IOException {
    Objects.requireNonNull(checkoutRoot, "checkoutRoot");
    Objects.requireNonNull(relativePaths, "relativePaths");
    final Path root = checkoutRoot.toAbsolutePath().normalize();
    if (!Files.isDirectory(root.resolve("cves"))) {
      throw new IOException("CVE List checkout has no cves directory: " + checkoutRoot);
    }
    final List<Path> orderedPaths = relativePaths.stream().map(Path::normalize).sorted().toList();
    final List<VulnerabilityFindingContribution> contributions = new ArrayList<>();
    int unsupportedMavenIdentityCount = 0;
    final MessageDigest revision = sha256();
    for (final Path relativePath : orderedPaths) {
      final Path recordPath = canonicalRecordPath(root, relativePath);
      final String fileName = relativePath.getName(3).toString();
      final String cveId = fileName.substring(0, fileName.length() - ".json".length());
      final CveSourceRecordReader.ObservedSource source;
      try {
        source = CveSourceRecordReader.read(checkoutRoot, cveId);
      } catch (final IOException failure) {
        throw new IOException("Could not index current CVE source record " + cveId, failure);
      }
      final List<VulnerabilityFindingContribution> recordContributions =
          adapter.contributions(source);
      contributions.addAll(recordContributions);
      if (PUBLISHED_STATE.equals(source.metadata().state())) {
        unsupportedMavenIdentityCount +=
            Math.max(0, source.affectedEntries().size() - recordContributions.size());
      }
      revision.update(
          root.relativize(recordPath)
              .toString()
              .replace('\\', '/')
              .getBytes(StandardCharsets.UTF_8));
      revision.update((byte) 0);
      revision.update(source.sourceRecordSha256().getBytes(StandardCharsets.US_ASCII));
      revision.update((byte) '\n');
    }
    final List<String> diagnostics =
        unsupportedMavenIdentityCount == 0
            ? List.of()
            : List.of(
                unsupportedMavenIdentityCount
                    + " published affected entries lacked a supported Maven package identity");
    return new IndexResult(
        contributions,
        HexFormat.of().formatHex(revision.digest()),
        orderedPaths.size(),
        diagnostics);
  }

  private static Path canonicalRecordPath(final Path checkoutRoot, final Path relativePath)
      throws IOException {
    canonicalCveId(relativePath);
    final Path path = checkoutRoot.resolve(relativePath).normalize();
    if (!path.startsWith(checkoutRoot) || !Files.isRegularFile(path)) {
      throw new IOException("Changed CVE source record is unavailable: " + relativePath);
    }
    return path;
  }

  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  static String canonicalCveId(final Path relativePath) throws IOException {
    if (!hasCanonicalRecordShape(relativePath)) {
      throw new IOException(
          "CVE change path is not a canonical CVE source record: " + relativePath);
    }
    final String cveId = cveIdFromFilename(relativePath);
    if (!CVE_ID.matcher(cveId).matches() || !hasMatchingYear(relativePath, cveId)) {
      throw new IOException(
          "CVE source record path has a mismatched year or filename: " + relativePath);
    }
    if (!hasMatchingSequenceGroup(relativePath, cveId)) {
      throw new IOException(
          "CVE source record path has a noncanonical sequence group: " + relativePath);
    }
    return cveId;
  }

  private static boolean hasCanonicalRecordShape(final Path relativePath) {
    return !relativePath.isAbsolute()
        && relativePath.getNameCount() == 4
        && "cves".equals(relativePath.getName(0).toString());
  }

  private static String cveIdFromFilename(final Path relativePath) {
    final String filename = relativePath.getName(3).toString();
    return filename.endsWith(".json") ? filename.substring(0, filename.length() - 5) : "";
  }

  private static boolean hasMatchingSequenceGroup(final Path relativePath, final String cveId) {
    return relativePath.getName(2).toString().equals(expectedSequenceGroup(cveId));
  }

  private static boolean hasMatchingYear(final Path relativePath, final String cveId) {
    return relativePath.getName(1).toString().equals(cveId.substring(4, 8));
  }

  private static String expectedSequenceGroup(final String cveId) {
    final String sequence = cveId.substring(cveId.lastIndexOf('-') + 1);
    return sequence.substring(0, sequence.length() - 3) + "xxx";
  }

  private static boolean isJson(final Path path) {
    final Path name = path.getFileName();
    return name != null && name.toString().toLowerCase(java.util.Locale.ROOT).endsWith(".json");
  }

  private static MessageDigest sha256() throws IOException {
    try {
      return MessageDigest.getInstance("SHA-256");
    } catch (final NoSuchAlgorithmException exception) {
      throw new IOException("SHA-256 is unavailable", exception);
    }
  }

  /** Contribution snapshot and source observation metadata for one index operation. */
  public record IndexResult(
      List<VulnerabilityFindingContribution> contributions,
      String revision,
      int sourceRecordCount,
      List<String> observationDiagnostics) {
    /** Validates the complete index result and snapshots its collection fields. */
    public IndexResult {
      contributions = List.copyOf(contributions);
      observationDiagnostics = List.copyOf(observationDiagnostics);
      observationDiagnostics.forEach(
          diagnostic -> {
            if (diagnostic == null || diagnostic.isBlank()) {
              throw new IllegalArgumentException("observation diagnostics must be non-blank");
            }
          });
      if (revision == null || !revision.matches("[0-9a-f]{64}")) {
        throw new IllegalArgumentException("revision must be a SHA-256 digest");
      }
      if (sourceRecordCount < 0) {
        throw new IllegalArgumentException("sourceRecordCount must not be negative");
      }
    }
  }
}
