/* WHY: This package controls creation of immutable VEX proof evidence. */

package io.github.spockz.elider.model;

import io.github.spockz.elider.trimmer.ArtifactDigests;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.IOException;
import java.nio.file.Path;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;
import java.util.TreeSet;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/** Proves mapped classes are absent from physical archives. */
public final class OmittedCodeProof {
  private OmittedCodeProof() {}

  /** Returns proof evidence or throws when checks fail. */
  public static VexAttestation prove(
      final VulnerabilitySymbolMapping mapping, final ArtifactTrimRecord trimRecord)
      throws IOException {
    requireMatchingIdentity(mapping, trimRecord);
    final ArtifactDigests originalDigests =
        verifyDigest(
            trimRecord.originalPath(), trimRecord.originalSha256(), trimRecord.originalSha1());
    final ArtifactDigests trimmedDigests =
        verifyDigest(
            trimRecord.trimmedPath(), trimRecord.trimmedSha256(), trimRecord.trimmedSha1());
    final Set<String> originalClasses = readClasses(trimRecord.originalPath());
    final Set<String> trimmedClasses = readClasses(trimRecord.trimmedPath());
    final Set<String> absent = verifySymbols(mapping, originalClasses, trimmedClasses);
    verifyUnchanged(trimRecord, originalDigests, trimmedDigests);
    return new VexAttestation(
        mapping.cveId(),
        trimRecord.coordinate(),
        "vulnerable_code_not_present",
        "Mapped vulnerable classes and their original nested classes are absent "
            + "from the trimmed artifact.",
        absent,
        originalDigests.sha256(),
        trimmedDigests.sha256());
  }

  private static void requireMatchingIdentity(
      final VulnerabilitySymbolMapping mapping, final ArtifactTrimRecord record) {
    if (mapping == null || record == null) {
      throw new IllegalArgumentException("mapping and trimRecord are required");
    }
    if (!sameArtifactIdentity(mapping.affectedCoordinate(), record.coordinate())) {
      throw new IllegalArgumentException("Mapping coordinate does not match trim record");
    }
    if (mapping.confidenceLevel() != VulnerabilitySymbolMapping.ConfidenceLevel.HIGH) {
      throw new IllegalArgumentException("Only HIGH confidence mappings can produce VEX evidence");
    }
  }

  private static ArtifactDigests verifyDigest(
      final Path path, final String expectedSha256, final String expectedSha1) throws IOException {
    final ArtifactDigests digests = ArtifactDigests.read(path);
    if (!digests.sha256().equals(expectedSha256) || !digests.sha1().equals(expectedSha1)) {
      throw new IllegalArgumentException("Artifact digest no longer matches trim record");
    }
    return digests;
  }

  private static Set<String> verifySymbols(
      final VulnerabilitySymbolMapping mapping,
      final Set<String> originalClasses,
      final Set<String> trimmedClasses) {
    final Set<String> absent = new TreeSet<>();
    for (final String mapped : mapping.vulnerableClasses()) {
      final String binaryName = mapped.replace('.', '/');
      if (!originalClasses.contains(binaryName)) {
        throw new IllegalArgumentException(
            "Mapped class is absent from original archive: " + mapped);
      }
      for (final String symbol : nestedSymbols(binaryName, originalClasses)) {
        if (trimmedClasses.contains(symbol)) {
          throw new IllegalArgumentException(
              "Vulnerable class survives trimmed archive: " + symbol.replace('/', '.'));
        }
        absent.add(symbol.replace('/', '.'));
      }
    }
    return absent;
  }

  private static Set<String> nestedSymbols(
      final String binaryName, final Set<String> originalClasses) {
    final Set<String> symbols = new HashSet<>();
    symbols.add(binaryName);
    final String nestedPrefix = binaryName + "$";
    for (final String original : originalClasses) {
      if (original.startsWith(nestedPrefix)) {
        symbols.add(original);
      }
    }
    return symbols;
  }

  private static void verifyUnchanged(
      final ArtifactTrimRecord record,
      final ArtifactDigests originalDigests,
      final ArtifactDigests trimmedDigests)
      throws IOException {
    final ArtifactDigests finalOriginal = ArtifactDigests.read(record.originalPath());
    final ArtifactDigests finalTrimmed = ArtifactDigests.read(record.trimmedPath());
    if (!finalOriginal.sha256().equals(originalDigests.sha256())
        || !finalOriginal.sha1().equals(originalDigests.sha1())
        || !finalTrimmed.sha256().equals(trimmedDigests.sha256())
        || !finalTrimmed.sha1().equals(trimmedDigests.sha1())) {
      throw new IllegalArgumentException("Artifact changed while archive contents were verified");
    }
  }

  private static boolean sameArtifactIdentity(
      final ArtifactCoordinate left, final ArtifactCoordinate right) {
    return left.groupId().equals(right.groupId())
        && left.artifactId().equals(right.artifactId())
        && left.version().equals(right.version())
        && left.type().equals(right.type())
        && left.classifier().equals(right.classifier());
  }

  private static Set<String> readClasses(final Path path) throws IOException {
    final Set<String> names = new HashSet<>();
    try (ZipFile zip = new ZipFile(path.toFile())) {
      final Enumeration<? extends ZipEntry> entries = zip.entries();
      while (entries.hasMoreElements()) {
        final ZipEntry entry = entries.nextElement();
        final String name = className(entry);
        if (name != null && !names.add(name)) {
          throw new IOException("Ambiguous duplicate class entry: " + name.replace('/', '.'));
        }
      }
    } catch (final IllegalArgumentException exception) {
      throw new IOException("Unreadable archive: " + path, exception);
    }
    return names;
  }

  private static String className(final ZipEntry entry) throws IOException {
    final String entryName = entry.getName();
    if (entry.isDirectory() || !entryName.endsWith(".class")) {
      return null;
    }
    String name = entryName.substring(0, entryName.length() - ".class".length());
    if (name.startsWith("META-INF/versions/")) {
      final int slash = name.indexOf('/', "META-INF/versions/".length());
      if (slash < 0) {
        throw new IOException("Malformed multi-release class entry: " + entryName);
      }
      name = name.substring(slash + 1);
    }
    if ("module-info".equals(name) || name.endsWith("/module-info")) {
      return null;
    }
    return name;
  }
}
