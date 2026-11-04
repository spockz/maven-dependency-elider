/* WHY: Shares exact archive and digest checks between POM and structured proof paths. */

package io.github.spockz.elider.model;

import io.github.spockz.elider.trimmer.ArtifactDigests;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.IOException;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;
import java.util.TreeSet;

/** Physical archive checks shared by the model's proof admission paths. */
final class PhysicalOmissionChecks {
  private PhysicalOmissionChecks() {}

  /* default */ static ArtifactDigests verifyDigest(
      final Path path, final String expectedSha256, final String expectedSha1) throws IOException {
    final ArtifactDigests digests = ArtifactDigests.read(path);
    if (!digests.sha256().equals(expectedSha256) || !digests.sha1().equals(expectedSha1)) {
      throw new IllegalArgumentException("Artifact digest no longer matches trim record");
    }
    return digests;
  }

  /* default */ static Set<String> verifySymbols(
      final Set<String> vulnerableClasses,
      final Set<String> originalClasses,
      final Set<String> trimmedClasses) {
    final Set<String> absent = new TreeSet<>();
    for (final String mapped : vulnerableClasses) {
      final String binaryName = mapped.replace('.', '/');
      if (originalClasses.contains(binaryName)) {
        absent.addAll(verifyPrunedSymbols(binaryName, originalClasses, trimmedClasses));
      }
      verifyNoSurvivingNested(binaryName, trimmedClasses);
    }
    if (absent.isEmpty()) {
      throw new IllegalArgumentException(
          "Mapped class is absent from original archive: "
              + String.join(", ", new TreeSet<>(vulnerableClasses)));
    }
    return absent;
  }

  private static Set<String> verifyPrunedSymbols(
      final String binaryName,
      final Set<String> originalClasses,
      final Set<String> trimmedClasses) {
    final Set<String> absent = new TreeSet<>();
    for (final String symbol : nestedSymbols(binaryName, originalClasses)) {
      if (trimmedClasses.contains(symbol)) {
        throw new IllegalArgumentException(
            "Vulnerable class survives trimmed archive: " + symbol.replace('/', '.'));
      }
      absent.add(symbol.replace('/', '.'));
    }
    return absent;
  }

  private static void verifyNoSurvivingNested(
      final String binaryName, final Set<String> trimmedClasses) {
    final String nestedPrefix = binaryName + "$";
    for (final String trimmed : trimmedClasses) {
      if (trimmed.startsWith(nestedPrefix)) {
        throw new IllegalArgumentException(
            "Vulnerable nested class survives trimmed archive: " + trimmed.replace('/', '.'));
      }
    }
  }

  /* default */ static void verifyUnchanged(
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

  /* default */ static boolean sameArtifactIdentity(
      final ArtifactCoordinate left, final ArtifactCoordinate right) {
    return left.groupId().equals(right.groupId())
        && left.artifactId().equals(right.artifactId())
        && left.version().equals(right.version())
        && left.type().equals(right.type())
        && left.classifier().equals(right.classifier());
  }

  /* default */ static Set<String> nestedSymbols(
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
}
