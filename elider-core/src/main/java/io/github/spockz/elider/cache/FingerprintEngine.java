/* WHY: Hashes input state so cached decisions cannot mask changes. */

package io.github.spockz.elider.cache;

import io.github.spockz.elider.engine.PruneConfig;
import io.github.spockz.elider.model.ArtifactFileRef;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

/** Computes a 64-bit fingerprint from current filesystem input metadata. */
public final class FingerprintEngine {
  /** Collection bound prevents hostile inputs from consuming unbounded memory. */
  private static final int MAX_INPUTS = 1_000_000;

  private FingerprintEngine() {}

  /** Fingerprints artifacts, traces, configuration, and analysis semantics. */
  public static long fingerprint(
      final Collection<ArtifactFileRef> artifacts,
      final Collection<Path> tracePaths,
      final PruneConfig config,
      final String semanticsVersion)
      throws IOException {
    Objects.requireNonNull(artifacts, "artifacts must not be null");
    Objects.requireNonNull(tracePaths, "tracePaths must not be null");
    Objects.requireNonNull(config, "config must not be null");
    Objects.requireNonNull(semanticsVersion, "semanticsVersion must not be null");
    final List<ArtifactFileRef> sortedArtifacts = uniqueArtifacts(artifacts);
    final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    try (DataOutputStream out = new DataOutputStream(bytes)) {
      writeFingerprintInputs(out, sortedArtifacts, tracePaths, config, semanticsVersion);
    }
    try {
      final byte[] digest = MessageDigest.getInstance("SHA-256").digest(bytes.toByteArray());
      long value = 0;
      for (int i = 0; i < Long.BYTES; i++) {
        value = (value << 8) | (digest[i] & 0xffL);
      }
      return value;
    } catch (NoSuchAlgorithmException impossible) {
      throw new AssertionError("SHA-256 is required by the Java platform", impossible);
    }
  }

  private static List<ArtifactFileRef> uniqueArtifacts(
      final Collection<ArtifactFileRef> artifacts) {
    final List<ArtifactFileRef> sorted = new ArrayList<>(artifacts);
    checkCountUnchecked(sorted.size(), "artifact count");
    sorted.sort(Comparator.comparing(ArtifactFileRef::coordinate));
    int index = 1;
    while (index < sorted.size()) {
      if (sorted.get(index - 1).coordinate().equals(sorted.get(index).coordinate())) {
        final ArtifactFileRef previous = sorted.get(index - 1);
        final ArtifactFileRef current = sorted.get(index);
        if (!previous.equals(current)) {
          throw new IllegalArgumentException(
              "Conflicting artifact references for coordinate " + current.coordinate());
        }
        sorted.remove(index);
      } else {
        index++;
      }
    }
    return sorted;
  }

  private static void writeFingerprintInputs(
      final DataOutputStream out,
      final List<ArtifactFileRef> artifacts,
      final Collection<Path> tracePaths,
      final PruneConfig config,
      final String semanticsVersion)
      throws IOException {
    FingerprintValues.writeString(out, "elider-fingerprint-v1");
    FingerprintValues.writeString(out, semanticsVersion);
    out.writeInt(artifacts.size());
    for (final ArtifactFileRef artifact : artifacts) {
      FingerprintValues.writeCoordinate(out, artifact.coordinate());
      final Path path = artifact.filePath().toAbsolutePath().normalize();
      FingerprintValues.writeString(out, path.toString());
      writeMetadata(out, path);
    }
    final List<Path> traces =
        tracePaths.stream().map(path -> path.toAbsolutePath().normalize()).sorted().toList();
    checkCountUnchecked(traces.size(), "trace count");
    out.writeInt(traces.size());
    for (final Path path : traces) {
      FingerprintValues.writeString(out, path.toString());
      writeMetadata(out, path);
    }
    FingerprintValues.writeStrings(out, config.keepScopes());
    FingerprintValues.writeCoordinates(out, config.keepArtifacts());
    FingerprintValues.writeStrings(out, config.eligibleScopes());
    FingerprintValues.writeCoordinates(out, config.excludedArtifacts());
  }

  private static void writeMetadata(final DataOutputStream out, final Path path)
      throws IOException {
    final BasicFileAttributes attrs = Files.readAttributes(path, BasicFileAttributes.class);
    if (!attrs.isRegularFile()) {
      throw new IOException("Cache input is not a regular file: " + path);
    }
    out.writeLong(attrs.lastModifiedTime().to(TimeUnit.NANOSECONDS));
    out.writeLong(attrs.size());
  }

  private static void checkCountUnchecked(final int count, final String label) {
    if (count > MAX_INPUTS) {
      throw new IllegalArgumentException("Fingerprint " + label + " exceeds maximum");
    }
  }
}
