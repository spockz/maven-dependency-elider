/* WHY: Bounds collection and string serialization before producing a cache payload. */

package io.github.spockz.elider.cache;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ElisionDecision;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Encodes complete decisions into the versioned cache payload and frame. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class ElisionCacheWriter {
  private ElisionCacheWriter() {}

  /** Encodes records for the package-private cache facade. */
  static byte[] encode(
      final long fingerprint,
      final Set<ArtifactCoordinate> inventory,
      final ElisionDecision decision)
      throws IOException {
    final ByteArrayOutputStream payloadBytes =
        new BoundedByteArrayOutputStream(ElisionCacheCodec.MAX_FILE_BYTES - 64);
    try (DataOutputStream payloadOutput = new DataOutputStream(payloadBytes)) {
      payloadOutput.writeLong(fingerprint);
      payloadOutput.writeLong(decision.elapsedNanos());
      writeCoordinates(payloadOutput, inventory);
      writeCoordinates(payloadOutput, decision.retainedArtifacts());
      writeCoordinates(payloadOutput, decision.elidedArtifacts());
      writeClassMap(payloadOutput, decision.retainedClassesPerArtifact());
      writeClassMap(payloadOutput, decision.unusedClassesPerArtifact());
    }
    final byte[] payload = payloadBytes.toByteArray();
    final ByteArrayOutputStream frame =
        new BoundedByteArrayOutputStream(ElisionCacheCodec.MAX_FILE_BYTES);
    try (DataOutputStream frameOutput = new DataOutputStream(frame)) {
      frameOutput.writeLong(ElisionCacheCodec.MAGIC);
      frameOutput.writeInt(ElisionCacheCodec.VERSION);
      frameOutput.writeInt(payload.length);
      frameOutput.write(payload);
      frameOutput.write(ElisionCacheCodec.checksum(payload));
    }
    return frame.toByteArray();
  }

  private static void writeCoordinates(
      final DataOutputStream output, final Set<ArtifactCoordinate> coordinates) throws IOException {
    checkCount(coordinates.size(), "coordinate count");
    final List<ArtifactCoordinate> sorted = coordinates.stream().sorted().toList();
    output.writeInt(sorted.size());
    for (final ArtifactCoordinate coordinate : sorted) {
      FingerprintValues.writeCoordinate(output, coordinate);
    }
  }

  private static void writeClassMap(
      final DataOutputStream output, final Map<ArtifactCoordinate, Set<String>> classesByArtifact)
      throws IOException {
    checkCount(classesByArtifact.size(), "class map count");
    final List<ArtifactCoordinate> coordinates =
        classesByArtifact.keySet().stream().sorted().toList();
    output.writeInt(coordinates.size());
    for (final ArtifactCoordinate coordinate : coordinates) {
      FingerprintValues.writeCoordinate(output, coordinate);
      final List<String> classes = classesByArtifact.get(coordinate).stream().sorted().toList();
      checkCount(classes.size(), "class count");
      output.writeInt(classes.size());
      for (final String className : classes) {
        FingerprintValues.writeString(output, className);
      }
    }
  }

  private static void checkCount(final int count, final String name) throws IOException {
    if (count < 0 || count > ElisionCacheCodec.MAX_ITEMS) {
      throw new IOException("Cache " + name + " exceeds limit");
    }
  }
}
