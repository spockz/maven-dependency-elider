/* WHY: Encodes typed fingerprint values in deterministic framed form. */

package io.github.spockz.elider.cache;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Collection;
import java.util.List;

/** Writes coordinates and configuration collections to fingerprint bytes. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class FingerprintValues {
  /** Maximum collection size and encoded UTF-8 value length. */
  private static final int MAX_INPUTS = 1_000_000;

  private FingerprintValues() {}

  static void writeCoordinate(final DataOutputStream output, final ArtifactCoordinate coordinate)
      throws IOException {
    writeString(output, coordinate.groupId());
    writeString(output, coordinate.artifactId());
    writeNullable(output, coordinate.version());
    writeString(output, coordinate.type());
    writeString(output, coordinate.classifier());
    writeString(output, coordinate.scope());
  }

  static void writeCoordinates(
      final DataOutputStream output, final Collection<ArtifactCoordinate> coordinates)
      throws IOException {
    checkCount(coordinates.size(), "coordinate configuration count");
    final List<ArtifactCoordinate> sortedCoordinates = coordinates.stream().sorted().toList();
    output.writeInt(sortedCoordinates.size());
    for (final ArtifactCoordinate coordinate : sortedCoordinates) {
      writeCoordinate(output, coordinate);
    }
  }

  static void writeStrings(final DataOutputStream output, final Collection<String> values)
      throws IOException {
    checkCount(values.size(), "string configuration count");
    final List<String> sortedValues = values.stream().sorted().toList();
    output.writeInt(sortedValues.size());
    for (final String value : sortedValues) {
      writeString(output, value);
    }
  }

  static void writeString(final DataOutputStream output, final String value) throws IOException {
    final byte[] encoded = value.getBytes(java.nio.charset.StandardCharsets.UTF_8);
    if (encoded.length > MAX_INPUTS) {
      throw new IOException("Fingerprint string exceeds maximum size");
    }
    output.writeInt(encoded.length);
    output.write(encoded);
  }

  static void writeNullable(final DataOutputStream output, final String value) throws IOException {
    output.writeBoolean(value != null);
    if (value != null) {
      writeString(output, value);
    }
  }

  private static void checkCount(final int count, final String label) throws IOException {
    if (count > MAX_INPUTS) {
      throw new IOException("Fingerprint " + label + " exceeds maximum");
    }
  }
}
