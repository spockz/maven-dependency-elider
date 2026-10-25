/* WHY: Decodes bounded values while preserving coordinate nulls and rejecting malformed entries. */

package io.github.spockz.elider.cache;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.io.DataInputStream;
import java.io.IOException;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/** Reads typed values from a validated cache payload. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class ElisionCacheReader {
  /** Maximum encoded UTF-8 string length. */
  private static final int MAX_STRING_BYTES = 1_000_000;

  /** Marker for an explicit nullable value. */
  private static final int NULL_MARKER = 0;

  /** Marker for a nullable value followed by bytes. */
  private static final int VALUE_MARKER = 1;

  private ElisionCacheReader() {}

  static Set<ArtifactCoordinate> readCoordinates(final DataInputStream input) throws IOException {
    final int count = bounded(input.readInt(), ElisionCacheCodec.MAX_ITEMS, "coordinate count");
    final Set<ArtifactCoordinate> coordinates = new HashSet<>();
    for (int index = 0; index < count; index++) {
      if (!coordinates.add(readCoordinate(input))) {
        throw invalid("duplicate coordinate");
      }
    }
    return Set.copyOf(coordinates);
  }

  static ArtifactCoordinate readCoordinate(final DataInputStream input) throws IOException {
    return new ArtifactCoordinate(
        readString(input),
        readString(input),
        readNullable(input),
        readString(input),
        readString(input),
        readString(input));
  }

  // Decoder-local state is never shared across threads.
  @SuppressWarnings("PMD.UseConcurrentHashMap")
  static Map<ArtifactCoordinate, Set<String>> readClassMap(final DataInputStream input)
      throws IOException {
    final int count = bounded(input.readInt(), ElisionCacheCodec.MAX_ITEMS, "class map count");
    final Map<ArtifactCoordinate, Set<String>> classesByArtifact = new LinkedHashMap<>();
    for (int index = 0; index < count; index++) {
      final ArtifactCoordinate coordinate = readCoordinate(input);
      final int classCount = bounded(input.readInt(), ElisionCacheCodec.MAX_ITEMS, "class count");
      final Set<String> classNames = readClasses(input, classCount);
      if (classesByArtifact.put(coordinate, Set.copyOf(classNames)) != null) {
        throw invalid("duplicate class map key");
      }
    }
    return Map.copyOf(classesByArtifact);
  }

  private static Set<String> readClasses(final DataInputStream input, final int count)
      throws IOException {
    final Set<String> classes = new HashSet<>();
    for (int index = 0; index < count; index++) {
      if (!classes.add(readString(input))) {
        throw invalid("duplicate class");
      }
    }
    return classes;
  }

  private static String readString(final DataInputStream input) throws IOException {
    final int size = bounded(input.readInt(), MAX_STRING_BYTES, "string size");
    if (size > input.available()) {
      throw invalid("truncated string");
    }
    final byte[] encoded = input.readNBytes(size);
    try {
      return java.nio.charset.StandardCharsets.UTF_8
          .newDecoder()
          .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
          .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
          .decode(java.nio.ByteBuffer.wrap(encoded))
          .toString();
    } catch (java.nio.charset.CharacterCodingException malformed) {
      throw new ElisionCacheCodec.InvalidCacheException("invalid UTF-8 string", malformed);
    }
  }

  private static String readNullable(final DataInputStream input) throws IOException {
    final int marker = input.readUnsignedByte();
    if (marker == NULL_MARKER) {
      return null;
    }
    if (marker == VALUE_MARKER) {
      return readString(input);
    }
    throw invalid("invalid nullable marker");
  }

  static int bounded(final int value, final int maximum, final String description)
      throws ElisionCacheCodec.InvalidCacheException {
    if (value < 0 || value > maximum) {
      throw invalid("invalid " + description);
    }
    return value;
  }

  private static ElisionCacheCodec.InvalidCacheException invalid(final String reason) {
    return new ElisionCacheCodec.InvalidCacheException(reason);
  }
}
