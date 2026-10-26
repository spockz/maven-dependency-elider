/* WHY: Decodes bounded values while preserving coordinate nulls and rejecting malformed entries. */

package io.github.spockz.elider.cache;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.io.DataInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CoderResult;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/** Reads typed values from a validated cache payload. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class ElisionCacheReader {
  /** Maximum encoded UTF-8 string length. */
  private static final int MAX_STRING_BYTES = 1_000_000;

  /** Largest byte and character arrays retained by each long-lived decoding thread. */
  private static final int MAX_RETAINED_STRING_BYTES = 16 * 1024;

  /** Smallest set size using the load-factor capacity adjustment below. */
  private static final int MIN_HASHED_SET_SIZE = 3;

  /** Correction for small set sizes below the default load-factor threshold. */
  private static final int SMALL_SET_CAPACITY = 1;

  /** Capacity correction approximating HashSet's default load factor. */
  private static final int HASH_LOAD_FACTOR_DIVISOR = 3;

  /** Marker for an explicit nullable value. */
  private static final int NULL_MARKER = 0;

  /** Marker for a nullable value followed by bytes. */
  private static final int VALUE_MARKER = 1;

  /** Reuses only capped decoder buffers across requests handled by the same thread. */
  private static final ThreadLocal<Utf8DecoderState> UTF8_DECODERS =
      ThreadLocal.withInitial(Utf8DecoderState::new);

  private ElisionCacheReader() {}

  static Set<ArtifactCoordinate> readCoordinates(final DataInputStream input) throws IOException {
    final int count = bounded(input.readInt(), ElisionCacheCodec.MAX_ITEMS, "coordinate count");
    final Set<ArtifactCoordinate> coordinates = new HashSet<>(hashCapacity(count));
    for (int index = 0; index < count; index++) {
      if (!coordinates.add(readCoordinate(input))) {
        throw invalid("duplicate coordinate");
      }
    }
    return coordinates;
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
    final Map<ArtifactCoordinate, Set<String>> classesByArtifact =
        new LinkedHashMap<>(hashCapacity(count));
    for (int index = 0; index < count; index++) {
      final ArtifactCoordinate coordinate = readCoordinate(input);
      final int classCount = bounded(input.readInt(), ElisionCacheCodec.MAX_ITEMS, "class count");
      final Set<String> classNames = readClasses(input, classCount);
      if (classesByArtifact.put(coordinate, classNames) != null) {
        throw invalid("duplicate class map key");
      }
    }
    return classesByArtifact;
  }

  private static Set<String> readClasses(final DataInputStream input, final int count)
      throws IOException {
    final Set<String> classes = new HashSet<>(hashCapacity(count));
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
    final Utf8DecoderState decoderState = UTF8_DECODERS.get();
    try {
      return decoderState.read(input, size);
    } catch (CharacterCodingException malformed) {
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

  private static int hashCapacity(final int expectedSize) {
    if (expectedSize < MIN_HASHED_SET_SIZE) {
      return expectedSize + SMALL_SET_CAPACITY;
    }
    return expectedSize + expectedSize / HASH_LOAD_FACTOR_DIVISOR + SMALL_SET_CAPACITY;
  }

  /** Holds reusable decoding buffers under the per-thread retention limit. */
  private static final class Utf8DecoderState {
    /** Reset before each non-ASCII string decode. */
    private final CharsetDecoder decoder =
        StandardCharsets.UTF_8
            .newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT);

    /** Reused input buffer for values within the thread-local retention cap. */
    private byte[] bytes = new byte[128];

    /** Reused character buffer for strict non-ASCII decoding. */
    private char[] chars = new char[128];

    /** Reused view over the byte buffer. */
    private ByteBuffer input = ByteBuffer.wrap(bytes);

    /** Reused view over the character buffer. */
    private CharBuffer output = CharBuffer.wrap(chars);

    String read(final DataInputStream source, final int length)
        throws IOException, CharacterCodingException {
      if (length > MAX_RETAINED_STRING_BYTES) {
        return readLargeString(source, length);
      }
      ensureCapacity(length);
      source.readFully(bytes, 0, length);
      if (isAscii(length)) {
        return new String(bytes, 0, length, StandardCharsets.US_ASCII);
      }
      input.clear();
      input.limit(length);
      output.clear();
      decoder.reset();
      throwIfError(decoder.decode(input, output, true));
      throwIfError(decoder.flush(output));
      return new String(chars, 0, output.position());
    }

    private String readLargeString(final DataInputStream source, final int length)
        throws IOException, CharacterCodingException {
      final byte[] largeBytes = new byte[length];
      source.readFully(largeBytes);
      if (isAscii(largeBytes, length)) {
        return new String(largeBytes, 0, length, StandardCharsets.US_ASCII);
      }
      final char[] largeChars = new char[length];
      final ByteBuffer largeInput = ByteBuffer.wrap(largeBytes);
      final CharBuffer largeOutput = CharBuffer.wrap(largeChars);
      decoder.reset();
      throwIfError(decoder.decode(largeInput, largeOutput, true));
      throwIfError(decoder.flush(largeOutput));
      return new String(largeChars, 0, largeOutput.position());
    }

    private boolean isAscii(final int length) {
      return isAscii(bytes, length);
    }

    private static boolean isAscii(final byte[] value, final int length) {
      for (int index = 0; index < length; index++) {
        if ((value[index] & 0x80) != 0) {
          return false;
        }
      }
      return true;
    }

    private static void throwIfError(final CoderResult result) throws CharacterCodingException {
      if (result.isError()) {
        result.throwException();
      }
    }

    private void ensureCapacity(final int required) {
      if (required <= bytes.length) {
        return;
      }
      int capacity = bytes.length;
      while (capacity < required) {
        capacity = Math.min(MAX_RETAINED_STRING_BYTES, capacity * 2);
      }
      bytes = new byte[capacity];
      chars = new char[capacity];
      input = ByteBuffer.wrap(bytes);
      output = CharBuffer.wrap(chars);
    }
  }
}
