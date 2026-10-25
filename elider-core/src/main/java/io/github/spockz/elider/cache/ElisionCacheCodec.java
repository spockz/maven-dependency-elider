/* WHY: Keeps binary framing and decision validation isolated from filesystem persistence. */

package io.github.spockz.elider.cache;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ElisionDecision;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.Set;

/** Reads bounded cache records validated against a complete inventory. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class ElisionCacheCodec {
  /** Fixed frame marker that distinguishes these files from unrelated binary data. */
  static final long MAGIC = 0x454c494445524331L;

  /** Incremented when the frame or payload layout changes. */
  static final int VERSION = 1;

  /** Maximum accepted and emitted cache record size. */
  static final int MAX_FILE_BYTES = 64 * 1024 * 1024;

  /** Maximum count for any encoded collection. */
  static final int MAX_ITEMS = 1_000_000;

  private ElisionCacheCodec() {}

  /** Decodes untrusted bytes; invalid frames and payloads become misses. */
  static ElisionCache.Lookup decode(
      final byte[] bytes,
      final long expectedFingerprint,
      final Set<ArtifactCoordinate> expectedInventory)
      throws IOException {
    try {
      return decodePayload(decodeFrame(bytes), expectedFingerprint, expectedInventory);
    } catch (InvalidCacheException e) {
      return ElisionCache.Lookup.miss(e.getMessage());
    } catch (IOException | IllegalArgumentException e) {
      return ElisionCache.Lookup.miss("malformed or truncated record");
    }
  }

  private static byte[] decodeFrame(final byte[] bytes) throws IOException {
    try (DataInputStream frame = new DataInputStream(new ByteArrayInputStream(bytes))) {
      validateFrameHeader(frame);
      return readAndValidatePayload(frame);
    }
  }

  private static void validateFrameHeader(final DataInputStream frame) throws IOException {
    if (frame.readLong() != MAGIC) {
      throw invalid("bad magic");
    }
    if (frame.readInt() != VERSION) {
      throw invalid("version mismatch");
    }
  }

  private static byte[] readAndValidatePayload(final DataInputStream frame) throws IOException {
    final int payloadSize =
        ElisionCacheReader.bounded(frame.readInt(), MAX_FILE_BYTES, "payload size");
    if (payloadSize > frame.available() - 32) {
      throw invalid("truncated");
    }
    final byte[] payload = frame.readNBytes(payloadSize);
    final byte[] storedChecksum = frame.readNBytes(32);
    if (storedChecksum.length != 32 || frame.available() != 0) {
      throw invalid("trailing or truncated data");
    }
    if (!MessageDigest.isEqual(storedChecksum, checksum(payload))) {
      throw invalid("checksum mismatch");
    }
    return payload;
  }

  private static ElisionCache.Lookup decodePayload(
      final byte[] payload,
      final long expectedFingerprint,
      final Set<ArtifactCoordinate> expectedInventory)
      throws IOException {
    try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(payload))) {
      final long fingerprint = input.readLong();
      if (fingerprint != expectedFingerprint) {
        throw invalid("fingerprint mismatch");
      }
      final long elapsed = input.readLong();
      if (elapsed < 0) {
        throw invalid("negative elapsed time");
      }
      final Set<ArtifactCoordinate> storedInventory = ElisionCacheReader.readCoordinates(input);
      if (!storedInventory.equals(expectedInventory)) {
        throw invalid("inventory mismatch");
      }
      final Set<ArtifactCoordinate> retained = ElisionCacheReader.readCoordinates(input);
      final Set<ArtifactCoordinate> elided = ElisionCacheReader.readCoordinates(input);
      final Map<ArtifactCoordinate, Set<String>> used = ElisionCacheReader.readClassMap(input);
      final Map<ArtifactCoordinate, Set<String>> unused = ElisionCacheReader.readClassMap(input);
      if (input.available() != 0) {
        throw invalid("trailing payload data");
      }
      final ElisionDecision decision = new ElisionDecision(retained, elided, used, unused, elapsed);
      ElisionDecisionValidator.validate(decision, expectedInventory);
      return ElisionCache.Lookup.hit(decision);
    }
  }

  static byte[] checksum(final byte[] value) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(value);
    } catch (NoSuchAlgorithmException e) {
      throw new AssertionError(e);
    }
  }

  private static InvalidCacheException invalid(final String reason) {
    return new InvalidCacheException(reason);
  }

  /** Signals malformed cache contents, which callers treat as a cache miss. */
  static final class InvalidCacheException extends IOException {
    private static final long serialVersionUID = 1L;

    /** Creates a cache-format validation error. */
    InvalidCacheException(final String message) {
      super(message);
    }

    /** Preserves the parser failure that made the payload invalid. */
    InvalidCacheException(final String message, final Throwable cause) {
      super(message, cause);
    }
  }
}
