/* WHY: Shares lowercase hexadecimal validation without compiling repeat hash patterns. */

package io.github.spockz.elider.model;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.regex.Pattern;

/** Validates and computes lowercase hexadecimal SHA-256 digests. */
public final class HexDigest {
  /** WHY: All serialized digest forms use lowercase hexadecimal text. */
  private static final Pattern LOWERCASE_HEX = Pattern.compile("[0-9a-f]+");

  /** Length of a lowercase hex-encoded SHA-256 digest. */
  private static final int SHA256_HEX_LENGTH = 64;

  private HexDigest() {
    throw new AssertionError("No instances");
  }

  /** Returns whether {@code value} is lowercase hexadecimal of the expected length. */
  public static boolean isLowercaseHex(final String value, final int length) {
    return value != null && value.length() == length && LOWERCASE_HEX.matcher(value).matches();
  }

  /** Validates that {@code value} is a lowercase 64-character SHA-256 digest. */
  public static String requireSha256(final String value, final String field) {
    if (!isLowercaseHex(value, SHA256_HEX_LENGTH)) {
      throw new IllegalArgumentException(field + " must be a 64-character lowercase SHA-256 hex");
    }
    return value;
  }

  /** Computes the lowercase SHA-256 digest of a file in a single streaming pass. */
  public static String sha256(final Path path) throws IOException {
    final MessageDigest digest = sha256Digest();
    try (InputStream input = Files.newInputStream(path)) {
      final byte[] buffer = new byte[8192];
      while (true) {
        final int count = input.read(buffer);
        if (count < 0) {
          return HexFormat.of().formatHex(digest.digest());
        }
        digest.update(buffer, 0, count);
      }
    }
  }

  /** Computes the lowercase SHA-256 digest of {@code bytes}. */
  public static String sha256(final byte[] bytes) {
    return HexFormat.of().formatHex(sha256Digest().digest(bytes));
  }

  /** Computes the lowercase SHA-256 digest of UTF-8 text. */
  public static String sha256(final String value) {
    return sha256(value.getBytes(StandardCharsets.UTF_8));
  }

  /** Computes a length-prefixed lowercase SHA-256 digest over ordered strings. */
  public static String sha256LengthPrefixed(final List<String> values) {
    final MessageDigest digest = sha256Digest();
    for (final String value : values) {
      final byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
      digest.update(Integer.toString(bytes.length).getBytes(StandardCharsets.US_ASCII));
      digest.update((byte) ':');
      digest.update(bytes);
    }
    return HexFormat.of().formatHex(digest.digest());
  }

  private static MessageDigest sha256Digest() {
    try {
      return MessageDigest.getInstance("SHA-256");
    } catch (final NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is unavailable", exception);
    }
  }
}
