/* WHY: Computes stable SHA-1 and SHA-256 provenance together from one archive read. */

package io.github.spockz.elider.trimmer;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/** Immutable SHA-256 and SHA-1 provenance captured for one artifact file. */
public final class ArtifactDigests {
  /** Keeps provenance bound to the normalized archive input. */
  private final Path sourcePath;

  /** Stores SHA-256 from the single source read. */
  private final String sha256Digest;

  /** Stores SHA-1 from the same source read for Maven's report. */
  private final String sha1Digest;

  private ArtifactDigests(final Path path, final String sha256, final String sha1) {
    this.sourcePath = path;
    this.sha256Digest = sha256;
    this.sha1Digest = sha1;
  }

  /** Returns the normalized source path whose bytes produced these digests. */
  public Path path() {
    return sourcePath;
  }

  /** Returns the source SHA-256 digest. */
  public String sha256() {
    return sha256Digest;
  }

  /** Returns the source SHA-1 digest. */
  public String sha1() {
    return sha1Digest;
  }

  /** Returns whether this provenance was captured for the supplied normalized path. */
  public boolean matchesPath(final Path candidate) {
    return sourcePath.equals(normalize(candidate));
  }

  /** Reads both digest algorithms from one stable file pass. */
  public static ArtifactDigests read(final Path path) throws IOException {
    final Path normalizedPath = normalize(path);
    final MessageDigest sha256 = digest("SHA-256");
    final MessageDigest sha1 = digest("SHA-1");
    try (InputStream input = Files.newInputStream(path)) {
      final byte[] buffer = new byte[8192];
      while (true) {
        final int count = input.read(buffer);
        if (count < 0) {
          break;
        }
        sha256.update(buffer, 0, count);
        sha1.update(buffer, 0, count);
      }
    }
    return new ArtifactDigests(
        normalizedPath,
        HexFormat.of().formatHex(sha256.digest()),
        HexFormat.of().formatHex(sha1.digest()));
  }

  private static Path normalize(final Path path) {
    return java.util.Objects.requireNonNull(path, "path").toAbsolutePath().normalize();
  }

  private static MessageDigest digest(final String algorithm) {
    try {
      return MessageDigest.getInstance(algorithm);
    } catch (final NoSuchAlgorithmException exception) {
      throw new IllegalStateException(
          "Required digest algorithm is unavailable: " + algorithm, exception);
    }
  }
}
