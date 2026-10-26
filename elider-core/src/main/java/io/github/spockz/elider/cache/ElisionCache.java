/* WHY: Owns cache-file I/O so storage failures stay visible while invalid records are misses. */

package io.github.spockz.elider.cache;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ElisionDecision;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.Set;
import java.util.UUID;

/** Filesystem facade for the binary decision cache. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
public final class ElisionCache {
  /** Maximum record size accepted from disk. */
  private static final int MAX_FILE_BYTES = 64 * 1024 * 1024;

  /** Creates a cache facade without retaining filesystem state. */
  public ElisionCache() {
    // No instance state is required; each operation owns its file resources.
  }

  /** Reports whether the requested fingerprint and inventory matched. */
  public record Lookup(boolean hit, ElisionDecision decision, String missReason) {
    /** Creates a miss. */
    // package-private cache factory.
    static Lookup miss(final String reason) {
      return new Lookup(false, null, reason);
    }

    /** Creates a hit. */
    // package-private cache factory.
    static Lookup hit(final ElisionDecision decision) {
      return new Lookup(true, decision, "");
    }
  }

  /** Loads a matching decision. Invalid records miss; filesystem errors propagate. */
  public Lookup load(
      final Path file, final long fingerprint, final Set<ArtifactCoordinate> expectedInventory)
      throws IOException {
    java.util.Objects.requireNonNull(file, "file must not be null");
    java.util.Objects.requireNonNull(expectedInventory, "expectedInventory must not be null");
    final byte[] bytes;
    try {
      final long fileSize = Files.size(file);
      if (fileSize > MAX_FILE_BYTES) {
        return Lookup.miss("oversized");
      }
      bytes = new byte[(int) fileSize];
      try (java.io.InputStream input = Files.newInputStream(file)) {
        if (input.readNBytes(bytes, 0, bytes.length) != bytes.length) {
          return Lookup.miss("truncated");
        }
        if (input.read() != -1) {
          return Lookup.miss("oversized");
        }
      }
    } catch (NoSuchFileException missing) {
      return Lookup.miss("missing");
    }
    return ElisionCacheCodec.decode(bytes, fingerprint, expectedInventory);
  }

  /** Writes atomically after the caller rechecks its inputs. */
  public void store(
      final Path file,
      final long fingerprint,
      final Set<ArtifactCoordinate> inventory,
      final ElisionDecision decision)
      throws IOException {
    ElisionDecisionValidator.validate(decision, inventory);
    final byte[] bytes = ElisionCacheWriter.encode(fingerprint, inventory, decision);
    final Path absolute = file.toAbsolutePath();
    final Path parent = absolute.getParent();
    if (parent == null) {
      throw new IOException("Cache file must have a parent directory: " + absolute);
    }
    Files.createDirectories(parent);
    final Path temp =
        parent.resolve("." + absolute.getFileName() + "." + UUID.randomUUID() + ".tmp");
    try {
      Files.write(temp, bytes, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
      Files.move(
          temp, absolute, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    } finally {
      Files.deleteIfExists(temp);
    }
  }
}
