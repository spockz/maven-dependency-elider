/* WHY: Binds external Native Image parsing to the exact files prepared for later publication. */

package io.github.spockz.elider.plugin.nativeimage;

import io.github.spockz.elider.model.HexDigest;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;

/** Captured identities for descriptors, sibling data, and archive references. */
public record NativeImageConsumedInput(
    Path logicalPath, Path canonicalPath, String role, long byteLength, String sha256) {
  /** Distinguishes directory membership snapshots during revalidation. */
  private static final String DIRECTORY_MEMBERSHIP_ROLE = "configuration-directory-membership";

  /** Tracks logical aliases; archive fingerprints separately cover their content. */
  private static final String ARCHIVE_REFERENCE_ROLE = "link-at-build-time-archive-reference";

  /** Validates and normalizes consumed native-image input metadata. */
  public NativeImageConsumedInput {
    logicalPath = logicalPath.toAbsolutePath().normalize();
    canonicalPath = canonicalPath.toAbsolutePath().normalize();
    if (role == null || role.isBlank() || sha256 == null || sha256.isBlank() || byteLength < 0) {
      throw new IllegalArgumentException("Invalid consumed native-image input snapshot");
    }
  }

  /* package */
  /** Returns consumed inputs sorted deterministically by identity. */
  public static List<NativeImageConsumedInput> ordered(
      final Collection<NativeImageConsumedInput> inputs) {
    return inputs.stream()
        .distinct()
        .sorted(Comparator.comparing(NativeImageConsumedInput::identity))
        .toList();
  }

  /* package */ static NativeImageConsumedInput directoryMembership(
      final Path directory, final List<String> members) throws IOException {
    final Path logical = directory.toAbsolutePath().normalize();
    final Path canonical = logical.toRealPath();
    final byte[] manifest = NativeImageConfigurationDirectorySupport.membershipBytes(members);
    return new NativeImageConsumedInput(
        logical, canonical, DIRECTORY_MEMBERSHIP_ROLE, manifest.length, digest(manifest));
  }

  /* package */ static NativeImageConsumedInput archiveReference(final Path logicalPath)
      throws IOException {
    final Path logical = logicalPath.toAbsolutePath().normalize();
    final Path canonical = logical.toRealPath();
    final byte[] target = canonical.toString().getBytes(StandardCharsets.UTF_8);
    return new NativeImageConsumedInput(
        logical, canonical, ARCHIVE_REFERENCE_ROLE, 0, digest(target));
  }

  /* package */
  /** Returns the stable identity string for this consumed input. */
  public String identity() {
    return frame(role)
        + frame(logicalPath.toString())
        + frame(canonicalPath.toString())
        + frame(Long.toString(byteLength))
        + frame(sha256);
  }

  private static String frame(final String value) {
    return value.length() + ":" + value;
  }

  /* package */
  static String digest(final byte[] bytes) {
    return HexDigest.sha256(bytes);
  }
}
