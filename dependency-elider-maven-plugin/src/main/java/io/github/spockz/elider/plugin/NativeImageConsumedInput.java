/* WHY: Binds external Native Image parsing to the exact files prepared for later publication. */

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collection;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;

/** Captured identities for descriptors, sibling data, and archive references. */
/* package */ record NativeImageConsumedInput(
    Path logicalPath, Path canonicalPath, String role, long byteLength, String sha256) {
  /** Distinguishes directory membership snapshots during revalidation. */
  private static final String DIRECTORY_MEMBERSHIP_ROLE = "configuration-directory-membership";

  /** Tracks logical aliases; archive fingerprints separately cover their content. */
  private static final String ARCHIVE_REFERENCE_ROLE = "link-at-build-time-archive-reference";

  NativeImageConsumedInput {
    logicalPath = logicalPath.toAbsolutePath().normalize();
    canonicalPath = canonicalPath.toAbsolutePath().normalize();
    if (role == null || role.isBlank() || sha256 == null || sha256.isBlank() || byteLength < 0) {
      throw new IllegalArgumentException("Invalid consumed native-image input snapshot");
    }
  }

  /* package */
  static List<NativeImageConsumedInput> ordered(final Collection<NativeImageConsumedInput> inputs) {
    return inputs.stream()
        .distinct()
        .sorted(Comparator.comparing(NativeImageConsumedInput::identity))
        .toList();
  }

  /* package */
  static void verifyAll(final Collection<NativeImageConsumedInput> inputs) throws IOException {
    for (final NativeImageConsumedInput input : ordered(inputs)) {
      input.verify();
    }
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
  String identity() {
    return frame(role)
        + frame(logicalPath.toString())
        + frame(canonicalPath.toString())
        + frame(Long.toString(byteLength))
        + frame(sha256);
  }

  private static String frame(final String value) {
    return value.length() + ":" + value;
  }

  private void verify() throws IOException {
    final Path currentCanonical = logicalPath.toRealPath();
    if (!canonicalPath.equals(currentCanonical)) {
      throw new IOException("Native-image input target changed after preparation: " + logicalPath);
    }
    if (DIRECTORY_MEMBERSHIP_ROLE.equals(role)) {
      verifyDirectoryMembership();
      return;
    }
    if (ARCHIVE_REFERENCE_ROLE.equals(role)) {
      verifyArchiveReference(currentCanonical);
      return;
    }
    verifyContent(currentCanonical);
  }

  private void verifyDirectoryMembership() throws IOException {
    final String currentMembership =
        digest(
            NativeImageConfigurationDirectorySupport.membershipBytes(
                NativeImageConfigurationDirectorySupport.membershipEntries(logicalPath)));
    if (!sha256.equals(currentMembership)) {
      throw new IOException(
          "Native-image configuration directory membership changed after preparation: "
              + logicalPath);
    }
  }

  private void verifyArchiveReference(final Path currentCanonical) throws IOException {
    if (!Files.isRegularFile(currentCanonical)) {
      throw new IOException("Native-image archive reference is no longer a file: " + logicalPath);
    }
  }

  private void verifyContent(final Path currentCanonical) throws IOException {
    final String currentDigest = digest(Files.readAllBytes(currentCanonical));
    if (!sha256.equals(currentDigest)) {
      throw new IOException("Native-image input content changed after preparation: " + logicalPath);
    }
  }

  /* package */
  static String digest(final byte[] bytes) {
    try {
      return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    } catch (final NoSuchAlgorithmException exception) {
      throw new AssertionError("SHA-256 is unavailable", exception);
    }
  }
}
