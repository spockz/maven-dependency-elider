/* WHY: Centralizes strict parsing of JEP 238 release paths before archive planning. */

package io.github.spockz.elider.trimmer;

import java.io.IOException;

/** Parses canonical versioned-entry paths. */
@SuppressWarnings({"PMD.CommentRequired", "PMD.CommentDefaultAccessModifier"})
final class MultiReleaseVersionedPath {
  private static final String PREFIX = "META-INF/versions/";

  private MultiReleaseVersionedPath() {}

  static MultiReleaseArchivePlan.VersionedPath parse(
      final String entryName, final boolean directory) throws IOException {
    if (!entryName.startsWith(PREFIX)) {
      throw new IOException("Malformed multi-release entry: " + entryName);
    }
    final String remainder = entryName.substring(PREFIX.length());
    final int separator = remainder.indexOf('/');
    if (separator < 0 || (separator == remainder.length() - 1 && !directory)) {
      throw new IOException("Malformed multi-release entry: " + entryName);
    }
    final int release = parseRelease(remainder.substring(0, separator), entryName);
    final String logicalName = remainder.substring(separator + 1);
    return logicalName.isEmpty()
        ? null
        : new MultiReleaseArchivePlan.VersionedPath(release, logicalName);
  }

  private static int parseRelease(final String text, final String entryName) throws IOException {
    final int release;
    try {
      release = Integer.parseInt(text);
    } catch (final NumberFormatException exception) {
      throw new IOException("Malformed multi-release entry: " + entryName, exception);
    }
    if (release < 9 || !Integer.toString(release).equals(text)) {
      throw new IOException("Invalid multi-release version directory: " + entryName);
    }
    return release;
  }
}
