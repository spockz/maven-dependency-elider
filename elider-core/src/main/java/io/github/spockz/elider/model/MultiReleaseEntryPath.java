// WHY: Centralizes strict parsing of JEP 238 multi-release archive entry paths.

package io.github.spockz.elider.model;

import java.io.IOException;
import java.util.Objects;

/** Parsed JEP 238 {@code META-INF/versions/<release>/<logicalName>} entry path. */
public record MultiReleaseEntryPath(int release, String logicalName) {
  /** Standard JEP 238 versioned-entry directory prefix. */
  public static final String PREFIX = "META-INF/versions/";

  /** Minimum Java feature release supported in versioned JAR entries. */
  public static final int MINIMUM_RELEASE = 9;

  /** Validates fields of a parsed multi-release entry path. */
  public MultiReleaseEntryPath {
    if (release < MINIMUM_RELEASE) {
      throw new IllegalArgumentException(
          "Multi-release version must be at least " + MINIMUM_RELEASE + ": " + release);
    }
    Objects.requireNonNull(logicalName, "logicalName");
  }

  /** Parses a {@code META-INF/versions/<release>/<logicalName>} path. */
  public static MultiReleaseEntryPath parse(final String entryName, final boolean allowDirectory)
      throws IOException {
    if (!entryName.startsWith(PREFIX)) {
      throw new IOException("Malformed multi-release entry: " + entryName);
    }
    final String remainder = entryName.substring(PREFIX.length());
    final int separator = remainder.indexOf('/');
    if (separator < 0 || (separator == remainder.length() - 1 && !allowDirectory)) {
      throw new IOException("Malformed multi-release entry: " + entryName);
    }
    final int release = parseRelease(remainder.substring(0, separator), entryName);
    final String logicalName = remainder.substring(separator + 1);
    return logicalName.isEmpty() ? null : new MultiReleaseEntryPath(release, logicalName);
  }

  private static int parseRelease(final String text, final String entryName) throws IOException {
    final int release;
    try {
      release = Integer.parseInt(text);
    } catch (final NumberFormatException exception) {
      throw new IOException("Malformed multi-release entry: " + entryName, exception);
    }
    if (release < MINIMUM_RELEASE || !Integer.toString(release).equals(text)) {
      throw new IOException("Invalid multi-release version directory: " + entryName);
    }
    return release;
  }
}
