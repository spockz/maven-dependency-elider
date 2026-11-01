/* WHY: Parses OSV's per-ecosystem change index before any cache state is published. */

package io.github.spockz.elider.scanner;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Objects;
import java.util.regex.Pattern;

/** Strict reader for the timestamp,record-ID rows in an ecosystem modified index. */
/* Package access keeps source-feed parsing internal to the cache refresh path. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class OsvModifiedIdReader {
  /** Restricts IDs to safe single-path JSON export names. */
  private final Pattern recordIdPattern;

  /** Creates a reader with the OSV record-ID rule. */
  // The default access modifier keeps parser construction inside the cache package.
  OsvModifiedIdReader() {
    recordIdPattern = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]*");
  }

  /** Reads and validates every row before cache publication. */
  // The default access modifier keeps feed parsing internal to the cache package.
  void read(final InputStream input, final ModifiedIdConsumer consumer) throws IOException {
    Objects.requireNonNull(input, "input");
    Objects.requireNonNull(consumer, "consumer");
    try (BufferedReader lines =
        new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8))) {
      int lineNumber = 0;
      while (true) {
        final String line = lines.readLine();
        if (line == null) {
          break;
        }
        lineNumber++;
        if (line.isEmpty()) {
          continue;
        }
        consumer.accept(parse(line, lineNumber));
      }
    }
  }

  private ModifiedId parse(final String line, final int lineNumber) throws IOException {
    final int delimiter = line.indexOf(',');
    if (delimiter <= 0 || delimiter != line.lastIndexOf(',') || delimiter == line.length() - 1) {
      throw malformed(lineNumber);
    }
    final String modifiedText = line.substring(0, delimiter);
    final String recordId = line.substring(delimiter + 1);
    final Instant modified;
    try {
      modified = Instant.parse(modifiedText);
    } catch (final DateTimeParseException exception) {
      throw new IOException(
          "Malformed OSV modified index timestamp on line " + lineNumber, exception);
    }
    if (!recordIdPattern.matcher(recordId).matches()) {
      throw malformed(lineNumber);
    }
    return new ModifiedId(modified, recordId);
  }

  private static IOException malformed(final int lineNumber) {
    return new IOException("Malformed OSV modified index row on line " + lineNumber);
  }

  /** One validated upstream revision claim. */
  // The default access modifier keeps revision rows internal to the updater.
  record ModifiedId(Instant modified, String recordId) {}

  /** Receives a validated row and may fail the refresh with an I/O error. */
  @FunctionalInterface
  // The default access modifier keeps callbacks internal to cache refresh.
  interface ModifiedIdConsumer {
    /** Handles one source record revision. */
    void accept(ModifiedId row) throws IOException;
  }
}
