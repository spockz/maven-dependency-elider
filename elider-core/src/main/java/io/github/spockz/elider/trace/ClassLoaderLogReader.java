/* WHY: Extracts successfully loaded class names from JVM unified class loading logs for runtime
 * reachability evidence. */

package io.github.spockz.elider.trace;

import io.github.spockz.elider.model.TraceData;
import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Reads class names from JVM {@code -Xlog:class+load} output.
 *
 * <p>Also accepts a plain list of class names.
 */
public final class ClassLoaderLogReader implements RuntimeTraceReader {
  /** Matches the class name field in unified logging entries. */
  private static final Pattern CLASS_LOAD_MARKER = Pattern.compile("\\[class,load](.*)$");

  /** Extracts the first field after the unified log class-load marker. */
  private static final Pattern CLASS_LOAD_NAME = Pattern.compile("^\\s*([^\\s]+)");

  /** Creates a reader for JVM class loading log files. */
  @SuppressWarnings("PMD.UncommentedEmptyConstructor")
  public ClassLoaderLogReader() {}

  /** Recognizes common text log suffixes. */
  @Override
  public boolean supports(final Path path) {
    return supportedFileName(path) != null;
  }

  /** Reads standard unified log entries and valid raw class-name lines. */
  @Override
  public TraceData read(final Path path) throws IOException {
    if (!supports(path)) {
      throw new IOException("Unsupported class loading log file: " + path);
    }
    final Set<String> classes = new HashSet<>();
    final boolean unifiedLog = hasClassLoadMarker(path);
    try (BufferedReader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
      if (unifiedLog) {
        readUnifiedLog(reader, path, classes);
      } else {
        readRawList(reader, path, classes);
      }
    }
    return TraceData.of(classes);
  }

  private static void readRawList(
      final BufferedReader reader, final Path path, final Set<String> classes) throws IOException {
    boolean hasClassName = false;
    while (true) {
      final String line = reader.readLine();
      if (line == null) {
        break;
      }
      if (!line.isBlank()) {
        if (!addClassName(line.trim(), classes)) {
          throw new IOException("Malformed raw class name in class list: " + line);
        }
        hasClassName = true;
      }
    }
    if (!hasClassName) {
      throw new IOException("No class names found in raw class list: " + path);
    }
  }

  private static void readUnifiedLog(
      final BufferedReader reader, final Path path, final Set<String> classes) throws IOException {
    boolean hasClassLoadRecord = false;
    while (true) {
      final String line = reader.readLine();
      if (line == null) {
        break;
      }
      final Matcher marker = CLASS_LOAD_MARKER.matcher(line);
      if (marker.find()) {
        addClassLoadRecord(marker.group(1), line, classes);
        hasClassLoadRecord = true;
      } else {
        addRawClassNameIfValid(line.trim(), classes);
      }
    }
    if (!hasClassLoadRecord) {
      throw new IOException("No class-load entries found in class loading log: " + path);
    }
  }

  private static void addClassLoadRecord(
      final String payload, final String line, final Set<String> classes) throws IOException {
    final Matcher className = CLASS_LOAD_NAME.matcher(payload);
    if (!className.find() || !addClassName(className.group(1), classes)) {
      throw new IOException("Malformed class name in class loading log: " + line);
    }
  }

  private static void addRawClassNameIfValid(final String candidate, final Set<String> classes) {
    if (TraceClassName.isValid(candidate) && !TraceClassName.isHidden(candidate)) {
      classes.add(candidate);
    }
  }

  private static boolean hasClassLoadMarker(final Path path) throws IOException {
    try (BufferedReader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
      while (true) {
        final String line = reader.readLine();
        if (line == null) {
          return false;
        }
        if (CLASS_LOAD_MARKER.matcher(line).find()) {
          return true;
        }
      }
    }
  }

  private static String supportedFileName(final Path path) {
    if (path == null) {
      return null;
    }
    final Path fileName = path.getFileName();
    if (fileName == null) {
      return null;
    }
    final String name = fileName.toString().toLowerCase(Locale.ROOT);
    return name.endsWith(".log") || name.endsWith(".txt") ? name : null;
  }

  private static boolean addClassName(final String candidate, final Set<String> classes) {
    if (!TraceClassName.isValid(candidate)) {
      return false;
    }
    if (!TraceClassName.isHidden(candidate)) {
      classes.add(candidate);
    }
    return true;
  }
}
