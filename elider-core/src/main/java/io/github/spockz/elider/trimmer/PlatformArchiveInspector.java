/* WHY: Determines platform source selection from ZIP central directories without retaining archive
 * bytes or decompressing class entries just to form cache identity. */

package io.github.spockz.elider.trimmer;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
import java.util.zip.ZipFile;

/** Checks JDK archive selection and release metadata. */
@SuppressWarnings({"PMD.CyclomaticComplexity", "PMD.CommentDefaultAccessModifier"})
final class PlatformArchiveInspector {
  /** JMOD's four-byte prefix before the ZIP structures. */
  private static final byte[] JMOD_HEADER = {'J', 'M', 1, 0};

  private PlatformArchiveInspector() {}

  static List<String> selectedSignatures(final Path source, final int release) throws IOException {
    final String releaseCode = releaseCode(release);
    final List<String> signatures = new ArrayList<>();
    final Set<String> selectedNames = new LinkedHashSet<>();
    try (ZipFile archive = new ZipFile(source.toFile())) {
      final Enumeration<? extends ZipEntry> entries = archive.entries();
      while (entries.hasMoreElements()) {
        final String entryName = entries.nextElement().getName();
        final String[] pathParts = entryName.split("/", 3);
        if (pathParts.length != 3
            || !pathParts[0].contains(releaseCode)
            || !pathParts[2].endsWith(".sig")) {
          continue;
        }
        final String internalName = pathParts[2].substring(0, pathParts[2].length() - 4);
        if (internalName.endsWith("module-info")) {
          continue;
        }
        if (!selectedNames.add(internalName)) {
          throw new IOException(
              "Multiple ct.sym signatures match Java " + release + " for class " + internalName);
        }
        signatures.add(entryName);
      }
    } catch (final ZipException exception) {
      throw new IOException("Could not inspect JDK API archive: " + source, exception);
    }
    return List.copyOf(signatures);
  }

  static void validateJmodHeader(final Path source) throws IOException {
    final byte[] header;
    try (InputStream input = Files.newInputStream(source)) {
      header = input.readNBytes(JMOD_HEADER.length);
    }
    if (!java.util.Arrays.equals(header, JMOD_HEADER)) {
      throw new IOException("Invalid JMOD header: " + source);
    }
  }

  static int readJdkRelease(final Path releaseFile) throws IOException {
    try (BufferedReader lines = Files.newBufferedReader(releaseFile, StandardCharsets.UTF_8)) {
      while (true) {
        final String line = lines.readLine();
        if (line == null) {
          break;
        }
        if (!line.startsWith("JAVA_VERSION=\"")) {
          continue;
        }
        final String version = line.substring("JAVA_VERSION=\"".length()).replace("\"", "");
        final int separator = version.indexOf('.');
        final String feature = separator < 0 ? version : version.substring(0, separator);
        try {
          return Integer.parseInt(feature);
        } catch (final NumberFormatException exception) {
          throw new IOException("Invalid JAVA_VERSION in JDK release metadata", exception);
        }
      }
    }
    return -1;
  }

  static boolean isJmod(final Path path) {
    final Path fileName = path.getFileName();
    return Files.isRegularFile(path) && fileName != null && fileName.toString().endsWith(".jmod");
  }

  private static String releaseCode(final int release) {
    return release <= 9
        ? Integer.toString(release)
        : Character.toString((char) ('A' + release - 10));
  }
}
