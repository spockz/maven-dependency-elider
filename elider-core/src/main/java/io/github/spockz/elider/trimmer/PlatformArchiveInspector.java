/* WHY: Validates captured platform inventories before publication.
 * It avoids parsing class declarations. */

package io.github.spockz.elider.trimmer;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/** Checks captured JDK archive selection and inventory metadata. */
@SuppressWarnings({"PMD.CyclomaticComplexity", "PMD.CommentDefaultAccessModifier"})
final class PlatformArchiveInspector {
  private PlatformArchiveInspector() {}

  static List<String> selectedSignatures(
      final JdkPlatformContext.CapturedFile source, final int release) throws IOException {
    final String releaseCode = releaseCode(release);
    final List<String> signatures = new ArrayList<>();
    final Set<String> selectedNames = new LinkedHashSet<>();
    try (ZipInputStream archive = new ZipInputStream(source.openStream())) {
      while (true) {
        final ZipEntry entry = archive.getNextEntry();
        if (entry == null) {
          break;
        }
        final String entryName = entry.getName();
        final String[] pathParts = entryName.split("/", 3);
        if (pathParts.length != 3
            || !pathParts[0].contains(releaseCode)
            || !pathParts[2].endsWith(".sig")) {
          archive.closeEntry();
          continue;
        }
        final String internalName = pathParts[2].substring(0, pathParts[2].length() - 4);
        if (internalName.endsWith("module-info")) {
          archive.closeEntry();
          continue;
        }
        if (!selectedNames.add(internalName)) {
          throw new IOException(
              "Multiple ct.sym signatures match Java " + release + " for class " + internalName);
        }
        signatures.add(entryName);
        archive.closeEntry();
      }
    } catch (final java.util.zip.ZipException exception) {
      throw new IOException(
          "Could not read captured JDK API archive: " + source.sourcePath(), exception);
    }
    return List.copyOf(signatures);
  }

  static int collectJmodClasses(
      final JdkPlatformContext.CapturedFile module, final Set<String> knownClasses)
      throws IOException {
    int count = 0;
    try (ZipInputStream archive = new ZipInputStream(module.openJmodStream())) {
      while (true) {
        final ZipEntry entry = archive.getNextEntry();
        if (entry == null) {
          break;
        }
        final String entryName = entry.getName();
        if (!entryName.startsWith("classes/") || !entryName.endsWith(".class")) {
          archive.closeEntry();
          continue;
        }
        final String className =
            entryName.substring("classes/".length(), entryName.length() - ".class".length());
        if (className.endsWith("module-info")) {
          archive.closeEntry();
          continue;
        }
        if (!knownClasses.add(className)) {
          throw new IOException("Duplicate runtime JDK class in captured jmods: " + className);
        }
        count++;
        archive.closeEntry();
      }
    } catch (final java.util.zip.ZipException exception) {
      throw new IOException(
          "Could not read captured JDK module archive: " + module.sourcePath(), exception);
    }
    return count;
  }

  static int readJdkRelease(final JdkPlatformContext.CapturedFile releaseFile) throws IOException {
    try (BufferedReader lines =
        new BufferedReader(
            new InputStreamReader(releaseFile.openStream(), StandardCharsets.UTF_8))) {
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
          throw new IOException("Invalid JAVA_VERSION in captured release metadata", exception);
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
