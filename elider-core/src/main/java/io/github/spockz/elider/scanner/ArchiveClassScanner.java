/* WHY: Scans selected JAR entries on demand without retaining class bytes. */

package io.github.spockz.elider.scanner;

import io.github.spockz.elider.model.MultiReleaseEntryPath;
import io.github.spockz.elider.model.TraceData;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import org.objectweb.asm.ClassReader;

/** Scans selected internal classes in a JAR without retaining byte arrays. */
public final class ArchiveClassScanner {
  /** Class file entry suffix. */
  private static final String CLASS_SUFFIX = ".class";

  /** Lookup count threshold before switching to a sequential scan. */
  private static final int DIRECT_LOOKUP_THRESHOLD = 64;

  private ArchiveClassScanner() {}

  /** Scans selected internal class names in a JAR without retaining class bytes. */
  public static Map<String, Set<String>> scanSelected(
      final Path archivePath, final Set<String> selectedInternalNames) throws IOException {
    if (archivePath == null || !Files.isRegularFile(archivePath)) {
      throw new IOException("Bytecode archive is missing or not a regular file: " + archivePath);
    }
    if (selectedInternalNames == null || selectedInternalNames.isEmpty()) {
      return Map.of();
    }
    final Path scope = archivePath.toAbsolutePath().normalize();
    final Map<String, Set<String>> byClass = HashMap.newHashMap(selectedInternalNames.size());
    try (JarFile archive = new JarFile(scope.toFile())) {
      if (selectedInternalNames.size() <= DIRECT_LOOKUP_THRESHOLD) {
        scanByLookup(archive, scope, selectedInternalNames, byClass);
      } else {
        scanByStream(archive, scope, selectedInternalNames, byClass);
      }
    }
    return byClass;
  }

  private static void scanByLookup(
      final JarFile archive,
      final Path scope,
      final Set<String> selectedInternalNames,
      final Map<String, Set<String>> byClass)
      throws IOException {
    for (final String internalName : selectedInternalNames) {
      final JarEntry entry = archive.getJarEntry(internalName + CLASS_SUFFIX);
      if (entry != null && !entry.isDirectory()) {
        byClass.put(internalName, scanEntryNonDebug(archive, scope, entry));
      }
    }
  }

  private static void scanByStream(
      final JarFile archive,
      final Path scope,
      final Set<String> selectedInternalNames,
      final Map<String, Set<String>> byClass)
      throws IOException {
    for (final JarEntry entry : archive.stream().toList()) {
      if (entry.isDirectory() || !entry.getName().endsWith(CLASS_SUFFIX)) {
        continue;
      }
      final String logicalName = logicalClassEntryName(entry.getName());
      final String internalName =
          logicalName.substring(0, logicalName.length() - CLASS_SUFFIX.length());
      if (selectedInternalNames.contains(internalName)) {
        byClass.put(internalName, scanEntryNonDebug(archive, scope, entry));
      }
    }
  }

  private static String logicalClassEntryName(final String entryName) throws IOException {
    if (!entryName.startsWith(MultiReleaseEntryPath.PREFIX)) {
      return entryName;
    }
    return MultiReleaseEntryPath.parse(entryName, false).logicalName();
  }

  @SuppressWarnings("PMD.AvoidCatchingGenericException")
  private static Set<String> scanEntryNonDebug(
      final JarFile archive, final Path scope, final JarEntry entry) throws IOException {
    final Set<String> references = new HashSet<>();
    try (InputStream input = archive.getInputStream(entry)) {
      new ClassReader(input)
          .accept(
              new AsmClassReferenceVisitor(
                  scope.resolve(entry.getName()).toString(),
                  true,
                  (internalName, kind) -> {
                    if (kind != AsmClassReferenceVisitor.ReferenceKind.DEBUG_METADATA) {
                      references.add(TraceData.normalizeToDot(internalName));
                    }
                  }),
              0);
    } catch (final RuntimeException exception) {
      throw new IOException(
          "Could not scan production class file: " + scope.resolve(entry.getName()), exception);
    }
    return Set.copyOf(references);
  }
}
