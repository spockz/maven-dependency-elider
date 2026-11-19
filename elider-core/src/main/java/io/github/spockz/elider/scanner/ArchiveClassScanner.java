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

  /** Opens a reusable scanner session backed by a single {@link JarFile}. */
  public static Session open(final Path archivePath) throws IOException {
    if (archivePath == null || !Files.isRegularFile(archivePath)) {
      throw new IOException("Bytecode archive is missing or not a regular file: " + archivePath);
    }
    final Path scope = archivePath.toAbsolutePath().normalize();
    return new Session(scope, new JarFile(scope.toFile()));
  }

  /** Scans selected internal class names in a JAR without retaining class bytes. */
  public static Map<String, Set<String>> scanSelected(
      final Path archivePath, final Set<String> selectedInternalNames) throws IOException {
    if (selectedInternalNames == null || selectedInternalNames.isEmpty()) {
      if (archivePath == null || !Files.isRegularFile(archivePath)) {
        throw new IOException("Bytecode archive is missing or not a regular file: " + archivePath);
      }
      return Map.of();
    }
    try (Session session = open(archivePath)) {
      return session.scanSelected(selectedInternalNames);
    }
  }

  /** Reusable archive scanner keeping one {@link JarFile} open across frontier scans. */
  public static final class Session implements AutoCloseable {
    /** Normalized archive path for diagnostic messages. */
    private final Path scope;

    /** Open archive handle shared across scans. */
    private final JarFile archive;

    private Session(final Path scope, final JarFile archive) {
      this.scope = scope;
      this.archive = archive;
    }

    /** Scans selected base internal class names in the open archive. */
    public Map<String, Set<String>> scanSelected(final Set<String> selectedInternalNames)
        throws IOException {
      if (selectedInternalNames == null || selectedInternalNames.isEmpty()) {
        return Map.of();
      }
      final Map<String, Set<String>> byClass = HashMap.newHashMap(selectedInternalNames.size());
      if (selectedInternalNames.size() <= DIRECT_LOOKUP_THRESHOLD) {
        scanByLookup(archive, scope, selectedInternalNames, byClass);
      } else {
        scanByStream(archive, scope, selectedInternalNames, byClass);
      }
      return byClass;
    }

    @Override
    public void close() throws IOException {
      archive.close();
    }
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
      final String name = entry.getName();
      if (entry.isDirectory()
          || !name.endsWith(CLASS_SUFFIX)
          || name.startsWith(MultiReleaseEntryPath.PREFIX)) {
        continue;
      }
      final String internalName = name.substring(0, name.length() - CLASS_SUFFIX.length());
      if (selectedInternalNames.contains(internalName)) {
        byClass.put(internalName, scanEntryNonDebug(archive, scope, entry));
      }
    }
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
