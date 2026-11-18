/* WHY: Separates direct symbolic references in production bytecode from runtime observations so
 * callers can compare these independent evidence sources. */

package io.github.spockz.elider.scanner;

import io.github.spockz.elider.model.TraceData;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.stream.Stream;
import org.objectweb.asm.ClassReader;

/** Scans class files beneath a caller supplied production output directory. */
public final class ProductionBytecodeReferenceScanner {
  /** The class-file suffix shared by directory and archive scans. */
  private static final String CLASS_SUFFIX = ".class";

  /** Creates a production class reference scanner. */
  public ProductionBytecodeReferenceScanner() {
    // Stateless scanner.
  }

  /** Scans all supplied class files and fails if the scan cannot complete. */
  public BytecodeReferenceScan scan(final Path productionOutput) throws IOException {
    if (productionOutput == null || !Files.isDirectory(productionOutput)) {
      throw new IOException(
          "Production class output directory is missing or not a directory: " + productionOutput);
    }
    final Path scope = productionOutput.toAbsolutePath().normalize();
    final Set<String> references = new HashSet<>();
    int count = 0;
    try (Stream<Path> paths = Files.walk(scope)) {
      for (final Path classFile : paths.sorted().toList()) {
        count += scanPath(classFile, references);
      }
    }
    return new BytecodeReferenceScan(scope, references, count, true);
  }

  /** Scans every class entry in a JAR, including each multi-release tier. */
  // Malformed class bytes must fail this input scan as an IOException.
  public BytecodeReferenceScan scanArchive(final Path archivePath) throws IOException {
    return scanArchive(archivePath, className -> true);
  }

  /** Scans retained classes across all JAR tiers, including MRJAR entries. */
  public BytecodeReferenceScan scanArchive(
      final Path archivePath, final Set<String> retainedInternalNames) throws IOException {
    if (retainedInternalNames == null) {
      throw new IllegalArgumentException("retainedInternalNames must not be null");
    }
    return scanArchive(archivePath, retainedInternalNames::contains);
  }

  private BytecodeReferenceScan scanArchive(
      final Path archivePath, final java.util.function.Predicate<String> selectedClass)
      throws IOException {
    if (archivePath == null || !Files.isRegularFile(archivePath)) {
      throw new IOException("Bytecode archive is missing or not a regular file: " + archivePath);
    }
    final Path scope = archivePath.toAbsolutePath().normalize();
    final Set<String> references = new HashSet<>();
    int count = 0;
    try (JarFile archive = new JarFile(scope.toFile())) {
      for (final JarEntry entry : archive.stream().toList()) {
        count += scanArchiveEntry(archive, scope, entry, selectedClass, references);
      }
    }
    return new BytecodeReferenceScan(scope, references, count, true);
  }

  private static int scanArchiveEntry(
      final JarFile archive,
      final Path scope,
      final JarEntry entry,
      final java.util.function.Predicate<String> selectedClass,
      final Set<String> references)
      throws IOException {
    if (entry.isDirectory() || !entry.getName().endsWith(CLASS_SUFFIX)) {
      return 0;
    }
    final String logicalName = logicalClassEntryName(entry.getName());
    final String internalName =
        logicalName.substring(0, logicalName.length() - CLASS_SUFFIX.length());
    if (!selectedClass.test(internalName)) {
      return 0;
    }
    try (java.io.InputStream input = archive.getInputStream(entry)) {
      return scanClassStream(scope.resolve(entry.getName()), input, references);
    }
  }

  // Each malformed version-path form is rejected before class selection.
  private static String logicalClassEntryName(final String entryName) throws IOException {
    if (!entryName.startsWith(io.github.spockz.elider.model.MultiReleaseEntryPath.PREFIX)) {
      return entryName;
    }
    return io.github.spockz.elider.model.MultiReleaseEntryPath.parse(entryName, false)
        .logicalName();
  }

  private static int scanPath(final Path path, final Set<String> references) throws IOException {
    final Path fileName = path.getFileName();
    if (!Files.isRegularFile(path) || fileName == null || !fileName.toString().endsWith(".class")) {
      return 0;
    }
    return scanClassFile(path, Files.readAllBytes(path), references);
  }

  /* package */
  @SuppressWarnings("PMD.AvoidCatchingGenericException")
  // ASM reports malformed class structures as unchecked exceptions.
  static int scanClassFile(final Path path, final byte[] content, final Set<String> references)
      throws IOException {
    try {
      scanReader(path, new ClassReader(content), references);
    } catch (final RuntimeException exception) {
      throw new IOException("Could not scan production class file: " + path, exception);
    }
    return 1;
  }

  @SuppressWarnings("PMD.AvoidCatchingGenericException")
  private static int scanClassStream(
      final Path path, final java.io.InputStream input, final Set<String> references)
      throws IOException {
    try {
      scanReader(path, new ClassReader(input), references);
    } catch (final RuntimeException exception) {
      throw new IOException("Could not scan production class file: " + path, exception);
    }
    return 1;
  }

  private static void scanReader(
      final Path path, final ClassReader reader, final Set<String> references) {
    reader.accept(
        new AsmClassReferenceVisitor(
            path.toString(),
            true,
            (internalName, unusedKind) -> references.add(TraceData.normalizeToDot(internalName))),
        0);
  }
}
