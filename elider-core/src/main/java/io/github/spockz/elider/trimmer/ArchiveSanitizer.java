/* WHY: Writes a per-artifact JAR containing the proven retained classes, preserved resources, and
 * valid manifest data after signature invalidation. */

package io.github.spockz.elider.trimmer;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import org.objectweb.asm.ClassReader;

/** Writes sanitized dependency JARs without merging artifact boundaries. */
@SuppressWarnings({
  "PMD.CyclomaticComplexity",
  "PMD.CognitiveComplexity",
  "PMD.AvoidInstantiatingObjectsInLoops",
  "PMD.AvoidCatchingGenericException"
})
public final class ArchiveSanitizer {
  /** Creates a stateless archive sanitizer. */
  @SuppressWarnings("PMD.UncommentedEmptyConstructor")
  public ArchiveSanitizer() {}

  /** Writes archive content and records input and output hashes. */
  public ArtifactTrimRecord sanitize(
      final Path originalJar,
      final Path trimmedJar,
      final ArtifactCoordinate coordinate,
      final DependencyJarTrimmer.TrimAnalysis analysis)
      throws IOException {
    Objects.requireNonNull(originalJar, "originalJar");
    Objects.requireNonNull(trimmedJar, "trimmedJar");
    Objects.requireNonNull(coordinate, "coordinate");
    Objects.requireNonNull(analysis, "analysis");
    if (!Files.isRegularFile(originalJar)) {
      throw new IOException("Original dependency is not a regular JAR file: " + originalJar);
    }
    if (analysis.retainedClasses().size() > analysis.totalClasses()) {
      throw new IOException("Trim analysis has more retained classes than total classes");
    }

    final ArtifactDigests originalDigests = ArtifactDigests.read(originalJar);
    final Path parent = trimmedJar.toAbsolutePath().normalize().getParent();
    final Path fileName = trimmedJar.getFileName();
    if (parent == null || fileName == null) {
      throw new IOException("Trimmed JAR path has no parent directory: " + trimmedJar);
    }
    Files.createDirectories(parent);
    final Path outputDirectory = parent.toRealPath();
    final Path outputPath = outputDirectory.resolve(fileName.toString());
    final Path originalPath = originalJar.toRealPath();
    if (outputPath.equals(originalPath)
        || (Files.exists(outputPath) && Files.isSameFile(originalPath, outputPath))) {
      throw new IOException("Trimmed JAR must not overwrite its original: " + originalJar);
    }
    final Path temporaryJar = Files.createTempFile(outputDirectory, ".trimmed-", ".jar.tmp");
    boolean moved = false;
    try {
      writeArchive(originalJar, temporaryJar, analysis);
      if (!originalDigests.equals(ArtifactDigests.read(originalJar))) {
        throw new IOException("Original dependency changed while being trimmed: " + originalJar);
      }
      moveIntoPlace(temporaryJar, outputPath);
      moved = true;
    } finally {
      if (!moved) {
        Files.deleteIfExists(temporaryJar);
      }
    }
    final ArtifactDigests trimmedDigests = ArtifactDigests.read(trimmedJar);
    return new ArtifactTrimRecord(
        coordinate,
        originalPath,
        originalDigests.sha256(),
        originalDigests.sha1(),
        outputPath,
        trimmedDigests.sha256(),
        trimmedDigests.sha1(),
        analysis.totalClasses(),
        analysis.retainedClasses().size());
  }

  private static void writeArchive(
      final Path originalJar,
      final Path temporaryJar,
      final DependencyJarTrimmer.TrimAnalysis analysis)
      throws IOException {
    final Set<String> retainedClasses = new HashSet<>(analysis.retainedClasses());
    final Set<String> seenNames = new HashSet<>();
    final Set<String> writtenClasses = new HashSet<>();
    final Set<String> inputClasses = new HashSet<>();
    try (JarFile input = new JarFile(originalJar.toFile());
        OutputStream fileOutput = Files.newOutputStream(temporaryJar);
        JarOutputStream output = new JarOutputStream(fileOutput)) {
      final Enumeration<JarEntry> entries = input.entries();
      while (entries.hasMoreElements()) {
        final JarEntry entry = entries.nextElement();
        final String name = entry.getName();
        if (!seenNames.add(name)) {
          throw new IOException("Duplicate archive entry cannot be preserved safely: " + name);
        }
        if (entry.isDirectory()) {
          writeEntry(input, output, entry);
          continue;
        }
        if (JarSignatureSanitizer.isSignatureFile(name)) {
          continue;
        }
        if (JarSignatureSanitizer.isManifest(name)) {
          final Manifest manifest;
          try (InputStream manifestInput = input.getInputStream(entry)) {
            manifest = new Manifest(manifestInput);
          }
          JarSignatureSanitizer.cleanse(manifest);
          JarSignatureSanitizer.writeManifest(output, entry, manifest);
          continue;
        }
        if (DependencyJarTrimmer.isVersionedModuleDescriptor(name)) {
          continue;
        }
        if (name.endsWith(".class")) {
          if ("module-info.class".equals(name) || name.startsWith("META-INF/versions/")) {
            throw new IOException("Unsupported modular or multi-release entry: " + name);
          }
          final String className;
          try (InputStream classInput = input.getInputStream(entry)) {
            className = new ClassReader(classInput).getClassName();
          } catch (final RuntimeException exception) {
            throw new IOException("Could not read class entry: " + name, exception);
          }
          if (!name.equals(className + ".class")) {
            throw new IOException("Class entry path does not match its declared name: " + name);
          }
          inputClasses.add(className);
          if (!retainedClasses.contains(className)) {
            continue;
          }
          writtenClasses.add(className);
        }
        writeEntry(input, output, entry);
      }
    }
    if (!inputClasses.containsAll(retainedClasses)) {
      final Set<String> missing = new HashSet<>(retainedClasses);
      missing.removeAll(inputClasses);
      throw new IOException(
          "Trim analysis references classes missing from original JAR: " + missing);
    }
    if (!writtenClasses.equals(retainedClasses)) {
      throw new IOException("Not all retained classes were written to the trimmed JAR");
    }
    if (inputClasses.size() != analysis.totalClasses()) {
      throw new IOException("Trim analysis class count does not match original JAR entries");
    }
  }

  private static void writeEntry(
      final JarFile input, final JarOutputStream output, final JarEntry entry) throws IOException {
    final JarEntry copy = new JarEntry(entry.getName());
    if (entry.getTime() >= 0) {
      copy.setTime(entry.getTime());
    }
    if (entry.getComment() != null) {
      copy.setComment(entry.getComment());
    }
    output.putNextEntry(copy);
    if (!entry.isDirectory()) {
      try (InputStream entryInput = input.getInputStream(entry)) {
        entryInput.transferTo(output);
      }
    }
    output.closeEntry();
  }

  private static void moveIntoPlace(final Path temporaryJar, final Path trimmedJar)
      throws IOException {
    try {
      Files.move(
          temporaryJar,
          trimmedJar,
          StandardCopyOption.ATOMIC_MOVE,
          StandardCopyOption.REPLACE_EXISTING);
    } catch (final AtomicMoveNotSupportedException exception) {
      throw new IOException(
          "Filesystem cannot atomically publish the trimmed JAR: " + trimmedJar, exception);
    }
  }
}
