/* WHY: Keeps ordinary single-release JAR entry copying separate from staging and publication. */

package io.github.spockz.elider.trimmer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import java.util.zip.ZipFile;
import org.objectweb.asm.ClassReader;

/** Writes the retained root view of an ordinary JAR. */
@SuppressWarnings({"PMD.CommentRequired", "PMD.CommentDefaultAccessModifier"})
final class SingleReleaseArchiveWriter {
  private SingleReleaseArchiveWriter() {}

  static long write(
      final Path originalJar,
      final Path temporaryJar,
      final DependencyJarTrimmer.TrimAnalysis analysis)
      throws IOException {
    final Set<String> retainedClasses = new HashSet<>(analysis.retainedClasses());
    final Set<String> seenNames = new HashSet<>();
    final Set<String> writtenClasses = new HashSet<>();
    final Set<String> inputClasses = new HashSet<>();
    final PrunedClassByteCounter prunedClassBytes = new PrunedClassByteCounter();
    try (JarFile input = new JarFile(originalJar.toFile());
        OutputStream fileOutput = Files.newOutputStream(temporaryJar);
        JarOutputStream output = new JarOutputStream(fileOutput)) {
      final Enumeration<JarEntry> entries = input.entries();
      while (entries.hasMoreElements()) {
        writeEntry(
            input,
            output,
            entries.nextElement(),
            retainedClasses,
            seenNames,
            writtenClasses,
            inputClasses,
            prunedClassBytes);
      }
    }
    verifyClasses(inputClasses, writtenClasses, retainedClasses, analysis.totalClasses());
    return prunedClassBytes.value();
  }

  static int countEntries(final Path archivePath) throws IOException {
    int count = 0;
    try (ZipFile archive = new ZipFile(archivePath.toFile())) {
      final Enumeration<? extends java.util.zip.ZipEntry> entries = archive.entries();
      while (entries.hasMoreElements()) {
        entries.nextElement();
        count = Math.addExact(count, 1);
      }
    } catch (final ArithmeticException exception) {
      throw new IOException("Archive entry count overflowed: " + archivePath, exception);
    }
    return count;
  }

  private static void writeEntry(
      final JarFile input,
      final JarOutputStream output,
      final JarEntry entry,
      final Set<String> retainedClasses,
      final Set<String> seenNames,
      final Set<String> writtenClasses,
      final Set<String> inputClasses,
      final PrunedClassByteCounter prunedClassBytes)
      throws IOException {
    final String name = entry.getName();
    if (!seenNames.add(name)) {
      throw new IOException("Duplicate archive entry cannot be preserved safely: " + name);
    }
    if (entry.isDirectory()) {
      copyEntry(input, output, entry);
    } else if (!JarSignatureSanitizer.isSignatureFile(name)) {
      writeNonSignatureEntry(
          input, output, entry, retainedClasses, writtenClasses, inputClasses, prunedClassBytes);
    }
  }

  private static void writeNonSignatureEntry(
      final JarFile input,
      final JarOutputStream output,
      final JarEntry entry,
      final Set<String> retainedClasses,
      final Set<String> writtenClasses,
      final Set<String> inputClasses,
      final PrunedClassByteCounter prunedClassBytes)
      throws IOException {
    final String name = entry.getName();
    if (JarSignatureSanitizer.isManifest(name)) {
      writeManifest(input, output, entry);
    } else if (!DependencyJarTrimmer.isVersionedModuleDescriptor(name)) {
      writeClassOrResource(
          input, output, entry, retainedClasses, writtenClasses, inputClasses, prunedClassBytes);
    }
  }

  private static void writeClassOrResource(
      final JarFile input,
      final JarOutputStream output,
      final JarEntry entry,
      final Set<String> retainedClasses,
      final Set<String> writtenClasses,
      final Set<String> inputClasses,
      final PrunedClassByteCounter prunedClassBytes)
      throws IOException {
    if (!entry.getName().endsWith(".class")) {
      copyEntry(input, output, entry);
      return;
    }
    final String name = entry.getName();
    if ("module-info.class".equals(name) || name.startsWith("META-INF/versions/")) {
      throw new IOException("Unsupported modular or multi-release entry: " + name);
    }
    writeClass(
        input, output, entry, retainedClasses, writtenClasses, inputClasses, prunedClassBytes);
  }

  private static void writeClass(
      final JarFile input,
      final JarOutputStream output,
      final JarEntry entry,
      final Set<String> retainedClasses,
      final Set<String> writtenClasses,
      final Set<String> inputClasses,
      final PrunedClassByteCounter prunedClassBytes)
      throws IOException {
    final String name = entry.getName();
    final String className;
    try (InputStream classInput = input.getInputStream(entry)) {
      className = new ClassReader(classInput).getClassName();
    } catch (final IllegalArgumentException | IndexOutOfBoundsException exception) {
      throw new IOException("Could not read class entry: " + name, exception);
    }
    if (!name.equals(className + ".class")) {
      throw new IOException("Class entry path does not match its declared name: " + name);
    }
    inputClasses.add(className);
    if (!retainedClasses.contains(className)) {
      prunedClassBytes.add(entry);
      return;
    }
    writtenClasses.add(className);
    copyEntry(input, output, entry);
  }

  private static void writeManifest(
      final JarFile input, final JarOutputStream output, final JarEntry entry) throws IOException {
    final Manifest manifest;
    try (InputStream manifestInput = input.getInputStream(entry)) {
      manifest = new Manifest(manifestInput);
    }
    JarSignatureSanitizer.cleanse(manifest);
    JarSignatureSanitizer.writeManifest(output, entry, manifest);
  }

  private static void copyEntry(
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
      try (InputStream contents = input.getInputStream(entry)) {
        contents.transferTo(output);
      }
    }
    output.closeEntry();
  }

  private static void verifyClasses(
      final Set<String> inputClasses,
      final Set<String> writtenClasses,
      final Set<String> retainedClasses,
      final int totalClasses)
      throws IOException {
    if (!inputClasses.containsAll(retainedClasses)) {
      final Set<String> missing = new HashSet<>(retainedClasses);
      missing.removeAll(inputClasses);
      throw new IOException(
          "Trim analysis references classes missing from original JAR: " + missing);
    }
    if (!writtenClasses.equals(retainedClasses)) {
      throw new IOException("Not all retained classes were written to the trimmed JAR");
    }
    if (inputClasses.size() != totalClasses) {
      throw new IOException("Trim analysis class count does not match original JAR entries");
    }
  }

  private static final class PrunedClassByteCounter {
    private long totalBytes;

    private void add(final JarEntry entry) throws IOException {
      if (entry.getSize() < 0) {
        throw new IOException("Class entry has unknown uncompressed size: " + entry.getName());
      }
      try {
        totalBytes = Math.addExact(totalBytes, entry.getSize());
      } catch (final ArithmeticException exception) {
        throw new IOException("Pruned class byte total overflowed", exception);
      }
    }

    private long value() {
      return totalBytes;
    }
  }
}
