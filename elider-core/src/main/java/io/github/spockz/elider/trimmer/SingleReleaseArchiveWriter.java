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
final class SingleReleaseArchiveWriter {
  /** WHY: Names separate ordinary entries from transformation metadata. */
  private static final String MODULE_DESCRIPTOR = "module-info.class";

  /** WHY: Routes versioned entries outside the ordinary class view. */
  private static final String VERSIONED_PREFIX = "META-INF/versions/";

  /** WHY: Shared suffix for physical class entry parsing. */
  private static final String CLASS_SUFFIX = ".class";

  /** WHY: Root service files carry global provider declarations. */
  private static final String SERVICE_PREFIX = "META-INF/services/";

  private SingleReleaseArchiveWriter() {}

  /* default */ static WriteResult write(
      final Path originalJar,
      final Path temporaryJar,
      final DependencyJarTrimmer.TrimAnalysis analysis)
      throws IOException {
    return write(originalJar, temporaryJar, analysis, false);
  }

  /* default */ static WriteResult write(
      final Path originalJar,
      final Path temporaryJar,
      final DependencyJarTrimmer.TrimAnalysis analysis,
      final boolean stripRootModuleDescriptor)
      throws IOException {
    return write(originalJar, temporaryJar, analysis, stripRootModuleDescriptor, Set.of());
  }

  /* default */ static WriteResult write(
      final Path originalJar,
      final Path temporaryJar,
      final DependencyJarTrimmer.TrimAnalysis analysis,
      final boolean stripRootModuleDescriptor,
      final Set<String> removedServiceProviders)
      throws IOException {
    final EntryWriter writer =
        new EntryWriter(analysis, stripRootModuleDescriptor, removedServiceProviders);
    try (JarFile input = new JarFile(originalJar.toFile())) {
      writer.scanInput(input);
      try (OutputStream fileOutput = Files.newOutputStream(temporaryJar);
          JarOutputStream output = new JarOutputStream(fileOutput)) {
        writer.writeEntries(input, output);
      }
    }
    writer.verify(analysis.totalClasses());
    return writer.result();
  }

  /** Class metrics from a physical single-release write. */
  /* default */ record WriteResult(long prunedClassBytes, int totalClasses, int retainedClasses) {}

  /* default */ static int countEntries(final Path archivePath) throws IOException {
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

  /** WHY: Keeps mutable entry state scoped to one archive write. */
  private static final class EntryWriter {
    /** WHY: These classes are the prepared output's preservation contract. */
    private final Set<String> retainedClasses;

    /** WHY: Duplicate physical names cannot be emitted safely. */
    private final Set<String> seenNames = new HashSet<>();

    /** WHY: Verifies the bytes match the prepared preservation contract. */
    private final Set<String> writtenClasses = new HashSet<>();

    /** WHY: Root classes drive resource filtering and physical counts. */
    private final Set<String> inputClasses = new HashSet<>();

    /** WHY: Output metrics count omitted class payload bytes. */
    private final PrunedClassByteCounter prunedClassBytes = new PrunedClassByteCounter();

    /** WHY: Selects the module-info-only classpath transformation. */
    private final boolean stripRootModuleDescriptor;

    /** WHY: Adjusts counts only when that physical entry is removed. */
    private boolean hasRootModuleDescriptor;

    /** WHY: The content writer shares decisions without duplicating archive state. */
    private final ContentWriter contentWriter;

    private EntryWriter(
        final DependencyJarTrimmer.TrimAnalysis analysis,
        final boolean stripRootModuleDescriptor,
        final Set<String> removedServiceProviders) {
      retainedClasses = new HashSet<>(analysis.retainedClasses());
      this.stripRootModuleDescriptor = stripRootModuleDescriptor;
      contentWriter =
          new ContentWriter(
              retainedClasses,
              removedServiceProviders,
              inputClasses,
              writtenClasses,
              prunedClassBytes,
              stripRootModuleDescriptor);
    }

    private void scanInput(final JarFile input) {
      final Enumeration<JarEntry> entries = input.entries();
      while (entries.hasMoreElements()) {
        final String name = entries.nextElement().getName();
        hasRootModuleDescriptor |= MODULE_DESCRIPTOR.equals(name);
        if (name.endsWith(CLASS_SUFFIX)
            && !MODULE_DESCRIPTOR.equals(name)
            && !name.startsWith(VERSIONED_PREFIX)) {
          inputClasses.add(name.substring(0, name.length() - CLASS_SUFFIX.length()));
        }
      }
      if (stripRootModuleDescriptor && hasRootModuleDescriptor) {
        retainedClasses.remove("module-info");
      }
    }

    private void writeEntries(final JarFile input, final JarOutputStream output)
        throws IOException {
      final Enumeration<JarEntry> entries = input.entries();
      while (entries.hasMoreElements()) {
        writeEntry(input, output, entries.nextElement());
      }
    }

    private void writeEntry(final JarFile input, final JarOutputStream output, final JarEntry entry)
        throws IOException {
      final String name = entry.getName();
      if (!seenNames.add(name)) {
        throw new IOException("Duplicate archive entry cannot be preserved safely: " + name);
      }
      if (entry.isDirectory()) {
        copyEntry(input, output, entry);
      } else if (!JarSignatureSanitizer.isSignatureFile(name)
          && !contentWriter.isVersionedServiceDescriptor(name)
          && !DependencyJarTrimmer.isVersionedModuleDescriptor(name)) {
        writeNonSignatureEntry(input, output, entry);
      }
    }

    private void writeNonSignatureEntry(
        final JarFile input, final JarOutputStream output, final JarEntry entry)
        throws IOException {
      if (JarSignatureSanitizer.isManifest(entry.getName())) {
        writeManifest(input, output, entry);
      } else {
        contentWriter.write(input, output, entry);
      }
    }

    private void verify(final int analysisTotalClasses) throws IOException {
      final int expectedTotalClasses =
          stripRootModuleDescriptor
                  && hasRootModuleDescriptor
                  && analysisTotalClasses == inputClasses.size() + 1
              ? inputClasses.size()
              : analysisTotalClasses;
      verifyClasses(inputClasses, writtenClasses, retainedClasses, expectedTotalClasses);
    }

    private WriteResult result() {
      return new WriteResult(prunedClassBytes.value(), inputClasses.size(), writtenClasses.size());
    }
  }

  /** WHY: Applies transformations that depend on archive content type. */
  private static final class ContentWriter {
    /** WHY: Required outputs remain in the physical archive. */
    private final Set<String> retainedClasses;

    /** WHY: Proven-absent known provider declarations are removed. */
    private final Set<String> removedServiceProviders;

    /** WHY: Physical roots determine counts and metadata filtering. */
    private final Set<String> inputClasses;

    /** WHY: The final output is checked against retained classes. */
    private final Set<String> writtenClasses;

    /** WHY: Pruned payload size is part of archive metrics. */
    private final PrunedClassByteCounter prunedClassBytes;

    /** WHY: Module descriptors are removed only in this mode. */
    private final boolean stripRootModuleDescriptor;

    private ContentWriter(
        final Set<String> retainedClasses,
        final Set<String> removedServiceProviders,
        final Set<String> inputClasses,
        final Set<String> writtenClasses,
        final PrunedClassByteCounter prunedClassBytes,
        final boolean stripRootModuleDescriptor) {
      this.retainedClasses = retainedClasses;
      this.removedServiceProviders = removedServiceProviders;
      this.inputClasses = inputClasses;
      this.writtenClasses = writtenClasses;
      this.prunedClassBytes = prunedClassBytes;
      this.stripRootModuleDescriptor = stripRootModuleDescriptor;
    }

    private void write(final JarFile input, final JarOutputStream output, final JarEntry entry)
        throws IOException {
      if (entry.getName().endsWith(CLASS_SUFFIX)) {
        writeClass(input, output, entry);
      } else {
        writeResource(input, output, entry);
      }
    }

    private void writeClass(final JarFile input, final JarOutputStream output, final JarEntry entry)
        throws IOException {
      final String name = entry.getName();
      if (MODULE_DESCRIPTOR.equals(name)) {
        if (!stripRootModuleDescriptor) {
          throw new IOException("Unsupported modular or multi-release entry: " + name);
        }
        return;
      }
      if (name.startsWith(VERSIONED_PREFIX)) {
        throw new IOException("Unsupported modular or multi-release entry: " + name);
      }
      final String className = className(input, entry, name);
      if (!name.equals(className + CLASS_SUFFIX)) {
        throw new IOException("Class entry path does not match its declared name: " + name);
      }
      if (retainedClasses.contains(className)) {
        inputClasses.add(className);
        writtenClasses.add(className);
        copyEntry(input, output, entry);
      } else {
        inputClasses.add(className);
        prunedClassBytes.add(entry);
      }
    }

    private String className(final JarFile input, final JarEntry entry, final String name)
        throws IOException {
      try (InputStream classInput = input.getInputStream(entry)) {
        return new ClassReader(classInput).getClassName();
      } catch (final IllegalArgumentException | IndexOutOfBoundsException exception) {
        throw new IOException("Could not read class entry: " + name, exception);
      }
    }

    private void writeResource(
        final JarFile input, final JarOutputStream output, final JarEntry entry)
        throws IOException {
      if (entry.getName().startsWith(SERVICE_PREFIX)) {
        final ServiceDescriptorFilter.Result descriptor =
            ServiceDescriptorFilter.filter(input, entry, removedServiceProviders);
        if (descriptor.outcome() == ServiceDescriptorFilter.Outcome.OMIT) {
          return;
        }
        if (descriptor.outcome() == ServiceDescriptorFilter.Outcome.REPLACED) {
          writeEntryBytes(output, entry, descriptor.bytes());
          return;
        }
      }
      if (AutoConfigurationDescriptorFilter.IMPORTS_PATH.equals(entry.getName())) {
        final java.util.Optional<byte[]> filtered =
            AutoConfigurationDescriptorFilter.filterImports(
                input, entry, inputClasses, retainedClasses);
        if (filtered.isPresent()) {
          writeEntryBytes(output, entry, filtered.get());
          return;
        }
      }
      copyEntry(input, output, entry);
    }

    private boolean isVersionedServiceDescriptor(final String name) {
      final int releaseEnd =
          name.startsWith(VERSIONED_PREFIX) ? name.indexOf('/', VERSIONED_PREFIX.length()) : -1;
      return releaseEnd >= 0 && name.startsWith(SERVICE_PREFIX, releaseEnd + 1);
    }
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

  private static void writeEntryBytes(
      final JarOutputStream output, final JarEntry entry, final byte[] bytes) throws IOException {
    final JarEntry copy = new JarEntry(entry.getName());
    if (entry.getTime() >= 0) {
      copy.setTime(entry.getTime());
    }
    if (entry.getComment() != null) {
      copy.setComment(entry.getComment());
    }
    output.putNextEntry(copy);
    output.write(bytes);
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
      throw new IOException(
          "Trim analysis class count does not match original JAR entries: "
              + inputClasses.size()
              + " != "
              + totalClasses);
    }
  }

  /** WHY: Counts omitted payload bytes without retaining each pruned class body. */
  private static final class PrunedClassByteCounter {
    /** WHY: Counts omitted bytes without holding class contents. */
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
