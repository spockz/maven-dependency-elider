/* WHY: Keeps ordinary single-release JAR entry copying separate from staging and publication. */

package io.github.spockz.elider.trimmer;

import io.github.spockz.elider.model.ArtifactDigests;
import java.io.IOException;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;

/** Writes the retained root view of an ordinary JAR. */
final class SingleReleaseArchiveWriter {
  /** WHY: Names separate ordinary entries from transformation metadata. */
  private static final String MODULE_DESCRIPTOR = "module-info.class";

  /** WHY: Routes versioned entries outside the ordinary class view. */
  private static final String VERSIONED_PREFIX = "META-INF/versions/";

  /** WHY: Shared suffix for physical class entry parsing. */
  private static final String CLASS_SUFFIX = ".class";

  private SingleReleaseArchiveWriter() {}

  /* default */ static ArchiveOutputStager.WriteResult write(
      final Path originalJar,
      final Path temporaryJar,
      final DependencyJarTrimmer.TrimAnalysis analysis)
      throws IOException {
    return write(originalJar, temporaryJar, analysis, false);
  }

  /* default */ static ArchiveOutputStager.WriteResult write(
      final Path originalJar,
      final Path temporaryJar,
      final DependencyJarTrimmer.TrimAnalysis analysis,
      final boolean stripRootModuleDescriptor)
      throws IOException {
    return write(originalJar, temporaryJar, analysis, stripRootModuleDescriptor, Set.of());
  }

  /* default */ static ArchiveOutputStager.WriteResult write(
      final Path originalJar,
      final Path temporaryJar,
      final DependencyJarTrimmer.TrimAnalysis analysis,
      final boolean stripRootModuleDescriptor,
      final Set<String> removedServiceProviders)
      throws IOException {
    final EntryWriter writer =
        new EntryWriter(analysis, stripRootModuleDescriptor, removedServiceProviders);
    final int trimmedEntries;
    final ArtifactDigests trimmedDigests;
    try (JarFile input = new JarFile(originalJar.toFile())) {
      writer.scanInput(input);
      try (ArtifactDigests.HashingOutputStream hashingOutput =
              ArchiveOutputStager.openHashingOutput(temporaryJar);
          ArchiveOutputStager.CountingJarOutputStream output =
              new ArchiveOutputStager.CountingJarOutputStream(hashingOutput)) {
        writer.writeEntries(input, output);
        output.finish();
        trimmedEntries = output.entryCount();
        trimmedDigests = hashingOutput.digests();
      }
    }
    writer.verify(analysis.totalClasses());
    return writer.result(trimmedEntries, trimmedDigests);
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
    private final MultiReleaseEntrySupport.PrunedClassByteCounter prunedClassBytes =
        new MultiReleaseEntrySupport.PrunedClassByteCounter();

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
      for (final JarEntry entry : input.stream().toList()) {
        final String name = entry.getName();
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
      for (final JarEntry entry : input.stream().toList()) {
        writeEntry(input, output, entry);
      }
    }

    private void writeEntry(final JarFile input, final JarOutputStream output, final JarEntry entry)
        throws IOException {
      final String name = entry.getName();
      if (!seenNames.add(name)) {
        throw new IOException("Duplicate archive entry cannot be preserved safely: " + name);
      }
      if (entry.isDirectory()) {
        MultiReleaseEntrySupport.copyEntry(input, output, entry);
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

    private ArchiveOutputStager.WriteResult result(
        final int trimmedPhysicalEntries, final ArtifactDigests trimmedDigests) {
      return new ArchiveOutputStager.WriteResult(
          prunedClassBytes.value(),
          inputClasses.size(),
          writtenClasses.size(),
          seenNames.size(),
          trimmedPhysicalEntries,
          trimmedDigests);
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
    private final MultiReleaseEntrySupport.PrunedClassByteCounter prunedClassBytes;

    /** WHY: Module descriptors are removed only in this mode. */
    private final boolean stripRootModuleDescriptor;

    private ContentWriter(
        final Set<String> retainedClasses,
        final Set<String> removedServiceProviders,
        final Set<String> inputClasses,
        final Set<String> writtenClasses,
        final MultiReleaseEntrySupport.PrunedClassByteCounter prunedClassBytes,
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
      final String className = MultiReleaseEntrySupport.readClassName(input, entry);
      if (retainedClasses.contains(className)) {
        inputClasses.add(className);
        writtenClasses.add(className);
        MultiReleaseEntrySupport.copyEntry(input, output, entry);
      } else {
        inputClasses.add(className);
        prunedClassBytes.add(entry);
      }
    }

    private void writeResource(
        final JarFile input, final JarOutputStream output, final JarEntry entry)
        throws IOException {
      MultiReleaseEntrySupport.writeFilteredResource(
          input, output, entry, inputClasses, retainedClasses, removedServiceProviders);
    }

    private boolean isVersionedServiceDescriptor(final String name) {
      return MultiReleaseEntrySupport.isVersionedServiceDescriptor(name);
    }
  }

  private static void writeManifest(
      final JarFile input, final JarOutputStream output, final JarEntry entry) throws IOException {
    final Manifest manifest = MultiReleaseEntrySupport.readManifest(input, entry);
    JarSignatureSanitizer.cleanse(manifest);
    JarSignatureSanitizer.writeManifest(output, entry, manifest);
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
}
