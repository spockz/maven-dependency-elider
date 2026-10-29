/* WHY: Owns ordered MRJAR rewriting and validates every planned class entry before publication. */

package io.github.spockz.elider.trimmer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;

/** Writes MRJAR entries in source ZIP order using an immutable elevation plan. */
@SuppressWarnings({"PMD.CommentRequired", "PMD.CommentDefaultAccessModifier"})
final class MultiReleaseArchiveWriter {
  private static final String VERSIONED_PREFIX = "META-INF/versions/";
  private static final String CLASS_SUFFIX = ".class";

  private MultiReleaseArchiveWriter() {}

  static long write(
      final Path originalJar,
      final Path temporaryJar,
      final DependencyJarTrimmer.TrimAnalysis analysis,
      final MultiReleaseArchivePlan plan)
      throws IOException {
    final WriteState state = new WriteState(plan);
    try (JarFile input = new JarFile(originalJar.toFile());
        OutputStream fileOutput = Files.newOutputStream(temporaryJar);
        JarOutputStream output = new JarOutputStream(fileOutput)) {
      final Enumeration<JarEntry> entries = input.entries();
      while (entries.hasMoreElements()) {
        writeEntry(input, output, entries.nextElement(), state);
      }
    }
    return state.finish(analysis);
  }

  private static void writeEntry(
      final JarFile input,
      final JarOutputStream output,
      final JarEntry entry,
      final WriteState state)
      throws IOException {
    final String name = entry.getName();
    state.requireUnseen(name);
    if (entry.isDirectory()) {
      writeDirectory(input, output, entry, state);
    } else if (!JarSignatureSanitizer.isSignatureFile(name)) {
      if (JarSignatureSanitizer.isManifest(name)) {
        writeManifest(input, output, entry, state);
      } else if (name.startsWith(VERSIONED_PREFIX)) {
        writeVersioned(input, output, entry, state);
      } else if (name.endsWith(CLASS_SUFFIX)) {
        writeRootClass(input, output, entry, state);
      } else {
        writeResource(input, output, entry, state);
      }
    }
  }

  private static void writeDirectory(
      final JarFile input,
      final JarOutputStream output,
      final JarEntry entry,
      final WriteState state)
      throws IOException {
    if (!entry.getName().startsWith(VERSIONED_PREFIX)) {
      MultiReleaseEntrySupport.copyEntry(input, output, entry);
      state.markWritten(entry.getName());
    }
  }

  private static void writeManifest(
      final JarFile input,
      final JarOutputStream output,
      final JarEntry entry,
      final WriteState state)
      throws IOException {
    final Manifest manifest;
    try (InputStream manifestInput = input.getInputStream(entry)) {
      manifest = new Manifest(manifestInput);
    }
    if (state.hasVersionedOutput()) {
      manifest.getMainAttributes().putValue("Multi-Release", "true");
    } else {
      manifest.getMainAttributes().remove(Attributes.Name.MULTI_RELEASE);
    }
    JarSignatureSanitizer.cleanse(manifest);
    JarSignatureSanitizer.writeManifest(output, entry, manifest);
    state.markWritten(entry.getName());
  }

  private static void writeVersioned(
      final JarFile input,
      final JarOutputStream output,
      final JarEntry entry,
      final WriteState state)
      throws IOException {
    final String name = entry.getName();
    final MultiReleaseArchivePlan.VersionedEntry action = state.versionedEntry(name);
    if (action == null) {
      throw new IOException("MRJAR elevation plan does not cover entry: " + name);
    }
    if (action.omitted()) {
      if (name.endsWith(CLASS_SUFFIX) && !MultiReleaseEntrySupport.isModuleDescriptor(name)) {
        state.addPruned(entry);
      }
      return;
    }
    final String outputName = action.outputName();
    state.reserve(outputName);
    MultiReleaseEntrySupport.writeEntryAs(input, output, entry, outputName);
    if (outputName.endsWith(CLASS_SUFFIX)) {
      final String logicalClass = MultiReleaseEntrySupport.logicalClassName(outputName);
      state.markWrittenClass(logicalClass, !outputName.startsWith(VERSIONED_PREFIX));
    }
  }

  private static void writeRootClass(
      final JarFile input,
      final JarOutputStream output,
      final JarEntry entry,
      final WriteState state)
      throws IOException {
    final String name = entry.getName();
    if (MultiReleaseEntrySupport.isModuleDescriptor(name)) {
      throw new IOException("Unsupported root module descriptor: " + name);
    }
    final String className = MultiReleaseEntrySupport.readClassName(input, entry);
    if (!state.isSelectedRetainedRootClass(name, className)) {
      state.addPruned(entry);
      return;
    }
    state.reserve(name);
    MultiReleaseEntrySupport.copyEntry(input, output, entry);
    state.markWrittenClass(className, true);
  }

  private static void writeResource(
      final JarFile input,
      final JarOutputStream output,
      final JarEntry entry,
      final WriteState state)
      throws IOException {
    final String name = entry.getName();
    if (state.rootResourceOverridden(name)) {
      return;
    }
    state.reserve(name);
    final Optional<byte[]> serviceContents =
        ServiceDescriptorFilter.filter(input, entry, state.removedServiceProviders());
    if (serviceContents.isEmpty()) {
      MultiReleaseEntrySupport.copyEntry(input, output, entry);
    } else {
      MultiReleaseEntrySupport.writeEntryAs(output, entry, name, serviceContents.orElseThrow());
    }
  }

  private static final class WriteState {
    private final MultiReleaseArchivePlan plan;
    private final Set<String> seenNames = new HashSet<>();
    private final Set<String> writtenNames = new HashSet<>();
    private final Set<String> writtenTargetClasses = new HashSet<>();
    private final Set<String> writtenLogicalClasses = new HashSet<>();
    private final PrunedClassByteCounter prunedClassBytes = new PrunedClassByteCounter();

    private WriteState(final MultiReleaseArchivePlan plan) {
      this.plan = plan;
    }

    private void requireUnseen(final String name) throws IOException {
      if (!seenNames.add(name)) {
        throw new IOException("Duplicate archive entry cannot be preserved safely: " + name);
      }
    }

    private void markWritten(final String name) {
      writtenNames.add(name);
    }

    private void markWrittenClass(final String name, final boolean targetClass) {
      writtenLogicalClasses.add(name);
      if (targetClass) {
        writtenTargetClasses.add(name);
      }
    }

    private void addPruned(final JarEntry entry) throws IOException {
      prunedClassBytes.add(entry);
    }

    private boolean hasVersionedOutput() {
      return plan.hasVersionedOutput();
    }

    private MultiReleaseArchivePlan.VersionedEntry versionedEntry(final String name) {
      return plan.versionedEntries().get(name);
    }

    private boolean isSelectedRetainedRootClass(final String entryName, final String className) {
      return entryName.equals(plan.selectedClassEntries().get(className))
          && plan.retainedTargetClasses().contains(className);
    }

    private boolean rootResourceOverridden(final String name) {
      return plan.rootResourcesOverridden().contains(name);
    }

    private Set<String> removedServiceProviders() {
      return plan.removedServiceProviders();
    }

    private void reserve(final String name) throws IOException {
      if (!writtenNames.add(name)) {
        throw new IOException("MRJAR elevation produces duplicate output entry: " + name);
      }
    }

    private long finish(final DependencyJarTrimmer.TrimAnalysis analysis) throws IOException {
      if (!writtenTargetClasses.equals(plan.retainedTargetClasses())) {
        throw new IOException("Not all retained target-release classes were written to the MRJAR");
      }
      if (!writtenLogicalClasses.equals(plan.retainedLogicalClasses())) {
        final Set<String> missing = new HashSet<>(plan.retainedLogicalClasses());
        missing.removeAll(writtenLogicalClasses);
        throw new IOException(
            "Not all retained logical classes were written to the MRJAR: " + missing);
      }
      if (analysis.totalClasses() != plan.targetClasses().size()) {
        throw new IOException(
            "Trim analysis class count does not match MRJAR target-release entries");
      }
      return prunedClassBytes.value();
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
