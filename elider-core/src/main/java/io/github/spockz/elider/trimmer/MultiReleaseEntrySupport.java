/* WHY: Shares byte-preserving ZIP copying and class-name validation across MR writer handlers. */

package io.github.spockz.elider.trimmer;

import java.io.IOException;
import java.io.InputStream;
import java.util.Optional;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import org.objectweb.asm.ClassReader;

/** Low-level helpers for writing an MRJAR entry and validating its class identity. */
@SuppressWarnings({"PMD.CommentRequired", "PMD.CommentDefaultAccessModifier"})
final class MultiReleaseEntrySupport {
  private static final String CLASS_SUFFIX = ".class";

  private MultiReleaseEntrySupport() {}

  static String readClassName(final JarFile input, final JarEntry entry) throws IOException {
    final String className;
    try (InputStream classInput = input.getInputStream(entry)) {
      className = new ClassReader(classInput).getClassName();
    } catch (final IllegalArgumentException | IndexOutOfBoundsException exception) {
      throw new IOException("Could not read class entry: " + entry.getName(), exception);
    }
    if (!entry.getName().equals(className + CLASS_SUFFIX)) {
      throw new IOException(
          "Class entry path does not match its declared name: " + entry.getName());
    }
    return className;
  }

  static boolean isModuleDescriptor(final String name) {
    return "module-info.class".equals(name) || name.endsWith("/module-info.class");
  }

  static boolean isVersionedServiceDescriptor(final String name) {
    final String versionsPrefix = "META-INF/versions/";
    if (!name.startsWith(versionsPrefix)) {
      return false;
    }
    final int releaseEnd = name.indexOf('/', versionsPrefix.length());
    return releaseEnd >= 0 && name.startsWith("META-INF/services/", releaseEnd + 1);
  }

  static Manifest readManifest(final JarFile input, final JarEntry entry) throws IOException {
    try (InputStream manifestInput = input.getInputStream(entry)) {
      return new Manifest(manifestInput);
    }
  }

  static String logicalClassName(final String entryName) {
    final String versionsPrefix = "META-INF/versions/";
    if (!entryName.startsWith(versionsPrefix)) {
      return entryName.substring(0, entryName.length() - CLASS_SUFFIX.length());
    }
    final int versionEnd = entryName.indexOf('/', versionsPrefix.length());
    return entryName.substring(versionEnd + 1, entryName.length() - CLASS_SUFFIX.length());
  }

  static void writeEntryAs(
      final JarFile input,
      final JarOutputStream output,
      final JarEntry original,
      final String outputName)
      throws IOException {
    final JarEntry copy = copyMetadata(original, outputName);
    output.putNextEntry(copy);
    try (InputStream contents = input.getInputStream(original)) {
      contents.transferTo(output);
    }
    output.closeEntry();
  }

  static void writeEntryAs(
      final JarOutputStream output,
      final JarEntry original,
      final String outputName,
      final byte[] contents)
      throws IOException {
    output.putNextEntry(copyMetadata(original, outputName));
    output.write(contents);
    output.closeEntry();
  }

  static void copyEntry(final JarFile input, final JarOutputStream output, final JarEntry original)
      throws IOException {
    output.putNextEntry(copyMetadata(original, original.getName()));
    if (!original.isDirectory()) {
      try (InputStream contents = input.getInputStream(original)) {
        contents.transferTo(output);
      }
    }
    output.closeEntry();
  }

  private static JarEntry copyMetadata(final JarEntry original, final String outputName) {
    final JarEntry copy = new JarEntry(outputName);
    if (original.getTime() >= 0) {
      copy.setTime(original.getTime());
    }
    if (original.getComment() != null) {
      copy.setComment(original.getComment());
    }
    return copy;
  }

  static void writeFilteredResource(
      final JarFile input,
      final JarOutputStream output,
      final JarEntry entry,
      final Set<String> inputClasses,
      final Set<String> retainedClasses,
      final Set<String> removedServiceProviders)
      throws IOException {
    final String name = entry.getName();
    if (name.startsWith("META-INF/services/")) {
      final ServiceDescriptorFilter.Result descriptor =
          ServiceDescriptorFilter.filter(input, entry, removedServiceProviders);
      if (descriptor.outcome() == ServiceDescriptorFilter.Outcome.OMIT) {
        return;
      }
      if (descriptor.outcome() == ServiceDescriptorFilter.Outcome.REPLACED) {
        writeEntryAs(output, entry, name, descriptor.bytes());
        return;
      }
    }
    if (AutoConfigurationDescriptorFilter.IMPORTS_PATH.equals(name)) {
      final Optional<byte[]> filtered =
          AutoConfigurationDescriptorFilter.filterImports(
              input, entry, inputClasses, retainedClasses);
      if (filtered.isPresent()) {
        writeEntryAs(output, entry, name, filtered.orElseThrow());
        return;
      }
    }
    copyEntry(input, output, entry);
  }

  /** Counts omitted payload bytes without retaining each pruned class body. */
  static final class PrunedClassByteCounter {
    private long totalBytes;

    void add(final JarEntry entry) throws IOException {
      if (entry.getSize() < 0) {
        throw new IOException("Class entry has unknown uncompressed size: " + entry.getName());
      }
      try {
        totalBytes = Math.addExact(totalBytes, entry.getSize());
      } catch (final ArithmeticException exception) {
        throw new IOException("Pruned class byte total overflowed", exception);
      }
    }

    long value() {
      return totalBytes;
    }
  }
}
