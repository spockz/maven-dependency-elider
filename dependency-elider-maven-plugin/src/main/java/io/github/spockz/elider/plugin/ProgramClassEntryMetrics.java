// WHY: Counts program class entry payloads consistently for whole-JAR drops.

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Path;
import java.util.Enumeration;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/** Measures program {@code .class} entries while excluding module descriptors. */
record ProgramClassEntryMetrics(int entries, long uncompressedBytes) {
  ProgramClassEntryMetrics {
    if (entries < 0 || uncompressedBytes < 0) {
      throw new IllegalArgumentException("Program class entry metrics must not be negative");
    }
  }

  /** Counts program class entries and their uncompressed payload bytes. */
  @SuppressWarnings("PMD.CommentDefaultAccessModifier") // Shared only inside the plugin package.
  static ProgramClassEntryMetrics scan(final Path jarPath) throws IOException {
    int count = 0;
    long bytes = 0;
    try (JarFile jar = new JarFile(jarPath.toFile())) {
      final Enumeration<JarEntry> entries = jar.entries();
      while (entries.hasMoreElements()) {
        final JarEntry entry = entries.nextElement();
        if (isProgramClass(entry.getName())) {
          count = Math.addExact(count, 1);
          bytes = Math.addExact(bytes, uncompressedSize(jar, entry));
        }
      }
    } catch (final ArithmeticException exception) {
      throw new IOException(
          "Program class entry metrics overflowed for JAR: " + jarPath, exception);
    }
    return new ProgramClassEntryMetrics(count, bytes);
  }

  private static boolean isProgramClass(final String name) {
    return name.endsWith(".class")
        && !"module-info.class".equals(name)
        && !name.endsWith("/module-info.class");
  }

  private static long uncompressedSize(final JarFile jar, final JarEntry entry) throws IOException {
    final long size = entry.getSize();
    if (size >= 0) {
      return size;
    }
    try (InputStream input = jar.getInputStream(entry)) {
      return input.transferTo(OutputStream.nullOutputStream());
    }
  }
}
