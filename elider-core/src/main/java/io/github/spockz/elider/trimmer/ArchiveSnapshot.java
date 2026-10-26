/* WHY: Holds one validated archive's immutable class bytes so analyses avoid reopening its ZIP. */

package io.github.spockz.elider.trimmer;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import org.objectweb.asm.ClassReader;
import proguard.classfile.ClassPool;
import proguard.classfile.LibraryClass;
import proguard.classfile.ProgramClass;
import proguard.classfile.io.LibraryClassReader;
import proguard.classfile.io.ProgramClassReader;

/** Validated archive bytes with fresh ProGuard pool construction. */
@SuppressWarnings({
  "PMD.CyclomaticComplexity",
  "PMD.CommentDefaultAccessModifier",
  "PMD.UseConcurrentHashMap",
  "PMD.AvoidInstantiatingObjectsInLoops",
  "PMD.AvoidCatchingGenericException"
})
final class ArchiveSnapshot {
  /** Entry path identifying an explicit module descriptor. */
  private static final String MODULE_DESCRIPTOR_ENTRY = "module-info.class";

  /** Class-entry bytes, retained in archive order for pool construction. */
  private final Map<String, byte[]> classBytes;

  /** Whether the archive contains a direct module descriptor. */
  private final boolean hasModuleDescriptor;

  private ArchiveSnapshot(final Map<String, byte[]> classBytes, final boolean hasModuleDescriptor) {
    this.classBytes = java.util.Collections.unmodifiableMap(new LinkedHashMap<>(classBytes));
    this.hasModuleDescriptor = hasModuleDescriptor;
  }

  private static boolean isNestedArchive(final String entryName) {
    return entryName.endsWith(".jar")
        || entryName.endsWith(".zip")
        || entryName.endsWith(".war")
        || entryName.endsWith(".ear");
  }

  @SuppressWarnings({"PMD.CommentDefaultAccessModifier", "PMD.CognitiveComplexity"})
  static ArchiveSnapshot read(final Path archivePath, final boolean candidate) throws IOException {
    final Path fileName = archivePath.getFileName();
    if (candidate && !Files.isRegularFile(archivePath)) {
      throw new IllegalArgumentException("Candidate JAR is not a regular file: " + archivePath);
    }
    if (!candidate
        && (Files.isDirectory(archivePath)
            || fileName == null
            || !fileName.toString().endsWith(".jar"))) {
      throw new IOException("Only flat sibling JAR libraries are supported: " + archivePath);
    }
    final Map<String, byte[]> classes = new LinkedHashMap<>();
    boolean hasModuleDescriptor = false;
    try (JarFile archive = new JarFile(archivePath.toFile())) {
      final java.util.Enumeration<JarEntry> entries = archive.entries();
      while (entries.hasMoreElements()) {
        final JarEntry entry = entries.nextElement();
        final String entryName = entry.getName();
        if (entry.isDirectory() || !entryName.endsWith(".class")) {
          if (isNestedArchive(entryName)) {
            throw new IOException("Nested archives are not supported: " + entryName);
          }
          continue;
        }
        if (candidate && MODULE_DESCRIPTOR_ENTRY.equals(entryName)) {
          throw new IOException("Cannot safely trim an explicit modular JAR: " + archivePath);
        }
        if (MODULE_DESCRIPTOR_ENTRY.equals(entryName)) {
          hasModuleDescriptor = true;
        }
        if (DependencyJarTrimmer.isVersionedModuleDescriptor(entryName)) {
          try (java.io.InputStream input = archive.getInputStream(entry)) {
            if (!"module-info".equals(new ClassReader(input).getClassName())) {
              throw new IOException(
                  "Invalid versioned module descriptor in classpath JAR: " + archivePath);
            }
          } catch (final RuntimeException exception) {
            throw new IOException(
                "Could not read versioned module descriptor in " + archivePath, exception);
          }
          continue;
        }
        if (entryName.startsWith("META-INF/versions/")) {
          final String kind = candidate ? "candidate" : "library";
          throw new IOException(
              "Cannot safely resolve a multi-release " + kind + " JAR: " + archivePath);
        }
        final byte[] bytes;
        try (java.io.InputStream input = archive.getInputStream(entry)) {
          bytes = input.readAllBytes();
        } catch (final RuntimeException exception) {
          throw new IOException("Could not read class entry " + entryName, exception);
        }
        final String declaredName;
        try {
          declaredName = new ClassReader(bytes).getClassName();
        } catch (final RuntimeException exception) {
          throw new IOException("Could not read class entry " + entryName, exception);
        }
        if (!entryName.equals(declaredName + ".class")) {
          throw new IOException(
              "Class entry path does not match its declared name in "
                  + archivePath
                  + ": "
                  + entryName
                  + " -> "
                  + declaredName);
        }
        if (classes.putIfAbsent(declaredName, bytes) != null) {
          throw new IOException(
              "Duplicate class definition in " + archivePath + ": " + declaredName);
        }
      }
    }
    return new ArchiveSnapshot(classes, hasModuleDescriptor);
  }

  void validateCandidate(final Path archivePath) throws IOException {
    if (hasModuleDescriptor) {
      throw new IOException("Cannot safely trim an explicit modular JAR: " + archivePath);
    }
  }

  Set<String> classNames() {
    return classBytes.keySet();
  }

  ClassPool newClassPool(final boolean library) throws IOException {
    final ClassPool pool = new ClassPool();
    for (final Map.Entry<String, byte[]> entry : classBytes.entrySet()) {
      try (DataInputStream input =
          new DataInputStream(new ByteArrayInputStream(entry.getValue()))) {
        if (library) {
          final LibraryClass clazz = new LibraryClass();
          clazz.accept(new LibraryClassReader(input, false, false));
          pool.addClass(clazz);
        } else {
          final ProgramClass clazz = new ProgramClass();
          clazz.accept(new ProgramClassReader(input));
          pool.addClass(clazz);
        }
      }
    }
    return pool;
  }
}
