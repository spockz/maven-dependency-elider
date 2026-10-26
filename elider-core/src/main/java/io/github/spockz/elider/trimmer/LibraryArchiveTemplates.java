/* WHY: Caches immutable declarations per archive while creating fresh initialized-pool inputs. */

package io.github.spockz.elider.trimmer;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;
import proguard.classfile.ClassPool;
import proguard.classfile.LibraryClass;
import proguard.classfile.io.LibraryClassReader;
import proguard.classfile.util.kotlin.KotlinMetadataInitializer;

/** Builds fresh library classes from cached symbolic declarations. */
@SuppressWarnings({"PMD.CommentDefaultAccessModifier", "PMD.UseConcurrentHashMap"})
final class LibraryArchiveTemplates {
  /** Immutable bytes retained by the owning archive snapshot. */
  private final Map<String, byte[]> classBytes;

  /** Guards lazy declaration capture and its deterministic parse counter. */
  private final ReentrantLock templateLock = new ReentrantLock();

  /** Becomes available after the first complete library parse. */
  private LibraryDeclarations cachedDeclarations;

  /** Counts LibraryClassReader calls, including metadata fallback materialization. */
  private int declarationReads;

  LibraryArchiveTemplates(final Map<String, byte[]> classBytes) {
    this.classBytes = classBytes;
  }

  ClassPool newClassPool() throws IOException {
    final LibraryDeclarations declarations = declarations();
    final ClassPool pool = new ClassPool();
    for (final Map.Entry<String, byte[]> entry : classBytes.entrySet()) {
      final String name = entry.getKey();
      if (declarations.metadataClasses().contains(name)) {
        pool.addClass(readLibraryClass(entry.getValue()));
      } else {
        pool.addClass(declarations.templates().get(name).materialize());
      }
    }
    return pool;
  }

  int parseCount() {
    templateLock.lock();
    try {
      return declarationReads;
    } finally {
      templateLock.unlock();
    }
  }

  private LibraryDeclarations declarations() throws IOException {
    templateLock.lock();
    try {
      if (cachedDeclarations == null) {
        final Map<String, LibraryClassTemplate> templates = new LinkedHashMap<>();
        final Set<String> metadataClasses = new LinkedHashSet<>();
        for (final Map.Entry<String, byte[]> entry : classBytes.entrySet()) {
          final LibraryClass parsedClass = readLibraryClass(entry.getValue());
          if (parsedClass.kotlinMetadata == null) {
            templates.put(entry.getKey(), LibraryClassTemplate.from(parsedClass));
          } else {
            metadataClasses.add(entry.getKey());
          }
        }
        cachedDeclarations =
            new LibraryDeclarations(Map.copyOf(templates), Set.copyOf(metadataClasses));
      }
      return cachedDeclarations;
    } finally {
      templateLock.unlock();
    }
  }

  private LibraryClass readLibraryClass(final byte[] classData) throws IOException {
    templateLock.lock();
    try {
      declarationReads++;
    } finally {
      templateLock.unlock();
    }
    try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(classData))) {
      final LibraryClass clazz = new LibraryClass();
      final AtomicReference<String> metadataFailure = new AtomicReference<>();
      final KotlinMetadataInitializer metadataInitializer =
          new KotlinMetadataInitializer(
              (ignoredClass, message) -> metadataFailure.compareAndSet(null, message));
      clazz.accept(
          new LibraryClassReader(
              input,
              false,
              false,
              (kind, version, data1, data2, extraInt, extraString, packageName) ->
                  metadataInitializer.initialize(
                      clazz, kind, version, data1, data2, extraInt, extraString, packageName)));
      if (metadataFailure.get() != null) {
        throw new IOException(
            "Could not safely read Kotlin metadata for "
                + clazz.getName()
                + ": "
                + metadataFailure.get());
      }
      return clazz;
    }
  }

  private record LibraryDeclarations(
      Map<String, LibraryClassTemplate> templates, Set<String> metadataClasses) {}
}
