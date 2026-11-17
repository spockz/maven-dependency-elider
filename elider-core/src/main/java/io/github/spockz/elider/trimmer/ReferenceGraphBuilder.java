/* WHY: Builds role-scoped immutable edges while keeping mutable ProGuard pools invocation-local. */

package io.github.spockz.elider.trimmer;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import proguard.classfile.ClassPool;
import proguard.classfile.Clazz;
import proguard.classfile.LibraryClass;

/** Constructs a graph from candidate, ordered siblings, platform, and role policy. */
@SuppressWarnings({"PMD.CommentDefaultAccessModifier", "PMD.TooManyMethods"})
final class ReferenceGraphBuilder {
  /** Candidate archive establishes program-class ownership. */
  private final Path candidateJar;

  /** Sibling paths retain lookup precedence during pool construction. */
  private final Collection<Path> libraryClassPath;

  /** Read-only JDK class templates resolved lazily on demand. */
  private final ClassPool jdkClassTable;

  /** Reuses validated archive bytes for this invocation. */
  private final ArchiveProvider archiveProvider;

  private ReferenceGraphBuilder(
      final Path candidateJar,
      final Collection<Path> libraryClassPath,
      final ClassPool jdkClassTable,
      final ArchiveProvider archiveProvider) {
    this.candidateJar = candidateJar;
    this.libraryClassPath = libraryClassPath;
    this.jdkClassTable = jdkClassTable;
    this.archiveProvider = archiveProvider;
  }

  /** Captures immutable inputs and defers graph initialization. */
  static PreparedAnalysisState prepare(
      final Path candidateJar,
      final Collection<Path> libraryClassPath,
      final ClassPool jdkClassTable,
      final boolean tolerateUnresolvedProgramReferences,
      final Set<String> toleratedUnresolvedLibraryClasses,
      final ArchiveProvider archiveProvider)
      throws IOException {
    return prepareWithSharedTier(
        candidateJar,
        libraryClassPath,
        jdkClassTable,
        tolerateUnresolvedProgramReferences,
        toleratedUnresolvedLibraryClasses,
        archiveProvider,
        null);
  }

  /** Defers graph construction for one candidate, reusing a shared tier index. */
  static PreparedAnalysisState prepareWithSharedTier(
      final Path candidateJar,
      final Collection<Path> libraryClassPath,
      final ClassPool jdkClassTable,
      final boolean tolerateUnresolvedProgramReferences,
      final Set<String> toleratedUnresolvedLibraryClasses,
      final ArchiveProvider archiveProvider,
      final TierLibraryIndex.Supplier sharedTierSupplier)
      throws IOException {
    requireInputs(
        candidateJar,
        libraryClassPath,
        jdkClassTable,
        toleratedUnresolvedLibraryClasses,
        archiveProvider);
    if (!Files.isRegularFile(candidateJar)) {
      throw new IllegalArgumentException("Candidate JAR is not a regular file: " + candidateJar);
    }
    final ArchiveSnapshot candidate = archiveProvider.read(candidateJar, true);
    final List<Path> orderedLibraries =
        java.util.Collections.unmodifiableList(new ArrayList<>(libraryClassPath));
    validateLibraries(orderedLibraries, archiveProvider);
    if (candidate.classNames().isEmpty()) {
      throw new IllegalArgumentException("Candidate JAR contains no classes: " + candidateJar);
    }
    final ClassPool isolatedJdkTable = isolateJdkClassTable(jdkClassTable);
    final ReferenceGraphBuilder builder =
        new ReferenceGraphBuilder(
            candidateJar, orderedLibraries, isolatedJdkTable, archiveProvider);
    return new PreparedAnalysisState(
        candidateJar,
        () -> {
          final TierLibraryIndex sharedTier =
              sharedTierSupplier == null ? null : sharedTierSupplier.get();
          return sharedTier == null
              ? builder.build(candidate)
              : builder.buildWithSharedTier(candidate, sharedTier);
        },
        candidate.classNames(),
        tolerateUnresolvedProgramReferences,
        toleratedUnresolvedLibraryClasses);
  }

  private static void validateLibraries(
      final Collection<Path> libraryPaths, final ArchiveProvider archiveProvider)
      throws IOException {
    for (final Path libraryPath : libraryPaths) {
      if (libraryPath == null || !Files.exists(libraryPath)) {
        throw new IllegalArgumentException(
            "Library classpath entry does not exist: " + libraryPath);
      }
      archiveProvider.read(libraryPath, false);
    }
  }

  static ClassPool isolateJdkClassTable(final ClassPool jdkClassTable) {
    if (jdkClassTable instanceof FrozenClassPool frozen && frozen.isPlainLibraryClassesOnly()) {
      return frozen;
    }
    for (final Clazz clazz : jdkClassTable.classes()) {
      if (!(clazz instanceof LibraryClass libraryClass)) {
        throw new IllegalArgumentException(
            "JDK class table entries must be LibraryClass instances: " + clazz.getName());
      }
      if (libraryClass.kotlinMetadata != null) {
        throw new IllegalArgumentException(
            "JDK class table entries with Kotlin metadata are unsupported: " + clazz.getName());
      }
    }
    return jdkClassTable instanceof FrozenClassPool
        ? jdkClassTable
        : FrozenClassPool.copyOf(PlatformClassSnapshot.copyOf(jdkClassTable));
  }

  private static void requireInputs(
      final Path candidateJar,
      final Collection<Path> libraryClassPath,
      final ClassPool jdkClassTable,
      final Set<String> toleratedUnresolvedLibraryClasses,
      final ArchiveProvider archiveProvider) {
    java.util.Objects.requireNonNull(candidateJar, "candidateJar");
    java.util.Objects.requireNonNull(libraryClassPath, "libraryClassPath");
    java.util.Objects.requireNonNull(jdkClassTable, "jdkClassTable");
    java.util.Objects.requireNonNull(
        toleratedUnresolvedLibraryClasses, "toleratedUnresolvedLibraryClasses");
    java.util.Objects.requireNonNull(archiveProvider, "archiveProvider");
  }

  static ClassPool checkedPool(
      final ArchiveSnapshot snapshot, final boolean library, final Path source) throws IOException {
    final ClassPool pool = snapshot.newClassPool(library);
    final Set<String> ingested = classNames(pool);
    if (!ingested.equals(snapshot.classNames())) {
      final String description = library ? "library" : "candidate";
      throw new IOException(
          "ProGuard Core ingested classes outside the "
              + description
              + " JAR's direct entries: "
              + source);
    }
    if (!library && pool.size() == 0) {
      throw new IllegalArgumentException("Candidate JAR contains no classes: " + source);
    }
    return pool;
  }

  private LibraryPools libraryPools(
      final ClassPool programPool, final Map<String, ArchiveSnapshot> archiveByClass)
      throws IOException {
    final Set<String> platformNames = new HashSet<>();
    final LazyPlatformClassPool libraryPool =
        new LazyPlatformClassPool(programPool, jdkClassTable, platformNames);
    for (final Path libraryPath : libraryClassPath) {
      if (libraryPath == null || !Files.exists(libraryPath)) {
        throw new IllegalArgumentException(
            "Library classpath entry does not exist: " + libraryPath);
      }
      addSiblingClasses(libraryPath, programPool, libraryPool, archiveByClass);
    }
    return new LibraryPools(libraryPool, platformNames);
  }

  private void addSiblingClasses(
      final Path libraryPath,
      final ClassPool programPool,
      final ClassPool libraryPool,
      final Map<String, ArchiveSnapshot> archiveByClass)
      throws IOException {
    final ArchiveSnapshot archive = archiveProvider.read(libraryPath, false);
    final ClassPool siblingPool = checkedPool(archive, true, libraryPath);
    for (final Clazz clazz : siblingPool.classes()) {
      if (programPool.getClass(clazz.getName()) == null
          && libraryPool.getClass(clazz.getName()) == null) {
        libraryPool.addClass(clazz);
        archiveByClass.putIfAbsent(clazz.getName(), archive);
      }
    }
  }

  private static Set<String> classNames(final ClassPool pool) {
    final Set<String> names = HashSet.newHashSet(pool.size());
    pool.classNames().forEachRemaining(names::add);
    return names;
  }

  private record LibraryPools(ClassPool pool, Set<String> platformNames) {}

  private ReferenceGraph build(final ArchiveSnapshot candidateArchive) throws IOException {
    final ClassPool programPool =
        FrozenClassPool.copyOf(checkedPool(candidateArchive, false, candidateJar));
    final Map<String, ArchiveSnapshot> archiveByClass =
        LinkedHashMap.newLinkedHashMap(candidateArchive.classNames().size());
    for (final String name : candidateArchive.classNames()) {
      archiveByClass.put(name, candidateArchive);
    }
    final LibraryPools libraries = libraryPools(programPool, archiveByClass);
    return new ReferenceGraphIndexer(
            programPool, libraries.pool(), libraries.platformNames(), archiveByClass)
        .build();
  }

  private ReferenceGraph buildWithSharedTier(
      final ArchiveSnapshot candidateArchive, final TierLibraryIndex sharedTier)
      throws IOException {
    final ClassPool programPool =
        FrozenClassPool.copyOf(checkedPool(candidateArchive, false, candidateJar));
    final Map<String, ArchiveSnapshot> archiveByClass =
        LinkedHashMap.newLinkedHashMap(candidateArchive.classNames().size());
    for (final String name : candidateArchive.classNames()) {
      archiveByClass.put(name, candidateArchive);
    }
    final Set<String> platformNames = new HashSet<>();
    final LazyPlatformClassPool lazyLibraryPool =
        new LazyPlatformClassPool(
            programPool,
            sharedTier.isolatedJdkTable(),
            sharedTier.siblingTemplates(),
            platformNames);
    return new ReferenceGraphIndexer(programPool, lazyLibraryPool, platformNames, archiveByClass)
        .buildProgramWithSharedTier(sharedTier);
  }
}
