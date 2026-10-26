/* WHY: Builds role-scoped immutable edges while keeping mutable ProGuard pools invocation-local. */

package io.github.spockz.elider.trimmer;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import proguard.classfile.ClassPool;
import proguard.classfile.Clazz;

/** Constructs a graph from candidate, ordered siblings, platform, and role policy. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class ReferenceGraphBuilder {
  /** Candidate archive establishes program-class ownership. */
  private final Path candidateJar;

  /** Sibling paths retain lookup precedence during pool construction. */
  private final Collection<Path> libraryClassPath;

  /** API class entries are captured at preparation to isolate later pool mutations. */
  private final List<Clazz> platformClasses;

  /** Reuses validated archive bytes for this invocation. */
  private final ArchiveProvider archiveProvider;

  private ReferenceGraphBuilder(
      final Path candidateJar,
      final Collection<Path> libraryClassPath,
      final List<Clazz> platformClasses,
      final ArchiveProvider archiveProvider) {
    this.candidateJar = candidateJar;
    this.libraryClassPath = libraryClassPath;
    this.platformClasses = platformClasses;
    this.archiveProvider = archiveProvider;
  }

  /** Captures immutable inputs and defers graph initialization. */
  static PreparedAnalysisState prepare(
      final Path candidateJar,
      final Collection<Path> libraryClassPath,
      final ClassPool platformLibraryPool,
      final boolean tolerateUnresolvedProgramReferences,
      final Set<String> toleratedUnresolvedLibraryClasses,
      final ArchiveProvider archiveProvider)
      throws IOException {
    requireInputs(
        candidateJar,
        libraryClassPath,
        platformLibraryPool,
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
    final List<Clazz> platformClasses = snapshotPlatformClasses(platformLibraryPool);
    final ReferenceGraphBuilder builder =
        new ReferenceGraphBuilder(candidateJar, orderedLibraries, platformClasses, archiveProvider);
    return new PreparedAnalysisState(
        candidateJar,
        () -> builder.build(candidate),
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

  private static List<Clazz> snapshotPlatformClasses(final ClassPool platformLibraryPool) {
    return PlatformClassSnapshot.copyOf(platformLibraryPool);
  }

  private static void requireInputs(
      final Path candidateJar,
      final Collection<Path> libraryClassPath,
      final ClassPool platformLibraryPool,
      final Set<String> toleratedUnresolvedLibraryClasses,
      final ArchiveProvider archiveProvider) {
    java.util.Objects.requireNonNull(candidateJar, "candidateJar");
    java.util.Objects.requireNonNull(libraryClassPath, "libraryClassPath");
    java.util.Objects.requireNonNull(platformLibraryPool, "platformLibraryPool");
    java.util.Objects.requireNonNull(
        toleratedUnresolvedLibraryClasses, "toleratedUnresolvedLibraryClasses");
    java.util.Objects.requireNonNull(archiveProvider, "archiveProvider");
  }

  private ClassPool checkedPool(
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

  private LibraryPools libraryPools(final ClassPool programPool) throws IOException {
    final ClassPool libraryPool = new ClassPool();
    final Set<String> platformNames = new HashSet<>();
    for (final Path libraryPath : libraryClassPath) {
      if (libraryPath == null || !Files.exists(libraryPath)) {
        throw new IllegalArgumentException(
            "Library classpath entry does not exist: " + libraryPath);
      }
      addSiblingClasses(libraryPath, programPool, libraryPool);
    }
    addPlatformClasses(programPool, libraryPool, platformNames);
    return new LibraryPools(libraryPool, platformNames);
  }

  private void addSiblingClasses(
      final Path libraryPath, final ClassPool programPool, final ClassPool libraryPool)
      throws IOException {
    final ArchiveSnapshot archive = archiveProvider.read(libraryPath, false);
    final ClassPool siblingPool = checkedPool(archive, true, libraryPath);
    for (final Clazz clazz : siblingPool.classes()) {
      if (programPool.getClass(clazz.getName()) == null
          && libraryPool.getClass(clazz.getName()) == null) {
        libraryPool.addClass(clazz);
      }
    }
  }

  private void addPlatformClasses(
      final ClassPool programPool, final ClassPool libraryPool, final Set<String> platformNames) {
    for (final Clazz clazz : platformClasses) {
      if (programPool.getClass(clazz.getName()) == null
          && libraryPool.getClass(clazz.getName()) == null) {
        libraryPool.addClass(clazz);
        platformNames.add(clazz.getName());
      }
    }
  }

  private static Set<String> classNames(final ClassPool pool) {
    final Set<String> names = new TreeSet<>();
    pool.classNames().forEachRemaining(names::add);
    return Set.copyOf(names);
  }

  private record LibraryPools(ClassPool pool, Set<String> platformNames) {}

  private ReferenceGraph build(final ArchiveSnapshot candidateArchive) throws IOException {
    final ClassPool programPool = checkedPool(candidateArchive, false, candidateJar);
    final LibraryPools libraries = libraryPools(programPool);
    return new ReferenceGraphIndexer(programPool, libraries.pool(), libraries.platformNames())
        .build();
  }
}
