/* WHY: Reuses validated archive bytes across closure passes without sharing mutable ProGuard
 * pools. */

package io.github.spockz.elider.trimmer;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.locks.ReentrantLock;
import proguard.classfile.ClassPool;

/** Holds immutable input snapshots for one multi-candidate trim invocation. */
@SuppressWarnings("PMD.UseConcurrentHashMap")
public final class TrimAnalysisSession {
  /** Engine used to construct an isolated reference model for each analysis. */
  private final DependencyJarTrimmer trimmer;

  /** Guards concurrent archive reads and map population. */
  private final ReentrantLock archiveLock = new ReentrantLock();

  /** Cached archive snapshots keyed by normalized path. */
  private final Map<Path, ArchiveSnapshot> archives = new HashMap<>();

  /** Creates a session for the supplied trimmer. */
  public TrimAnalysisSession(final DependencyJarTrimmer trimmer) {
    this.trimmer = trimmer;
  }

  /** Analyzes one candidate with cached archive bytes and fresh ProGuard pools. */
  public DependencyJarTrimmer.TrimAnalysis analyze(
      final Path candidateJar,
      final Collection<Path> libraryClassPath,
      final Collection<String> retainedRoots)
      throws IOException {
    return analyze(candidateJar, libraryClassPath, new ClassPool(), retainedRoots);
  }

  /**
   * Analyzes with platform API classes; Kotlin metadata is rejected.
   *
   * @param platformLibraryPool ProGuard {@code LibraryClass} API definitions
   */
  public DependencyJarTrimmer.TrimAnalysis analyze(
      final Path candidateJar,
      final Collection<Path> libraryClassPath,
      final ClassPool platformLibraryPool,
      final Collection<String> retainedRoots)
      throws IOException {
    return trimmer.analyzeInternal(
        candidateJar,
        libraryClassPath,
        platformLibraryPool,
        retainedRoots,
        false,
        Set.of(),
        this::archive);
  }

  /**
   * Prepares an unchanged candidate; Kotlin metadata is rejected.
   *
   * @param platformLibraryPool ProGuard {@code LibraryClass} API definitions
   */
  public DependencyJarTrimmer.PreparedAnalysis prepareUnchangedPassThrough(
      final Path candidateJar,
      final Collection<Path> libraryClassPath,
      final ClassPool platformLibraryPool,
      final Collection<String> unchangedPassThroughClassNames)
      throws IOException {
    // Copy API signatures now so later caller mutations cannot change this context.
    return trimmer.prepareInternal(
        candidateJar,
        libraryClassPath,
        platformLibraryPool,
        true,
        normalizeClassNames(unchangedPassThroughClassNames),
        this::archive);
  }

  /**
   * Prepares candidate closure; Kotlin metadata is rejected.
   *
   * @param platformLibraryPool ProGuard {@code LibraryClass} API definitions
   */
  public DependencyJarTrimmer.PreparedAnalysis prepareWithUnchangedPassThroughLibraries(
      final Path candidateJar,
      final Collection<Path> libraryClassPath,
      final ClassPool platformLibraryPool,
      final Collection<String> unchangedPassThroughClassNames)
      throws IOException {
    // Copy API signatures now so later caller mutations cannot change this context.
    return trimmer.prepareInternal(
        candidateJar,
        libraryClassPath,
        platformLibraryPool,
        false,
        normalizeClassNames(unchangedPassThroughClassNames),
        this::archive);
  }

  /**
   * Analyzes an unchanged candidate; Kotlin metadata is rejected.
   *
   * @param platformLibraryPool ProGuard {@code LibraryClass} API definitions
   */
  public DependencyJarTrimmer.TrimAnalysis analyzeUnchangedPassThrough(
      final Path candidateJar,
      final Collection<Path> libraryClassPath,
      final ClassPool platformLibraryPool,
      final Collection<String> retainedRoots,
      final Collection<String> unchangedPassThroughClassNames)
      throws IOException {
    return trimmer.analyzeInternal(
        candidateJar,
        libraryClassPath,
        platformLibraryPool,
        retainedRoots,
        true,
        normalizeClassNames(unchangedPassThroughClassNames),
        this::archive);
  }

  /**
   * Tolerates unresolved sibling links; Kotlin metadata is rejected.
   *
   * @param platformLibraryPool ProGuard {@code LibraryClass} API definitions
   */
  public DependencyJarTrimmer.TrimAnalysis analyzeWithUnchangedPassThroughLibraries(
      final Path candidateJar,
      final Collection<Path> libraryClassPath,
      final ClassPool platformLibraryPool,
      final Collection<String> retainedRoots,
      final Collection<String> unchangedPassThroughClassNames)
      throws IOException {
    return trimmer.analyzeInternal(
        candidateJar,
        libraryClassPath,
        platformLibraryPool,
        retainedRoots,
        false,
        normalizeClassNames(unchangedPassThroughClassNames),
        this::archive);
  }

  @SuppressWarnings("PMD.CyclomaticComplexity")
  private ArchiveSnapshot archive(final Path path, final boolean candidate) throws IOException {
    if (candidate && !Files.isRegularFile(path)) {
      throw new IllegalArgumentException("Candidate JAR is not a regular file: " + path);
    }
    final Path fileName = path.getFileName();
    if (!candidate
        && (Files.isDirectory(path) || fileName == null || !fileName.toString().endsWith(".jar"))) {
      throw new IOException("Only flat sibling JAR libraries are supported: " + path);
    }
    final Path key = path.toAbsolutePath().normalize();
    archiveLock.lock();
    try {
      ArchiveSnapshot snapshot = archives.get(key);
      if (snapshot == null) {
        snapshot = ArchiveSnapshot.read(key, candidate);
        archives.put(key, snapshot);
      }
      if (candidate) {
        snapshot.validateCandidate(key);
      }
      return snapshot;
    } finally {
      archiveLock.unlock();
    }
  }

  private static Set<String> normalizeClassNames(final Collection<String> classNames) {
    Objects.requireNonNull(classNames, "classNames");
    final Set<String> normalized = new HashSet<>();
    classNames.forEach(name -> normalized.add(name.replace('.', '/')));
    return normalized;
  }
}
