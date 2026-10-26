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
import proguard.classfile.ClassPool;

/** Holds immutable input snapshots for one multi-candidate trim invocation. */
@SuppressWarnings("PMD.UseConcurrentHashMap")
public final class TrimAnalysisSession {
  /** Engine used to construct an isolated reference model for each analysis. */
  private final DependencyJarTrimmer trimmer;

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

  /** Analyzes one candidate with the supplied platform API and fresh ProGuard pools. */
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

  /** Prepares an unchanged candidate with its supplied API context. */
  public DependencyJarTrimmer.PreparedAnalysis prepareUnchangedPassThrough(
      final Path candidateJar,
      final Collection<Path> libraryClassPath,
      final ClassPool platformLibraryPool,
      final Collection<String> unchangedPassThroughClassNames)
      throws IOException {
    // The pool is read on the first non-empty query.
    return trimmer.prepareInternal(
        candidateJar,
        libraryClassPath,
        platformLibraryPool,
        true,
        normalizeClassNames(unchangedPassThroughClassNames),
        this::archive);
  }

  /** Prepares a candidate with tolerated unchanged sibling classes. */
  public DependencyJarTrimmer.PreparedAnalysis prepareWithUnchangedPassThroughLibraries(
      final Path candidateJar,
      final Collection<Path> libraryClassPath,
      final ClassPool platformLibraryPool,
      final Collection<String> unchangedPassThroughClassNames)
      throws IOException {
    // The pool is read on the first non-empty query.
    return trimmer.prepareInternal(
        candidateJar,
        libraryClassPath,
        platformLibraryPool,
        false,
        normalizeClassNames(unchangedPassThroughClassNames),
        this::archive);
  }

  /** Analyzes an unchanged pass-through candidate with cached sibling archive bytes. */
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

  /** Tolerates unresolved references originating in unchanged sibling libraries. */
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
    ArchiveSnapshot snapshot = archives.get(key);
    if (snapshot == null) {
      snapshot = ArchiveSnapshot.read(key, candidate);
      archives.put(key, snapshot);
    }
    if (candidate) {
      snapshot.validateCandidate(key);
    }
    return snapshot;
  }

  private static Set<String> normalizeClassNames(final Collection<String> classNames) {
    Objects.requireNonNull(classNames, "classNames");
    final Set<String> normalized = new HashSet<>();
    classNames.forEach(name -> normalized.add(name.replace('.', '/')));
    return normalized;
  }
}
