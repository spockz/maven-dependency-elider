/* WHY: Reuses validated archive bytes across closure passes without sharing mutable ProGuard
 * pools. */

package io.github.spockz.elider.trimmer;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collection;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;
import proguard.classfile.ClassPool;

/** Holds immutable input snapshots for one multi-candidate trim invocation. */
public final class TrimAnalysisSession {
  /** Engine used to construct an isolated reference model for each analysis. */
  private final DependencyJarTrimmer trimmer;

  /** Single-flight archive reads keyed by normalized path. */
  private final ArchiveSnapshots archives = new ArchiveSnapshots();

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

  private ArchiveSnapshot archive(final Path path, final boolean candidate) throws IOException {
    return archives.read(path, candidate);
  }

  private static Set<String> normalizeClassNames(final Collection<String> classNames) {
    Objects.requireNonNull(classNames, "classNames");
    final Set<String> normalized = new HashSet<>();
    classNames.forEach(name -> normalized.add(name.replace('.', '/')));
    return normalized;
  }

  /** Coordinates path-keyed single-flight archive snapshot loading. */
  private static final class ArchiveSnapshots {
    /** Single-flight archive reads keyed by normalized path. */
    private final ConcurrentMap<Path, FutureTask<ArchiveSnapshot>> archives =
        new ConcurrentHashMap<>();

    private ArchiveSnapshot read(final Path path, final boolean candidate) throws IOException {
      validatePath(path, candidate);
      final Path key = path.toAbsolutePath().normalize();
      final FutureTask<ArchiveSnapshot> newRead =
          new FutureTask<>(() -> ArchiveSnapshot.read(key, false));
      FutureTask<ArchiveSnapshot> read = archives.putIfAbsent(key, newRead);
      if (read == null) {
        read = newRead;
        read.run();
      }
      final ArchiveSnapshot snapshot = await(key, read);
      if (candidate) {
        snapshot.validateCandidate(key);
      }
      return snapshot;
    }

    private static void validatePath(final Path path, final boolean candidate) throws IOException {
      if (candidate && !Files.isRegularFile(path)) {
        throw new IllegalArgumentException("Candidate JAR is not a regular file: " + path);
      }
      final Path fileName = path.getFileName();
      if (!candidate
          && (Files.isDirectory(path)
              || fileName == null
              || !fileName.toString().endsWith(".jar"))) {
        throw new IOException("Only flat sibling JAR libraries are supported: " + path);
      }
    }

    // Restore interrupt status so the caller can cancel its parallel stage.
    @SuppressWarnings("PMD.DoNotUseThreads")
    private ArchiveSnapshot await(final Path key, final FutureTask<ArchiveSnapshot> read)
        throws IOException {
      try {
        return read.get();
      } catch (final InterruptedException exception) {
        Thread.currentThread().interrupt();
        throw new IOException("Interrupted while reading archive snapshot: " + key, exception);
      } catch (final ExecutionException exception) {
        return failedRead(key, read, exception);
      }
    }

    private ArchiveSnapshot failedRead(
        final Path key, final FutureTask<ArchiveSnapshot> read, final ExecutionException exception)
        throws IOException {
      archives.remove(key, read);
      final Throwable cause = exception.getCause();
      if (cause instanceof IOException ioException) {
        throw ioException;
      }
      if (cause instanceof RuntimeException runtimeException) {
        throw new IOException("Could not read archive snapshot: " + key, runtimeException);
      }
      if (cause instanceof Error error) {
        throw error;
      }
      throw new IOException("Could not read archive snapshot: " + key, cause);
    }
  }
}
