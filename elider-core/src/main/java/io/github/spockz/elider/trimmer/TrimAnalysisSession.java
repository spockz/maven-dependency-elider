/* WHY: Reuses validated archive bytes across closure passes without sharing mutable ProGuard
 * pools. */

package io.github.spockz.elider.trimmer;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Collection;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;
import java.util.concurrent.locks.ReentrantLock;
import proguard.classfile.ClassPool;

/** Holds immutable input snapshots for one multi-candidate trim invocation. */
@SuppressWarnings({"PMD.CommentSize", "PMD.TooManyMethods"})
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
   * Analyzes with JDK class table declarations; Kotlin metadata is rejected.
   *
   * @param jdkClassTable ProGuard {@code LibraryClass} API definitions
   */
  public DependencyJarTrimmer.TrimAnalysis analyze(
      final Path candidateJar,
      final Collection<Path> libraryClassPath,
      final ClassPool jdkClassTable,
      final Collection<String> retainedRoots)
      throws IOException {
    return trimmer.analyzeInternal(
        candidateJar,
        libraryClassPath,
        jdkClassTable,
        retainedRoots,
        false,
        Set.of(),
        this::archive);
  }

  /**
   * Prepares an unchanged candidate; Kotlin metadata is rejected.
   *
   * @param jdkClassTable ProGuard {@code LibraryClass} API definitions
   */
  public DependencyJarTrimmer.PreparedAnalysis prepareUnchangedPassThrough(
      final Path candidateJar,
      final Collection<Path> libraryClassPath,
      final ClassPool jdkClassTable,
      final Collection<String> unchangedPassThroughClassNames)
      throws IOException {
    // Copy API signatures now so later caller mutations cannot change this context.
    return trimmer.prepareInternal(
        candidateJar,
        libraryClassPath,
        jdkClassTable,
        true,
        normalizeClassNames(unchangedPassThroughClassNames),
        this::archive);
  }

  /**
   * Prepares candidate closure; Kotlin metadata is rejected.
   *
   * @param jdkClassTable ProGuard {@code LibraryClass} API definitions
   */
  public DependencyJarTrimmer.PreparedAnalysis prepareWithUnchangedPassThroughLibraries(
      final Path candidateJar,
      final Collection<Path> libraryClassPath,
      final ClassPool jdkClassTable,
      final Collection<String> unchangedPassThroughClassNames)
      throws IOException {
    return prepareWithUnchangedPassThroughLibraries(
        candidateJar, libraryClassPath, jdkClassTable, unchangedPassThroughClassNames, false);
  }

  /**
   * Prepares candidate closure; optionally allowing modular candidates in classpath-only mode.
   *
   * @param candidateJar candidate archive under analysis
   * @param libraryClassPath resolved compile dependencies
   * @param jdkClassTable ProGuard {@code LibraryClass} API definitions
   * @param unchangedPassThroughClassNames classes passed through unchanged
   * @param allowModularCandidate whether to allow modular candidates in classpath-only mode
   * @return prepared analysis
   * @throws IOException on read or analysis error
   */
  public DependencyJarTrimmer.PreparedAnalysis prepareWithUnchangedPassThroughLibraries(
      final Path candidateJar,
      final Collection<Path> libraryClassPath,
      final ClassPool jdkClassTable,
      final Collection<String> unchangedPassThroughClassNames,
      final boolean allowModularCandidate)
      throws IOException {
    return prepareWithUnchangedPassThroughLibraries(
        candidateJar,
        libraryClassPath,
        jdkClassTable,
        unchangedPassThroughClassNames,
        allowModularCandidate,
        false);
  }

  /**
   * Prepares candidate closure; optionally tolerating unresolved program references.
   *
   * @param candidateJar candidate archive under analysis
   * @param libraryClassPath resolved compile dependencies
   * @param jdkClassTable ProGuard {@code LibraryClass} API definitions
   * @param unchangedPassThroughClassNames classes passed through unchanged
   * @param allowModularCandidate whether to allow modular candidates in classpath-only mode
   * @param tolerateUnresolvedProgramReferences whether to tolerate references absent from the
   *     classpath
   * @return prepared analysis
   * @throws IOException on read or analysis error
   */
  public DependencyJarTrimmer.PreparedAnalysis prepareWithUnchangedPassThroughLibraries(
      final Path candidateJar,
      final Collection<Path> libraryClassPath,
      final ClassPool jdkClassTable,
      final Collection<String> unchangedPassThroughClassNames,
      final boolean allowModularCandidate,
      final boolean tolerateUnresolvedProgramReferences)
      throws IOException {
    // Copy API signatures now so later caller mutations cannot change this context.
    return trimmer.prepareInternal(
        candidateJar,
        libraryClassPath,
        jdkClassTable,
        tolerateUnresolvedProgramReferences,
        normalizeClassNames(unchangedPassThroughClassNames),
        (path, candidate) -> archives.read(path, candidate, allowModularCandidate));
  }

  /**
   * Analyzes an unchanged candidate; Kotlin metadata is rejected.
   *
   * @param jdkClassTable ProGuard {@code LibraryClass} API definitions
   */
  public DependencyJarTrimmer.TrimAnalysis analyzeUnchangedPassThrough(
      final Path candidateJar,
      final Collection<Path> libraryClassPath,
      final ClassPool jdkClassTable,
      final Collection<String> retainedRoots,
      final Collection<String> unchangedPassThroughClassNames)
      throws IOException {
    return trimmer.analyzeInternal(
        candidateJar,
        libraryClassPath,
        jdkClassTable,
        retainedRoots,
        true,
        normalizeClassNames(unchangedPassThroughClassNames),
        this::archive);
  }

  /**
   * Tolerates unresolved sibling links; Kotlin metadata is rejected.
   *
   * @param jdkClassTable ProGuard {@code LibraryClass} API definitions
   */
  public DependencyJarTrimmer.TrimAnalysis analyzeWithUnchangedPassThroughLibraries(
      final Path candidateJar,
      final Collection<Path> libraryClassPath,
      final ClassPool jdkClassTable,
      final Collection<String> retainedRoots,
      final Collection<String> unchangedPassThroughClassNames)
      throws IOException {
    return trimmer.analyzeInternal(
        candidateJar,
        libraryClassPath,
        jdkClassTable,
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

  private DependencyJarTrimmer.PreparedAnalysis prepareWithSharedTier(
      final Path candidateJar,
      final Collection<Path> libraryClassPath,
      final ClassPool jdkClassTable,
      final boolean tolerateUnresolvedProgramReferences,
      final Set<String> toleratedUnresolvedLibraryClasses,
      final ArchiveProvider archiveProvider,
      final TierLibraryIndex.Supplier sharedTierSupplier)
      throws IOException {
    return new DependencyJarTrimmer.PreparedAnalysis(
        ReferenceGraphBuilder.prepareWithSharedTier(
            candidateJar,
            libraryClassPath,
            jdkClassTable,
            tolerateUnresolvedProgramReferences,
            toleratedUnresolvedLibraryClasses,
            archiveProvider,
            sharedTierSupplier));
  }

  private ArchiveSnapshot readArchive(
      final Path path, final boolean candidate, final boolean allowModularCandidate)
      throws IOException {
    return archives.read(path, candidate, allowModularCandidate);
  }

  /**
   * Creates a shared tier context that pre-indexes library-role edges once across targets.
   *
   * @param tierArchives all unique-owner archives in the tier classpath
   * @param jdkClassTable ProGuard {@code LibraryClass} API definitions
   * @return shared tier preparation context
   */
  public SharedTierContext prepareSharedTierContext(
      final Collection<Path> tierArchives, final ClassPool jdkClassTable) {
    Objects.requireNonNull(tierArchives, "tierArchives");
    Objects.requireNonNull(jdkClassTable, "jdkClassTable");
    return new SharedTierContext(this, java.util.List.copyOf(tierArchives), jdkClassTable);
  }

  /** Shares one lazily constructed library-role reference index across a tier's targets. */
  public static final class SharedTierContext {
    /** Owning session providing archive snapshots and trimmer engine. */
    private final TrimAnalysisSession session;

    /** Ordered tier archives whose library-role edges are indexed once. */
    private final Collection<Path> tierArchives;

    /** JDK class table templates for the tier. */
    private final ClassPool jdkClassTable;

    /** Serializes lazy single-flight index construction across parallel workers. */
    private final ReentrantLock buildLock = new ReentrantLock();

    /** True once {@link #getOrBuild()} has attempted construction. */
    private boolean attempted;

    /** Cached library-role tier index, or {@code null} when duplicates force fallback. */
    private TierLibraryIndex cachedIndex;

    private SharedTierContext(
        final TrimAnalysisSession session,
        final Collection<Path> tierArchives,
        final ClassPool jdkClassTable) {
      this.session = session;
      this.tierArchives = tierArchives;
      this.jdkClassTable = jdkClassTable;
    }

    /** Prepares an unchanged pass-through program archive using the shared tier index. */
    public DependencyJarTrimmer.PreparedAnalysis prepareUnchangedPassThrough(
        final Path candidateJar,
        final Collection<Path> libraryClassPath,
        final Collection<String> unchangedPassThroughClassNames)
        throws IOException {
      return session.prepareWithSharedTier(
          candidateJar,
          libraryClassPath,
          jdkClassTable,
          true,
          normalizeClassNames(unchangedPassThroughClassNames),
          session::archive,
          this::getOrBuild);
    }

    /** Prepares candidate closure using the shared tier index. */
    public DependencyJarTrimmer.PreparedAnalysis prepareWithUnchangedPassThroughLibraries(
        final Path candidateJar,
        final Collection<Path> libraryClassPath,
        final Collection<String> unchangedPassThroughClassNames,
        final boolean allowModularCandidate)
        throws IOException {
      return prepareWithUnchangedPassThroughLibraries(
          candidateJar,
          libraryClassPath,
          unchangedPassThroughClassNames,
          allowModularCandidate,
          false);
    }

    /** Prepares candidate closure using the shared tier index. */
    public DependencyJarTrimmer.PreparedAnalysis prepareWithUnchangedPassThroughLibraries(
        final Path candidateJar,
        final Collection<Path> libraryClassPath,
        final Collection<String> unchangedPassThroughClassNames,
        final boolean allowModularCandidate,
        final boolean tolerateUnresolvedProgramReferences)
        throws IOException {
      return session.prepareWithSharedTier(
          candidateJar,
          libraryClassPath,
          jdkClassTable,
          tolerateUnresolvedProgramReferences,
          normalizeClassNames(unchangedPassThroughClassNames),
          (path, candidate) -> session.readArchive(path, candidate, allowModularCandidate),
          this::getOrBuild);
    }

    /* default */ boolean indexBuilt() {
      buildLock.lock();
      try {
        return attempted;
      } finally {
        buildLock.unlock();
      }
    }

    private TierLibraryIndex getOrBuild() throws IOException {
      buildLock.lock();
      try {
        if (!attempted) {
          cachedIndex =
              TierLibraryIndex.build(
                  tierArchives,
                  jdkClassTable,
                  (path, candidate) -> session.readArchive(path, false, false));
          attempted = true;
        }
        return cachedIndex;
      } finally {
        buildLock.unlock();
      }
    }
  }

  /** Coordinates path-keyed single-flight archive snapshot loading. */
  private static final class ArchiveSnapshots {
    /** Single-flight archive reads keyed by normalized path. */
    private final ConcurrentMap<Path, FutureTask<ArchiveSnapshot>> archives =
        new ConcurrentHashMap<>();

    private ArchiveSnapshot read(final Path path, final boolean candidate) throws IOException {
      return read(path, candidate, false);
    }

    private ArchiveSnapshot read(
        final Path path, final boolean candidate, final boolean allowModularCandidate)
        throws IOException {
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
        snapshot.validateCandidate(key, allowModularCandidate);
      }
      return snapshot;
    }

    private static void validatePath(final Path path, final boolean candidate) throws IOException {
      ArchiveSnapshot.validatePath(path, candidate);
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
