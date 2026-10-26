/* WHY: Computes per-artifact class retention with ProGuard Core so a retained dependency can be
 * reduced without merging it with sibling artifacts. */

package io.github.spockz.elider.trimmer;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;
import proguard.classfile.ClassPool;

/** Computes class retention from roots; it does not discover them. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
public final class DependencyJarTrimmer {
  /** Creates a dependency trimmer backed by ProGuard Core's class-file model. */
  @SuppressWarnings("PMD.UncommentedEmptyConstructor")
  public DependencyJarTrimmer() {}

  /**
   * Computes closure from caller roots and flat, non-MR sibling JARs.
   *
   * @param libraryClassPath flat sibling JAR paths
   * @param retainedRoots complete caller roots; empty retains all candidate classes
   */
  public TrimAnalysis analyze(
      final Path candidateJar,
      final Collection<Path> libraryClassPath,
      final Collection<String> retainedRoots)
      throws IOException {
    return analyzeInternal(
        candidateJar,
        libraryClassPath,
        new ClassPool(),
        retainedRoots,
        false,
        Set.of(),
        ArchiveSnapshot::read);
  }

  /**
   * Adds the explicitly selected compiler/JDK API pool to closure analysis.
   *
   * @param platformLibraryPool API classes for the effective compiler release
   */
  public TrimAnalysis analyze(
      final Path candidateJar,
      final Collection<Path> libraryClassPath,
      final ClassPool platformLibraryPool,
      final Collection<String> retainedRoots)
      throws IOException {
    return analyzeInternal(
        candidateJar,
        libraryClassPath,
        platformLibraryPool,
        retainedRoots,
        false,
        Set.of(),
        ArchiveSnapshot::read);
  }

  /**
   * Computes links from every class in an unchanged pass-through archive.
   *
   * <p>Unresolved links from unchanged classes are ignored.
   *
   * <p>Absent classes cannot identify candidates. Sibling gaps remain fatal.
   */
  public TrimAnalysis analyzeUnchangedPassThrough(
      final Path candidateJar,
      final Collection<Path> libraryClassPath,
      final ClassPool platformLibraryPool,
      final Collection<String> retainedRoots)
      throws IOException {
    return analyzeUnchangedPassThrough(
        candidateJar, libraryClassPath, platformLibraryPool, retainedRoots, Set.of());
  }

  /** Computes closure for one unchanged pass-through archive and its sibling owners. */
  public TrimAnalysis analyzeUnchangedPassThrough(
      final Path candidateJar,
      final Collection<Path> libraryClassPath,
      final ClassPool platformLibraryPool,
      final Collection<String> retainedRoots,
      final Collection<String> unchangedPassThroughClassNames)
      throws IOException {
    Objects.requireNonNull(unchangedPassThroughClassNames, "unchangedPassThroughClassNames");
    final Set<String> toleratedNames = normalizeClassNames(unchangedPassThroughClassNames);
    return analyzeInternal(
        candidateJar,
        libraryClassPath,
        platformLibraryPool,
        retainedRoots,
        true,
        toleratedNames,
        ArchiveSnapshot::read);
  }

  /** Computes candidate closure with unchanged-library tolerance. */
  public TrimAnalysis analyzeWithUnchangedPassThroughLibraries(
      final Path candidateJar,
      final Collection<Path> libraryClassPath,
      final ClassPool platformLibraryPool,
      final Collection<String> retainedRoots,
      final Collection<String> unchangedPassThroughClassNames)
      throws IOException {
    Objects.requireNonNull(unchangedPassThroughClassNames, "unchangedPassThroughClassNames");
    final Set<String> toleratedNames = normalizeClassNames(unchangedPassThroughClassNames);
    return analyzeInternal(
        candidateJar,
        libraryClassPath,
        platformLibraryPool,
        retainedRoots,
        false,
        toleratedNames,
        ArchiveSnapshot::read);
  }

  /** Package scope builds one lazy graph context for repeated closure queries. */
  TrimAnalysis analyzeInternal(
      final Path candidateJar,
      final Collection<Path> libraryClassPath,
      final ClassPool platformLibraryPool,
      final Collection<String> retainedRoots,
      final boolean tolerateUnresolvedProgramReferences,
      final Set<String> toleratedUnresolvedLibraryClasses,
      final ArchiveProvider archiveProvider)
      throws IOException {
    return prepareInternal(
            candidateJar,
            libraryClassPath,
            platformLibraryPool,
            tolerateUnresolvedProgramReferences,
            toleratedUnresolvedLibraryClasses,
            archiveProvider)
        .analyze(retainedRoots);
  }

  /** Package scope creates a reusable context without retaining ProGuard pools. */
  PreparedAnalysis prepareInternal(
      final Path candidateJar,
      final Collection<Path> libraryClassPath,
      final ClassPool platformLibraryPool,
      final boolean tolerateUnresolvedProgramReferences,
      final Set<String> toleratedUnresolvedLibraryClasses,
      final ArchiveProvider archiveProvider)
      throws IOException {
    return new PreparedAnalysis(
        ReferenceGraphBuilder.prepare(
            candidateJar,
            libraryClassPath,
            platformLibraryPool,
            tolerateUnresolvedProgramReferences,
            toleratedUnresolvedLibraryClasses,
            archiveProvider));
  }

  /** Reuses one graph across closure queries. */
  public static final class PreparedAnalysis {
    /** Holds transactional traversal state and the lazily constructed adjacency graph. */
    private final PreparedAnalysisState state;

    private PreparedAnalysis(final PreparedAnalysisState state) {
      this.state = state;
    }

    /** Computes closure from roots, extending a prior successful closure when possible. */
    public TrimAnalysis analyze(final Collection<String> retainedRoots) throws IOException {
      return state.analyze(retainedRoots);
    }

    /** Package scope exposes the number of nodes expanded across successful queries. */
    int expandedNodeCount() {
      return state.expandedNodeCount();
    }

    /** Package scope exposes whether adjacency has been constructed. */
    boolean referenceGraphBuilt() {
      return state.graphBuilt();
    }
  }

  /** Package scope normalizes root names for the reusable traversal state. */
  static Set<String> normalizeRoots(final Collection<String> roots) {
    final Set<String> normalized = new LinkedHashSet<>();
    for (final String root : roots) {
      if (root == null || root.isBlank()) {
        throw new IllegalArgumentException("Retained roots must not contain null or blank names");
      }
      final String name = root.replace('.', '/');
      if (name.startsWith("[") || name.endsWith(".class") || name.contains(";")) {
        throw new IllegalArgumentException(
            "Root must be a class name, not a descriptor or path: " + root);
      }
      normalized.add(name);
    }
    return normalized;
  }

  private static Set<String> normalizeClassNames(final Collection<String> classNames) {
    Objects.requireNonNull(classNames, "classNames");
    final Set<String> normalized = new HashSet<>();
    classNames.forEach(name -> normalized.add(name.replace('.', '/')));
    return normalized;
  }

  /** Package scope shares the accepted archive rule with the sanitizer. */
  static boolean isVersionedModuleDescriptor(final String entryName) {
    return entryName.matches("META-INF/versions/[0-9]+/module-info\\.class");
  }

  /** Immutable analysis result preserving roots for audit callers. */
  public record TrimAnalysis(
      int totalClasses,
      Set<String> retainedClasses,
      Set<String> roots,
      Set<String> reachableLibraryClasses) {
    /** Preserves the prior constructor for existing callers. */
    public TrimAnalysis(
        final int totalClasses, final Set<String> retainedClasses, final Set<String> roots) {
      this(totalClasses, retainedClasses, roots, Set.of());
    }

    /** Copies the result sets into immutable snapshots. */
    public TrimAnalysis {
      retainedClasses = Set.copyOf(retainedClasses);
      roots = Set.copyOf(roots);
      reachableLibraryClasses = Set.copyOf(reachableLibraryClasses);
    }
  }

  /** Reports unresolved links so callers cannot emit an incomplete JAR. */
  public static final class UnresolvedReferenceException extends IOException {
    private static final long serialVersionUID = 1L;

    /** Creates a failure listing unresolved candidate references. */
    public UnresolvedReferenceException(final Path candidateJar, final Set<String> references) {
      super("Cannot safely trim " + candidateJar + "; unresolved references: " + references);
    }
  }
}
