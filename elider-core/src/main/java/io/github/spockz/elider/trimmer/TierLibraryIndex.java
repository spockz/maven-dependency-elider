/* WHY: Shares immutable library-role edge indexes across one tier classpath. */

package io.github.spockz.elider.trimmer;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.AbstractMap;
import java.util.AbstractSet;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Stream;
import proguard.classfile.ClassPool;
import proguard.classfile.Clazz;

/** Immutable pre-indexed library-role reference graph shared across one tier. */
@SuppressWarnings({"PMD.CommentDefaultAccessModifier", "PMD.UseConcurrentHashMap"})
final class TierLibraryIndex {
  /** Isolated read-only JDK API templates for on-demand platform resolution. */
  private final ClassPool jdkTable;

  /** Unlinked sibling library templates cloned lazily per target. */
  private final FrozenClassPool templates;

  /** Known sibling class names in this tier. */
  private final Set<String> classNames;

  /** Pre-indexed library-role reference graph for this tier. */
  private final ReferenceGraph libraryGraph;

  TierLibraryIndex(
      final ClassPool jdkTable,
      final FrozenClassPool templates,
      final Set<String> classNames,
      final ReferenceGraph libraryGraph) {
    this.jdkTable = Objects.requireNonNull(jdkTable, "jdkTable");
    this.templates = Objects.requireNonNull(templates, "templates");
    this.classNames = Set.copyOf(classNames);
    this.libraryGraph = Objects.requireNonNull(libraryGraph, "libraryGraph");
  }

  /** Builds a shared tier index using first-wins sibling precedence. */
  static TierLibraryIndex build(
      final Collection<Path> tierArchives,
      final ClassPool jdkClassTable,
      final ArchiveProvider archiveProvider)
      throws IOException {
    final ClassPool isolatedJdkTable = ReferenceGraphBuilder.isolateJdkClassTable(jdkClassTable);
    final ClassPool emptyProgramPool = new ClassPool();
    final Set<String> platformNames = new HashSet<>();
    final LazyPlatformClassPool lazyPool =
        new LazyPlatformClassPool(emptyProgramPool, isolatedJdkTable, platformNames);
    final ClassPool siblingTemplates = new ClassPool();
    final Map<String, ArchiveSnapshot> archiveByClass = new LinkedHashMap<>();
    for (final Path archivePath : tierArchives) {
      if (archivePath == null || !Files.exists(archivePath)) {
        throw new IllegalArgumentException(
            "Library classpath entry does not exist: " + archivePath);
      }
      final ArchiveSnapshot archive = archiveProvider.read(archivePath, false);
      final ClassPool pool = ReferenceGraphBuilder.checkedPool(archive, true, archivePath);
      for (final Clazz clazz : pool.classes()) {
        if (archiveByClass.putIfAbsent(clazz.getName(), archive) == null) {
          lazyPool.addClass(clazz);
          siblingTemplates.addClass(PlatformClassSnapshot.copyLibraryClassPreservingKotlin(clazz));
        }
      }
    }
    final ReferenceGraph libraryGraph =
        new ReferenceGraphIndexer(emptyProgramPool, lazyPool, platformNames, archiveByClass)
            .buildLibraryTier();
    return new TierLibraryIndex(
        isolatedJdkTable,
        FrozenClassPool.copyOf(siblingTemplates),
        archiveByClass.keySet(),
        libraryGraph);
  }

  ClassPool isolatedJdkTable() {
    return jdkTable;
  }

  FrozenClassPool siblingTemplates() {
    return templates;
  }

  boolean containsClass(final String internalName) {
    return classNames.contains(internalName);
  }

  ReferenceGraph overlayWithProgram(final ReferenceGraph programGraph) {
    final Set<String> programClassNames = programGraph.programClassNames();
    return new ReferenceGraph(
        programClassNames,
        new ExcludingSet(libraryGraph.libraryClassNames(), programClassNames),
        overlay(programClassNames, programGraph.edges(), libraryGraph.edges()),
        overlay(programClassNames, programGraph.typedEdges(), libraryGraph.typedEdges()),
        overlay(
            programClassNames, programGraph.unclassifiedEdges(), libraryGraph.unclassifiedEdges()),
        overlay(
            programClassNames,
            programGraph.unusedConstantPoolEdges(),
            libraryGraph.unusedConstantPoolEdges()),
        overlay(
            programClassNames,
            programGraph.unrecognizedClassAttributes(),
            libraryGraph.unrecognizedClassAttributes()),
        programGraph.unresolvedProgramReferences(),
        overlay(programClassNames, Map.of(), libraryGraph.unresolvedLibraryReferences()),
        overlay(programClassNames, programGraph.edgeFailures(), libraryGraph.edgeFailures()),
        programGraph.totalClasses());
  }

  private static <V> Map<String, V> overlay(
      final Set<String> programClassNames,
      final Map<String, V> programMap,
      final Map<String, V> libraryMap) {
    return new OverlayMap<>(programClassNames, programMap, libraryMap);
  }

  /** Supplies the lazily constructed shared tier index. */
  @FunctionalInterface
  interface Supplier {
    /** Returns the shared tier index or {@code null} when fallback is required. */
    TierLibraryIndex get() throws IOException;
  }

  /** Excludes candidate program classes from the shared library set. */
  private static final class ExcludingSet extends AbstractSet<String> {
    /** Shared library class names. */
    private final Set<String> base;

    /** Candidate program class names to exclude. */
    private final Set<String> excluded;

    private ExcludingSet(final Set<String> base, final Set<String> excluded) {
      super();
      this.base = base;
      this.excluded = excluded;
    }

    @Override
    public boolean contains(final Object value) {
      return value instanceof String name && base.contains(name) && !excluded.contains(name);
    }

    @Override
    public Iterator<String> iterator() {
      return base.stream().filter(name -> !excluded.contains(name)).iterator();
    }

    @Override
    public int size() {
      return Math.toIntExact(base.stream().filter(name -> !excluded.contains(name)).count());
    }
  }

  /** Shadows shared library entries for candidate program classes. */
  private static final class OverlayMap<V> extends AbstractMap<String, V> {
    /** Candidate program class names that take precedence over library entries. */
    private final Set<String> programClassNames;

    /** Candidate program entries. */
    private final Map<String, V> programMap;

    /** Shared tier library entries. */
    private final Map<String, V> libraryMap;

    private OverlayMap(
        final Set<String> programClassNames,
        final Map<String, V> programMap,
        final Map<String, V> libraryMap) {
      super();
      this.programClassNames = programClassNames;
      this.programMap = programMap;
      this.libraryMap = libraryMap;
    }

    @Override
    public V get(final Object key) {
      if (key instanceof String name && programClassNames.contains(name)) {
        return programMap.get(name);
      }
      return libraryMap.get(key);
    }

    @Override
    public boolean containsKey(final Object key) {
      if (key instanceof String name && programClassNames.contains(name)) {
        return programMap.containsKey(name);
      }
      return libraryMap.containsKey(key);
    }

    @Override
    public Set<Entry<String, V>> entrySet() {
      return new AbstractSet<>() {
        @Override
        public Iterator<Entry<String, V>> iterator() {
          return Stream.concat(
                  programMap.entrySet().stream(),
                  libraryMap.entrySet().stream()
                      .filter(entry -> !programClassNames.contains(entry.getKey())))
              .iterator();
        }

        @Override
        public int size() {
          final long libraryCount =
              libraryMap.keySet().stream()
                  .filter(name -> !programClassNames.contains(name))
                  .count();
          return Math.toIntExact(programMap.size() + libraryCount);
        }
      };
    }
  }
}
