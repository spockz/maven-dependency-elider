/* WHY: Closes compiled test references over allowed originals without changing production. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.scanner.BytecodeReferenceScan;
import io.github.spockz.elider.scanner.ProductionBytecodeReferenceScanner;
import io.github.spockz.elider.trimmer.ClosureQueryPolicy;
import io.github.spockz.elider.trimmer.DependencyJarTrimmer;
import io.github.spockz.elider.trimmer.TrimAnalysisSession;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Stream;
import proguard.classfile.ClassPool;

/** Builds a test addition from compiled roots. */
@SuppressWarnings({
  "PMD.CommentDefaultAccessModifier",
  "PMD.CommentRequired",
  "PMD.CouplingBetweenObjects",
  "PMD.GodClass",
  "PMD.TestClassWithoutTestCases",
  "PMD.UseConcurrentHashMap",
  "PMD.AvoidInstantiatingObjectsInLoops",
  "PMD.CognitiveComplexity",
  "PMD.CyclomaticComplexity",
  "PMD.ExcessiveParameterList",
  "PMD.ForLoopCanBeForeach",
  "PMD.AvoidLiteralsInIfCondition",
  "PMD.NPathComplexity",
  "PMD.AvoidDeeplyNestedIfStmts"
})
final class TestAdditionsAnalyzer {
  private static final String CLASS_SUFFIX = ".class";

  private TestAdditionsAnalyzer() {}

  /** Original and effective JAR paths. */
  record ArtifactInput(
      String identity, Path originalJar, Optional<Path> effectiveRuntimeJar, boolean testScoped) {
    ArtifactInput(
        final String identity, final Path originalJar, final Optional<Path> effectiveRuntimeJar) {
      this(identity, originalJar, effectiveRuntimeJar, false);
    }

    ArtifactInput {
      Objects.requireNonNull(identity, "identity");
      Objects.requireNonNull(originalJar, "originalJar");
      Objects.requireNonNull(effectiveRuntimeJar, "effectiveRuntimeJar");
      if (identity.isBlank()) {
        throw new IllegalArgumentException("Original artifact identity must not be blank");
      }
      originalJar = originalJar.toAbsolutePath().normalize();
      effectiveRuntimeJar = effectiveRuntimeJar.map(path -> path.toAbsolutePath().normalize());
    }
  }

  /** An absent archive means no addition was needed. */
  record Result(
      Optional<Path> additionsJar,
      Map<String, Set<String>> addedClassesByArtifact,
      boolean conservativeFallbackUsed) {
    Result {
      additionsJar = Objects.requireNonNull(additionsJar, "additionsJar");
      addedClassesByArtifact =
          Collections.unmodifiableMap(new LinkedHashMap<>(addedClassesByArtifact));
    }
  }

  static Result prepare(
      final Path compiledTestClasses,
      final Path mainClasses,
      final List<ArtifactInput> allowedOriginals,
      final Path outputJar,
      final ClassPool jdkClassTable,
      final ClosureQueryPolicy queryPolicy)
      throws IOException {
    Objects.requireNonNull(compiledTestClasses, "compiledTestClasses");
    Objects.requireNonNull(mainClasses, "mainClasses");
    Objects.requireNonNull(allowedOriginals, "allowedOriginals");
    Objects.requireNonNull(outputJar, "outputJar");
    Objects.requireNonNull(jdkClassTable, "jdkClassTable");
    Objects.requireNonNull(queryPolicy, "queryPolicy");
    final Path output = outputJar.toAbsolutePath().normalize();
    if (!Files.exists(compiledTestClasses)) {
      Files.deleteIfExists(output);
      return new Result(Optional.empty(), Map.of(), false);
    }
    final Set<String> testNames = directoryClasses(compiledTestClasses);
    final Set<String> mainNames =
        Files.exists(mainClasses) ? directoryClasses(mainClasses) : Set.of();
    final List<TestAdditionsArchiveWriter.Inventory> originals =
        TestAdditionsArchiveWriter.inspect(allowedOriginals);
    verifyResourceView(originals);
    final Map<String, Integer> ownerByClass = owners(originals, testNames, mainNames);
    final RuntimeView runtime = runtimeView(originals);
    final boolean missingOriginalClasses =
        ownerByClass.entrySet().stream()
            .anyMatch(
                entry ->
                    !Objects.equals(runtime.firstOwners().get(entry.getKey()), entry.getValue()));
    if (!missingOriginalClasses) {
      Files.deleteIfExists(output);
      return new Result(Optional.empty(), Map.of(), false);
    }
    final BytecodeReferenceScan testReferences =
        new ProductionBytecodeReferenceScanner().scan(compiledTestClasses);
    final Set<String> testRoots = new TreeSet<>(testReferences.referencedClasses());
    final TestDynamicClassScanner.ScanResult testReflection =
        TestDynamicClassScanner.scanDirectory(compiledTestClasses);
    for (final String reflective : testReflection.literalNames()) {
      if (ownerByClass.containsKey(reflective.replace('.', '/'))) {
        testRoots.add(reflective);
      }
    }
    final List<Set<String>> roots = new ArrayList<>(originals.size());
    for (int index = 0; index < originals.size(); index++) {
      roots.add(new TreeSet<>());
    }
    addRoots(testRoots, ownerByClass, testNames, mainNames, jdkClassTable, roots);
    final boolean initialFallback = !testReflection.unresolvedDynamicCalls().isEmpty();
    if (initialFallback) {
      seedAllMissingClasses(ownerByClass, runtime.firstOwners(), roots);
    }
    if (roots.stream().allMatch(Set::isEmpty)) {
      Files.deleteIfExists(output);
      return new Result(Optional.empty(), Map.of(), false);
    }
    final ClosureResult closure =
        close(
            originals,
            roots,
            ownerByClass,
            runtime.firstOwners(),
            initialFallback,
            testNames,
            mainNames,
            compiledTestClasses,
            mainClasses,
            jdkClassTable,
            queryPolicy,
            output);
    final Map<String, Set<String>> additions =
        missingClasses(
            originals,
            closure.retained(),
            ownerByClass,
            runtime.firstOwners(),
            testNames,
            mainNames);
    TestAdditionsArchiveWriter.verifyServiceProviderView(
        originals, ownerByClass, runtime.firstOwners(), additions);
    if (additions.isEmpty()) {
      Files.deleteIfExists(output);
      return new Result(Optional.empty(), Map.of(), false);
    }
    TestAdditionsArchiveWriter.write(output, originals, additions);
    return new Result(Optional.of(output), additions, closure.conservativeFallbackUsed());
  }

  private static void verifyResourceView(final List<TestAdditionsArchiveWriter.Inventory> originals)
      throws IOException {
    for (final TestAdditionsArchiveWriter.Inventory original : originals) {
      if (original.resources().isEmpty()) {
        continue;
      }
      final Optional<Path> effective = original.input().effectiveRuntimeJar();
      if (effective.isEmpty()) {
        throw new IOException(
            "Dropped test artifact has dynamic resource roots requiring a complete test view: "
                + original.input().identity()
                + " "
                + original.resources());
      }
      final Path runtime = effective.orElseThrow();
      if (!Files.isSameFile(original.input().originalJar(), runtime)) {
        final Optional<String> changed =
            TestAdditionsArchiveWriter.changedResource(original, runtime);
        if (changed.isPresent()) {
          throw TestAdditionsArchiveWriter.changedResource(original, changed.orElseThrow());
        }
      }
    }
  }

  private static boolean seedAllMissingClasses(
      final Map<String, Integer> originalOwners,
      final Map<String, Integer> runtimeOwners,
      final List<Set<String>> roots)
      throws IOException {
    boolean changed = false;
    for (final String name : new TreeSet<>(originalOwners.keySet())) {
      final Integer originalOwner = originalOwners.get(name);
      final Integer runtimeOwner = runtimeOwners.get(name);
      if (runtimeOwner == null) {
        changed |= roots.get(originalOwner).add(name);
      } else if (!runtimeOwner.equals(originalOwner)) {
        throw new IOException("Effective test classpath selects a different provider for " + name);
      }
    }
    return changed;
  }

  private static Set<String> directoryClasses(final Path directory) throws IOException {
    if (!Files.isDirectory(directory)) {
      throw new IOException("Compiled class output directory is missing: " + directory);
    }
    final Set<String> names = new TreeSet<>();
    try (Stream<Path> paths = Files.walk(directory)) {
      for (final Path path : paths.filter(Files::isRegularFile).sorted().toList()) {
        if (!path.toString().endsWith(CLASS_SUFFIX)) {
          continue;
        }
        final String relative = directory.relativize(path).toString().replace('\\', '/');
        if ("module-info.class".equals(relative)) {
          throw new IOException(
              "Modular project class output is not supported by test additions: " + directory);
        }
        names.add(relative.substring(0, relative.length() - CLASS_SUFFIX.length()));
      }
    }
    return names;
  }

  private static Map<String, Integer> owners(
      final List<TestAdditionsArchiveWriter.Inventory> originals,
      final Set<String> testNames,
      final Set<String> mainNames)
      throws IOException {
    final Map<String, Integer> owners = new HashMap<>();
    for (int index = 0; index < originals.size(); index++) {
      for (final String name : originals.get(index).classes()) {
        if (testNames.contains(name) || mainNames.contains(name)) {
          throw new IOException("Duplicate project and dependency class provider: " + name);
        }
        if (owners.putIfAbsent(name, index) != null) {
          throw new IOException("Duplicate original test class provider: " + name);
        }
      }
    }
    return owners;
  }

  private static boolean addRoots(
      final Set<String> references,
      final Map<String, Integer> owners,
      final Set<String> testNames,
      final Set<String> mainNames,
      final ClassPool platform,
      final List<Set<String>> roots)
      throws IOException {
    boolean changed = false;
    for (final String dotted : references) {
      final String name = dotted.replace('.', '/');
      if (testNames.contains(name) || mainNames.contains(name) || platform.getClass(name) != null) {
        continue;
      }
      final Integer owner = owners.get(name);
      if (owner == null) {
        throw new IOException(
            "Compiled test reference has no allowed original provider: " + dotted);
      }
      changed |= roots.get(owner).add(name);
    }
    return changed;
  }

  private static ClosureResult close(
      final List<TestAdditionsArchiveWriter.Inventory> originals,
      final List<Set<String>> roots,
      final Map<String, Integer> ownerByClass,
      final Map<String, Integer> runtimeOwners,
      final boolean initialFallback,
      final Set<String> testNames,
      final Set<String> mainNames,
      final Path testDirectory,
      final Path mainDirectory,
      final ClassPool platform,
      final ClosureQueryPolicy queryPolicy,
      final Path output)
      throws IOException {
    boolean fallbackUsed = initialFallback;
    final List<Set<String>> retained = new ArrayList<>(originals.size());
    for (int index = 0; index < originals.size(); index++) {
      retained.add(Set.of());
    }
    try (ProjectClassArchive projectClasses =
            ProjectClassArchive.create(output, testDirectory, mainDirectory, testNames, mainNames);
        ProjectedArtifacts projected = ProjectedArtifacts.create(output, originals)) {
      final List<Path> classpath = projected.paths();
      final List<Path> tierClasspath = new ArrayList<>(projectClasses.paths());
      tierClasspath.addAll(classpath);
      final TrimAnalysisSession session = new TrimAnalysisSession(new DependencyJarTrimmer());
      try {
        final TrimAnalysisSession.SharedTierContext shared =
            session.prepareSharedTierContext(tierClasspath, platform);
        final List<Optional<DependencyJarTrimmer.PreparedAnalysis>> analyses = new ArrayList<>();
        for (int index = 0; index < classpath.size(); index++) {
          analyses.add(Optional.empty());
        }
        final List<Set<String>> scanned = new ArrayList<>(classpath.size());
        for (int index = 0; index < classpath.size(); index++) {
          scanned.add(new TreeSet<>());
        }
        boolean changed;
        do {
          changed = false;
          for (int index = 0; index < originals.size(); index++) {
            if (roots.get(index).isEmpty()) {
              continue;
            }
            if (analyses.get(index).isEmpty()) {
              final Path candidate = classpath.get(index);
              final List<Path> siblings = new ArrayList<>(tierClasspath);
              siblings.remove(candidate);
              analyses.set(
                  index,
                  Optional.of(
                      shared.prepareWithUnchangedPassThroughLibraries(
                          candidate, siblings, Set.of(), true, false)));
            }
            final DependencyJarTrimmer.TrimAnalysis analysis =
                analyses.get(index).orElseThrow().analyze(roots.get(index), queryPolicy);
            retained.set(index, analysis.retainedClasses());
            final Set<String> newlyRetained = new TreeSet<>(analysis.retainedClasses());
            newlyRetained.removeAll(scanned.get(index));
            if (!newlyRetained.isEmpty()) {
              scanned.get(index).addAll(newlyRetained);
              final TestDynamicClassScanner.ScanResult reflection =
                  TestDynamicClassScanner.scanArchiveClasses(classpath.get(index), newlyRetained);
              if (!reflection.unresolvedDynamicCalls().isEmpty()) {
                if (!fallbackUsed) {
                  changed |= seedAllMissingClasses(ownerByClass, runtimeOwners, roots);
                }
                fallbackUsed = true;
              }
              changed |=
                  addRoots(
                      reflection.literalNames().stream()
                          .filter(name -> ownerByClass.containsKey(name.replace('.', '/')))
                          .collect(java.util.stream.Collectors.toSet()),
                      ownerByClass,
                      testNames,
                      mainNames,
                      platform,
                      roots);
            }
            for (final String reached : analysis.reachableLibraryClasses()) {
              if (testNames.contains(reached)
                  || mainNames.contains(reached)
                  || platform.getClass(reached) != null) {
                continue;
              }
              final Integer owner = ownerByClass.get(reached);
              if (owner == null) {
                throw new IOException("Reached class has no allowed original provider: " + reached);
              }
              changed |= roots.get(owner).add(reached);
            }
          }
        } while (changed);
      } finally {
        session.clearSnapshots();
      }
    }
    return new ClosureResult(retained, fallbackUsed);
  }

  private record ClosureResult(List<Set<String>> retained, boolean conservativeFallbackUsed) {}

  private static Map<String, Set<String>> missingClasses(
      final List<TestAdditionsArchiveWriter.Inventory> originals,
      final List<Set<String>> retained,
      final Map<String, Integer> ownerByClass,
      final Map<String, Integer> runtimeOwners,
      final Set<String> testNames,
      final Set<String> mainNames)
      throws IOException {
    final Map<String, Set<String>> additions = new LinkedHashMap<>();
    for (int index = 0; index < originals.size(); index++) {
      final Set<String> missing = new TreeSet<>();
      for (final String name : retained.get(index)) {
        if (testNames.contains(name) || mainNames.contains(name)) {
          continue;
        }
        if (!Objects.equals(ownerByClass.get(name), index)) {
          throw new IOException("Test closure selected a non-owning provider: " + name);
        }
        final Integer runtimeOwner = runtimeOwners.get(name);
        if (runtimeOwner == null) {
          missing.add(name);
        } else if (runtimeOwner != index) {
          throw new IOException(
              "Effective test classpath selects a different provider for " + name);
        }
      }
      if (!missing.isEmpty()) {
        additions.put(originals.get(index).input().identity(), Set.copyOf(missing));
      }
    }
    return additions;
  }

  private static RuntimeView runtimeView(final List<TestAdditionsArchiveWriter.Inventory> originals)
      throws IOException {
    final Map<String, Integer> owners = new HashMap<>();
    for (int index = 0; index < originals.size(); index++) {
      final Optional<Path> runtime = originals.get(index).input().effectiveRuntimeJar();
      final Set<String> names =
          runtime.isEmpty()
              ? Set.of()
              : TestAdditionsArchiveWriter.classNames(runtime.orElseThrow());
      for (final String name : names) {
        owners.putIfAbsent(name, index);
      }
    }
    return new RuntimeView(Map.copyOf(owners));
  }

  private record RuntimeView(Map<String, Integer> firstOwners) {}

  /** Flattened release views are analysis inputs and never enter the runtime overlay. */
  private record ProjectedArtifacts(Path directory, List<Path> paths) implements AutoCloseable {
    static ProjectedArtifacts create(
        final Path output, final List<TestAdditionsArchiveWriter.Inventory> originals)
        throws IOException {
      final Path parent = output.getParent();
      if (parent == null) {
        throw new IOException("Test additions JAR has no parent: " + output);
      }
      Files.createDirectories(parent);
      final Path directory = Files.createTempDirectory(parent, ".test-projections-");
      final List<Path> paths = new ArrayList<>(originals.size());
      try {
        for (int index = 0; index < originals.size(); index++) {
          final Path original = originals.get(index).input().originalJar();
          final ArtifactCoordinate coordinate =
              new ArtifactCoordinate("test-view", "artifact-" + index, "1", "jar", "", "test");
          paths.add(
              MultiReleaseLibraryProjection.create(
                  original, coordinate, directory, Runtime.version().feature()));
        }
        return new ProjectedArtifacts(directory, List.copyOf(paths));
      } catch (final IOException failure) {
        deleteDirectory(directory);
        throw failure;
      }
    }

    @Override
    public void close() throws IOException {
      deleteDirectory(directory);
    }

    private static void deleteDirectory(final Path directory) throws IOException {
      try (Stream<Path> paths = Files.list(directory)) {
        for (final Path path : paths.toList()) {
          Files.delete(path);
        }
      }
      Files.delete(directory);
    }
  }

  /** Class directories resolve links without entering additions. */
  private record ProjectClassArchive(List<Path> paths) implements AutoCloseable {
    static ProjectClassArchive create(
        final Path output,
        final Path testDirectory,
        final Path mainDirectory,
        final Set<String> testNames,
        final Set<String> mainNames)
        throws IOException {
      final Path parent = output.getParent();
      if (parent == null) {
        throw new IOException("Test additions JAR has no parent: " + output);
      }
      Files.createDirectories(parent);
      final List<Path> paths = new ArrayList<>(2);
      try {
        addDirectoryArchive(paths, testDirectory, testNames, parent);
        addDirectoryArchive(paths, mainDirectory, mainNames, parent);
        return new ProjectClassArchive(List.copyOf(paths));
      } catch (final IOException failure) {
        for (final Path path : paths) {
          Files.deleteIfExists(path);
        }
        throw failure;
      }
    }

    @Override
    public void close() throws IOException {
      for (final Path path : paths) {
        Files.deleteIfExists(path);
      }
    }

    private static void addDirectoryArchive(
        final List<Path> paths, final Path directory, final Set<String> names, final Path parent)
        throws IOException {
      if (names.isEmpty()) {
        return;
      }
      final Path archive = Files.createTempFile(parent, ".test-analysis-", ".jar");
      paths.add(archive);
      try (java.util.jar.JarOutputStream output =
          new java.util.jar.JarOutputStream(Files.newOutputStream(archive))) {
        for (final String name : new TreeSet<>(names)) {
          final java.util.jar.JarEntry entry = new java.util.jar.JarEntry(name + CLASS_SUFFIX);
          entry.setTime(0L);
          output.putNextEntry(entry);
          Files.copy(directory.resolve(name + CLASS_SUFFIX), output);
          output.closeEntry();
        }
      }
    }
  }
}
