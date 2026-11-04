/* WHY: Finds the duplicate classes the user agreed to tolerate so planning and reporting agree. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.plugin.DuplicateClassPolicy.Action;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.jar.JarFile;
import java.util.zip.ZipFile;

/** Resolves tolerated duplicate classes from the scanned class inventory. */
final class DuplicateClasses {
  /** The smallest ownership count that constitutes a duplicate. */
  private static final int MIN_DUPLICATE_OWNERS = 2;

  private DuplicateClasses() {}

  /** One class provided by several JARs and the action the user chose for it. */
  /* package */ record ToleratedDuplicate(
      String className, Action action, List<ArtifactCoordinate> owners) {
    /* package */ ToleratedDuplicate {
      owners = List.copyOf(owners);
    }
  }

  /** Returns tolerated duplicates among retained production analysis libraries. */
  /* package */ static List<ToleratedDuplicate> resolveRetained(final TrimRequest request)
      throws IOException {
    if (request.policy().duplicateClasses().isEmpty()) {
      return List.of();
    }
    return resolve(
        request,
        request.candidates().stream()
            .filter(
                snapshot -> MavenDependencyTrimmer.JAR_TYPE.equals(snapshot.coordinate().type()))
            .filter(
                snapshot ->
                    MavenDependencyTrimmer.ANALYSIS_LIBRARY_SCOPES.contains(
                        snapshot.coordinate().scope()))
            .filter(snapshot -> request.retainedCoordinates().contains(snapshot.coordinate()))
            .toList());
  }

  /** Returns tolerated duplicates among the given libraries, ordered by class name. */
  /* package */ static List<ToleratedDuplicate> resolve(
      final TrimRequest request, final List<ElisionAnalysisModel.ArtifactSnapshot> libraries)
      throws IOException {
    if (request.policy().duplicateClasses().isEmpty()) {
      return List.of();
    }
    final TrimExecutionEnvironment environment =
        MavenDependencyTrimmer.executionEnvironment(request);
    return resolve(
        request.policy().duplicateClasses(),
        libraries,
        Math.max(environment.targetRelease(), environment.runtimeRelease()));
  }

  @SuppressWarnings({"PMD.UseConcurrentHashMap", "PMD.AvoidInstantiatingObjectsInLoops"})
  /* package */ static List<ToleratedDuplicate> resolve(
      final DuplicateClassPolicy policy,
      final List<ElisionAnalysisModel.ArtifactSnapshot> libraries,
      final int release)
      throws IOException {
    if (policy.isEmpty()) {
      return List.of();
    }
    final Map<String, List<ArtifactCoordinate>> owners = new TreeMap<>();
    for (final ElisionAnalysisModel.ArtifactSnapshot library : libraries) {
      for (final String className : effectiveClassNames(library.filePath(), release)) {
        if (policy.tolerates(className)) {
          owners.computeIfAbsent(className, ignored -> new ArrayList<>()).add(library.coordinate());
        }
      }
    }
    final List<ToleratedDuplicate> result = new ArrayList<>();
    owners.forEach(
        (className, coordinates) -> {
          if (coordinates.size() >= MIN_DUPLICATE_OWNERS) {
            result.add(
                new ToleratedDuplicate(
                    className, policy.actionFor(className).orElseThrow(), coordinates));
          }
        });
    return result;
  }

  private static Set<String> effectiveClassNames(final Path path, final int release)
      throws IOException {
    try (JarFile archive =
        new JarFile(
            path.toFile(),
            false,
            ZipFile.OPEN_READ,
            Runtime.Version.parse(Integer.toString(release)))) {
      return archive
          .versionedStream()
          .filter(entry -> !entry.isDirectory())
          .map(java.util.jar.JarEntry::getName)
          .filter(name -> name.endsWith(".class") && !name.startsWith("META-INF/versions/"))
          .filter(name -> !MultiReleaseClassInventory.isModuleDescriptor(name))
          .map(name -> name.substring(0, name.length() - ".class".length()).replace('/', '.'))
          .collect(java.util.stream.Collectors.toCollection(TreeSet::new));
    }
  }

  /** Returns the libraries that own a duplicate whose JARs must be retained whole. */
  /* package */ static List<ElisionAnalysisModel.ArtifactSnapshot> retainedOwners(
      final TrimRequest request, final List<ElisionAnalysisModel.ArtifactSnapshot> libraries)
      throws IOException {
    final Set<ArtifactCoordinate> coordinates = new java.util.LinkedHashSet<>();
    for (final ToleratedDuplicate duplicate : resolveRetained(request)) {
      if (duplicate.action() == Action.RETAIN_JARS) {
        coordinates.addAll(duplicate.owners());
      }
    }
    return libraries.stream()
        .filter(library -> coordinates.contains(library.coordinate()))
        .toList();
  }
}
