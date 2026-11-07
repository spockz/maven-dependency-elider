// WHY: Reports unresolved dynamic roots with their declaring archive without promoting unrelated
// inputs.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Builds deterministic diagnostics for dynamic roots outside the known workload. */
final class DynamicRootDiagnostics {
  private DynamicRootDiagnostics() {}

  /* package */ static List<String> unresolvedRoots(
      final Map<ArtifactCoordinate, Set<String>> rootsByDeclaringArtifact,
      final Set<String> indexedClasses,
      final Set<String> applicationClasses) {
    final Set<String> knownClasses = new HashSet<>();
    indexedClasses.forEach(name -> knownClasses.add(normalize(name)));
    applicationClasses.forEach(name -> knownClasses.add(normalize(name)));
    final List<String> diagnostics = new ArrayList<>();
    rootsByDeclaringArtifact.forEach(
        (archive, roots) ->
            roots.stream()
                .map(DynamicRootDiagnostics::normalize)
                .filter(root -> !knownClasses.contains(root) && !isPlatformClass(root))
                .sorted()
                .forEach(
                    root ->
                        diagnostics.add(
                            "Dynamic root "
                                + root
                                + " declared by archive "
                                + archive
                                + " does not resolve to an application or dependency class; "
                                + "it will not retain unrelated archives.")));
    return List.copyOf(diagnostics);
  }

  private static String normalize(final String className) {
    return className.replace('/', '.');
  }

  private static boolean isPlatformClass(final String className) {
    final String resourceName = className.replace('.', '/') + ".class";
    return ClassLoader.getPlatformClassLoader().getResource(resourceName) != null;
  }
}
