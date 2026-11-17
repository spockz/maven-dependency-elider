/* WHY: Verifies unresolved dynamic roots retain their declaring archive provenance. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** Ensures known application and platform classes are not called external roots. */
final class DynamicRootDiagnosticsTest {
  @SuppressWarnings({
    "PMD.CommentDefaultAccessModifier",
    "PMD.UncommentedEmptyConstructor",
    "PMD.UnnecessaryConstructor"
  })
  DynamicRootDiagnosticsTest() {}

  @Test
  void reportsUnknownRootOnceWithDeclaringArchiveButNotKnownClasses() {
    final ArtifactCoordinate archive = ArtifactCoordinate.of("fixture", "roots", "1.0");
    final Map<ArtifactCoordinate, Set<String>> roots =
        Map.of(archive, Set.of("external.Optional", "fixture.ApplicationRoot", "java.lang.String"));

    final List<String> diagnostics =
        DynamicRootDiagnostics.unresolvedRoots(roots, Set.of(), Set.of("fixture.ApplicationRoot"));

    assertAll(
        "unknown dynamic root is reported once with declaring archive while known classes are"
            + " omitted",
        () -> assertThat(diagnostics).hasSize(1),
        () ->
            assertThat(diagnostics.getFirst())
                .contains("external.Optional")
                .contains(archive.toString())
                .contains("does not resolve to an application or dependency class")
                .contains("will not retain unrelated archives"));
  }

  @Test
  @SuppressWarnings("PMD.UseConcurrentHashMap")
  void diagnosticOrderDoesNotDependOnArchiveMapIteration() {
    final ArtifactCoordinate later = ArtifactCoordinate.of("z.example", "roots", "1.0");
    final ArtifactCoordinate earlier = ArtifactCoordinate.of("a.example", "roots", "1.0");
    final Map<ArtifactCoordinate, Set<String>> roots = new LinkedHashMap<>();
    roots.put(later, Set.of("external.Later"));
    roots.put(earlier, Set.of("external.Earlier"));

    final List<String> diagnostics =
        DynamicRootDiagnostics.unresolvedRoots(roots, Set.of(), Set.of());

    assertThat(diagnostics)
        .containsExactly(
            "Dynamic root external.Earlier declared by archive "
                + earlier
                + " does not resolve to an application or dependency class; it will not retain"
                + " unrelated archives.",
            "Dynamic root external.Later declared by archive "
                + later
                + " does not resolve to an application or dependency class; it will not retain"
                + " unrelated archives.");
  }
}
