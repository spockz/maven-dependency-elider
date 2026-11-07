/* WHY: Pins the distinction between conservative static closure and trace-bounded typed closure. */

package io.github.spockz.elider.trimmer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Exercises conservative and closed-world closure over one shared fixture setup. */
class ClosedWorldClosurePolicyTest {
  /** Names the rule narrowly waived for JUnit's package-private test discovery. */
  private static final String DEFAULT_ACCESS_RULE = "PMD.CommentDefaultAccessModifier";

  /** Isolates each test's generated candidate archives. */
  @TempDir private Path temporaryDirectory;

  // Default access lets JUnit construct this fixture-injected class.
  @SuppressWarnings({
    "PMD.UnnecessaryConstructor",
    "PMD.UncommentedEmptyConstructor",
    DEFAULT_ACCESS_RULE
  })
  ClosedWorldClosurePolicyTest() {}

  /** Covers allowed-set semantics and unresolved body/structural targets. */
  /* The default access modifier is required for JUnit discovery. */
  @Nested
  @SuppressWarnings(DEFAULT_ACCESS_RULE)
  class QueryPolicyCases {
    // The default access modifier lets JUnit construct the nested suite.
    @SuppressWarnings({
      "PMD.UnnecessaryConstructor",
      "PMD.UncommentedEmptyConstructor",
      DEFAULT_ACCESS_RULE
    })
    QueryPolicyCases() {}

    @Test
    @DisplayName("ADR-0003: prepared closure distinguishes closed-world empty from conservative")
    void policySwitchRecomputesPreparedClosureAndConservativeModeIsStatic() throws Exception {
      final Path candidate =
          writeJar(
              "policy-switch.jar",
              Map.of(
                  ClosedWorldTestFixtures.ROOT,
                      ClosedWorldTestFixtures.classWithSuperclassAndCalls(
                          ClosedWorldTestFixtures.ROOT,
                          ClosedWorldTestFixtures.BASE,
                          ClosedWorldTestFixtures.BODY),
                  ClosedWorldTestFixtures.BASE,
                      ClosedWorldTestFixtures.simpleClass(ClosedWorldTestFixtures.BASE),
                  ClosedWorldTestFixtures.BODY,
                      ClosedWorldTestFixtures.simpleClass(ClosedWorldTestFixtures.BODY)));
      final DependencyJarTrimmer.PreparedAnalysis prepared =
          ClosedWorldTestFixtures.prepare(candidate);

      final DependencyJarTrimmer.TrimAnalysis boundedEmpty =
          prepared.analyze(
              List.of(ClosedWorldTestFixtures.ROOT_NAME), ClosureQueryPolicy.closedWorld(Set.of()));
      final DependencyJarTrimmer.TrimAnalysis boundedGrown =
          prepared.analyze(
              List.of(ClosedWorldTestFixtures.ROOT_NAME),
              ClosureQueryPolicy.closedWorld(Set.of("fixture.Body")));
      final DependencyJarTrimmer.TrimAnalysis boundedShrunk =
          prepared.analyze(
              List.of(ClosedWorldTestFixtures.ROOT_NAME), ClosureQueryPolicy.closedWorld(Set.of()));
      final DependencyJarTrimmer.TrimAnalysis conservative =
          prepared.analyze(
              List.of(ClosedWorldTestFixtures.ROOT_NAME), ClosureQueryPolicy.conservative());
      final DependencyJarTrimmer.TrimAnalysis freshGrown =
          ClosedWorldTestFixtures.prepare(candidate)
              .analyze(
                  List.of(ClosedWorldTestFixtures.ROOT_NAME),
                  ClosureQueryPolicy.closedWorld(Set.of("fixture.Body")));

      assertAll(
          "query policy changes closure for unchanged roots",
          () ->
              assertThat(boundedEmpty.retainedClasses())
                  .containsExactlyInAnyOrder(
                      ClosedWorldTestFixtures.ROOT, ClosedWorldTestFixtures.BASE),
          () ->
              assertThat(boundedGrown.retainedClasses())
                  .containsExactlyInAnyOrder(
                      ClosedWorldTestFixtures.ROOT,
                      ClosedWorldTestFixtures.BASE,
                      ClosedWorldTestFixtures.BODY),
          () -> assertThat(boundedShrunk).isEqualTo(boundedEmpty),
          () -> assertThat(boundedGrown).isEqualTo(freshGrown),
          () ->
              assertThat(conservative.retainedClasses())
                  .containsExactlyInAnyOrder(
                      ClosedWorldTestFixtures.ROOT,
                      ClosedWorldTestFixtures.BASE,
                      ClosedWorldTestFixtures.BODY));
    }

    @Test
    @DisplayName(
        "ADR-0003: closed-world closure keeps allowed body targets and suppresses excluded missing"
            + " targets")
    void closedWorldTraversesAllowedBodyTargetAndSuppressesExcludedMissingTarget()
        throws Exception {
      final Path candidate =
          writeJar(
              "typed-body.jar",
              Map.of(
                  ClosedWorldTestFixtures.ROOT,
                      ClosedWorldTestFixtures.classWithSuperclassAndCalls(
                          ClosedWorldTestFixtures.ROOT,
                          ClosedWorldTestFixtures.BASE,
                          ClosedWorldTestFixtures.BODY,
                          ClosedWorldTestFixtures.MISSING_BODY),
                  ClosedWorldTestFixtures.BASE,
                      ClosedWorldTestFixtures.simpleClass(ClosedWorldTestFixtures.BASE),
                  ClosedWorldTestFixtures.BODY,
                      ClosedWorldTestFixtures.simpleClass(ClosedWorldTestFixtures.BODY)));
      final DependencyJarTrimmer.TrimAnalysis analysis =
          ClosedWorldTestFixtures.prepare(candidate)
              .analyze(
                  List.of(ClosedWorldTestFixtures.ROOT_NAME),
                  ClosureQueryPolicy.closedWorld(
                      Set.of(ClosedWorldTestFixtures.ROOT_NAME, "fixture.Base", "fixture.Body")));

      assertThat(analysis.retainedClasses())
          .containsExactlyInAnyOrder(
              ClosedWorldTestFixtures.ROOT,
              ClosedWorldTestFixtures.BASE,
              ClosedWorldTestFixtures.BODY)
          .doesNotContain(ClosedWorldTestFixtures.MISSING_BODY);
    }

    @Test
    @DisplayName("ADR-0003: closed-world closure rejects an unresolved allowed body target")
    void closedWorldFailsForMissingAllowedBodyTarget() throws Exception {
      final Path candidate =
          writeJar(
              "allowed-missing-body.jar",
              Map.of(
                  ClosedWorldTestFixtures.ROOT,
                      ClosedWorldTestFixtures.classWithSuperclassAndCalls(
                          ClosedWorldTestFixtures.ROOT,
                          ClosedWorldTestFixtures.BASE,
                          ClosedWorldTestFixtures.MISSING_BODY),
                  ClosedWorldTestFixtures.BASE,
                      ClosedWorldTestFixtures.simpleClass(ClosedWorldTestFixtures.BASE)));

      assertThatThrownBy(
              () ->
                  ClosedWorldTestFixtures.prepare(candidate)
                      .analyze(
                          List.of(ClosedWorldTestFixtures.ROOT_NAME),
                          ClosureQueryPolicy.closedWorld(
                              Set.of(
                                  ClosedWorldTestFixtures.ROOT_NAME,
                                  "fixture.Base",
                                  "fixture.MissingBody"))))
          .isInstanceOf(DependencyJarTrimmer.UnresolvedReferenceException.class)
          .hasMessageContaining(ClosedWorldTestFixtures.MISSING_BODY);
    }

    @Test
    @DisplayName("ADR-0003: closed-world closure always rejects missing structural targets")
    void closedWorldFailsForMissingStructuralTargetOutsideAllowedSet() throws Exception {
      final Path candidate =
          writeJar(
              "excluded-missing-superclass.jar",
              Map.of(
                  ClosedWorldTestFixtures.ROOT,
                  ClosedWorldTestFixtures.classWithSuperclassAndCalls(
                      ClosedWorldTestFixtures.ROOT, "fixture/MissingBase")));

      assertThatThrownBy(
              () ->
                  ClosedWorldTestFixtures.prepare(candidate)
                      .analyze(
                          List.of(ClosedWorldTestFixtures.ROOT_NAME),
                          ClosureQueryPolicy.closedWorld(
                              Set.of(ClosedWorldTestFixtures.ROOT_NAME))))
          .isInstanceOf(DependencyJarTrimmer.UnresolvedReferenceException.class)
          .hasMessageContaining("fixture/MissingBase");
    }

    @Test
    @DisplayName(
        "ADR-0003: structural evidence wins when the same missing target is also a body edge")
    void structuralEdgeRemainsFatalWhenTargetAlsoAppearsInBody() throws Exception {
      final Path candidate =
          writeJar(
              "same-structural-body-edge.jar",
              Map.of(
                  ClosedWorldTestFixtures.ROOT,
                  ClosedWorldTestFixtures.classWithSuperclassAndCalls(
                      ClosedWorldTestFixtures.ROOT,
                      ClosedWorldTestFixtures.MISSING,
                      ClosedWorldTestFixtures.MISSING)));

      assertThatThrownBy(
              () ->
                  ClosedWorldTestFixtures.prepare(candidate)
                      .analyze(
                          List.of(ClosedWorldTestFixtures.ROOT_NAME),
                          ClosureQueryPolicy.closedWorld(
                              Set.of(ClosedWorldTestFixtures.ROOT_NAME))))
          .isInstanceOf(DependencyJarTrimmer.UnresolvedReferenceException.class)
          .hasMessageContaining(ClosedWorldTestFixtures.MISSING);
    }
  }

  /** Covers structural metadata and sibling-library role behavior. */
  /* The default access modifier is required for JUnit discovery. */
  @Nested
  @SuppressWarnings(DEFAULT_ACCESS_RULE)
  class StructuralEvidenceCases {
    // The default access modifier lets JUnit construct the nested suite.
    @SuppressWarnings({
      "PMD.UnnecessaryConstructor",
      "PMD.UncommentedEmptyConstructor",
      DEFAULT_ACCESS_RULE
    })
    StructuralEvidenceCases() {}

    @Test
    @DisplayName("ADR-0003: all structural reference forms remain live in closed-world mode")
    void structuralReferencesRemainLiveTogether() throws Exception {
      final Path candidate =
          writeJar(
              "structural-references.jar", ClosedWorldTestFixtures.Structural.fixtureClasses());
      final DependencyJarTrimmer.PreparedAnalysis prepared =
          ClosedWorldTestFixtures.prepare(candidate);
      final DependencyJarTrimmer.TrimAnalysis bounded =
          prepared.analyze(
              List.of(ClosedWorldTestFixtures.ROOT_NAME),
              ClosureQueryPolicy.closedWorld(Set.of(ClosedWorldTestFixtures.ROOT_NAME)));
      final DependencyJarTrimmer.TrimAnalysis conservative =
          prepared.analyze(
              List.of(ClosedWorldTestFixtures.ROOT_NAME), ClosureQueryPolicy.conservative());
      assertAll(
          "class-linking metadata remains structural regardless of allowed body classes",
          () ->
              assertThat(bounded.retainedClasses())
                  .containsAll(ClosedWorldTestFixtures.Structural.targets()),
          () ->
              assertThat(conservative.retainedClasses())
                  .containsAll(ClosedWorldTestFixtures.Structural.targets()));
    }

    @Test
    @DisplayName("ADR-0003: unchanged sibling declarations do not acquire method-body edges")
    void closedWorldDoesNotFollowUnchangedSiblingMethodBodies() throws Exception {
      final Path candidate =
          writeJar(
              "sibling-body-candidate.jar",
              Map.of(
                  ClosedWorldTestFixtures.ROOT,
                  ClosedWorldTestFixtures.classWithField(
                      ClosedWorldTestFixtures.ROOT, ClosedWorldTestFixtures.LIBRARY_ROOT)));
      final Path sibling =
          writeJar(
              "sibling-body-library.jar",
              Map.of(
                  ClosedWorldTestFixtures.LIBRARY_ROOT,
                  ClosedWorldTestFixtures.classWithSuperclassAndCalls(
                      ClosedWorldTestFixtures.LIBRARY_ROOT,
                      ClosedWorldTestFixtures.OBJECT,
                      "fixture/Dependency"),
                  "fixture/Dependency",
                  ClosedWorldTestFixtures.simpleClass("fixture/Dependency")));
      final DependencyJarTrimmer.TrimAnalysis bounded =
          ClosedWorldTestFixtures.prepare(candidate, List.of(sibling))
              .analyze(
                  List.of(ClosedWorldTestFixtures.ROOT_NAME),
                  ClosureQueryPolicy.closedWorld(
                      Set.of(
                          ClosedWorldTestFixtures.ROOT_NAME,
                          "fixture.LibraryRoot",
                          "fixture.Dependency")));

      assertAll(
          "the library role follows declarations but not method bodies",
          () -> assertThat(bounded.retainedClasses()).containsExactly(ClosedWorldTestFixtures.ROOT),
          () ->
              assertThat(bounded.reachableLibraryClasses())
                  .containsExactly(ClosedWorldTestFixtures.LIBRARY_ROOT));
    }

    @Test
    @DisplayName("ADR-0003: closed-world rejects missing typed sibling signature targets")
    void closedWorldRejectsMissingSiblingSignatureTarget() throws Exception {
      final Path candidate =
          writeJar(
              "sibling-signature-candidate.jar",
              Map.of(
                  ClosedWorldTestFixtures.ROOT,
                  ClosedWorldTestFixtures.classWithField(
                      ClosedWorldTestFixtures.ROOT, ClosedWorldTestFixtures.LIBRARY_ROOT)));
      final Path sibling =
          writeJar(
              "sibling-signature-library.jar",
              Map.of(
                  ClosedWorldTestFixtures.LIBRARY_ROOT,
                  ClosedWorldTestFixtures.classWithGenericField(
                      ClosedWorldTestFixtures.LIBRARY_ROOT,
                      "Ljava/lang/Object;",
                      "Lfixture/Missing;")));

      assertThatThrownBy(
              () ->
                  ClosedWorldTestFixtures.prepare(candidate, List.of(sibling))
                      .analyze(
                          List.of(ClosedWorldTestFixtures.ROOT_NAME),
                          ClosureQueryPolicy.closedWorld(
                              Set.of(ClosedWorldTestFixtures.ROOT_NAME, "fixture.LibraryRoot"))))
          .isInstanceOf(DependencyJarTrimmer.UnresolvedReferenceException.class)
          .hasMessageContaining(ClosedWorldTestFixtures.MISSING);
    }

    @Test
    @DisplayName("ADR-0003: closed-world policy does not suppress malformed root class data")
    void malformedRootClassFailsClosed() throws Exception {
      final Path candidate =
          writeJar(
              "malformed-root.jar", Map.of(ClosedWorldTestFixtures.ROOT, new byte[] {1, 2, 3}));

      assertThatThrownBy(
              () ->
                  ClosedWorldTestFixtures.prepare(candidate)
                      .analyze(
                          List.of(ClosedWorldTestFixtures.ROOT_NAME),
                          ClosureQueryPolicy.closedWorld(Set.of())))
          .isInstanceOf(IOException.class)
          .hasMessageContaining("Could not read class entry fixture/Root.class");
    }

    @Test
    @DisplayName("ADR-0003: closed-world policy keeps unclassified extraction failures fatal")
    void unclassifiedReferenceExtractionFailureFailsClosed() throws Exception {
      final Path candidate =
          writeJar(
              "unclassified-reference.jar",
              Map.of(
                  ClosedWorldTestFixtures.ROOT,
                  ClosedWorldTestFixtures.malformedDescriptorClass()));
      final DependencyJarTrimmer.PreparedAnalysis prepared =
          ClosedWorldTestFixtures.prepare(candidate);

      assertThatThrownBy(
              () ->
                  prepared.analyze(
                      List.of(ClosedWorldTestFixtures.ROOT_NAME),
                      ClosureQueryPolicy.closedWorld(Set.of(ClosedWorldTestFixtures.ROOT_NAME))))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining(
              "Could not classify unclassified reference evidence for class fixture/Root");
    }
  }

  private Path writeJar(final String name, final Map<String, byte[]> classes) throws IOException {
    return ClosedWorldTestFixtures.writeJar(temporaryDirectory, name, classes);
  }
}
