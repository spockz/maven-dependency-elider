/* WHY: Pins the distinction between conservative static closure and trace-bounded typed closure. */

package io.github.spockz.elider.trimmer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
    @DisplayName("ADR-0003: unused class constants are not treated as links")
    void unusedConstantPoolClassDoesNotBlockClosedWorldClosure() throws Exception {
      final byte[] rootBytes =
          ClassFileConstantPool.appendUnreferencedClassConstant(
              ClosedWorldTestFixtures.simpleClass(ClosedWorldTestFixtures.ROOT),
              ClosedWorldTestFixtures.MISSING_BODY);
      final boolean hasUnreferencedClassToken =
          ClassFileConstantPool.containsClassConstant(
              rootBytes, ClosedWorldTestFixtures.MISSING_BODY);
      final Path candidate =
          writeJar("unused-class-constant.jar", Map.of(ClosedWorldTestFixtures.ROOT, rootBytes));

      final DependencyJarTrimmer.TrimAnalysis bounded =
          ClosedWorldTestFixtures.prepare(candidate)
              .analyze(
                  List.of(ClosedWorldTestFixtures.ROOT_NAME),
                  ClosureQueryPolicy.closedWorld(Set.of(ClosedWorldTestFixtures.ROOT_NAME)));

      assertAll(
          "unreferenced class tokens do not enter closed-world closure",
          () ->
              assertTrue(
                  hasUnreferencedClassToken,
                  "the fixture contains the constant before closure is analyzed"),
          () ->
              assertThat(bounded.retainedClasses()).containsExactly(ClosedWorldTestFixtures.ROOT));
    }

    @Test
    @DisplayName("ADR-0003: only closed-world closure ignores unused class constants")
    void unusedClassConstantIsIgnoredOnlyByClosedWorldClosure() throws Exception {
      final String unusedClass = "fixture/UnusedConstant";
      final byte[] rootBytes =
          ClassFileConstantPool.appendUnreferencedClassConstant(
              ClosedWorldTestFixtures.simpleClass(ClosedWorldTestFixtures.ROOT), unusedClass);
      final Path candidate =
          writeJar(
              "conservative-unused-class-constant.jar",
              Map.of(
                  ClosedWorldTestFixtures.ROOT,
                  rootBytes,
                  unusedClass,
                  ClosedWorldTestFixtures.simpleClass(unusedClass)));
      final DependencyJarTrimmer.PreparedAnalysis prepared =
          ClosedWorldTestFixtures.prepare(candidate);

      final DependencyJarTrimmer.TrimAnalysis conservative =
          prepared.analyze(
              List.of(ClosedWorldTestFixtures.ROOT_NAME), ClosureQueryPolicy.conservative());
      final DependencyJarTrimmer.TrimAnalysis closedWorld =
          prepared.analyze(
              List.of(ClosedWorldTestFixtures.ROOT_NAME),
              ClosureQueryPolicy.closedWorld(Set.of(ClosedWorldTestFixtures.ROOT_NAME)));

      assertAll(
          "closed-world liveness filters only the query whose contract permits it",
          () -> assertThat(conservative.retainedClasses()).contains(unusedClass),
          () ->
              assertThat(closedWorld.retainedClasses())
                  .containsExactly(ClosedWorldTestFixtures.ROOT));
    }

    @Test
    @DisplayName("ADR-0003: an unknown class-file attribute blocks pool-entry classification")
    void unknownAttributePreventsIgnoringUnclassifiedClassConstant() throws Exception {
      final byte[] classWithUnknownAttribute =
          ClassFileConstantPool.appendUnreferencedClassConstant(
              ClosedWorldTestFixtures.classWithUnknownAttribute(
                  ClosedWorldTestFixtures.ROOT, "FixtureUnknownAttribute"),
              ClosedWorldTestFixtures.MISSING_BODY);
      final Path candidate =
          writeJar(
              "unknown-attribute-reference.jar",
              Map.of(ClosedWorldTestFixtures.ROOT, classWithUnknownAttribute));

      assertThatThrownBy(
              () ->
                  ClosedWorldTestFixtures.prepare(candidate)
                      .analyze(
                          List.of(ClosedWorldTestFixtures.ROOT_NAME),
                          ClosureQueryPolicy.closedWorld(
                              Set.of(ClosedWorldTestFixtures.ROOT_NAME))))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("Unrecognized class-file attributes in fixture/Root")
          .hasMessageContaining("FixtureUnknownAttribute");
    }

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

  /** WHY: Structural variants share one prepared-analysis fixture. */
  /* The default access modifier is required for JUnit discovery. */
  @Nested
  @SuppressWarnings({"PMD.TooManyMethods", DEFAULT_ACCESS_RULE})
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
    @DisplayName(
        "ADR-0003: stack-map frame types remain structural when their methods are uncalled")
    void frameTypeRemainsLiveOutsideTheAllowedBodySet() throws Exception {
      final String frameType = "fixture/FrameType";
      final Path candidate =
          writeJar(
              "stack-map-frame-reference.jar",
              Map.of(
                  ClosedWorldTestFixtures.ROOT,
                  ClosedWorldTestFixtures.classWithFrameReference(
                      ClosedWorldTestFixtures.ROOT, frameType),
                  frameType,
                  ClosedWorldTestFixtures.simpleClass(frameType)));

      final DependencyJarTrimmer.TrimAnalysis bounded =
          ClosedWorldTestFixtures.prepare(candidate)
              .analyze(
                  List.of(ClosedWorldTestFixtures.ROOT_NAME),
                  ClosureQueryPolicy.closedWorld(Set.of(ClosedWorldTestFixtures.ROOT_NAME)));

      assertThat(bounded.retainedClasses())
          .containsExactlyInAnyOrder(ClosedWorldTestFixtures.ROOT, frameType);
    }

    @Test
    @DisplayName("ADR-0003: debug local-variable metadata does not create a structural link")
    void localVariableDebugTypeDoesNotBlockClosedWorldClosure() throws Exception {
      final String debugOnlyType = "fixture/DebugOnlyType";
      final Path candidate =
          writeJar(
              "local-variable-debug-reference.jar",
              Map.of(
                  ClosedWorldTestFixtures.ROOT,
                  ClosedWorldTestFixtures.classWithLocalVariableType(
                      ClosedWorldTestFixtures.ROOT, debugOnlyType),
                  debugOnlyType,
                  ClosedWorldTestFixtures.simpleClass(debugOnlyType)));
      final DependencyJarTrimmer.PreparedAnalysis prepared =
          ClosedWorldTestFixtures.prepare(candidate);

      final DependencyJarTrimmer.TrimAnalysis conservative =
          prepared.analyze(
              List.of(ClosedWorldTestFixtures.ROOT_NAME), ClosureQueryPolicy.conservative());
      final DependencyJarTrimmer.TrimAnalysis bounded =
          prepared.analyze(
              List.of(ClosedWorldTestFixtures.ROOT_NAME),
              ClosureQueryPolicy.closedWorld(Set.of(ClosedWorldTestFixtures.ROOT_NAME)));
      final DependencyJarTrimmer.TrimAnalysis observedDebugType =
          prepared.analyze(
              List.of(ClosedWorldTestFixtures.ROOT_NAME),
              ClosureQueryPolicy.closedWorld(
                  Set.of(ClosedWorldTestFixtures.ROOT_NAME, debugOnlyType.replace('/', '.'))));

      assertAll(
          "debug-only local variable types do not become live classes",
          () ->
              assertThat(conservative.retainedClasses())
                  .containsExactly(ClosedWorldTestFixtures.ROOT),
          () -> assertThat(bounded.retainedClasses()).containsExactly(ClosedWorldTestFixtures.ROOT),
          () ->
              assertThat(observedDebugType.retainedClasses())
                  .containsExactlyInAnyOrder(ClosedWorldTestFixtures.ROOT, debugOnlyType));
    }

    @Test
    @DisplayName("ADR-0003: missing local-variable debug descriptor and signature are ignored")
    void missingLocalVariableDebugTypesDoNotBlockClosure() throws Exception {
      final byte[] rootBytes =
          ClosedWorldTestFixtures.classWithLocalVariableMetadata(
              ClosedWorldTestFixtures.ROOT,
              "Lfixture/DebugDescriptorType;",
              "Ljava/util/List<Lfixture/DebugGenericType;>;");
      final Path candidate =
          writeJar(
              "missing-local-variable-debug-types.jar",
              Map.of(ClosedWorldTestFixtures.ROOT, rootBytes));
      final DependencyJarTrimmer.PreparedAnalysis prepared =
          ClosedWorldTestFixtures.prepare(candidate);

      final DependencyJarTrimmer.TrimAnalysis conservative =
          prepared.analyze(
              List.of(ClosedWorldTestFixtures.ROOT_NAME), ClosureQueryPolicy.conservative());
      final DependencyJarTrimmer.TrimAnalysis bounded =
          prepared.analyze(
              List.of(ClosedWorldTestFixtures.ROOT_NAME),
              ClosureQueryPolicy.closedWorld(Set.of(ClosedWorldTestFixtures.ROOT_NAME)));

      assertAll(
          "debug-only local descriptors and signatures do not require their target classes",
          () ->
              assertThat(conservative.retainedClasses())
                  .containsExactly(ClosedWorldTestFixtures.ROOT),
          () ->
              assertThat(bounded.retainedClasses()).containsExactly(ClosedWorldTestFixtures.ROOT));
    }

    @Test
    @DisplayName("ADR-0003: debug metadata does not hide a missing structural field type")
    void localVariableDebugTypeDoesNotHideStructuralReference() throws Exception {
      final String target = "fixture/StructuralAndDebugType";
      final Path candidate =
          writeJar(
              "structural-and-debug-reference.jar",
              Map.of(
                  ClosedWorldTestFixtures.ROOT,
                  ClosedWorldTestFixtures.classWithFieldAndLocalVariableType(
                      ClosedWorldTestFixtures.ROOT, target)));

      assertThatThrownBy(
              () ->
                  ClosedWorldTestFixtures.prepare(candidate)
                      .analyze(
                          List.of(ClosedWorldTestFixtures.ROOT_NAME),
                          ClosureQueryPolicy.closedWorld(
                              Set.of(ClosedWorldTestFixtures.ROOT_NAME))))
          .isInstanceOf(DependencyJarTrimmer.UnresolvedReferenceException.class)
          .hasMessageContaining("unresolved structural class " + target);
    }

    @Test
    @DisplayName("ADR-0003: debug metadata does not hide a missing allowed body type")
    void localVariableDebugTypeDoesNotHideAllowedBodyReference() throws Exception {
      final String target = "fixture/AllowedBodyAndDebugType";
      final Path candidate =
          writeJar(
              "allowed-body-and-debug-reference.jar",
              Map.of(
                  ClosedWorldTestFixtures.ROOT,
                  ClosedWorldTestFixtures.classWithLocalVariableTypeAndBodyCall(
                      ClosedWorldTestFixtures.ROOT, target, target)));

      assertThatThrownBy(
              () ->
                  ClosedWorldTestFixtures.prepare(candidate)
                      .analyze(
                          List.of(ClosedWorldTestFixtures.ROOT_NAME),
                          ClosureQueryPolicy.closedWorld(
                              Set.of(ClosedWorldTestFixtures.ROOT_NAME, target.replace('/', '.')))))
          .isInstanceOf(DependencyJarTrimmer.UnresolvedReferenceException.class)
          .hasMessageContaining("unresolved body class " + target);
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
    @DisplayName("ADR-0003: reached sibling method annotations remain structural")
    void closedWorldFollowsSiblingMethodMetadataButNotItsBody() throws Exception {
      final String annotationType = "fixture/MethodAnnotation";
      final String bodyType = "fixture/BodyOnly";
      final Path candidate =
          writeJar(
              "sibling-method-metadata-candidate.jar",
              Map.of(
                  ClosedWorldTestFixtures.ROOT,
                  ClosedWorldTestFixtures.classWithField(
                      ClosedWorldTestFixtures.ROOT, ClosedWorldTestFixtures.LIBRARY_ROOT),
                  annotationType,
                  ClosedWorldTestFixtures.simpleClass(annotationType),
                  bodyType,
                  ClosedWorldTestFixtures.simpleClass(bodyType)));
      final Path sibling =
          writeJar(
              "sibling-method-metadata-library.jar",
              Map.of(
                  ClosedWorldTestFixtures.LIBRARY_ROOT,
                  ClosedWorldTestFixtures.classWithAnnotatedMethodAndBodyCall(
                      ClosedWorldTestFixtures.LIBRARY_ROOT, annotationType, bodyType)));

      final DependencyJarTrimmer.TrimAnalysis bounded =
          ClosedWorldTestFixtures.prepare(candidate, List.of(sibling))
              .analyze(
                  List.of(ClosedWorldTestFixtures.ROOT_NAME),
                  ClosureQueryPolicy.closedWorld(
                      Set.of(ClosedWorldTestFixtures.ROOT_NAME, "fixture.LibraryRoot")));

      assertAll(
          "sibling declaration metadata stays live while its method body stays out of scope",
          () ->
              assertThat(bounded.retainedClasses())
                  .containsExactlyInAnyOrder(ClosedWorldTestFixtures.ROOT, annotationType)
                  .doesNotContain(bodyType),
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
