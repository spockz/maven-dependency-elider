/* WHY: Covers routine grammar, attribution abstentions, and immutable claim-resolution results. */

package io.github.spockz.elider.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.scanner.JarSourceFileIndex;
import io.github.spockz.elider.scanner.JarSourceFileIndex.ClassSourceFile;
import io.github.spockz.elider.scanner.JarSourceFileIndex.MethodIdentity;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** Exercises supported routine locators and conservative attribution boundaries. */
@SuppressWarnings({"PMD.AtLeastOneConstructor", "PMD.AvoidDuplicateLiterals", "PMD.TooManyMethods"})
final class CodeAttributionResolverBoundaryTest {
  @Test
  void dottedDescriptorShortOwnerAndNestedOwnerResolveExactly() {
    final JarSourceFileIndex index =
        index(
            type("p/Owner.class", "p.Owner", method("run", "()V"), method("run", "(I)V")),
            type("p/Outer$Inner.class", "p.Outer$Inner", method("read", "()V")));
    final CodeAttributionResolver.Result result =
        resolve(index, "p.Owner.run(I)V", "Owner.run", "p.Outer$Inner.read");

    assertAll(
        "dotted descriptors, unique short owners, and nested binary owners retain exact families",
        () ->
            assertThat(result.declarations())
                .allSatisfy(
                    declaration ->
                        assertThat(declaration.status())
                            .isEqualTo(CodeAttributionResolver.Status.RESOLVED)),
        () -> assertThat(result.declarations().get(0).classFamily()).containsExactly("p.Owner"),
        () -> assertThat(result.declarations().get(1).classFamily()).containsExactly("p.Owner"),
        () ->
            assertThat(result.declarations().get(2).classFamily())
                .containsExactly("p.Outer$Inner"));
  }

  @Test
  void descriptorMismatchAndAmbiguousBareMethodHaveExplicitReasons() {
    final JarSourceFileIndex index =
        index(
            type("p/One.class", "p.One", method("run", "()V")),
            type("q/Two.class", "q.Two", method("run", "()V")));
    final CodeAttributionResolver.Result result = resolve(index, "p.One.run(I)V", "run");

    assertAll(
        "unmatched descriptors and multiple exact owners remain unresolved",
        () ->
            assertThat(result.declarations().get(0).reasons())
                .containsExactly(CodeAttributionResolver.Reason.ROUTINE_METHOD_NOT_FOUND),
        () -> assertThat(result.declarations().get(0).classFamily()).isEmpty(),
        () ->
            assertThat(result.declarations().get(1).reasons())
                .containsExactly(CodeAttributionResolver.Reason.ROUTINE_OWNER_AMBIGUOUS),
        () -> assertThat(result.declarations().get(1).classFamily()).isEmpty());
  }

  @Test
  void inheritedOnlyAndUnknownRoutineSyntaxRemainUnresolved() {
    final JarSourceFileIndex index =
        index(
            type("p/Child.class", "p.Child"), type("p/Base.class", "p.Base", method("run", "()V")));
    final CodeAttributionResolver.Result result =
        resolve(index, "p.Child.run", "p.Child#run(nope)");

    assertAll(
        "the index attributes only locally declared methods with supported syntax",
        () ->
            assertThat(result.declarations().get(0).reasons())
                .containsExactly(CodeAttributionResolver.Reason.ROUTINE_METHOD_NOT_FOUND),
        () ->
            assertThat(result.declarations().get(1).reasons())
                .containsExactly(CodeAttributionResolver.Reason.UNSUPPORTED_ROUTINE_SYNTAX),
        () ->
            assertThat(result.declarations())
                .allSatisfy(value -> assertThat(value.classFamily()).isEmpty()));
  }

  @Test
  void resultCollectionsAreImmutableAndAcceptedMergedOriginalPathRemainsUsable() {
    final CodeReference merged =
        new CodeReference(
            CodeReference.Kind.SOURCE_FILE,
            "p/Foo.java",
            Set.of("src/main/java/p/Foo.java", "p/Foo.java"));
    final CodeAttributionResolver.Result result =
        CodeAttributionResolver.resolve(
            List.of(CodeClaim.declared(merged)),
            index(type("p/Foo.class", "p.Foo", "Foo.java")),
            false);

    assertAll(
        "the resolver applies layout policy per original spelling and freezes all outputs",
        () ->
            assertThat(result.declarations().getFirst().status())
                .isEqualTo(CodeAttributionResolver.Status.RESOLVED),
        () -> assertThat(result.declarations().getFirst().reasons()).isEmpty(),
        () ->
            assertThatThrownBy(() -> result.declarations().clear())
                .isInstanceOf(UnsupportedOperationException.class),
        () ->
            assertThatThrownBy(() -> result.declarations().getFirst().classFamily().clear())
                .isInstanceOf(UnsupportedOperationException.class));
  }

  @Test
  void normalizesSeparatorsAndDotSegmentsWithoutChangingPackageCase() {
    final CodeAttributionResolver.Result result =
        CodeAttributionResolver.resolve(
            List.of(
                CodeClaim.declared(CodeReference.sourceFile("src\\main\\java\\P\\.\\Foo.java"))),
            index(type("P/Foo.class", "P.Foo", "Foo.java")),
            true);

    assertThat(result.declarations().getFirst().classFamily()).containsExactly("P.Foo");
  }

  @Test
  void normalizedRootsAreStillControlledByTheFlagAndOriginalSpelling() {
    final CodeClaim claim =
        CodeClaim.declared(CodeReference.sourceFile("./src/./main/java/p/Foo.java"));
    final JarSourceFileIndex index = index(type("p/Foo.class", "p.Foo", "Foo.java"));

    final CodeAttributionResolver.DeclarationResult disallowed =
        CodeAttributionResolver.resolve(List.of(claim), index, false).declarations().getFirst();
    final CodeAttributionResolver.DeclarationResult allowed =
        CodeAttributionResolver.resolve(List.of(claim), index, true).declarations().getFirst();

    assertAll(
        "normalizing dot segments does not bypass the conventional-layout option",
        () -> assertThat(disallowed.status()).isEqualTo(CodeAttributionResolver.Status.UNRESOLVED),
        () ->
            assertThat(disallowed.reasons())
                .contains(CodeAttributionResolver.Reason.SOURCE_ROOT_REQUIRES_LAYOUT_ASSUMPTION),
        () -> assertThat(allowed.classFamily()).containsExactly("p.Foo"));
  }

  @Test
  void completeSourceFileFamilyHasNoIncompleteReasons() {
    final CodeAttributionResolver.DeclarationResult result =
        CodeAttributionResolver.resolve(
                List.of(CodeClaim.declared(CodeReference.sourceFile("p/Foo.java"))),
                index(type("p/Foo.class", "p.Foo", "Foo.java")),
                false)
            .declarations()
            .getFirst();

    assertAll(
        "exact SourceFile and package metadata resolve the complete family",
        () -> assertThat(result.status()).isEqualTo(CodeAttributionResolver.Status.RESOLVED),
        () -> assertThat(result.classFamily()).containsExactly("p.Foo"),
        () -> assertThat(result.reasons()).isEmpty());
  }

  @Test
  void whitespaceOnlyPackageSegmentIsNotCollapsedIntoAnExactSourcePath() {
    final CodeAttributionResolver.DeclarationResult result =
        CodeAttributionResolver.resolve(
                List.of(CodeClaim.declared(CodeReference.sourceFile("p/ /Foo.java"))),
                index(type("p/Foo.class", "p.Foo", "Foo.java")),
                false)
            .declarations()
            .getFirst();

    assertAll(
        "whitespace directory names cannot be erased to turn a different path into a match",
        () -> assertThat(result.status()).isEqualTo(CodeAttributionResolver.Status.UNRESOLVED),
        () -> assertThat(result.classFamily()).isEmpty());
  }

  @Test
  void embeddedDotPackagePathDoesNotAliasSeparatedComponents() {
    final JarSourceFileIndex index = index(type("p/q/Foo.class", "p.q.Foo", "Foo.java"));
    final CodeAttributionResolver.DeclarationResult dotted =
        CodeAttributionResolver.resolve(
                List.of(CodeClaim.declared(CodeReference.sourceFile("p.q/Foo.java"))), index, false)
            .declarations()
            .getFirst();
    final CodeAttributionResolver.DeclarationResult segmented =
        CodeAttributionResolver.resolve(
                List.of(CodeClaim.declared(CodeReference.sourceFile("p/q/Foo.java"))), index, false)
            .declarations()
            .getFirst();

    assertAll(
        "a package separator must remain a path separator, not an embedded dot",
        () -> assertThat(dotted.status()).isEqualTo(CodeAttributionResolver.Status.UNRESOLVED),
        () -> assertThat(dotted.classFamily()).isEmpty(),
        () -> assertThat(segmented.status()).isEqualTo(CodeAttributionResolver.Status.RESOLVED),
        () -> assertThat(segmented.classFamily()).containsExactly("p.q.Foo"));
  }

  private static CodeAttributionResolver.Result resolve(
      final JarSourceFileIndex index, final String... routines) {
    return CodeAttributionResolver.resolve(
        java.util.Arrays.stream(routines)
            .map(value -> CodeClaim.declared(CodeReference.routine(value)))
            .toList(),
        index,
        false);
  }

  private static ClassSourceFile type(
      final String path, final String binaryName, final MethodIdentity... methods) {
    return new ClassSourceFile(path, binaryName, 0, null, Set.of(methods));
  }

  private static ClassSourceFile type(
      final String path, final String binaryName, final String sourceFile) {
    return new ClassSourceFile(path, binaryName, 0, sourceFile, Set.of());
  }

  private static MethodIdentity method(final String name, final String descriptor) {
    return new MethodIdentity(name, descriptor);
  }

  private static JarSourceFileIndex index(final ClassSourceFile... classes) {
    return new JarSourceFileIndex("d".repeat(64), List.of(classes));
  }
}
