/* WHY: Verifies generic code claims resolve to only the class families their locators identify. */

package io.github.spockz.elider.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.scanner.JarSourceFileIndex;
import io.github.spockz.elider.scanner.JarSourceFileIndex.ClassSourceFile;
import io.github.spockz.elider.scanner.JarSourceFileIndex.MethodIdentity;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** Exercises immutable attribution outcomes for generic claims. */
@SuppressWarnings({
  "PMD.AtLeastOneConstructor",
  "PMD.CommentRequired",
  "PMD.AvoidDuplicateLiterals",
  "PMD.TooManyMethods"
})
final class CodeAttributionResolverTest {
  private static final String DIGEST = "a".repeat(64);

  @Test
  void classAndFileClaimsIncludeEveryKnownNestedAndSecondaryClass() {
    final JarSourceFileIndex index =
        index(
            type("p/Foo.class", "p.Foo", "Foo.java"),
            type("p/Foo$Inner.class", "p.Foo$Inner", "Foo.java"),
            type("p/Other.class", "p.Other", "Foo.java"),
            type("p/Unrelated.class", "p.Unrelated", "Unrelated.java"));

    final CodeAttributionResolver.Result result =
        CodeAttributionResolver.resolve(
            List.of(
                declared(CodeReference.className("p.Foo")),
                declared(CodeReference.sourceFile("p/Foo.java"))),
            index,
            false);

    assertAll(
        "class and source claims keep their distinct ownership scopes",
        () -> assertThat(result.declarations()).hasSize(2),
        () ->
            assertThat(result.declarations().get(0).status())
                .isEqualTo(CodeAttributionResolver.Status.RESOLVED),
        () ->
            assertThat(result.declarations().get(0).classFamily())
                .containsExactlyInAnyOrder("p.Foo", "p.Foo$Inner"),
        () ->
            assertThat(result.declarations().get(1).classFamily())
                .containsExactlyInAnyOrder("p.Foo", "p.Foo$Inner", "p.Other"));
  }

  @Test
  void sourceClaimsPreservePackageAndCaseAndDoNotMatchOnlyByBasename() {
    final JarSourceFileIndex index =
        index(
            type("p/Foo.class", "p.Foo", "Foo.java"),
            type("q/Foo.class", "q.Foo", "Foo.java"),
            type("p/foo.class", "p.foo", "foo.java"));

    final CodeAttributionResolver.Result result =
        CodeAttributionResolver.resolve(
            List.of(declared(CodeReference.sourceFile("src/main/java/p/Foo.java"))), index, true);

    assertThat(result.declarations().getFirst().classFamily()).containsExactly("p.Foo");
  }

  @Test
  void conventionalRootRequiresTheExplicitLayoutFlag() {
    final JarSourceFileIndex index = index(type("p/Foo.class", "p.Foo", "Foo.java"));
    final CodeClaim claim = declared(CodeReference.sourceFile("src/main/java/p/Foo.java"));

    final CodeAttributionResolver.Result disallowed =
        CodeAttributionResolver.resolve(List.of(claim), index, false);
    final CodeAttributionResolver.Result allowed =
        CodeAttributionResolver.resolve(List.of(claim), index, true);

    assertAll(
        "recognized source roots are used only under the configured layout assumption",
        () ->
            assertThat(disallowed.declarations().getFirst().status())
                .isEqualTo(CodeAttributionResolver.Status.UNRESOLVED),
        () -> assertThat(allowed.declarations().getFirst().classFamily()).containsExactly("p.Foo"));
  }

  @Test
  void unknownSourceFileMetadataMakesFileFamilyPartial() {
    final JarSourceFileIndex index =
        index(type("p/Foo.class", "p.Foo", "Foo.java"), type("p/Hidden.class", "p.Hidden", null));

    final CodeAttributionResolver.DeclarationResult result =
        CodeAttributionResolver.resolve(
                List.of(declared(CodeReference.sourceFile("p/Foo.java"))), index, false)
            .declarations()
            .getFirst();

    assertAll(
        "known file outputs remain visible while possible siblings block completeness",
        () -> assertThat(result.status()).isEqualTo(CodeAttributionResolver.Status.PARTIAL),
        () -> assertThat(result.classFamily()).containsExactly("p.Foo"),
        () ->
            assertThat(result.reasons())
                .contains(CodeAttributionResolver.Reason.POSSIBLE_UNIDENTIFIED_FILE_SIBLING));
  }

  @Test
  void routinesResolveExactOwnersWithoutSourceFileAndHandleOverloads() {
    final JarSourceFileIndex index =
        index(
            type("p/Owner.class", "p.Owner", null, method("run", "()V"), method("run", "(I)V")),
            type("p/Owner$Nested.class", "p.Owner$Nested", null),
            type("q/Other.class", "q.Other", "Other.java", method("run", "()V")));

    final CodeAttributionResolver.Result result =
        CodeAttributionResolver.resolve(
            List.of(
                declared(CodeReference.routine("p.Owner.run")),
                declared(CodeReference.routine("p.Owner#run(I)V"))),
            index,
            false);

    assertAll(
        "descriptor-free and exact-descriptor claims resolve to the declared owner family",
        () ->
            assertThat(result.declarations().get(0).status())
                .isEqualTo(CodeAttributionResolver.Status.RESOLVED),
        () ->
            assertThat(result.declarations().get(0).classFamily())
                .containsExactlyInAnyOrder("p.Owner", "p.Owner$Nested"),
        () ->
            assertThat(result.declarations().get(1).classFamily())
                .containsExactlyInAnyOrder("p.Owner", "p.Owner$Nested"));
  }

  @Test
  void missingDescriptorAndUnqualifiedOwnerAmbiguityAbstain() {
    final JarSourceFileIndex index =
        index(
            type("p/One.class", "p.One", null, method("run", "()V")),
            type("q/Two.class", "q.Two", null, method("run", "()V")));

    final CodeAttributionResolver.Result result =
        CodeAttributionResolver.resolve(
            List.of(
                declared(CodeReference.routine("p.One.run(I)V")),
                declared(CodeReference.routine("run"))),
            index,
            false);

    assertAll(
        "routine claims require a declared matching method and one exact owner",
        () ->
            assertThat(result.declarations().get(0).status())
                .isEqualTo(CodeAttributionResolver.Status.UNRESOLVED),
        () ->
            assertThat(result.declarations().get(1).status())
                .isEqualTo(CodeAttributionResolver.Status.UNRESOLVED));
  }

  @Test
  void heuristicClaimsRemainNonblockingReviewLeads() {
    final JarSourceFileIndex index = index(type("p/Foo.class", "p.Foo", "Foo.java"));
    final CodeAttributionResolver.Result result =
        CodeAttributionResolver.resolve(
            List.of(
                declared(CodeReference.className("p.Foo")),
                CodeClaim.heuristic(CodeReference.className("missing.Type"))),
            index,
            false);

    assertAll(
        "a heuristic lead is visible but cannot block a valid declared mapping",
        () -> assertThat(result.declarations()).hasSize(2),
        () ->
            assertThat(result.declarations().get(0).status())
                .isEqualTo(CodeAttributionResolver.Status.RESOLVED),
        () ->
            assertThat(result.declarations().get(1).status())
                .isEqualTo(CodeAttributionResolver.Status.REVIEW_LEAD));
  }

  private static CodeClaim declared(final CodeReference reference) {
    return CodeClaim.declared(reference);
  }

  private static ClassSourceFile type(
      final String physicalPath,
      final String className,
      final String sourceFile,
      final MethodIdentity... methods) {
    return new ClassSourceFile(physicalPath, className, 0, sourceFile, Set.of(methods));
  }

  private static MethodIdentity method(final String name, final String descriptor) {
    return new MethodIdentity(name, descriptor);
  }

  private static JarSourceFileIndex index(final ClassSourceFile... classes) {
    return new JarSourceFileIndex(DIGEST, List.of(classes));
  }
}
