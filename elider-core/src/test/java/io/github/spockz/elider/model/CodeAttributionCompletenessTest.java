/* WHY: Tests partial file attribution when SourceFile metadata cannot identify siblings. */

package io.github.spockz.elider.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.scanner.JarSourceFileIndex;
import io.github.spockz.elider.scanner.JarSourceFileIndex.ClassSourceFile;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** Covers the source-file family completeness boundary. */
@SuppressWarnings({"PMD.AtLeastOneConstructor", "PMD.AvoidDuplicateLiterals"})
final class CodeAttributionCompletenessTest {
  @Test
  void infersOnlyTheConventionalOwnerFamilyAndMarksMissingSourceMetadataPartial() {
    final JarSourceFileIndex index =
        new JarSourceFileIndex(
            "c".repeat(64),
            List.of(
                type("p/Foo.class", "p.Foo"),
                type("p/Foo$Inner.class", "p.Foo$Inner"),
                type("p/MaybeSibling.class", "p.MaybeSibling")));

    final CodeAttributionResolver.DeclarationResult result =
        CodeAttributionResolver.resolve(
                List.of(CodeClaim.declared(CodeReference.sourceFile("src/main/java/p/Foo.java"))),
                index,
                true)
            .declarations()
            .getFirst();

    assertAll(
        "conventional filename inference exposes a candidate family without claiming completeness",
        () -> assertThat(result.status()).isEqualTo(CodeAttributionResolver.Status.PARTIAL),
        () -> assertThat(result.classFamily()).containsExactlyInAnyOrder("p.Foo", "p.Foo$Inner"),
        () ->
            assertThat(result.reasons())
                .contains(CodeAttributionResolver.Reason.POSSIBLE_UNIDENTIFIED_FILE_SIBLING));
  }

  @Test
  void nestedClassWithConflictingSourceFileMetadataMakesOwnerFamilyPartial() {
    final JarSourceFileIndex index =
        new JarSourceFileIndex(
            "e".repeat(64),
            List.of(
                new ClassSourceFile("p/Foo.class", "p.Foo", 0, "Foo.java", Set.of()),
                new ClassSourceFile(
                    "p/Foo$Inner.class", "p.Foo$Inner", 0, "Other.java", Set.of())));

    final CodeAttributionResolver.DeclarationResult result =
        CodeAttributionResolver.resolve(
                List.of(CodeClaim.declared(CodeReference.sourceFile("p/Foo.java"))), index, false)
            .declarations()
            .getFirst();

    assertAll(
        "a nested family member with conflicting file metadata remains included but incomplete",
        () -> assertThat(result.status()).isEqualTo(CodeAttributionResolver.Status.PARTIAL),
        () -> assertThat(result.classFamily()).containsExactlyInAnyOrder("p.Foo", "p.Foo$Inner"),
        () ->
            assertThat(result.reasons())
                .contains(CodeAttributionResolver.Reason.CONFLICTING_NESTED_SOURCE_FILE_METADATA));
  }

  @Test
  void nestedOwnerIncludesItsNestedDescendantsAndConflictsRemainPartial() {
    final JarSourceFileIndex index =
        new JarSourceFileIndex(
            "f".repeat(64),
            List.of(
                new ClassSourceFile("p/Foo$Inner.class", "p.Foo$Inner", 0, "Inner.java", Set.of()),
                new ClassSourceFile(
                    "p/Foo$Inner$Deep.class", "p.Foo$Inner$Deep", 0, "Other.java", Set.of())));

    final CodeAttributionResolver.DeclarationResult result =
        CodeAttributionResolver.resolve(
                List.of(CodeClaim.declared(CodeReference.sourceFile("p/Inner.java"))), index, false)
            .declarations()
            .getFirst();

    assertAll(
        "nested owners include descendants and conflicting SourceFile metadata stays incomplete",
        () -> assertThat(result.status()).isEqualTo(CodeAttributionResolver.Status.PARTIAL),
        () ->
            assertThat(result.classFamily())
                .containsExactlyInAnyOrder("p.Foo$Inner", "p.Foo$Inner$Deep"),
        () ->
            assertThat(result.reasons())
                .contains(CodeAttributionResolver.Reason.CONFLICTING_NESTED_SOURCE_FILE_METADATA));
  }

  private static ClassSourceFile type(final String path, final String name) {
    return new ClassSourceFile(path, name, 0, null, Set.of());
  }
}
