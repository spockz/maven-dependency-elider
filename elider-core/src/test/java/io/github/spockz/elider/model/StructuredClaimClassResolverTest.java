/* WHY: Checks how JarSourceFileIndex binds CNA claims to class families. */

package io.github.spockz.elider.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.scanner.JarSourceFileIndex;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Verifies file claims map to classes using JarSourceFileIndex. */
@SuppressWarnings({
  "PMD.CommentRequired",
  "PMD.CommentDefaultAccessModifier",
  "PMD.AtLeastOneConstructor",
  "PMD.AvoidDuplicateLiterals"
})
final class StructuredClaimClassResolverTest {
  private static final String OUTER_BINARY_NAME = "org.example.Outer";
  private static final String OUTER_SOURCE = "src/main/java/org/example/Outer.java";

  @TempDir Path tempDir;

  @Test
  void fileClaimsSelectEveryClassEmittedByTheirMappedSourceUnit() throws IOException {
    final Path jar = tempDir.resolve("test.jar");
    try (JarOutputStream out = new JarOutputStream(Files.newOutputStream(jar))) {
      out.putNextEntry(new JarEntry("org/example/Outer.class"));
      out.write(new byte[] {(byte) 0xca, (byte) 0xfe, (byte) 0xba, (byte) 0xbe});
      out.closeEntry();
    }
    final JarSourceFileIndex index =
        new JarSourceFileIndex(
            "b".repeat(64),
            List.of(
                new JarSourceFileIndex.ClassSourceFile(
                    "org/example/Outer.class", "org.example.Outer", 0, "Outer.java")));

    final StructuredClaimClassResolver.Result result =
        StructuredClaimClassResolver.derive(FixtureData.outerFileEntry(), index, jar, true);

    assertAll(
        "file claim binds the matched class",
        () -> assertThat(result.classNames()).containsExactly(OUTER_BINARY_NAME),
        () ->
            assertThat(result.attributions())
                .singleElement()
                .satisfies(
                    attribution -> {
                      assertThat(attribution.type())
                          .isEqualTo(StructuredProofProvenance.ClaimType.FILE);
                      assertThat(attribution.sourceEntry()).isEqualTo(OUTER_SOURCE);
                      assertThat(attribution.emittedClasses()).hasSize(1);
                    }));
  }

  @Test
  void routineClaimsResolveToOwnerAndNestedClasses() throws IOException {
    final Path jar = tempDir.resolve("test-routine.jar");
    try (JarOutputStream out = new JarOutputStream(Files.newOutputStream(jar))) {
      out.putNextEntry(new JarEntry("org/example/Outer.class"));
      out.write(new byte[] {(byte) 0xca, (byte) 0xfe, (byte) 0xba, (byte) 0xbe});
      out.closeEntry();
    }
    final JarSourceFileIndex index =
        new JarSourceFileIndex(
            "b".repeat(64),
            List.of(
                new JarSourceFileIndex.ClassSourceFile(
                    "org/example/Outer.class",
                    "org.example.Outer",
                    0,
                    "Outer.java",
                    Set.of("run"))));

    final StructuredClaimClassResolver.Result result =
        StructuredClaimClassResolver.derive(FixtureData.routineEntry(), index, jar, true);

    assertAll(
        "routine claim binds the owner class",
        () -> assertThat(result.classNames()).containsExactly(OUTER_BINARY_NAME),
        () ->
            assertThat(result.attributions())
                .singleElement()
                .satisfies(
                    attribution -> {
                      assertThat(attribution.type())
                          .isEqualTo(StructuredProofProvenance.ClaimType.ROUTINE);
                      assertThat(attribution.claim()).isEqualTo("run");
                      assertThat(attribution.routineOwnerBinaryName()).isEqualTo(OUTER_BINARY_NAME);
                      assertThat(attribution.emittedClasses()).hasSize(1);
                    }));
  }

  @Test
  void missingFileMappingAbstains() throws IOException {
    final Path jar = tempDir.resolve("test-missing.jar");
    Files.createFile(jar);
    final JarSourceFileIndex index = new JarSourceFileIndex("b".repeat(64), List.of());

    assertThatThrownBy(
            () ->
                StructuredClaimClassResolver.derive(FixtureData.outerFileEntry(), index, jar, true))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("no exact archive match");
  }

  @SuppressWarnings({"PMD.CommentRequired", "PMD.UnnecessaryConstructor"})
  private static final class FixtureData {
    private static final String ARCHIVE_SHA256 = "b".repeat(64);

    private FixtureData() {}

    private static CveAffectedEntryContext outerFileEntry() {
      return entry(Set.of(OUTER_SOURCE), Set.of());
    }

    private static CveAffectedEntryContext routineEntry() {
      return entry(Set.of(), Set.of("run"));
    }

    private static CveAffectedEntryContext entry(
        final Set<String> files, final Set<String> routines) {
      return new CveAffectedEntryContext(
          "containers.cna.affected[0]",
          new CveSourceRecordMetadata(
              true, true, true, "CVE-2025-12345", true, "PUBLISHED", ARCHIVE_SHA256),
          "Example",
          "library",
          "pkg:maven/org.example/library",
          null,
          null,
          null,
          List.of(),
          files,
          routines);
    }
  }
}
