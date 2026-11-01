// WHY: Exercises complete source-to-class reproduction through the public core engine.

package io.github.spockz.elider.correspondence;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Checks positive reproduction and fail-closed public engine outcomes. */
@SuppressWarnings("PMD.AtLeastOneConstructor") // JUnit supplies the test instance lifecycle.
final class SourceReproductionEngineTest {
  /** Exact Java source archive entry used by the ordinary-layout fixture. */
  private static final String SOURCE_ENTRY = "src/main/java/org/example/Outer.java";

  /** Source unit whose complete output family is checked by the positive case. */
  private static final String SOURCE =
      "package org.example; public class Outer { public void parse() {}"
          + " public Runnable create() { class Local { void runLocal() {} }"
          + " final Local local = new Local();"
          + " return new Runnable() { public void run() { local.runLocal(); } }; }"
          + " public static class Nested {} } class Sibling {}";

  /** Candidate and resolved sources coordinates bind the independently read archives. */
  private static final ArtifactCoordinate CANDIDATE =
      ArtifactCoordinate.of("org.example", "demo", "1.0");

  /** Resolver provenance is descriptive input, never an authority value. */
  private static final String SOURCE_REPOSITORY = "remote:fixture-repository";

  /** Isolates source and binary fixture archives for each test. */
  @TempDir private Path temporaryDirectory;

  @Test
  // One result covers independent inventory and provenance contracts.
  @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
  void reproducesEveryPhysicalClassAndUniqueRoutineFromExactArchives() throws IOException {
    final SourceReproductionTestArchives.Archives archives =
        archives(
            temporaryDirectory.resolve("positive"),
            SOURCE_ENTRY,
            SOURCE,
            false,
            Optional.empty(),
            false);
    final SourceReproductionResult result =
        SourceReproductionEngine.forCurrentJdk()
            .reproduce(request(archives, List.of(SOURCE_ENTRY), List.of("parse"), false));

    assertThat(result).isInstanceOf(SourceReproductionResult.Completed.class);
    final SourceReproductionResult.Completed completed =
        (SourceReproductionResult.Completed) result;
    assertAll(
        "the isolated source compilation must reproduce the entire original class family",
        () -> assertCompletedIdentity(completed),
        () -> assertCompletePhysicalInventory(completed),
        () -> assertParsedSourceUnit(completed),
        () -> assertThat(completed.compilerOptions()).contains("--release=21", "-proc:none"));
  }

  @Test
  void conventionalPathTranslationRequiresTheExplicitLayoutAssumption() throws IOException {
    final String archiveEntry = "org/example/Outer.java";
    final SourceReproductionTestArchives.Archives archives =
        archives(
            temporaryDirectory.resolve("layout"),
            archiveEntry,
            SOURCE,
            false,
            Optional.empty(),
            false);
    final SourceReproductionEngine engine = SourceReproductionEngine.forCurrentJdk();

    final SourceReproductionResult assumed =
        engine.reproduce(request(archives, List.of(SOURCE_ENTRY), List.of(), true));
    final SourceReproductionResult unassumed =
        engine.reproduce(request(archives, List.of(SOURCE_ENTRY), List.of(), false));

    assertAll(
        "only the explicit conventional-layout flag permits translating the source root",
        () -> assertThat(assumed).isInstanceOf(SourceReproductionResult.Completed.class),
        () ->
            assertThat(((SourceReproductionResult.Completed) assumed).mappedClaims())
                .containsEntry(SOURCE_ENTRY, archiveEntry),
        () -> assertThat(unassumed).isInstanceOf(SourceReproductionResult.Abstained.class),
        () ->
            assertThat(((SourceReproductionResult.Abstained) unassumed).rationale())
                .contains("absent from the exact sources archive"));
  }

  @Test
  void duplicateRoutineOwnersAndNonemptyManifestClassPathAbstain() throws IOException {
    final SourceReproductionTestArchives.Archives repeated =
        archives(
            temporaryDirectory.resolve("repeated"),
            SOURCE_ENTRY,
            SOURCE,
            false,
            Optional.of(
                new SourceReproductionTestArchives.AdditionalSource(
                    "src/main/java/org/example/Other.java",
                    "package org.example; public class Other { public void parse() {} }")),
            false);
    final SourceReproductionTestArchives.Archives manifest =
        archives(
            temporaryDirectory.resolve("manifest"),
            SOURCE_ENTRY,
            SOURCE,
            true,
            Optional.empty(),
            false);
    final SourceReproductionEngine engine = SourceReproductionEngine.forCurrentJdk();
    final SourceReproductionResult repeatedResult =
        engine.reproduce(request(repeated, List.of(), List.of("parse"), false));
    final SourceReproductionResult manifestResult =
        engine.reproduce(request(manifest, List.of(SOURCE_ENTRY), List.of(), false));

    assertAll(
        "unsupported ownership or classpath inputs cannot produce a completed result",
        () -> assertThat(repeatedResult).isInstanceOf(SourceReproductionResult.Abstained.class),
        () ->
            assertThat(((SourceReproductionResult.Abstained) repeatedResult).rationale())
                .contains("multiple possible owners or overloads"),
        () -> assertThat(manifestResult).isInstanceOf(SourceReproductionResult.Abstained.class),
        () ->
            assertThat(((SourceReproductionResult.Abstained) manifestResult).rationale())
                .contains("Manifest Class-Path is unsupported"));
  }

  @Test
  void extraPhysicalClassesAndUnsafeSourceEntriesAbstain() throws IOException {
    final SourceReproductionTestArchives.Archives extra =
        archives(
            temporaryDirectory.resolve("extra"),
            SOURCE_ENTRY,
            SOURCE,
            false,
            Optional.empty(),
            true);
    final SourceReproductionTestArchives.Archives unsafe =
        archives(
            temporaryDirectory.resolve("unsafe"),
            "../Escape.java",
            "class Escape {}",
            false,
            Optional.empty(),
            false);
    final SourceReproductionEngine engine = SourceReproductionEngine.forCurrentJdk();
    final SourceReproductionResult extraResult =
        engine.reproduce(request(extra, List.of(SOURCE_ENTRY), List.of(), false));
    final SourceReproductionResult unsafeResult =
        engine.reproduce(request(unsafe, List.of("../Escape.java"), List.of(), false));

    assertAll(
        "the engine rejects extra inventory and unsafe archive paths",
        () -> assertThat(extraResult).isInstanceOf(SourceReproductionResult.Abstained.class),
        () ->
            assertThat(((SourceReproductionResult.Abstained) extraResult).rationale())
                .contains("inventory differs from original JAR"),
        () -> assertThat(unsafeResult).isInstanceOf(SourceReproductionResult.Abstained.class),
        () ->
            assertThat(((SourceReproductionResult.Abstained) unsafeResult).rationale())
                .contains("Unsafe archive entry path"));
  }

  private static SourceReproductionRequest request(
      final SourceReproductionTestArchives.Archives archives,
      final List<String> files,
      final List<String> routines,
      final boolean assumeLayout) {
    final ArtifactCoordinate sources =
        new ArtifactCoordinate("org.example", "demo", "1.0", "jar", "sources", "compile");
    return new SourceReproductionRequest(
        CANDIDATE,
        sources,
        archives.originalJar(),
        archives.sourcesJar(),
        SOURCE_REPOSITORY,
        files,
        routines,
        assumeLayout);
  }

  private static SourceReproductionTestArchives.Archives archives(
      final Path directory,
      final String sourceEntry,
      final String source,
      final boolean manifest,
      final Optional<SourceReproductionTestArchives.AdditionalSource> additionalSource,
      final boolean extraClass)
      throws IOException {
    return SourceReproductionTestArchives.write(
        directory, sourceEntry, source, manifest, additionalSource, extraClass);
  }

  private static void assertCompletedIdentity(final SourceReproductionResult.Completed completed) {
    assertAll(
        () -> assertThat(completed.candidate()).isEqualTo(CANDIDATE),
        () -> assertThat(completed.sourcesCoordinate().classifier()).isEqualTo("sources"),
        () -> assertThat(completed.sourceRepositoryProvenance()).isEqualTo(SOURCE_REPOSITORY));
  }

  private static void assertCompletePhysicalInventory(
      final SourceReproductionResult.Completed completed) {
    assertAll(
        () -> assertThat(completed.originalClassInventory()).hasSize(5),
        () ->
            assertThat(
                    completed.originalClassInventory().stream()
                        .map(SourceReproductionResult.ClassEntry::path))
                .containsExactlyInAnyOrder(
                    "org/example/Outer.class",
                    "org/example/Outer$1.class",
                    "org/example/Outer$1Local.class",
                    "org/example/Outer$Nested.class",
                    "org/example/Sibling.class"),
        () ->
            assertThat(completed.sourceUnits().getFirst().emittedClasses())
                .containsExactlyElementsOf(completed.originalClassInventory()));
  }

  private static void assertParsedSourceUnit(final SourceReproductionResult.Completed completed) {
    assertAll(
        () -> assertThat(completed.sourceUnits()).hasSize(1),
        () ->
            assertThat(completed.sourceUnits().getFirst().topLevelTypes())
                .containsExactlyInAnyOrder("org.example.Outer", "org.example.Sibling"),
        () ->
            assertThat(completed.sourceUnits().getFirst().routineDeclarations())
                .contains(
                    new SourceReproductionResult.RoutineDeclaration("parse", "org.example.Outer")),
        () -> assertThat(completed.mappedClaims()).containsEntry(SOURCE_ENTRY, SOURCE_ENTRY));
  }
}
