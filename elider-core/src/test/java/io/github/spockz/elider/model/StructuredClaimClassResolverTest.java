/* WHY: Checks how fresh reproduced outputs bind CNA claims to class families. */

package io.github.spockz.elider.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.correspondence.SourceReproductionResult;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** Verifies file families and uniquely resolved routine-owner families. */
final class StructuredClaimClassResolverTest {
  /** Expected owner class emitted by the synthetic reproduction. */
  private static final String OUTER_BINARY_NAME = "org.example.Outer";

  /** Public package-private constructor permits JUnit's package-local test lifecycle. */
  /* default */ StructuredClaimClassResolverTest() {
    // JUnit creates one isolated test instance for each scenario.
  }

  @Test
  void fileClaimsSelectEveryClassEmittedByTheirMappedSourceUnit() throws IOException {
    final StructuredClaimClassResolver.Result result =
        StructuredClaimClassResolver.derive(
            FixtureData.outerFileEntry(), FixtureData.completedResult());

    assertAll(
        "file claim binds the entire reproduced source unit",
        () ->
            assertThat(result.classNames())
                .containsExactlyInAnyOrder(OUTER_BINARY_NAME, OUTER_BINARY_NAME + "$Nested"),
        () ->
            assertThat(result.attributions())
                .singleElement()
                .satisfies(
                    attribution -> {
                      assertThat(attribution.type())
                          .isEqualTo(StructuredProofProvenance.ClaimType.FILE);
                      assertThat(attribution.sourceEntry()).isEqualTo(FixtureData.OUTER_SOURCE);
                      assertThat(attribution.emittedClasses()).hasSize(2);
                    }));
  }

  @Test
  void routineClaimsSelectOnlyTheUniqueOwnerClassFamily() throws IOException {
    final StructuredClaimClassResolver.Result result =
        StructuredClaimClassResolver.derive(
            FixtureData.routineEntry(), FixtureData.completedResult());

    assertAll(
        "routine claim binds only its unique declaring class family",
        () ->
            assertThat(result.classNames())
                .containsExactlyInAnyOrder(OUTER_BINARY_NAME, OUTER_BINARY_NAME + "$Nested"),
        () ->
            assertThat(result.attributions())
                .singleElement()
                .satisfies(
                    attribution -> {
                      assertThat(attribution.type())
                          .isEqualTo(StructuredProofProvenance.ClaimType.ROUTINE);
                      assertThat(attribution.routineOwnerBinaryName()).isEqualTo(OUTER_BINARY_NAME);
                    }));
  }

  @Test
  void missingFileMappingAndAmbiguousRoutineOwnersAbstain() {
    assertAll(
        "unmapped and ambiguous claims both abstain",
        () ->
            assertThatThrownBy(
                    () ->
                        StructuredClaimClassResolver.derive(
                            FixtureData.fileEntry(), FixtureData.withoutFileMapping()))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("no exact archive match"),
        () ->
            assertThatThrownBy(
                    () ->
                        StructuredClaimClassResolver.derive(
                            FixtureData.routineEntry(), FixtureData.duplicateRoutineOwner()))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("no unique reproduced owner"));
  }

  /** Builds a consistent immutable resolver fixture graph. */
  @SuppressWarnings("PMD.TooManyMethods")
  private static final class FixtureData {
    /** Stable source digest for synthetic completed reproduction results. */
    private static final String SOURCE_SHA256 = "a".repeat(64);

    /** Stable archive digest for synthetic completed reproduction results. */
    private static final String ARCHIVE_SHA256 = "b".repeat(64);

    /** One source unit that emits the owner class family. */
    private static final String OUTER_SOURCE = "src/main/java/org/example/Outer.java";

    /** One source unit that emits a sibling top-level class. */
    private static final String SIBLING_SOURCE = "src/main/java/org/example/Sibling.java";

    /** One method name used to test unique routine ownership. */
    private static final String ROUTINE_NAME = "run";

    /** Prevents fixture helpers from being instantiated. */
    private FixtureData() {
      // Static factory methods keep immutable reproduction fixtures reusable.
    }

    private static CveAffectedEntryContext outerFileEntry() {
      return entry(Set.of(OUTER_SOURCE), Set.of());
    }

    private static CveAffectedEntryContext fileEntry() {
      return outerFileEntry();
    }

    private static CveAffectedEntryContext routineEntry() {
      return entry(Set.of(), Set.of(ROUTINE_NAME));
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

    private static SourceReproductionResult.Completed completedResult(
        final Map<String, String> mappedClaims,
        final List<SourceReproductionResult.SourceUnit> units) {
      return new SourceReproductionResult.Completed(
          ArtifactCoordinate.of("org.example", "library", "1.0"),
          new ArtifactCoordinate("org.example", "library", "1.0", "jar", "sources", "compile"),
          "local repository",
          ARCHIVE_SHA256,
          SOURCE_SHA256,
          "pinned JDK 21",
          List.of("--release", "21"),
          units.stream().flatMap(unit -> unit.emittedClasses().stream()).toList(),
          units,
          mappedClaims);
    }

    private static SourceReproductionResult.Completed completedResult() {
      return completedResult(
          Map.of(OUTER_SOURCE, OUTER_SOURCE), List.of(outerUnit(), siblingUnit()));
    }

    private static SourceReproductionResult.Completed withoutFileMapping() {
      return completedResult(Map.of(), List.of(outerUnit(), siblingUnit()));
    }

    private static SourceReproductionResult.Completed duplicateRoutineOwner() {
      return completedResult(
          Map.of(),
          List.of(
              outerUnit(),
              unit(
                  SIBLING_SOURCE,
                  "org.example.Sibling",
                  List.of(routine(ROUTINE_NAME, "org.example.Sibling")),
                  classEntry("org/example/Sibling.class"))));
    }

    private static SourceReproductionResult.SourceUnit outerUnit() {
      return unit(
          OUTER_SOURCE,
          OUTER_BINARY_NAME,
          List.of(routine(ROUTINE_NAME, OUTER_BINARY_NAME)),
          classEntry("org/example/Outer.class"),
          classEntry("org/example/Outer$Nested.class"));
    }

    private static SourceReproductionResult.SourceUnit siblingUnit() {
      return unit(
          SIBLING_SOURCE,
          "org.example.Sibling",
          List.of(),
          classEntry("org/example/Sibling.class"));
    }

    private static SourceReproductionResult.SourceUnit unit(
        final String sourceEntry,
        final String binaryName,
        final List<SourceReproductionResult.RoutineDeclaration> routines,
        final SourceReproductionResult.ClassEntry... classes) {
      return new SourceReproductionResult.SourceUnit(
          sourceEntry, SOURCE_SHA256, Set.of(binaryName), routines, List.of(classes));
    }

    private static SourceReproductionResult.ClassEntry classEntry(final String path) {
      return new SourceReproductionResult.ClassEntry(path, SOURCE_SHA256);
    }

    private static SourceReproductionResult.RoutineDeclaration routine(
        final String name, final String owner) {
      return new SourceReproductionResult.RoutineDeclaration(name, owner);
    }
  }
}
