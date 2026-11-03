// WHY: Exercises source correspondence from exact matched claims through Maven assessment.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.correspondence.SourceReproductionResult;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Checks source reproduction and routine ownership in assessment. */
@SuppressWarnings("PMD.AtLeastOneConstructor") // JUnit supplies the test instance lifecycle.
final class MavenSourceCorrespondenceAssessmentTest {
  /** Routine name used by positive and ambiguity fixtures. */
  private static final String PARSE_ROUTINE = "parse";

  /** Extra class entry used to prove complete inventory mismatch refusal. */
  private static final String EXTRA_CLASS_ENTRY = "org/example/Extra.class";

  /** Source file emits this top-level sibling and related declaration families. */
  private static final String SIBLING_BINARY_NAME = "org.example.Sibling";

  /** Entry emitted for the top-level sibling. */
  private static final String SIBLING_CLASS_ENTRY = "org/example/Sibling.class";

  /** Binary name of the package-private sibling interface. */
  private static final String SIBLING_CONTRACT = "org.example.SiblingContract";

  /** Binary name of the package-private sibling enum. */
  private static final String SIBLING_KIND = "org.example.SiblingKind";

  /** Binary name of the package-private sibling annotation interface. */
  private static final String SIBLING_ANNOTATION = "org.example.SiblingAnnotation";

  /** Binary name of the package-private sibling record. */
  private static final String SIBLING_RECORD = "org.example.SiblingRecord";

  /** Isolates generated archive fixtures for this test instance. */
  @TempDir private Path temporaryDirectory;

  @Test
  void uniquelyOwnedRoutineAndConventionalFileClaimReproduceExactArtifact() throws IOException {
    org.junit.jupiter.api.Assumptions.assumeTrue(
        io.github.spockz.elider.correspondence.SourceReproductionEngine.isSupportedJdk(),
        "Skipping source reproduction tests on non-pinned JDK");
    final Path directory = temporaryDirectory.resolve("unique");
    final MavenCorroboratedSourceScenario.Prepared prepared =
        MavenCorroboratedSourceScenario.prepareReproducibleClaim(
            directory,
            List.of(MavenSourceCorrespondenceTestArtifacts.SOURCE_ENTRY),
            List.of(PARSE_ROUTINE));
    final MavenSourceCorrespondenceTestArtifacts.Archives archives =
        MavenSourceCorrespondenceTestArtifacts.write(directory, false, false);
    final MavenVulnerabilityAssessment.Result result =
        MavenCorroboratedSourceScenario.assessWithSourceClassifier(
            prepared,
            archives.originalJar(),
            new MavenSourceClassifierResolver(
                MavenSourceCorrespondenceTestArtifacts.resolver(archives.sourcesJar())),
            true);
    final SourceBuildCorrespondence.Matched match =
        (SourceBuildCorrespondence.Matched) result.sourceCorrespondences().getFirst();
    final MavenVulnerabilityAssessment.Result withoutLayoutAssumption =
        MavenCorroboratedSourceScenario.assessWithSourceClassifier(
            prepared,
            archives.originalJar(),
            new MavenSourceClassifierResolver(
                MavenSourceCorrespondenceTestArtifacts.resolver(archives.sourcesJar())),
            false);

    assertAll(
        "the enabled path-root translation and unique routine owner match the exact JAR bytes",
        () -> assertThat(result.sourceCorrespondences()).hasSize(1),
        () ->
            assertThat(result.sourceCorrespondences().getFirst())
                .isInstanceOf(SourceBuildCorrespondence.Matched.class),
        () -> assertThat(result.attestations()).isEmpty(),
        () -> assertThat(result.provenVulnerableCodeAbsent()).isEmpty(),
        () -> assertThat(result.inactiveDueToMissingPrerequisites()).isEmpty(),
        () -> assertThat(result.potentiallyConservativeCves()).isEmpty(),
        () ->
            assertThat(match.compilerIdentity())
                .contains("javacClassSha256=", "compilerImageSha256=", "platformImageSha256=")
                .contains("releaseApiImageSha256="),
        () ->
            assertThat(match.mappedProgramFiles())
                .containsEntry(
                    MavenSourceCorrespondenceTestArtifacts.SOURCE_ENTRY, "org/example/Outer.java"),
        () ->
            assertThat(match.sourceUnits().getFirst().routineDeclarations())
                .contains(
                    new SourceReproductionResult.RoutineDeclaration(
                        PARSE_ROUTINE, "org.example.Outer")),
        () ->
            assertThat(match.sourceUnits().getFirst().topLevelTypes())
                .containsExactlyInAnyOrder(
                    "org.example.Outer",
                    SIBLING_BINARY_NAME,
                    SIBLING_CONTRACT,
                    SIBLING_KIND,
                    SIBLING_ANNOTATION,
                    SIBLING_RECORD),
        () ->
            assertThat(
                    match.originalClassInventory().stream()
                        .map(SourceReproductionResult.ClassEntry::path))
                .containsExactlyInAnyOrder(
                    "org/example/Outer.class",
                    "org/example/Outer$1.class",
                    "org/example/Outer$1Local.class",
                    "org/example/Outer$Nested.class",
                    SIBLING_CLASS_ENTRY,
                    "org/example/SiblingContract.class",
                    "org/example/SiblingKind.class",
                    "org/example/SiblingAnnotation.class",
                    "org/example/SiblingRecord.class"),
        () ->
            assertThat(match.sourceUnits().getFirst().emittedClasses())
                .containsExactlyElementsOf(match.originalClassInventory()),
        () ->
            assertThat(withoutLayoutAssumption.sourceCorrespondences().getFirst())
                .isInstanceOf(SourceBuildCorrespondence.Abstained.class)
                .extracting(value -> ((SourceBuildCorrespondence.Abstained) value).rationale())
                .asString()
                .contains("absent from the exact sources archive"),
        () ->
            assertThat(result.matchedAdvisoryEvidence())
                .anyMatch(
                    value ->
                        value.evidence()
                            instanceof
                            io.github.spockz.elider.model.CorroboratedSourceClassCandidate));
  }

  @Test
  void routineOnlyUniqueOwnerCanBeMatchedButOverloadsAndRepeatedNamesAbstain() throws IOException {
    org.junit.jupiter.api.Assumptions.assumeTrue(
        io.github.spockz.elider.correspondence.SourceReproductionEngine.isSupportedJdk(),
        "Skipping source reproduction tests on non-pinned JDK");
    assertAll(
        "routine names resolve only to one source declaration",
        () -> assertUniqueRoutineOnly(temporaryDirectory.resolve("routine-only")),
        () -> assertRoutineAbstains(temporaryDirectory.resolve("overloaded"), true, false),
        () -> assertRoutineAbstains(temporaryDirectory.resolve("repeated"), false, true),
        () -> assertPairedRoutineDoesNotHideAnotherOwner(temporaryDirectory.resolve("paired")));
  }

  @Test
  void missingExtraAndChangedPhysicalOutputsAbstain() {
    org.junit.jupiter.api.Assumptions.assumeTrue(
        io.github.spockz.elider.correspondence.SourceReproductionEngine.isSupportedJdk(),
        "Skipping source reproduction tests on non-pinned JDK");
    assertAll(
        "the reproduced disjoint output union must equal the complete original inventory",
        () ->
            assertInventoryMismatch(
                temporaryDirectory.resolve("missing-output"), SIBLING_CLASS_ENTRY, null, true),
        () ->
            assertInventoryMismatch(
                temporaryDirectory.resolve("extra-output"),
                EXTRA_CLASS_ENTRY,
                new byte[] {1, 2, 3},
                false),
        () ->
            assertInventoryMismatch(
                temporaryDirectory.resolve("changed-output"),
                "org/example/Outer.class",
                new byte[] {4, 5, 6},
                false));
  }

  @Test
  void unsupportedSourceArchiveEntriesAbstainBeforeCompilation() throws IOException {
    org.junit.jupiter.api.Assumptions.assumeTrue(
        io.github.spockz.elider.correspondence.SourceReproductionEngine.isSupportedJdk(),
        "Skipping source reproduction tests on non-pinned JDK");
    final Path directory = temporaryDirectory.resolve("unsupported-input");
    final MavenCorroboratedSourceScenario.Prepared prepared =
        MavenCorroboratedSourceScenario.prepareReproducibleClaim(
            directory, List.of(MavenSourceCorrespondenceTestArtifacts.SOURCE_ENTRY), List.of());
    final MavenSourceCorrespondenceTestArtifacts.Archives archives =
        MavenSourceCorrespondenceTestArtifacts.write(directory, false, false);
    MavenSourceCorrespondenceTestArtifacts.addSourcesEntry(
        archives.sourcesJar(),
        "../escape.java",
        "class Escape {}".getBytes(java.nio.charset.StandardCharsets.UTF_8));
    final MavenVulnerabilityAssessment.Result result =
        MavenCorroboratedSourceScenario.assessWithSourceClassifier(
            prepared,
            archives.originalJar(),
            new MavenSourceClassifierResolver(
                MavenSourceCorrespondenceTestArtifacts.resolver(archives.sourcesJar())),
            true);

    assertAbstainedWithoutProof(result, "Unsafe archive entry path");
  }

  @Test
  void manifestClassPathIsRejectedEvenWhenItWouldResolveTheExactCompilationDependency()
      throws IOException {
    org.junit.jupiter.api.Assumptions.assumeTrue(
        io.github.spockz.elider.correspondence.SourceReproductionEngine.isSupportedJdk(),
        "Skipping source reproduction tests on non-pinned JDK");
    final Path directory = temporaryDirectory.resolve("manifest-classpath");
    final MavenCorroboratedSourceScenario.Prepared prepared =
        MavenCorroboratedSourceScenario.prepareReproducibleClaim(
            directory, List.of(MavenSourceCorrespondenceTestArtifacts.SOURCE_ENTRY), List.of());
    final MavenSourceCorrespondenceTestArtifacts.Archives archives =
        MavenSourceCorrespondenceTestArtifacts.write(directory, false, false, true);
    final MavenVulnerabilityAssessment.Result result =
        MavenCorroboratedSourceScenario.assessWithSourceClassifier(
            prepared,
            archives.originalJar(),
            new MavenSourceClassifierResolver(
                MavenSourceCorrespondenceTestArtifacts.resolver(archives.sourcesJar())),
            true);

    assertThat(result.sourceCorrespondences().getFirst())
        .isInstanceOf(SourceBuildCorrespondence.Abstained.class)
        .extracting(value -> ((SourceBuildCorrespondence.Abstained) value).rationale())
        .asString()
        .contains("Manifest Class-Path is unsupported");
  }

  private static void assertUniqueRoutineOnly(final Path directory) throws IOException {
    final MavenCorroboratedSourceScenario.Prepared prepared =
        MavenCorroboratedSourceScenario.prepareReproducibleClaim(
            directory, List.of(), List.of(PARSE_ROUTINE));
    final MavenSourceCorrespondenceTestArtifacts.Archives archives =
        MavenSourceCorrespondenceTestArtifacts.write(directory, false, false);
    final MavenVulnerabilityAssessment.Result result =
        MavenCorroboratedSourceScenario.assessWithSourceClassifier(
            prepared,
            archives.originalJar(),
            new MavenSourceClassifierResolver(
                MavenSourceCorrespondenceTestArtifacts.resolver(archives.sourcesJar())),
            false);
    assertThat(result.sourceCorrespondences().getFirst())
        .isInstanceOf(SourceBuildCorrespondence.Matched.class);
  }

  private static void assertPairedRoutineDoesNotHideAnotherOwner(final Path directory)
      throws IOException {
    final MavenCorroboratedSourceScenario.Prepared prepared =
        MavenCorroboratedSourceScenario.prepareReproducibleClaim(
            directory,
            List.of(MavenSourceCorrespondenceTestArtifacts.SOURCE_ENTRY),
            List.of(PARSE_ROUTINE));
    final MavenSourceCorrespondenceTestArtifacts.Archives archives =
        MavenSourceCorrespondenceTestArtifacts.write(directory, false, true);
    final MavenVulnerabilityAssessment.Result result =
        MavenCorroboratedSourceScenario.assessWithSourceClassifier(
            prepared,
            archives.originalJar(),
            new MavenSourceClassifierResolver(
                MavenSourceCorrespondenceTestArtifacts.resolver(archives.sourcesJar())),
            true);

    assertAbstainedWithoutProof(result, "multiple possible owners or overloads");
  }

  private static void assertInventoryMismatch(
      final Path directory, final String entry, final byte[] replacement, final boolean remove)
      throws IOException {
    final MavenCorroboratedSourceScenario.Prepared prepared =
        MavenCorroboratedSourceScenario.prepareReproducibleClaim(
            directory, List.of(MavenSourceCorrespondenceTestArtifacts.SOURCE_ENTRY), List.of());
    final MavenSourceCorrespondenceTestArtifacts.Archives archives =
        MavenSourceCorrespondenceTestArtifacts.write(directory, false, false);
    if (remove) {
      MavenSourceCorrespondenceTestArtifacts.removeOriginalEntry(archives.originalJar(), entry);
    } else if (EXTRA_CLASS_ENTRY.equals(entry)) {
      MavenSourceCorrespondenceTestArtifacts.addOriginalEntry(
          archives.originalJar(), entry, replacement);
    } else {
      MavenSourceCorrespondenceTestArtifacts.replaceOriginalEntry(
          archives.originalJar(), entry, replacement);
    }
    final MavenVulnerabilityAssessment.Result result =
        MavenCorroboratedSourceScenario.assessWithSourceClassifier(
            prepared,
            archives.originalJar(),
            new MavenSourceClassifierResolver(
                MavenSourceCorrespondenceTestArtifacts.resolver(archives.sourcesJar())),
            true);

    assertAbstainedWithoutProof(result, "Reproduced class inventory differs");
  }

  private static void assertAbstainedWithoutProof(
      final MavenVulnerabilityAssessment.Result result, final String rationale) {
    assertAll(
        "unsupported or incomplete correspondence remains review-only",
        () ->
            assertThat(result.sourceCorrespondences().getFirst())
                .isInstanceOf(SourceBuildCorrespondence.Abstained.class)
                .extracting(value -> ((SourceBuildCorrespondence.Abstained) value).rationale())
                .asString()
                .contains(rationale),
        () -> assertThat(result.attestations()).isEmpty(),
        () -> assertThat(result.provenVulnerableCodeAbsent()).isEmpty(),
        () -> assertThat(result.inactiveDueToMissingPrerequisites()).isEmpty(),
        () -> assertThat(result.potentiallyConservativeCves()).isEmpty());
  }

  private static void assertRoutineAbstains(
      final Path directory, final boolean overloaded, final boolean repeated) throws IOException {
    final MavenCorroboratedSourceScenario.Prepared prepared =
        MavenCorroboratedSourceScenario.prepareReproducibleClaim(
            directory, List.of(), List.of(PARSE_ROUTINE));
    final MavenSourceCorrespondenceTestArtifacts.Archives archives =
        MavenSourceCorrespondenceTestArtifacts.write(directory, overloaded, repeated);
    final MavenVulnerabilityAssessment.Result result =
        MavenCorroboratedSourceScenario.assessWithSourceClassifier(
            prepared,
            archives.originalJar(),
            new MavenSourceClassifierResolver(
                MavenSourceCorrespondenceTestArtifacts.resolver(archives.sourcesJar())),
            false);
    assertThat(result.sourceCorrespondences().getFirst())
        .isInstanceOf(SourceBuildCorrespondence.Abstained.class)
        .extracting(value -> ((SourceBuildCorrespondence.Abstained) value).rationale())
        .asString()
        .contains("multiple possible owners or overloads");
  }
}
