// WHY: Keeps POM precedence and heuristic review evidence separate from structured proof.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.io.IOException;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.jar.JarFile;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Exercises structured proof isolation from other advisory evidence. */
@SuppressWarnings("PMD.AtLeastOneConstructor")
final class MavenStructuredProofEvidenceIsolationTest {
  /** Structured routine owner emitted by the shared fixture source unit. */
  private static final String OUTER = "org.example.Outer";

  /** Unrelated class named only by heuristic review evidence. */
  private static final String HEURISTIC_ONLY = "org.example.HeuristicOnly";

  /** Archive path for the heuristic-only class. */
  private static final String HEURISTIC_ONLY_ENTRY = "org/example/HeuristicOnly.class";

  /** Top-level sibling emitted by the source unit. */
  private static final String SIBLING = "org.example.Sibling";

  /** Isolates generated Maven and JAR fixtures. */
  @TempDir private Path temporaryDirectory;

  @Test
  void applicableMavenMappingOverridesRoutineProofWhenItsClassSurvives() throws IOException {
    final Path directory = temporaryDirectory.resolve("pom-override");
    final MavenCorroboratedSourceScenario.Prepared prepared =
        MavenCorroboratedSourceScenario.prepareReproducibleClaim(
            directory, List.of(), List.of("parse"));
    final MavenSourceCorrespondenceTestArtifacts.Archives archives =
        MavenSourceCorrespondenceTestArtifacts.write(directory, false, false);
    final Path successfulTrim =
        MavenSourceCorrespondenceTestArtifacts.writeEmptyTrimmedJar(
            directory.resolve("routine-control.jar"));
    final MavenVulnerabilityAssessment.Result control =
        MavenStructuredProofScenario.assess(prepared, archives, successfulTrim, true);
    final Path retainedSibling =
        MavenAdversarialSourceArchiveFixtures.copyJarKeepingEntry(
            archives.originalJar(),
            directory.resolve("pom-override-trimmed.jar"),
            "org/example/Sibling.class");

    final MavenVulnerabilityAssessment.Result overridden =
        MavenStructuredProofScenario.assess(
            prepared,
            archives,
            retainedSibling,
            true,
            ConfiguredVulnerabilityMappings.fromPom(List.of(pomMapping(SIBLING))),
            ignored -> {});

    assertAll(
        "the POM override is sensitive because the routine proof succeeds without it",
        () ->
            assertThat(control.attestations())
                .singleElement()
                .satisfies(
                    attestation ->
                        assertThat(attestation.evidenceSymbols())
                            .contains(OUTER)
                            .doesNotContain(SIBLING)),
        () -> assertThat(overridden.attestations()).isEmpty(),
        () -> assertThat(overridden.provenVulnerableCodeAbsent()).isEmpty(),
        () -> assertThat(overridden.inactiveDueToMissingPrerequisites()).isEmpty());
  }

  @Test
  void heuristicClassesStayOutsideStructuredProof() throws IOException {
    final Path directory = temporaryDirectory.resolve("heuristic-isolation");
    final MavenCorroboratedSourceScenario.Prepared prepared = preparedWithHeuristic(directory);
    final MavenSourceCorrespondenceTestArtifacts.Archives archives =
        MavenSourceCorrespondenceTestArtifacts.write(directory, false, false, false, true);
    final Path trimmed =
        MavenSourceCorrespondenceTestArtifacts.writeEmptyTrimmedJar(
            directory.resolve("trimmed.jar"));

    final MavenVulnerabilityAssessment.Result result =
        MavenStructuredProofScenario.assess(prepared, archives, trimmed, true);

    assertAll(
        "only fresh structured reproduction classes are included in proof",
        () ->
            assertThat(result.attestations())
                .singleElement()
                .satisfies(
                    attestation ->
                        assertThat(attestation.evidenceSymbols())
                            .contains(OUTER, SIBLING)
                            .doesNotContain(HEURISTIC_ONLY)),
        () -> assertHeuristicRowContains(result, HEURISTIC_ONLY));
  }

  @Test
  void heuristicClassCannotCompensateForSurvivingStructuredClass() throws IOException {
    final Path directory = temporaryDirectory.resolve("heuristic-and-surviving-structured");
    final MavenCorroboratedSourceScenario.Prepared prepared = preparedWithHeuristic(directory);
    final MavenSourceCorrespondenceTestArtifacts.Archives archives =
        MavenSourceCorrespondenceTestArtifacts.write(directory, false, false, false, true);
    final Path trimmed =
        MavenSourceCorrespondenceTestArtifacts.copyJarWithoutEntry(
            archives.originalJar(), directory.resolve("trimmed.jar"), HEURISTIC_ONLY_ENTRY);

    final MavenVulnerabilityAssessment.Result result =
        MavenStructuredProofScenario.assess(prepared, archives, trimmed, true);

    assertAll(
        "a heuristic class does not replace the structured omitted-class requirement",
        () ->
            assertThat(archiveContains(archives.originalJar(), HEURISTIC_ONLY_ENTRY))
                .as("the heuristic candidate must exist in the original archive")
                .isTrue(),
        () ->
            assertThat(archiveContains(trimmed, HEURISTIC_ONLY_ENTRY))
                .as("the negative case removes only the heuristic class")
                .isFalse(),
        () -> assertCompleteClassInventoryRetained(archives.originalJar(), trimmed),
        () -> assertThat(result.attestations()).isEmpty(),
        () -> assertThat(result.provenVulnerableCodeAbsent()).isEmpty(),
        () -> assertHeuristicRowContains(result, HEURISTIC_ONLY));
  }

  private static boolean archiveContains(final Path archive, final String entry)
      throws IOException {
    try (JarFile jar = new JarFile(archive.toFile())) {
      return jar.getEntry(entry) != null;
    }
  }

  private static void assertCompleteClassInventoryRetained(final Path original, final Path trimmed)
      throws IOException {
    final Set<String> expected = new HashSet<>(classEntries(original));
    expected.remove(HEURISTIC_ONLY_ENTRY);
    assertThat(classEntries(trimmed))
        .as("the trimmed archive keeps every original class except the heuristic candidate")
        .containsExactlyInAnyOrderElementsOf(expected);
  }

  private static Set<String> classEntries(final Path archive) throws IOException {
    try (JarFile jar = new JarFile(archive.toFile())) {
      return jar.stream()
          .map(java.util.jar.JarEntry::getName)
          .filter(name -> name.endsWith(".class"))
          .collect(java.util.stream.Collectors.toUnmodifiableSet());
    }
  }

  private MavenCorroboratedSourceScenario.Prepared preparedWithHeuristic(final Path directory)
      throws IOException {
    final MavenCorroboratedSourceScenario.Prepared prepared =
        MavenCorroboratedSourceScenario.prepareReproducibleClaim(
            directory, List.of(MavenSourceCorrespondenceTestArtifacts.SOURCE_ENTRY), List.of());
    MavenStructuredProofCacheFixtures.addHeuristicEvidence(prepared);
    return prepared;
  }

  private static void assertHeuristicRowContains(
      final MavenVulnerabilityAssessment.Result result, final String className) {
    assertThat(result.heuristicAdvisoryFindings())
        .anySatisfy(finding -> assertThat(finding.candidateClasses()).contains(className));
  }

  private static VulnerabilityMappingConfig pomMapping(final String className) {
    final VulnerabilityMappingConfig mapping = new VulnerabilityMappingConfig();
    mapping.setCveId(MavenCorroboratedSourceArchiveFixtures.CVE_ID);
    mapping.setGroupId(MavenCorroboratedSourceArchiveFixtures.GROUP_ID);
    mapping.setArtifactId(MavenCorroboratedSourceArchiveFixtures.ARTIFACT_ID);
    mapping.setVersion(MavenCorroboratedSourceArchiveFixtures.VERSION);
    mapping.setVersionRangeSpec("[1.0,2.0)");
    mapping.setVulnerableClasses(List.of(className));
    return mapping;
  }
}
