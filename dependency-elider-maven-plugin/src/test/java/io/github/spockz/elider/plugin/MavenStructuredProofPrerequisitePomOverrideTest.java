// WHY: Protects whole-CVE POM precedence when a configured row has no class assertion.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Checks prerequisite-only configured rows suppress cached structured proof. */
@SuppressWarnings("PMD.AtLeastOneConstructor") // JUnit supplies the test instance lifecycle.
final class MavenStructuredProofPrerequisitePomOverrideTest {
  /** Isolated workspace for the positive proof control and configured override. */
  @TempDir private Path temporaryDirectory;

  @Test
  void prerequisiteOnlyPomRowOverridesStructuredProofForTheWholeCve() throws IOException {
    final Path directory = temporaryDirectory.resolve("prerequisite-only-pom-override");
    final MavenCorroboratedSourceScenario.Prepared prepared =
        MavenCorroboratedSourceScenario.prepareReproducibleClaim(
            directory, List.of(), List.of("parse"));
    final MavenSourceCorrespondenceTestArtifacts.Archives archives =
        MavenSourceCorrespondenceTestArtifacts.write(directory, false, false);
    final Path trimmed =
        MavenSourceCorrespondenceTestArtifacts.writeEmptyTrimmedJar(
            directory.resolve("routine-control.jar"));
    final MavenVulnerabilityAssessment.Result control =
        MavenStructuredProofScenario.assess(prepared, archives, trimmed, true);
    final MavenVulnerabilityAssessment.Result overridden =
        MavenStructuredProofScenario.assess(
            prepared,
            archives,
            trimmed,
            true,
            ConfiguredVulnerabilityMappings.fromPom(List.of(prerequisiteOnlyPomMapping())),
            ignored -> {});

    assertAll(
        "a prerequisite-only POM row overrides the otherwise successful structured proof",
        () -> assertThat(control.attestations()).hasSize(1),
        () -> assertThat(control.provenVulnerableCodeAbsent()).hasSize(1),
        () -> assertThat(overridden.attestations()).isEmpty(),
        () -> assertThat(overridden.provenVulnerableCodeAbsent()).isEmpty(),
        () -> assertThat(overridden.inactiveDueToMissingPrerequisites()).isEmpty());
  }

  private static VulnerabilityMappingConfig prerequisiteOnlyPomMapping() {
    final VulnerabilityMappingConfig mapping = new VulnerabilityMappingConfig();
    mapping.setCveId(MavenCorroboratedSourceArchiveFixtures.CVE_ID);
    mapping.setGroupId(MavenCorroboratedSourceArchiveFixtures.GROUP_ID);
    mapping.setArtifactId(MavenCorroboratedSourceArchiveFixtures.ARTIFACT_ID);
    mapping.setVersion(MavenCorroboratedSourceArchiveFixtures.VERSION);
    mapping.setVersionRangeSpec("[1.0,2.0)");
    mapping.setRequiresDependency("org.example:missing-prerequisite");
    return mapping;
  }
}
