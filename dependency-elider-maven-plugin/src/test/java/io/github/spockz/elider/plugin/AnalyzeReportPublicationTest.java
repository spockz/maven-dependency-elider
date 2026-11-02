// WHY: Proves a failed Analyze assessment leaves the previous class-usage report untouched.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.apache.maven.plugin.MojoFailureException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Checks failure preservation. JUnit constructs the test. */
@SuppressWarnings("PMD.AtLeastOneConstructor")
final class AnalyzeReportPublicationTest {
  /** Isolates the old report and the failing Analyze run. */
  @TempDir private Path temporaryDirectory;

  @Test
  void assessmentFailurePreservesExistingReport() throws Exception {
    final AnalyzeMojoTestArtifactSupport.Fixture fixture =
        AnalyzeMojoTestArtifactSupport.fixture(temporaryDirectory, "used/Sample\n");
    final Path report = temporaryDirectory.resolve("fixture-report.json");
    Files.writeString(report, "previous complete report");
    final VulnerabilityMappingConfig invalidMapping = new VulnerabilityMappingConfig();
    invalidMapping.setCveId("CVE-2026-19001");
    invalidMapping.setGroupId("org.example");
    invalidMapping.setArtifactId("used");
    invalidMapping.setVersion("1.0");
    invalidMapping.setConfidenceLevel("UNKNOWN");
    AnalyzeMojoTestFieldSupport.set(
        fixture.mojo(), "vulnerabilityMappings", List.of(invalidMapping));

    assertAll(
        "assessment validation completes before a report can replace the prior version",
        () ->
            assertThatThrownBy(fixture.mojo()::execute)
                .isInstanceOf(MojoFailureException.class)
                .hasMessageContaining("Dependency analysis failed closed"),
        () -> assertThat(report).hasContent("previous complete report"));
  }
}
