// WHY: Verifies saved catalog adoption replays after its repository bytes are gone.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.apache.maven.plugin.MojoFailureException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Checks replay from saved catalog adoption evidence. */
@SuppressWarnings("PMD.AtLeastOneConstructor")
final class ReportMojoCatalogReplayTest {
  /** WHY: The saved snapshot and deleted source share this isolated test directory. */
  @TempDir private Path temporaryDirectory;

  @Test
  void replaysCatalogAdoptionAfterTheRepositoryArtifactIsGone()
      throws IOException, ReflectiveOperationException, MojoFailureException {
    final Path repositoryArtifact = temporaryDirectory.resolve("repository/catalog.jar");
    Files.createDirectories(repositoryArtifact.getParent());
    Files.writeString(repositoryArtifact, "catalog bytes are no longer needed for replay");
    final MavenVulnerabilityMappingCatalogResolver.Adoption adoption =
        new MavenVulnerabilityMappingCatalogResolver.Adoption(
            new MavenVulnerabilityMappingCatalogResolver.Coordinate(
                "org.example", "catalog", "1.2.3", "jar", ""),
            "b".repeat(64),
            "saved-catalog",
            1,
            List.of(),
            List.of(),
            List.of(),
            List.of(),
            "explicit-maven-catalog-coordinate",
            List.of());
    final Path snapshotFile = temporaryDirectory.resolve("report.json");
    MavenElisionReportWriter.write(
        snapshotFile,
        ReportMojoTestSupport.snapshot(temporaryDirectory, false)
            .withCatalogAdoptions(List.of(adoption)));
    Files.delete(repositoryArtifact);
    final List<String> messages = new ArrayList<>();

    ReportMojoTestSupport.mojo(
            snapshotFile, ReportMojoTestSupport.project(temporaryDirectory), messages)
        .execute();
    final boolean repositoryArtifactIsGone = Files.notExists(repositoryArtifact);

    assertAll(
        "report replay uses saved adoption evidence after the source artifact disappears",
        () ->
            assertTrue(
                repositoryArtifactIsGone,
                "report replay must not need the deleted catalog artifact"),
        () -> assertThat(messages).anyMatch(line -> line.contains("saved-catalog")),
        () -> assertThat(messages).anyMatch(line -> line.contains("org.example:catalog:1.2.3")));
  }
}
