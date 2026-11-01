// WHY: Verifies uncommitted ephemeral trim output restores prior project state.

package io.github.spockz.elider.plugin;

import static org.junit.jupiter.api.Assertions.assertEquals;

import io.github.spockz.elider.trimmer.ArtifactDigests;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.Objects;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** Verifies aborting ephemeral output preserves prior project state. */
final class MavenElisionServiceEphemeralRollbackTest
    extends MavenElisionServiceEffectiveOutputSupport {
  /** Creates shared fixture support for rollback coverage. */
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  MavenElisionServiceEphemeralRollbackTest() {
    super();
  }

  @Test
  void abortedProductionStagingRemovesEphemeralArchiveAndRestoresProjectState() throws Exception {
    final Fixture fixture = fixture(false);
    final ServiceOperation operation =
        operationWithProducer(
            fixture,
            trace(temporaryDirectory, "closure/a/Entry"),
            MavenPluginDescriptorFixtures.unavailableProducerResolution());
    final ElisionAnalysisModel.EffectiveAnalysis effective =
        operation.service().finishAnalysis(operation.prepared());
    final Path manifest = EffectiveOutputCacheTestFiles.cacheManifest(fixture.mavenProject());
    final Path generationRoot =
        EffectiveOutputCacheTestFiles.generationDirectory(fixture.mavenProject());
    final Path projectGeneration = generationRoot.resolve("pre-existing-generation");
    final Path generationMarker = projectGeneration.resolve("marker.bin");
    final byte[] priorManifestBytes = "prior-manifest".getBytes(StandardCharsets.UTF_8);
    final byte[] priorGenerationBytes = "prior-generation".getBytes(StandardCharsets.UTF_8);
    Files.createDirectories(projectGeneration);
    Files.write(generationMarker, priorGenerationBytes);
    Files.createDirectories(manifest.getParent());
    Files.write(manifest, priorManifestBytes);

    final TrimResult result = MavenDependencyTrimmer.stageEffectiveOutputs(effective);
    final ArtifactTrimRecord record =
        EffectiveOutputCacheTestFiles.record(result.records(), fixture.coordinate("a"));
    final Path ephemeralArchive = record.trimmedPath();
    final TrimOutputGenerationCommitHandle handle =
        Objects.requireNonNull(
            result.generationCommit(), "production staging must return a rollback handle");
    final EphemeralState published;
    try (handle) {
      published =
          state(fixture, ephemeralArchive, manifest, generationMarker, record.trimmedSha256());
    }
    final EphemeralState rolledBack =
        state(fixture, ephemeralArchive, manifest, generationMarker, record.trimmedSha256());
    final String manifestDigest = HexFormat.of().formatHex(priorManifestBytes);
    final String generationDigest = HexFormat.of().formatHex(priorGenerationBytes);
    final EphemeralTransactionState expected =
        new EphemeralTransactionState(
            new EphemeralState(
                true,
                record.trimmedSha256(),
                Set.of("closure.a.Entry"),
                manifestDigest,
                generationDigest,
                1),
            new EphemeralState(false, null, Set.of(), manifestDigest, generationDigest, 1));
    final EphemeralTransactionState actual = new EphemeralTransactionState(published, rolledBack);
    assertEquals(
        expected,
        actual,
        "closing the production no-identity result removes its archive "
            + "and preserves project state");
  }

  private static EphemeralState state(
      final Fixture fixture,
      final Path archive,
      final Path manifest,
      final Path generationMarker,
      final String expectedArchiveDigest)
      throws IOException {
    final boolean archiveExists = Files.isRegularFile(archive);
    final String archiveDigest = archiveExists ? ArtifactDigests.read(archive).sha256() : null;
    final Set<String> archiveClasses = archiveExists ? TrimPaths.classNames(archive) : Set.of();
    if (archiveExists && !expectedArchiveDigest.equals(archiveDigest)) {
      throw new IOException("Ephemeral archive digest differs from its trim record");
    }
    return new EphemeralState(
        archiveExists,
        archiveDigest,
        archiveClasses,
        HexFormat.of().formatHex(Files.readAllBytes(manifest)),
        HexFormat.of().formatHex(Files.readAllBytes(generationMarker)),
        EffectiveOutputCacheTestFiles.generationCount(fixture.mavenProject()));
  }

  private record EphemeralTransactionState(EphemeralState published, EphemeralState rolledBack) {}

  private record EphemeralState(
      boolean archiveExists,
      String archiveDigest,
      Set<String> archiveClasses,
      String manifestDigest,
      String generationDigest,
      long generationCount) {}
}
