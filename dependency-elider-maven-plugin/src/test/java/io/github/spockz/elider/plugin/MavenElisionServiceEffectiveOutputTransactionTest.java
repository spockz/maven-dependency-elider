// WHY: Exercises output-generation rollback, cache repair, and source-digest rejection.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.spockz.elider.trimmer.ArtifactDigests;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

/** Verifies the cache manifest is a commit marker for complete output generations. */
@SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
final class MavenElisionServiceEffectiveOutputTransactionTest
    extends MavenElisionServiceEffectiveOutputSupport {
  /** Trace root used to generate deterministic output cache entries. */
  private static final String ENTRY_TRACE = "closure/a/Entry";

  /** Creates the test group for output publication failure cases. */
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  MavenElisionServiceEffectiveOutputTransactionTest() {
    super();
  }

  @Test
  void samePathInputMutationFailsBeforePublishingAnyGeneration() throws Exception {
    final Fixture fixture = fixture(false);
    final ServiceOperation operation =
        operation(fixture, trace(temporaryDirectory, ENTRY_TRACE), null);
    final Path originalInput = fixture.snapshot("a").filePath();
    Files.writeString(
        originalInput, "changed at the same path", java.nio.file.StandardOpenOption.APPEND);

    assertThatThrownBy(() -> trimEffective(operation))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Live Maven resolved artifact view changed");
    assertThat(EffectiveOutputCacheTestFiles.cacheManifest(fixture.mavenProject())).doesNotExist();
    assertThat(EffectiveOutputCacheTestFiles.generationDirectory(fixture.mavenProject()))
        .doesNotExist();
  }

  @Test
  void manifestSwitchFailureRestoresPriorGenerationAndRetryCommitsNewRoots() throws Exception {
    final Fixture fixture = fixture(false);
    final MavenElisionService service = new MavenElisionService();
    final ServiceOperation original =
        operation(fixture, trace(temporaryDirectory.resolve("entry"), ENTRY_TRACE), null);
    final ArtifactTrimRecord originalRecord = outputRecord(trimEffective(original), fixture);
    final Path manifest = EffectiveOutputCacheTestFiles.cacheManifest(fixture.mavenProject());
    final byte[] oldManifest = Files.readAllBytes(manifest);
    final String oldOutputDigest = ArtifactDigests.read(originalRecord.trimmedPath()).sha256();

    final ServiceOperation changed =
        operation(fixture, trace(temporaryDirectory.resolve("extra"), "closure/a/Extra"), null);
    final MavenElisionService.EffectiveAnalysis effective =
        service.finishAnalysis(changed.prepared());
    assertThatThrownBy(
            () ->
                MavenDependencyTrimmer.trimEffectiveOutputs(
                    effective,
                    (source, target, replace) -> {
                      if (manifest
                          .toAbsolutePath()
                          .normalize()
                          .equals(target.toAbsolutePath().normalize())) {
                        throw new IOException("injected manifest switch failure");
                      }
                      TrimOutputGenerationFileOps.atomicMove(source, target, replace);
                    }))
        .isInstanceOf(IOException.class)
        .hasMessage("injected manifest switch failure");

    assertThat(Files.readAllBytes(manifest)).isEqualTo(oldManifest);
    assertThat(ArtifactDigests.read(originalRecord.trimmedPath()).sha256())
        .isEqualTo(oldOutputDigest);
    assertThat(EffectiveOutputCacheTestFiles.generationCount(fixture.mavenProject())).isEqualTo(1);

    final MavenDependencyTrimmer.TrimResult retry = trimEffective(changed);
    final ArtifactTrimRecord retriedRecord = outputRecord(retry, fixture);
    assertThat(retry.cacheHits()).isZero();
    assertThat(retriedRecord.trimmedPath()).isNotEqualTo(originalRecord.trimmedPath());
    assertThat(ArtifactDigests.read(retriedRecord.trimmedPath()).sha256())
        .isEqualTo(retriedRecord.trimmedSha256());
  }

  @Test
  void manifestBackupFailureRestoresTheReferencedGeneration() throws Exception {
    final Fixture fixture = fixture(false);
    final ServiceOperation operation =
        operation(fixture, trace(temporaryDirectory, ENTRY_TRACE), null);
    final ArtifactTrimRecord original = outputRecord(trimEffective(operation), fixture);
    final Path manifest =
        EffectiveOutputCacheTestFiles.cacheManifest(fixture.mavenProject())
            .toAbsolutePath()
            .normalize();
    final byte[] originalManifest = Files.readAllBytes(manifest);
    Files.writeString(original.trimmedPath(), "damaged prior generation before backup failure");
    final byte[] originalOutput = Files.readAllBytes(original.trimmedPath());
    final MavenElisionService.EffectiveAnalysis effective =
        operation.service().finishAnalysis(operation.prepared());

    assertThatThrownBy(
            () ->
                MavenDependencyTrimmer.trimEffectiveOutputs(
                    effective,
                    (source, target, replace) -> {
                      if (manifest.equals(source.toAbsolutePath().normalize())
                          && target.getFileName().toString().contains(".backup-")) {
                        throw new IOException("injected manifest backup failure");
                      }
                      TrimOutputGenerationFileOps.atomicMove(source, target, replace);
                    }))
        .isInstanceOf(IOException.class)
        .hasMessage("injected manifest backup failure");

    assertThat(Files.readAllBytes(manifest)).isEqualTo(originalManifest);
    assertThat(Files.readAllBytes(original.trimmedPath())).isEqualTo(originalOutput);
    assertThat(EffectiveOutputCacheTestFiles.generationCount(fixture.mavenProject())).isEqualTo(1);
    final ArtifactTrimRecord retry = outputRecord(trimEffective(operation), fixture);
    assertThat(ArtifactDigests.read(retry.trimmedPath()).sha256()).isEqualTo(retry.trimmedSha256());
  }

  @Test
  void manifestBackupMoveThatCompletesBeforeThrowRestoresGenerationAndManifest() throws Exception {
    final Fixture fixture = fixture(false);
    final ServiceOperation operation =
        operation(fixture, trace(temporaryDirectory, ENTRY_TRACE), null);
    final ArtifactTrimRecord original = outputRecord(trimEffective(operation), fixture);
    final Path manifest =
        EffectiveOutputCacheTestFiles.cacheManifest(fixture.mavenProject())
            .toAbsolutePath()
            .normalize();
    final Path generation = original.trimmedPath().getParent().getParent();
    final byte[] originalManifest = Files.readAllBytes(manifest);
    Files.writeString(original.trimmedPath(), "damaged prior generation before completed backup");
    final byte[] originalOutput = Files.readAllBytes(original.trimmedPath());
    final MavenElisionService.EffectiveAnalysis effective =
        operation.service().finishAnalysis(operation.prepared());

    assertThatThrownBy(
            () ->
                MavenDependencyTrimmer.trimEffectiveOutputs(
                    effective,
                    (source, target, replace) -> {
                      TrimOutputGenerationFileOps.atomicMove(source, target, replace);
                      if (manifest.equals(source.toAbsolutePath().normalize())) {
                        throw new IOException("injected completed manifest backup failure");
                      }
                    }))
        .isInstanceOf(IOException.class)
        .hasMessage("injected completed manifest backup failure");

    assertThat(Files.readAllBytes(manifest)).isEqualTo(originalManifest);
    assertThat(Files.readAllBytes(original.trimmedPath())).isEqualTo(originalOutput);
    assertThat(generation).isDirectory();
    assertThat(EffectiveOutputCacheTestFiles.generationCount(fixture.mavenProject())).isEqualTo(1);
    final ArtifactTrimRecord repaired = outputRecord(trimEffective(operation), fixture);
    assertThat(ArtifactDigests.read(repaired.trimmedPath()).sha256())
        .isEqualTo(repaired.trimmedSha256());
  }

  @Test
  void sameGenerationSwitchFailureRestoresExistingBytesAndRetryRepairsThem() throws Exception {
    final Fixture fixture = fixture(false);
    final ServiceOperation operation =
        operation(fixture, trace(temporaryDirectory, ENTRY_TRACE), null);
    final ArtifactTrimRecord original = outputRecord(trimEffective(operation), fixture);
    final Path manifest = EffectiveOutputCacheTestFiles.cacheManifest(fixture.mavenProject());
    final byte[] originalManifest = Files.readAllBytes(manifest);

    Files.writeString(original.trimmedPath(), "damaged prior generation");
    final byte[] damagedBytes = Files.readAllBytes(original.trimmedPath());
    final String damagedDigest = ArtifactDigests.read(original.trimmedPath()).sha256();
    final MavenElisionService.EffectiveAnalysis effective =
        operation.service().finishAnalysis(operation.prepared());
    assertThatThrownBy(
            () ->
                MavenDependencyTrimmer.trimEffectiveOutputs(
                    effective,
                    (source, target, replace) -> {
                      if (manifest
                          .toAbsolutePath()
                          .normalize()
                          .equals(target.toAbsolutePath().normalize())) {
                        throw new IOException("injected same-generation manifest failure");
                      }
                      TrimOutputGenerationFileOps.atomicMove(source, target, replace);
                    }))
        .isInstanceOf(IOException.class)
        .hasMessage("injected same-generation manifest failure");

    assertThat(Files.readAllBytes(manifest)).isEqualTo(originalManifest);
    assertThat(Files.readAllBytes(original.trimmedPath())).isEqualTo(damagedBytes);

    final ArtifactTrimRecord repaired = outputRecord(trimEffective(operation), fixture);
    assertThat(ArtifactDigests.read(repaired.trimmedPath()).sha256())
        .isEqualTo(repaired.trimmedSha256())
        .isNotEqualTo(damagedDigest);
  }

  @Test
  void manifestMoveThatCompletesBeforeThrowIsRecognizedAsCommitted() throws Exception {
    final Fixture fixture = fixture(false);
    final ServiceOperation operation =
        operation(fixture, trace(temporaryDirectory, ENTRY_TRACE), null);
    final ArtifactTrimRecord original = outputRecord(trimEffective(operation), fixture);
    Files.writeString(original.trimmedPath(), "damaged prior generation");
    final String damagedDigest = ArtifactDigests.read(original.trimmedPath()).sha256();
    final Path manifest =
        EffectiveOutputCacheTestFiles.cacheManifest(fixture.mavenProject())
            .toAbsolutePath()
            .normalize();
    final MavenElisionService.EffectiveAnalysis effective =
        operation.service().finishAnalysis(operation.prepared());

    final MavenDependencyTrimmer.TrimResult committed =
        MavenDependencyTrimmer.trimEffectiveOutputs(
            effective,
            (source, target, replace) -> {
              TrimOutputGenerationFileOps.atomicMove(source, target, replace);
              if (manifest.equals(target.toAbsolutePath().normalize())) {
                throw new IOException("injected post-move report failure");
              }
            });

    final ArtifactTrimRecord repaired = outputRecord(committed, fixture);
    assertThat(committed.cacheHits()).isZero();
    assertThat(ArtifactDigests.read(repaired.trimmedPath()).sha256())
        .isEqualTo(repaired.trimmedSha256());
    assertThat(ArtifactDigests.read(repaired.trimmedPath()).sha256()).isNotEqualTo(damagedDigest);
    assertThat(EffectiveOutputCacheTestFiles.generationCount(fixture.mavenProject())).isEqualTo(1);
  }

  @Test
  void compilerReleaseChangeAfterAnalysisFailsBeforeOutputPublication() throws Exception {
    final Fixture fixture = fixture(false);
    final ServiceOperation operation =
        operation(fixture, trace(temporaryDirectory, ENTRY_TRACE), null);
    final MavenElisionService.EffectiveAnalysis effective =
        operation.service().finishAnalysis(operation.prepared());
    fixture.mavenProject().getProperties().setProperty("maven.compiler.release", "17");

    assertThatThrownBy(() -> MavenDependencyTrimmer.trimEffectiveOutputs(effective))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("context changed after effective analysis");
    assertThat(EffectiveOutputCacheTestFiles.cacheManifest(fixture.mavenProject())).doesNotExist();
    assertThat(EffectiveOutputCacheTestFiles.generationDirectory(fixture.mavenProject()))
        .doesNotExist();
  }

  private static ArtifactTrimRecord outputRecord(
      final MavenDependencyTrimmer.TrimResult result, final Fixture fixture) {
    return EffectiveOutputCacheTestFiles.record(result.records(), fixture.coordinate("a"));
  }
}
