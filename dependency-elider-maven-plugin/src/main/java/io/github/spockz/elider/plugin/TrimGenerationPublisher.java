/* WHY: Publishes complete archive and manifest generations together so
 * rollback cannot expose partial trim outputs. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.CacheProducerIdentity;
import io.github.spockz.elider.plugin.JarTrimCache.CacheEntry;
import io.github.spockz.elider.plugin.JarTrimCache.CacheManifest;
import io.github.spockz.elider.plugin.TrimFingerprint.FingerprintSnapshot;
import io.github.spockz.elider.trimmer.ArtifactDigests;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/** Publishes complete output and manifest generations with rollback. */
final class TrimGenerationPublisher {
  private TrimGenerationPublisher() {}

  /* package */ record EffectiveOutputPlan(
      ElisionAnalysisModel.PreparedAnalysis prepared,
      TrimAnalysisResult analysis,
      Map<TrimArtifactRootKey, Set<String>> roots,
      Set<ArtifactCoordinate> unchangedCoordinates,
      Set<ArtifactCoordinate> retainedCoordinates,
      String inventoryFingerprint,
      String directInventoryFingerprint,
      String operationFingerprint,
      String productionOutputFingerprint,
      Set<String> bytecodeReferences,
      List<String> explicitRoots,
      List<String> explicitPassThroughCoordinates,
      boolean sourceRootsComplete,
      boolean productionClassesComplete,
      String mrjarStrategy,
      boolean failOnUnsupportedModuleInfo,
      TrimOutputGenerationPublisher.MoveOperation move) {
    EffectiveOutputPlan {
      roots = TrimRootPlanner.immutableRootMap(roots);
      unchangedCoordinates = Set.copyOf(unchangedCoordinates);
      retainedCoordinates = Set.copyOf(retainedCoordinates);
      bytecodeReferences = Set.copyOf(bytecodeReferences);
      explicitRoots = List.copyOf(explicitRoots);
      explicitPassThroughCoordinates = List.copyOf(explicitPassThroughCoordinates);
    }
  }

  /* package */ record EffectivePublication(
      EffectiveOutputPlan outputPlan,
      List<TrimCandidate> work,
      FingerprintSnapshot fingerprint,
      Path manifest,
      String completeFingerprint,
      Path generation,
      Optional<CacheProducerIdentity> producer,
      List<ArtifactCoordinate> multiRelease,
      List<ArtifactCoordinate> moduleInfo,
      List<ArtifactCoordinate> configured,
      int analysisRuns) {
    EffectivePublication {
      java.util.Objects.requireNonNull(producer, "producer");
      java.util.Objects.requireNonNull(generation, "generation");
      work = List.copyOf(work);
      multiRelease = List.copyOf(multiRelease);
      moduleInfo = List.copyOf(moduleInfo);
      configured = List.copyOf(configured);
    }
  }

  /* package */ record PreparedEffectiveOutputs(
      Map<TrimCandidate, CacheEntry> entries, List<ArtifactTrimRecord> records) {}

  /* package */ @SuppressWarnings("PMD.AvoidCatchingGenericException")
  static TrimResult publishEffectiveOutputs(final EffectivePublication publication)
      throws IOException {
    final EffectiveOutputPlan output = publication.outputPlan();
    final FingerprintSnapshot fingerprint = publication.fingerprint();
    final PreparedGeneration generation = prepareGeneration(publication);
    final EffectiveOutputStaging staging = generation.staging();
    TrimOutputGenerationCommitHandle generationCommit = null;
    try {
      try (staging) {
        final PreparedEffectiveOutputs prepared =
            staging.prepareOutputs(
                publication.work(),
                fingerprint.inputDigests(),
                output,
                output.prepared().options().trim().workers());
        final List<CacheEntry> entries =
            JarTrimCache.orderedEntries(
                publication.work(), prepared.entries(), "Missing effective trim cache entry: ");
        if (publication.producer().isPresent()) {
          JarTrimCache.writeManifest(
              generation.stagedManifest(),
              new CacheManifest(
                  MavenDependencyTrimmer.CACHE_SCHEMA_VERSION,
                  MavenDependencyTrimmer.CACHE_FORMAT_ID,
                  publication.producer().orElseThrow(),
                  publication.completeFingerprint(),
                  entries));
        }
        verifyEffectiveInputs(output, fingerprint);
        generationCommit =
            publication.producer().isPresent()
                ? TrimOutputGenerationPublisher.publish(
                    generation.stagedGeneration(),
                    generation.generation(),
                    generation.stagedManifest(),
                    publication.manifest(),
                    output.move())
                : TrimOutputGenerationPublisher.publishEphemeral(
                    generation.stagedGeneration(), generation.generation(), output.move());
        return new TrimResult(
            prepared.records(),
            publication.multiRelease(),
            publication.moduleInfo(),
            publication.configured(),
            0,
            0L,
            publication.analysisRuns(),
            new TrimExecutionEnvironment(
                output.analysis().targetRelease(), output.analysis().runtimeRelease()),
            generationCommit);
      }
    } catch (final IOException | RuntimeException failure) {
      if (generationCommit != null) {
        try {
          generationCommit.close();
        } catch (final IOException cleanupFailure) {
          failure.addSuppressed(cleanupFailure);
        }
      }
      throw failure;
    }
  }

  private record PreparedGeneration(
      EffectiveOutputStaging staging,
      Path stagedGeneration,
      Path stagedManifest,
      Path generation) {}

  private static PreparedGeneration prepareGeneration(final EffectivePublication publication)
      throws IOException {
    final Path manifest = publication.manifest();
    final Path generation = publication.generation();
    final Path stagedGeneration;
    final Path stagedManifest;
    if (publication.producer().isPresent()) {
      final Path generationParent = generation.getParent();
      if (generationParent == null) {
        throw new IOException("Trim generation has no parent directory: " + generation);
      }
      Files.createDirectories(generationParent);
      final Path manifestParent = manifest.getParent();
      if (manifestParent == null) {
        throw new IOException("Trim cache manifest has no parent directory: " + manifest);
      }
      Files.createDirectories(manifestParent);
      final Path stagingRoot = manifestParent.resolve(".staging");
      Files.createDirectories(stagingRoot);
      stagedGeneration = Files.createTempDirectory(stagingRoot, "trim-");
      stagedManifest = Files.createTempFile(manifestParent, ".trim-cache-stage-", ".json.tmp");
    } else {
      final Path stagingRoot = Files.createTempDirectory("dependency-elider-trim-stage-");
      stagingRoot.toFile().deleteOnExit();
      stagedGeneration = Files.createTempDirectory(stagingRoot, "trim-");
      stagedGeneration.toFile().deleteOnExit();
      stagedManifest = null;
    }
    return new PreparedGeneration(
        new EffectiveOutputStaging(stagedGeneration, stagedManifest),
        stagedGeneration,
        stagedManifest,
        generation);
  }

  /* package */ static void deleteTree(final Path root) throws IOException {
    if (!Files.exists(root)) {
      return;
    }
    try (java.util.stream.Stream<Path> paths = Files.walk(root)) {
      for (final Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
        Files.delete(path);
      }
    }
  }

  /* package */ static void verifyEffectiveInputs(
      final EffectiveOutputPlan plan, final FingerprintSnapshot fingerprint) throws IOException {
    MavenArtifactInventory.verifyPreparedInventory(plan.prepared());
    for (final Map.Entry<Path, ArtifactDigests> entry : fingerprint.inputDigests().entrySet()) {
      if (!entry.getValue().sha256().equals(ArtifactDigests.read(entry.getKey()).sha256())) {
        throw new IOException(
            "Artifact input changed during effective output trim: " + entry.getKey());
      }
    }
    final ElisionAnalysisModel.PreparedAnalysis prepared = plan.prepared();
    if (prepared.bytecodeScan().isPresent()
        && !plan.productionOutputFingerprint()
            .equals(
                ProductionOutputFingerprint.fingerprint(
                    prepared.bytecodeScan().orElseThrow().scope()))) {
      throw new IOException("Production output changed during effective output trim");
    }
  }
}
