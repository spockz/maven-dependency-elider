// WHY: Publishes completed per-file trim outputs before storing the cache manifest.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.CacheProducerIdentity;
import io.github.spockz.elider.plugin.JarTrimCache.CacheEntry;
import io.github.spockz.elider.plugin.JarTrimCache.CacheManifest;
import io.github.spockz.elider.plugin.TrimFingerprint.FingerprintSnapshot;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/** Publishes effective outputs and their cache metadata. */
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
      boolean failOnUnsupportedModuleInfo) {
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

  /* package */ static TrimResult publishEffectiveOutputs(final EffectivePublication publication)
      throws IOException {
    final EffectiveOutputPlan output = publication.outputPlan();
    final FingerprintSnapshot fingerprint = publication.fingerprint();
    Files.createDirectories(publication.generation());
    try (EffectiveOutputStaging staging = new EffectiveOutputStaging(publication.generation())) {
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
        JarTrimCache.storeCache(
            publication.manifest(),
            new CacheManifest(
                MavenDependencyTrimmer.CACHE_SCHEMA_VERSION,
                MavenDependencyTrimmer.CACHE_FORMAT_ID,
                publication.producer().orElseThrow(),
                publication.completeFingerprint(),
                entries));
      }
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
          List.of());
    }
  }
}
