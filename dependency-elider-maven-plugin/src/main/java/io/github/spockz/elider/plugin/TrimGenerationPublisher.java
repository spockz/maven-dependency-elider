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
      int analysisRuns,
      Map<Path, io.github.spockz.elider.trimmer.MultiReleaseArchivePlan.SourceData>
          multiReleaseSources) {
    EffectivePublication {
      java.util.Objects.requireNonNull(producer, "producer");
      java.util.Objects.requireNonNull(generation, "generation");
      work = List.copyOf(work);
      multiRelease = List.copyOf(multiRelease);
      moduleInfo = List.copyOf(moduleInfo);
      configured = List.copyOf(configured);
      multiReleaseSources = Map.copyOf(multiReleaseSources);
    }

    /* package */
    @SuppressWarnings("PMD.ExcessiveParameterList")
    EffectivePublication(
        final EffectiveOutputPlan outputPlan,
        final List<TrimCandidate> work,
        final FingerprintSnapshot fingerprint,
        final Path manifest,
        final String completeFingerprint,
        final Path generation,
        final Optional<CacheProducerIdentity> producer,
        final List<ArtifactCoordinate> multiRelease,
        final List<ArtifactCoordinate> moduleInfo,
        final List<ArtifactCoordinate> configured,
        final int analysisRuns) {
      this(
          outputPlan,
          work,
          fingerprint,
          manifest,
          completeFingerprint,
          generation,
          producer,
          multiRelease,
          moduleInfo,
          configured,
          analysisRuns,
          Map.of());
    }
  }

  /* package */ record PreparedEffectiveOutputs(
      Map<TrimCandidate, CacheEntry> entries, List<ArtifactTrimRecord> records) {}

  /* package */ record StagedArchive(Path inspectedPath, Path outputPath) {}

  /** Policy check shared by staged and cached effective archive paths. */
  @FunctionalInterface
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  /* package */ interface OutputCheck {
    /** Checks archive bytes before publication. */
    void check(Map<ArtifactCoordinate, StagedArchive> archives) throws IOException;
  }

  /* package */ static TrimResult publishEffectiveOutputs(final EffectivePublication publication)
      throws IOException {
    return publishEffectiveOutputs(publication, null);
  }

  /* package */ static TrimResult publishEffectiveOutputs(
      final EffectivePublication publication, final OutputCheck outputCheck) throws IOException {
    final EffectiveOutputPlan output = publication.outputPlan();
    final FingerprintSnapshot fingerprint = publication.fingerprint();
    Files.createDirectories(publication.generation());
    try (EffectiveOutputStaging staging = new EffectiveOutputStaging(publication.generation())) {
      final PreparedEffectiveOutputs prepared =
          staging.prepareOutputs(
              publication.work(),
              fingerprint.inputDigests(),
              output,
              output.prepared().options().trim().workers(),
              publication.multiReleaseSources(),
              outputCheck);
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
