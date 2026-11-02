/* WHY: Canonicalizes effective-plan evidence into the cache identity without
 * changing the persisted fingerprint envelope. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.plugin.TrimGenerationPublisher.EffectiveOutputPlan;
import io.github.spockz.elider.trimmer.ArtifactDigests;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Serializes the effective-plan evidence used in cache fingerprints. */
final class EffectiveTrimCacheContext {
  private EffectiveTrimCacheContext() {}

  /* package */ record EffectiveCacheIdentity(
      int schema,
      String inventoryFingerprint,
      String directInventoryFingerprint,
      String operationFingerprint,
      String productionOutputFingerprint,
      List<ArtifactCacheIdentity> inventory,
      List<ArtifactCoordinate> retainedCoordinates,
      List<ArtifactCoordinate> unchangedCoordinates,
      List<ArtifactRootsIdentity> artifactRoots,
      int targetRelease,
      int runtimeRelease,
      List<String> platformIdentities,
      List<Integer> analyzedTiers,
      List<String> bytecodeReferences,
      List<String> explicitRoots,
      List<String> explicitPassThroughCoordinates,
      boolean sourceRootsComplete,
      boolean productionClassesComplete,
      String mrjarStrategy,
      boolean failOnUnsupportedModuleInfo) {}

  /* package */ record ArtifactCacheIdentity(
      String groupId,
      String artifactId,
      String version,
      String type,
      String classifier,
      String scope,
      String path,
      String sha256) {}

  /* package */ record ArtifactRootsIdentity(
      ArtifactCoordinate coordinate, String path, String sha256, List<String> roots) {}

  /* package */ static String effectiveCacheContext(
      final TrimRequest request, final EffectiveOutputPlan output) throws IOException {
    final List<ArtifactCacheIdentity> inventory = new ArrayList<>();
    for (final ElisionAnalysisModel.ArtifactSnapshot snapshot :
        TrimCandidatePlanner.fullJarInventory(request.candidates())) {
      inventory.add(artifactCacheIdentity(snapshot));
    }
    final List<ArtifactRootsIdentity> artifactRoots =
        output.roots().entrySet().stream()
            .sorted(
                Comparator.comparing(
                        (Map.Entry<TrimArtifactRootKey, Set<String>> entry) ->
                            entry.getKey().coordinate())
                    .thenComparing(entry -> entry.getKey().path()))
            .map(
                entry ->
                    new ArtifactRootsIdentity(
                        entry.getKey().coordinate(),
                        entry.getKey().path().toString(),
                        entry.getKey().sha256(),
                        entry.getValue().stream().sorted().toList()))
            .toList();
    final EffectiveCacheIdentity identity =
        new EffectiveCacheIdentity(
            2,
            output.inventoryFingerprint(),
            output.directInventoryFingerprint(),
            output.operationFingerprint(),
            output.productionOutputFingerprint(),
            inventory,
            request.retainedCoordinates().stream().sorted().toList(),
            output.unchangedCoordinates().stream().sorted().toList(),
            artifactRoots,
            output.analysis().targetRelease(),
            output.analysis().runtimeRelease(),
            output.analysis().platformIdentities(),
            output.analysis().analyzedTiers(),
            output.bytecodeReferences().stream().sorted().toList(),
            output.explicitRoots().stream().sorted().toList(),
            output.explicitPassThroughCoordinates().stream().sorted().toList(),
            output.sourceRootsComplete(),
            output.productionClassesComplete(),
            request.policy().mrjarStrategy(),
            output.failOnUnsupportedModuleInfo());
    try {
      return TrimInputDigests.hash(JarTrimCache.serializeIdentity(identity));
    } catch (final com.fasterxml.jackson.core.JsonProcessingException exception) {
      throw new IOException("Could not serialize effective trim cache identity", exception);
    }
  }

  private static ArtifactCacheIdentity artifactCacheIdentity(
      final ElisionAnalysisModel.ArtifactSnapshot snapshot) throws IOException {
    final ArtifactCoordinate coordinate = snapshot.coordinate();
    final Path path = snapshot.filePath().toAbsolutePath().normalize();
    return new ArtifactCacheIdentity(
        coordinate.groupId(),
        coordinate.artifactId(),
        coordinate.version(),
        coordinate.type(),
        coordinate.classifier(),
        coordinate.scope(),
        path.toString(),
        ArtifactDigests.read(path).sha256());
  }
}
