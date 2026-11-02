/* WHY: Removes provider declarations only when their implementation is
 * proven absent from retained archive outputs. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.plugin.TrimGenerationPublisher.EffectiveOutputPlan;
import java.io.IOException;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Tracks providers whose implementations survive retained outputs. */
final class ServiceProviderTrimInventory {
  private ServiceProviderTrimInventory() {}

  /* package */ static ServiceProviderInventory serviceProviderInventory(
      final EffectiveOutputPlan outputPlan, final List<TrimCandidate> candidates)
      throws IOException {
    final Map<ArtifactCoordinate, TrimCandidate> candidatesByCoordinate =
        TrimCollections.lookupMap();
    candidates.forEach(
        candidate ->
            candidatesByCoordinate.put(candidate.archive().snapshot().coordinate(), candidate));
    final Set<String> ownedClasses = new HashSet<>();
    final Set<String> retainedClasses = new HashSet<>();
    final Path projectionDirectory =
        TrimPaths.analysisLibraryDirectory(outputPlan.prepared().project());
    for (final ElisionAnalysisModel.ArtifactSnapshot snapshot :
        outputPlan.prepared().resolvedSnapshots()) {
      if (!MavenDependencyTrimmer.JAR_TYPE.equals(snapshot.coordinate().type())) {
        continue;
      }
      final Path source = snapshot.filePath().toAbsolutePath().normalize();
      final Set<String> logicalClasses = TrimPaths.logicalClassNames(source);
      ownedClasses.addAll(logicalClasses);
      if (!outputPlan.retainedCoordinates().contains(snapshot.coordinate())) {
        continue;
      }
      final TrimCandidate candidate = candidatesByCoordinate.get(snapshot.coordinate());
      if (candidate != null) {
        candidate.analysis().retainedClasses().stream()
            .map(name -> name.replace('/', '.'))
            .forEach(retainedClasses::add);
      } else if (MultiReleaseClassInventory.hasUnsupportedVersionedClasses(source)) {
        final Path projection =
            MultiReleaseLibraryProjection.create(
                source,
                snapshot.coordinate(),
                projectionDirectory,
                outputPlan.analysis().targetRelease());
        retainedClasses.addAll(TrimPaths.classNames(projection));
      } else {
        retainedClasses.addAll(logicalClasses);
      }
    }
    return new ServiceProviderInventory(ownedClasses, retainedClasses);
  }

  /* package */ static Set<String> removedServiceProviders(
      final TrimCandidate candidate,
      final TrimScanInputs scanInputs,
      final ServiceProviderInventory inventory)
      throws IOException {
    final Path source = candidate.archive().snapshot().filePath().toAbsolutePath().normalize();
    final DependencyDynamicRoots.RootScan scan = scanInputs.dynamicRootScans().get(source);
    if (scan == null) {
      throw new IOException(
          "Missing service descriptor scan for " + candidate.archive().snapshot().coordinate());
    }
    final Set<String> removed = new HashSet<>();
    for (final DependencyDynamicRoots.ServiceDescriptor descriptor : scan.serviceDescriptors()) {
      for (final String provider : descriptor.providers()) {
        if (inventory.ownedClasses().contains(provider)
            && !inventory.retainedClasses().contains(provider)) {
          removed.add(provider);
        }
      }
    }
    return Set.copyOf(removed);
  }

  /* package */ record ServiceProviderInventory(
      Set<String> ownedClasses, Set<String> retainedClasses) {
    ServiceProviderInventory {
      ownedClasses = Set.copyOf(ownedClasses);
      retainedClasses = Set.copyOf(retainedClasses);
    }
  }
}
