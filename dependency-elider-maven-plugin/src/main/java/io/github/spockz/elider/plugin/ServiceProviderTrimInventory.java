/* WHY: Removes provider declarations only when their implementation is
 * proven absent from retained archive outputs. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.MultiReleaseClassInventory;
import io.github.spockz.elider.plugin.TrimGenerationPublisher.EffectiveOutputPlan;
import io.github.spockz.elider.plugin.nativeimage.DependencyDynamicRoots;
import java.io.IOException;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Tracks providers whose implementations survive retained outputs. */
final class ServiceProviderTrimInventory {
  private ServiceProviderTrimInventory() {}

  /* package */ static void planDescriptorOutputs(
      final EffectiveOutputPlan outputPlan, final List<TrimCandidate> candidates)
      throws IOException {
    final ServiceProviderInventory inventory = serviceProviderInventory(outputPlan, candidates);
    final TrimScanInputs scanInputs =
        new TrimScanInputs(
            outputPlan.prepared().index(), outputPlan.prepared().dynamicRootInputs().scansByPath());
    for (final TrimCandidate candidate : candidates) {
      final Set<String> removed = removedServiceProviders(candidate, scanInputs, inventory);
      final DependencyDynamicRoots.RootScan scan = serviceScan(candidate, scanInputs);
      final List<ServiceDescriptorChange> changes = descriptorChanges(scan, removed);
      candidate.serviceDescriptorPlan(removed, changes);
    }
  }

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
    retainedClasses.addAll(outputPlan.prepared().projectOutputClasses());
    for (final ElisionAnalysisModel.ArtifactSnapshot snapshot :
        outputPlan.prepared().resolvedSnapshots()) {
      if (!MavenDependencyTrimmer.JAR_TYPE.equals(snapshot.coordinate().type())) {
        continue;
      }
      final Path source = snapshot.filePath().toAbsolutePath().normalize();
      final Set<String> logicalClasses = MultiReleaseClassInventory.logicalClassNames(source);
      ownedClasses.addAll(logicalClasses);
      if (!outputPlan.retainedCoordinates().contains(snapshot.coordinate())) {
        continue;
      }
      final TrimCandidate candidate = candidatesByCoordinate.get(snapshot.coordinate());
      if (candidate != null) {
        candidate.analysis().retainedClasses().stream()
            .map(name -> name.replace('/', '.'))
            .forEach(retainedClasses::add);
      } else {
        retainedClasses.addAll(logicalClasses);
      }
      if (candidate != null && candidate.archive().multiRelease()) {
        candidate.archive().upperTierClasses().stream()
            .map(name -> name.replace('/', '.'))
            .forEach(retainedClasses::add);
      }
    }
    return new ServiceProviderInventory(ownedClasses, retainedClasses);
  }

  /* package */ static Set<String> removedServiceProviders(
      final TrimCandidate candidate,
      final TrimScanInputs scanInputs,
      final ServiceProviderInventory inventory)
      throws IOException {
    final DependencyDynamicRoots.RootScan scan = serviceScan(candidate, scanInputs);
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

  private static DependencyDynamicRoots.RootScan serviceScan(
      final TrimCandidate candidate, final TrimScanInputs scanInputs) throws IOException {
    final Path source = candidate.archive().snapshot().filePath().toAbsolutePath().normalize();
    DependencyDynamicRoots.RootScan scan = scanInputs.dynamicRootScans().get(source);
    if (scan == null && java.nio.file.Files.exists(source)) {
      scan = scanInputs.dynamicRootScans().get(source.toRealPath());
    }
    if (scan == null) {
      throw new IOException(
          "Missing service descriptor scan for " + candidate.archive().snapshot().coordinate());
    }
    return scan;
  }

  private static List<ServiceDescriptorChange> descriptorChanges(
      final DependencyDynamicRoots.RootScan scan, final Set<String> removedProviders) {
    return scan.serviceDescriptors().stream()
        .filter(descriptor -> descriptor.providers().stream().anyMatch(removedProviders::contains))
        .map(
            descriptor -> {
              final boolean hasRemainingProvider =
                  descriptor.providers().stream()
                      .anyMatch(provider -> !removedProviders.contains(provider));
              return new ServiceDescriptorChange(
                  "META-INF/services/" + descriptor.serviceInterface(),
                  hasRemainingProvider
                      ? ServiceDescriptorChange.Outcome.REPLACED
                      : ServiceDescriptorChange.Outcome.OMIT);
            })
        .sorted()
        .toList();
  }

  /* package */ record ServiceProviderInventory(
      Set<String> ownedClasses, Set<String> retainedClasses) {
    ServiceProviderInventory {
      ownedClasses = Set.copyOf(ownedClasses);
      retainedClasses = Set.copyOf(retainedClasses);
    }
  }
}
