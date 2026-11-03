/* WHY: Binds common and dynamic roots to prepared single-release candidate
 * pools. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.plugin.SingleReleasePlatforms.JdkClassTables;
import io.github.spockz.elider.plugin.SingleReleaseTrimInventory.DynamicRootPlan;
import io.github.spockz.elider.plugin.SingleReleaseTrimInventory.SingleReleaseInventory;
import io.github.spockz.elider.plugin.SingleReleaseTrimInventory.SingleReleaseLayout;
import io.github.spockz.elider.plugin.TrimRootPlanner.CommonRootOwners;
import io.github.spockz.elider.trimmer.DependencyJarTrimmer;
import java.io.IOException;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/** Binds common and dynamic roots to prepared single-release candidate pools. */
final class SingleReleaseRootPlanner {
  private SingleReleaseRootPlanner() {}

  /* package */ record SingleReleaseRootPlan(
      Map<ElisionAnalysisModel.ArtifactSnapshot, Set<String>> candidateRoots,
      Map<ElisionAnalysisModel.ArtifactSnapshot, DependencyJarTrimmer.PreparedAnalysis>
          preparedCandidates,
      Map<ElisionAnalysisModel.ArtifactSnapshot, DependencyJarTrimmer.PreparedAnalysis>
          preparedPrograms,
      Set<ArtifactCoordinate> reachableArtifacts) {}

  /* package */ static SingleReleaseRootPlan singleReleaseRootPlan(
      final TrimRequest request,
      final SingleReleaseInventory inventory,
      final SingleReleaseLayout layout,
      final SingleReleasePlatforms.AnalysisPlatform platform)
      throws IOException {
    final Set<String> commonRoots = TrimRootPlanner.commonRoots(request);
    final Set<String> platformClasses = platformClasses(platform.tables());
    final CommonRootOwners common =
        TrimRootPlanner.commonRootOwners(
            commonRoots,
            inventory.ownerByClass(),
            request,
            layout.retainedCoordinates(),
            inventory.classesByArtifact(),
            platformClasses);
    final DynamicRootPlan dynamic =
        SingleReleaseTrimInventory.dynamicRootPlan(request, inventory, layout, platformClasses);
    final Map<ElisionAnalysisModel.ArtifactSnapshot, Set<String>> roots =
        SingleReleaseTrimInventory.candidateRoots(inventory, layout, common, dynamic);
    final SingleReleasePoolPreparer.PreparedPools prepared =
        SingleReleasePoolPreparer.prepare(
            inventory,
            layout,
            SingleReleaseTrimInventory.fullClasspath(inventory),
            platform.tables(),
            request.policy().trimWorkers(),
            MavenDependencyTrimmer.MRJAR_CLASSPATH_ONLY.equals(request.policy().mrjarStrategy()));
    final Set<ArtifactCoordinate> reachable = new LinkedHashSet<>(common.droppedArtifacts());
    reachable.addAll(dynamic.droppedArtifacts());
    return new SingleReleaseRootPlan(roots, prepared.candidates(), prepared.programs(), reachable);
  }

  /* package */ static Set<String> platformClasses(final JdkClassTables tables) {
    final Set<String> result = new HashSet<>();
    tables.candidate().classNames().forEachRemaining(name -> result.add(name.replace('/', '.')));
    tables.passThrough().classNames().forEachRemaining(name -> result.add(name.replace('/', '.')));
    return Set.copyOf(result);
  }
}
