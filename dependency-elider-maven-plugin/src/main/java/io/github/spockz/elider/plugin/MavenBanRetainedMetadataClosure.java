// WHY: Checks references named by retained service and provider metadata without scanning the
// metadata in audit-only artifacts.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ArtifactFileRef;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.maven.plugin.MojoFailureException;

/** Verifies retained service roots and raw provider declarations. */
final class MavenBanRetainedMetadataClosure {
  private MavenBanRetainedMetadataClosure() {}

  /* package */ static void verify(
      final ElisionAnalysisModel.PreparedAnalysis prepared,
      final Set<ArtifactCoordinate> retained,
      final Map<String, List<ArtifactCoordinate>> absentOwners,
      final Map<String, List<ArtifactCoordinate>> effectiveOwners)
      throws MojoFailureException, IOException {
    for (final ArtifactFileRef declaring : prepared.scanCandidates()) {
      if (!retained.contains(declaring.coordinate())) {
        continue;
      }
      final DependencyDynamicRoots.RootScan scan = scanFor(declaring, prepared);
      verifyRoots(scan, declaring, prepared, retained, absentOwners, effectiveOwners);
      verifyServiceDeclarations(scan, declaring, prepared, retained, absentOwners, effectiveOwners);
    }
  }

  private static DependencyDynamicRoots.RootScan scanFor(
      final ArtifactFileRef declaring, final ElisionAnalysisModel.PreparedAnalysis prepared)
      throws IOException {
    final DependencyDynamicRoots.RootScan scan =
        prepared.dynamicRootInputs().scansByPath().get(declaring.filePath());
    if (scan == null) {
      throw new IOException(
          "Retained archive is missing its dynamic-root scan: " + declaring.filePath());
    }
    return scan;
  }

  private static void verifyRoots(
      final DependencyDynamicRoots.RootScan scan,
      final ArtifactFileRef declaring,
      final ElisionAnalysisModel.PreparedAnalysis prepared,
      final Set<ArtifactCoordinate> retained,
      final Map<String, List<ArtifactCoordinate>> absentOwners,
      final Map<String, List<ArtifactCoordinate>> effectiveOwners)
      throws MojoFailureException {
    for (final String className : scan.roots()) {
      MavenBanClassProviderClosure.verifyReference(
          className,
          "retained metadata in " + declaring.coordinate(),
          absentOwners,
          effectiveOwners,
          retained,
          prepared.projectOutputClasses());
    }
  }

  private static void verifyServiceDeclarations(
      final DependencyDynamicRoots.RootScan scan,
      final ArtifactFileRef declaring,
      final ElisionAnalysisModel.PreparedAnalysis prepared,
      final Set<ArtifactCoordinate> retained,
      final Map<String, List<ArtifactCoordinate>> absentOwners,
      final Map<String, List<ArtifactCoordinate>> effectiveOwners)
      throws MojoFailureException {
    for (final DependencyDynamicRoots.ServiceDescriptor descriptor : scan.serviceDescriptors()) {
      verifyServiceClass(
          descriptor.serviceInterface(),
          "retained service descriptor in " + declaring.coordinate(),
          prepared,
          retained,
          absentOwners,
          effectiveOwners);
      for (final String provider : descriptor.providers()) {
        verifyServiceClass(
            provider,
            "retained service provider declared by " + declaring.coordinate(),
            prepared,
            retained,
            absentOwners,
            effectiveOwners);
      }
    }
  }

  private static void verifyServiceClass(
      final String className,
      final String location,
      final ElisionAnalysisModel.PreparedAnalysis prepared,
      final Set<ArtifactCoordinate> retained,
      final Map<String, List<ArtifactCoordinate>> absentOwners,
      final Map<String, List<ArtifactCoordinate>> effectiveOwners)
      throws MojoFailureException {
    MavenBanClassProviderClosure.verifyReference(
        className,
        location,
        absentOwners,
        effectiveOwners,
        retained,
        prepared.projectOutputClasses());
  }
}
