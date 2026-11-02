// WHY: Checks retained resource lookups against frozen original-only providers without activating
// metadata from those providers.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ArtifactFileRef;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentSkipListMap;
import org.apache.maven.plugin.MojoFailureException;

/** Verifies that retained resource patterns do not select original-only providers. */
final class MavenBanRetainedResourceClosure {
  private MavenBanRetainedResourceClosure() {}

  /* package */ static void verify(
      final List<MavenOriginalInputAudit.AuditArtifact> auditOnlyArtifacts,
      final ElisionAnalysisModel.PreparedAnalysis prepared,
      final Set<ArtifactCoordinate> retained)
      throws IOException, MojoFailureException {
    if (auditOnlyArtifacts.isEmpty()) {
      return;
    }
    final List<ArtifactFileRef> effectiveProviders = retainedProviders(prepared, retained);
    final AuditLookup auditLookup = auditLookup(auditOnlyArtifacts, effectiveProviders);
    verifyDistinctProviderPaths(auditLookup, effectiveProviders);
    final NativeImageScanContext scanContext = resourceScanContext(prepared, auditLookup);
    for (final ArtifactFileRef declaring : effectiveProviders) {
      verifySelection(declaring, prepared, scanContext, auditLookup.coordinatesByPath());
    }
  }

  private static List<ArtifactFileRef> retainedProviders(
      final ElisionAnalysisModel.PreparedAnalysis prepared,
      final Set<ArtifactCoordinate> retained) {
    return prepared.scanCandidates().stream()
        .filter(candidate -> retained.contains(candidate.coordinate()))
        .toList();
  }

  @SuppressWarnings("PMD.UseConcurrentHashMap")
  // This local index retains audit coordinate order.
  private static AuditLookup auditLookup(
      final List<MavenOriginalInputAudit.AuditArtifact> auditOnlyArtifacts,
      final List<ArtifactFileRef> effectiveProviders)
      throws IOException {
    final Map<Path, List<ArtifactCoordinate>> coordinatesByPath = new ConcurrentSkipListMap<>();
    final List<ArtifactFileRef> lookupCandidates = new ArrayList<>(effectiveProviders);
    for (final MavenOriginalInputAudit.AuditArtifact artifact : auditOnlyArtifacts) {
      if (artifact.filePath() == null) {
        throw new IOException(
            "Original-only resource provider has no audited bytes: " + artifact.coordinate());
      }
      final Path path = Path.of(artifact.filePath()).toAbsolutePath().normalize().toRealPath();
      coordinatesByPath
          .computeIfAbsent(path, ignored -> newCoordinateList())
          .add(artifact.coordinate());
      lookupCandidates.add(lookupCandidate(artifact, path));
    }
    return new AuditLookup(lookupCandidates, coordinatesByPath);
  }

  private static List<ArtifactCoordinate> newCoordinateList() {
    return new ArrayList<>();
  }

  private static ArtifactFileRef lookupCandidate(
      final MavenOriginalInputAudit.AuditArtifact artifact, final Path path) throws IOException {
    return ArtifactFileRef.fromPath(artifact.coordinate(), path);
  }

  private static void verifyDistinctProviderPaths(
      final AuditLookup auditLookup, final List<ArtifactFileRef> effectiveProviders)
      throws IOException, MojoFailureException {
    final Set<Path> effectivePaths = new HashSet<>();
    for (final ArtifactFileRef provider : effectiveProviders) {
      effectivePaths.add(provider.filePath().toRealPath());
    }
    for (final Path path : auditLookup.coordinatesByPath().keySet()) {
      if (effectivePaths.contains(path)) {
        throw MavenBanClassProviderClosure.conflict(
            auditLookup.coordinatesByPath().get(path).getFirst(),
            "original-only and retained artifacts share one resource provider path");
      }
    }
  }

  private static NativeImageScanContext resourceScanContext(
      final ElisionAnalysisModel.PreparedAnalysis prepared, final AuditLookup auditLookup)
      throws IOException {
    return NativeImageScanContext.create(
        auditLookup.lookupCandidates(),
        MavenAnalysisInvocationBase.forProject(prepared.project(), prepared.options()));
  }

  private static void verifySelection(
      final ArtifactFileRef declaring,
      final ElisionAnalysisModel.PreparedAnalysis prepared,
      final NativeImageScanContext scanContext,
      final Map<Path, List<ArtifactCoordinate>> auditCoordinatesByPath)
      throws IOException, MojoFailureException {
    final DependencyDynamicRoots.RootScan scan =
        prepared.dynamicRootInputs().scansByPath().get(declaring.filePath());
    if (scan == null) {
      throw new IOException(
          "Retained archive is missing its dynamic-root scan: " + declaring.filePath());
    }
    final NativeImagePolicyRoots.ResourcePatternSelection selection = scan.resourcePatterns();
    if (selection.includes().isEmpty() && selection.bundles().isEmpty()) {
      return;
    }
    final Set<Path> selectedProviders = new HashSet<>();
    NativeImagePolicyRoots.applyResourcePatterns(
        List.of(selection), scanContext, new HashSet<>(), selectedProviders);
    verifySelectedAuditProviders(declaring, selectedProviders, auditCoordinatesByPath);
  }

  private static void verifySelectedAuditProviders(
      final ArtifactFileRef declaring,
      final Set<Path> selectedProviders,
      final Map<Path, List<ArtifactCoordinate>> auditCoordinatesByPath)
      throws IOException, MojoFailureException {
    final Set<Path> selectedAuditPaths = new HashSet<>();
    for (final Path path : selectedProviders) {
      final Path realPath = path.toRealPath();
      if (auditCoordinatesByPath.containsKey(realPath)) {
        selectedAuditPaths.add(realPath);
      }
    }
    final List<ArtifactCoordinate> selectedAuditOnly =
        selectedAuditPaths.stream()
            .flatMap(path -> auditCoordinatesByPath.get(path).stream())
            .distinct()
            .sorted()
            .toList();
    if (!selectedAuditOnly.isEmpty()) {
      throw MavenBanClassProviderClosure.conflict(
          selectedAuditOnly.getFirst(),
          "retained resource pattern in "
              + declaring.coordinate()
              + " selects an original-only provider"
              + (selectedAuditOnly.size() == 1 ? "" : " among ambiguous providers"));
    }
  }

  private record AuditLookup(
      List<ArtifactFileRef> lookupCandidates,
      Map<Path, List<ArtifactCoordinate>> coordinatesByPath) {
    AuditLookup {
      lookupCandidates = List.copyOf(lookupCandidates);
      coordinatesByPath = Map.copyOf(coordinatesByPath);
    }
  }
}
