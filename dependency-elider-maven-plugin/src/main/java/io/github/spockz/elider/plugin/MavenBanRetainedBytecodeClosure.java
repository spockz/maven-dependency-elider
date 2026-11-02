// WHY: Checks references exposed by the bytecode that will remain after trimming and publication.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ElisionDecision;
import io.github.spockz.elider.scanner.BytecodeReferenceScan;
import io.github.spockz.elider.scanner.ProductionBytecodeReferenceScanner;
import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.maven.plugin.MojoFailureException;

/** Verifies bytecode references across each retained archive tier. */
final class MavenBanRetainedBytecodeClosure {
  private MavenBanRetainedBytecodeClosure() {}

  /* package */ static void verify(
      final ElisionAnalysisModel.PreparedAnalysis prepared,
      final ElisionDecision effectiveDecision,
      final TrimAnalysisResult trimAnalysis,
      final Set<ArtifactCoordinate> forcedUnchanged,
      final Map<String, List<ArtifactCoordinate>> absentOwners,
      final Map<String, List<ArtifactCoordinate>> effectiveOwners)
      throws IOException, MojoFailureException {
    final Set<ArtifactCoordinate> retained = effectiveDecision.retainedArtifacts();
    final Set<String> passThrough = passThrough(prepared, retained);
    final ProductionBytecodeReferenceScanner scanner = new ProductionBytecodeReferenceScanner();
    for (final ElisionAnalysisModel.ArtifactSnapshot snapshot : prepared.resolvedSnapshots()) {
      verifyCandidate(
          prepared,
          snapshot,
          retained,
          forcedUnchanged,
          passThrough,
          trimAnalysis,
          scanner,
          absentOwners,
          effectiveOwners);
    }
  }

  private static Set<String> passThrough(
      final ElisionAnalysisModel.PreparedAnalysis prepared, final Set<ArtifactCoordinate> retained)
      throws IOException {
    if (!prepared.options().trim().enabled()) {
      return Set.of();
    }
    return TrimPassThroughPlanner.passThroughPlan(
            TrimRequestFactory.fromPreparedAnalysis(
                prepared, retained, prepared.sourceRequiredClasses()))
        .skippedArtifactIdentities();
  }

  private static void verifyCandidate(
      final ElisionAnalysisModel.PreparedAnalysis prepared,
      final ElisionAnalysisModel.ArtifactSnapshot snapshot,
      final Set<ArtifactCoordinate> retained,
      final Set<ArtifactCoordinate> forcedUnchanged,
      final Set<String> passThrough,
      final TrimAnalysisResult trimAnalysis,
      final ProductionBytecodeReferenceScanner scanner,
      final Map<String, List<ArtifactCoordinate>> absentOwners,
      final Map<String, List<ArtifactCoordinate>> effectiveOwners)
      throws IOException, MojoFailureException {
    final ArtifactCoordinate coordinate = snapshot.coordinate();
    if (!retained.contains(coordinate)
        || !"jar".equals(coordinate.type())
        || !Set.of("compile", "runtime").contains(coordinate.scope())) {
      return;
    }
    if (!MavenArtifactInventory.isJarCandidate(snapshot)) {
      throw new IOException("Retained provider is not a readable JAR: " + coordinate);
    }
    final io.github.spockz.elider.trimmer.DependencyJarTrimmer.TrimAnalysis candidateAnalysis =
        trimAnalysis.candidateAnalyses().get(coordinate);
    final BytecodeReferenceScan scan =
        scanRetainedContent(
            snapshot,
            coordinate,
            candidateAnalysis,
            forcedUnchanged,
            passThrough,
            prepared,
            trimAnalysis,
            scanner);
    verifyReferences(
        scan.referencedClasses(),
        coordinate,
        retained,
        absentOwners,
        effectiveOwners,
        prepared.projectOutputClasses());
  }

  private static BytecodeReferenceScan scanRetainedContent(
      final ElisionAnalysisModel.ArtifactSnapshot snapshot,
      final ArtifactCoordinate coordinate,
      final io.github.spockz.elider.trimmer.DependencyJarTrimmer.TrimAnalysis candidateAnalysis,
      final Set<ArtifactCoordinate> forcedUnchanged,
      final Set<String> passThrough,
      final ElisionAnalysisModel.PreparedAnalysis prepared,
      final TrimAnalysisResult trimAnalysis,
      final ProductionBytecodeReferenceScanner scanner)
      throws IOException {
    final boolean scanEveryClass =
        !prepared.options().trim().enabled()
            || forcedUnchanged.contains(coordinate)
            || passThrough.contains(TrimPassThroughPlanner.artifactIdentity(coordinate))
            || candidateAnalysis == null;
    if (scanEveryClass) {
      return scanner.scanArchive(snapshot.filePath());
    }
    final Set<String> retainedClasses = new HashSet<>(candidateAnalysis.retainedClasses());
    retainedClasses.addAll(trimAnalysis.upperTierClasses().getOrDefault(coordinate, Set.of()));
    return scanner.scanArchive(snapshot.filePath(), Set.copyOf(retainedClasses));
  }

  private static void verifyReferences(
      final Set<String> references,
      final ArtifactCoordinate coordinate,
      final Set<ArtifactCoordinate> retained,
      final Map<String, List<ArtifactCoordinate>> absentOwners,
      final Map<String, List<ArtifactCoordinate>> effectiveOwners,
      final Set<String> projectOutputClasses)
      throws MojoFailureException {
    for (final String className : references) {
      MavenBanClassProviderClosure.verifyReference(
          className,
          "retained archive " + coordinate + " bytecode",
          absentOwners,
          effectiveOwners,
          retained,
          projectOutputClasses);
    }
  }
}
