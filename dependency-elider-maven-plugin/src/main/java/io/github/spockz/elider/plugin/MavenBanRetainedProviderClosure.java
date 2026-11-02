// WHY: Checks retained final archive references against the actual effective and absent class
// providers immediately before plan publication.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ArtifactFileRef;
import io.github.spockz.elider.scanner.ArtifactClassIndex;
import io.github.spockz.elider.scanner.BytecodeReferenceScan;
import io.github.spockz.elider.scanner.JarIndexScanner;
import io.github.spockz.elider.scanner.ProductionBytecodeReferenceScanner;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.project.MavenProject;

/** Verifies bytecode references in the final retained effective provider set. */
final class MavenBanRetainedProviderClosure {
  private MavenBanRetainedProviderClosure() {}

  /* package */ static void verify(
      final MavenBanPlan banPlan,
      final MavenProject project,
      final ElisionAnalysisModel.Analysis analysis)
      throws IOException, MojoFailureException {
    banPlan.verifyAuditBytesFresh();
    final Map<String, List<ArtifactCoordinate>> absentOwners = absentOwners(banPlan);
    if (absentOwners.isEmpty()) {
      return;
    }
    final List<ElisionAnalysisModel.ArtifactSnapshot> finalSnapshots = finalSnapshots(project);
    final List<ArtifactFileRef> providers = retainedJars(finalSnapshots);
    final Set<String> requiredClasses = retainedBytecodeReferences(providers, analysis);
    final Map<String, List<ArtifactCoordinate>> effectiveOwners = ownersByClass(providers);
    final Set<ArtifactCoordinate> retainedCoordinates = retainedCoordinates(finalSnapshots);
    verifyRequiredClasses(
        requiredClasses, absentOwners, effectiveOwners, retainedCoordinates, analysis);
  }

  private static List<ElisionAnalysisModel.ArtifactSnapshot> finalSnapshots(
      final MavenProject project) throws IOException {
    final List<ElisionAnalysisModel.ArtifactSnapshot> snapshots =
        MavenArtifactInventory.snapshots(new ArrayList<>(project.getArtifacts()));
    MavenArtifactPathValidation.validateIdentityPaths(snapshots);
    return snapshots;
  }

  private static List<ArtifactFileRef> retainedJars(
      final List<ElisionAnalysisModel.ArtifactSnapshot> snapshots) throws IOException {
    final List<ArtifactFileRef> providers = new ArrayList<>();
    for (final ElisionAnalysisModel.ArtifactSnapshot snapshot : snapshots) {
      if (!isCompileOrRuntimeJar(snapshot.coordinate())) {
        continue;
      }
      if (!MavenArtifactInventory.isJarCandidate(snapshot)) {
        throw new IOException("Retained provider is not a readable JAR: " + snapshot.coordinate());
      }
      providers.add(ArtifactFileRef.fromPath(snapshot.coordinate(), snapshot.filePath()));
    }
    return List.copyOf(providers);
  }

  private static boolean isCompileOrRuntimeJar(final ArtifactCoordinate coordinate) {
    return "jar".equals(coordinate.type())
        && Set.of("compile", "runtime").contains(coordinate.scope());
  }

  private static Set<String> retainedBytecodeReferences(
      final List<ArtifactFileRef> providers, final ElisionAnalysisModel.Analysis analysis)
      throws IOException {
    final Set<String> references = new TreeSet<>();
    final ProductionBytecodeReferenceScanner scanner = new ProductionBytecodeReferenceScanner();
    for (final ArtifactFileRef provider : providers) {
      final BytecodeReferenceScan scan = scanner.scanArchive(provider.filePath());
      if (!scan.complete()) {
        throw new IOException("Final provider bytecode scan is incomplete: " + provider.filePath());
      }
      references.addAll(scan.referencedClasses());
    }
    addProductionReferences(references, analysis);
    return Set.copyOf(references);
  }

  private static void addProductionReferences(
      final Set<String> references, final ElisionAnalysisModel.Analysis analysis)
      throws IOException {
    if (!analysis.evidence().productionClassesComplete()) {
      return;
    }
    final BytecodeReferenceScan production =
        analysis
            .evidence()
            .bytecodeScan()
            .orElseThrow(
                () -> new IOException("Complete production bytecode evidence disappeared"));
    if (!production.complete()) {
      throw new IOException("Production bytecode evidence is incomplete during ban publication");
    }
    references.addAll(production.referencedClasses());
  }

  private static Map<String, List<ArtifactCoordinate>> ownersByClass(
      final List<ArtifactFileRef> providers) throws IOException {
    final ArtifactClassIndex index = new JarIndexScanner().scan(providers);
    final Map<String, List<ArtifactCoordinate>> owners = new ConcurrentHashMap<>();
    index
        .classesByArtifact()
        .forEach(
            (artifact, classes) ->
                classes.forEach(
                    name ->
                        owners
                            .computeIfAbsent(name, ignored -> new ArrayList<>())
                            .add(artifact.coordinate())));
    owners.replaceAll((ignored, values) -> List.copyOf(new TreeSet<>(values)));
    return Map.copyOf(owners);
  }

  private static Set<ArtifactCoordinate> retainedCoordinates(
      final List<ElisionAnalysisModel.ArtifactSnapshot> snapshots) {
    return snapshots.stream()
        .map(ElisionAnalysisModel.ArtifactSnapshot::coordinate)
        .collect(java.util.stream.Collectors.toUnmodifiableSet());
  }

  private static void verifyRequiredClasses(
      final Set<String> requiredClasses,
      final Map<String, List<ArtifactCoordinate>> absentOwners,
      final Map<String, List<ArtifactCoordinate>> effectiveOwners,
      final Set<ArtifactCoordinate> retainedCoordinates,
      final ElisionAnalysisModel.Analysis analysis)
      throws MojoFailureException {
    for (final String required : requiredClasses) {
      MavenBanClassProviderClosure.verifyReference(
          required,
          "final retained bytecode",
          absentOwners,
          effectiveOwners,
          retainedCoordinates,
          analysis.evidence().projectOutputClasses());
    }
  }

  private static Map<String, List<ArtifactCoordinate>> absentOwners(final MavenBanPlan banPlan) {
    final Map<String, List<ArtifactCoordinate>> owners = new ConcurrentHashMap<>();
    banPlan
        .forcedAbsentClassProviders()
        .forEach(
            (coordinate, classes) -> classes.forEach(name -> addOwner(owners, name, coordinate)));
    banPlan
        .auditContext()
        .auditOnlyClassIndex()
        .classesByArtifact()
        .forEach(
            (artifact, classes) ->
                classes.forEach(name -> addOwner(owners, name, artifact.coordinate())));
    owners.replaceAll((ignored, values) -> List.copyOf(new TreeSet<>(values)));
    return Map.copyOf(owners);
  }

  private static void addOwner(
      final Map<String, List<ArtifactCoordinate>> owners,
      final String className,
      final ArtifactCoordinate coordinate) {
    owners.computeIfAbsent(className, ignored -> new ArrayList<>()).add(coordinate);
  }
}
