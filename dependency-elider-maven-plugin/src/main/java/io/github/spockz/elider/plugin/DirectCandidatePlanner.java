/* WHY: Separates direct candidate root selection and ownership checks from
 * effective-plan evidence so each path keeps its own validation contract. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactFileRef;
import io.github.spockz.elider.plugin.TrimCandidatePlanner.CandidatePlan;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.apache.maven.project.MavenProject;

/** Plans direct candidates before any archive is analyzed or published. */
final class DirectCandidatePlanner {
  private DirectCandidatePlanner() {}

  private record RootInputs(
      MavenProject project,
      Map<ArtifactFileRef, Set<String>> classesByArtifact,
      Set<String> roots,
      Set<String> dynamicRoots) {}

  /* package */ static CandidatePlan candidatePlan(
      final MavenProject project,
      final List<ElisionAnalysisModel.ArtifactSnapshot> libraries,
      final List<ElisionAnalysisModel.ArtifactSnapshot> retained,
      final TrimScanInputs scans,
      final Map<ArtifactFileRef, Set<String>> classesByArtifact,
      final Set<String> roots)
      throws IOException {
    final List<Path> inputs =
        libraries.stream().map(ElisionAnalysisModel.ArtifactSnapshot::filePath).toList();
    final Set<String> dynamic = new HashSet<>();
    for (final ElisionAnalysisModel.ArtifactSnapshot snapshot : libraries) {
      dynamic.addAll(requiredScan(scans, snapshot).roots());
    }
    final RootInputs rootInputs = new RootInputs(project, classesByArtifact, roots, dynamic);
    final Set<Path> outputs = new HashSet<>();
    final List<TrimCandidate> work = new ArrayList<>();
    for (final ElisionAnalysisModel.ArtifactSnapshot snapshot :
        retained.stream().sorted(TrimCandidatePlanner.artifactSnapshotOrder()).toList()) {
      addCandidate(snapshot, rootInputs, outputs, work);
    }
    final Map<String, List<TrimCandidate>> owners = TrimCollections.lookupMap();
    final Map<String, Path> paths = TrimCollections.lookupMap();
    for (final TrimCandidate candidate : work) {
      registerOwners(candidate, owners, paths);
    }
    return new CandidatePlan(inputs, work, owners, paths);
  }

  private static DependencyDynamicRoots.RootScan requiredScan(
      final TrimScanInputs scans, final ElisionAnalysisModel.ArtifactSnapshot snapshot)
      throws IOException {
    final DependencyDynamicRoots.RootScan scan = scans.dynamicRootScans().get(snapshot.filePath());
    if (scan == null) {
      throw new IOException(
          "Missing dynamic-root scan for retained artifact " + snapshot.coordinate());
    }
    return scan;
  }

  private static void addCandidate(
      final ElisionAnalysisModel.ArtifactSnapshot snapshot,
      final RootInputs inputs,
      final Set<Path> outputs,
      final List<TrimCandidate> work)
      throws IOException {
    final Set<String> classes =
        inputs.classesByArtifact().entrySet().stream()
            .filter(entry -> entry.getKey().filePath().equals(snapshot.filePath()))
            .map(Map.Entry::getValue)
            .findFirst()
            .orElseThrow(
                () -> new IOException("Missing indexed classes for " + snapshot.coordinate()));
    if (classes.isEmpty()) {
      return;
    }
    final Set<String> roots = new TreeSet<>();
    TrimCandidatePlanner.addPresentRoots(roots, inputs.roots(), classes);
    TrimCandidatePlanner.addPresentRoots(roots, inputs.dynamicRoots(), classes);
    final Path output = TrimPaths.outputPath(inputs.project(), snapshot.coordinate());
    if (!outputs.add(output)) {
      throw new IOException(
          "Distinct Maven artifacts map to the same trimmed output path: " + output);
    }
    work.add(new TrimCandidate(snapshot, classes, roots, output));
  }

  private static void registerOwners(
      final TrimCandidate candidate,
      final Map<String, List<TrimCandidate>> owners,
      final Map<String, Path> paths)
      throws IOException {
    for (final String className : candidate.archive().classes()) {
      registerOwner(candidate, className, owners, paths);
    }
  }

  private static void registerOwner(
      final TrimCandidate candidate,
      final String className,
      final Map<String, List<TrimCandidate>> owners,
      final Map<String, Path> paths)
      throws IOException {
    final Path path = candidate.archive().snapshot().filePath();
    final Path previous = paths.putIfAbsent(className, path);
    if (previous != null && !previous.equals(path)) {
      throw new IOException(
          "Duplicate class across retained dependency JARs makes library order ambiguous: "
              + className);
    }
    owners.computeIfAbsent(className, ignored -> new ArrayList<>()).add(candidate);
  }
}
