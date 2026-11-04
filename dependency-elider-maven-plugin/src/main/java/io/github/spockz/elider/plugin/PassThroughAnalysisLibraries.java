/* WHY: Builds runtime projections and verifies pass-through class ownership. */

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/** Builds runtime projections and verifies pass-through class ownership. */
final class PassThroughAnalysisLibraries {
  private PassThroughAnalysisLibraries() {}

  /* package */ record AnalysisLibraries(
      List<Path> paths, List<SkippedProgram> skippedPrograms, Set<String> passThroughClassNames) {}

  /* package */ static AnalysisLibraries analysisLibraries(
      final TrimPassThroughPlan passThroughPlan,
      final Path analysisLibraryDirectory,
      final int runtimeRelease,
      final DuplicateClassPolicy duplicates)
      throws IOException {
    final List<Path> analysisLibraries = new ArrayList<>();
    final List<SkippedProgram> skippedPrograms = new ArrayList<>();
    for (final ElisionAnalysisModel.ArtifactSnapshot snapshot :
        passThroughPlan.retainedLibraries()) {
      if (passThroughPlan
          .skippedArtifactIdentities()
          .contains(TrimPassThroughPlanner.artifactIdentity(snapshot.coordinate()))) {
        final boolean multiRelease =
            passThroughPlan
                .multiReleaseIdentities()
                .contains(TrimPassThroughPlanner.artifactIdentity(snapshot.coordinate()));
        final boolean rootModuleDescriptor =
            MultiReleaseLibraryProjection.hasRootModuleDescriptor(snapshot.filePath());
        final Path analysisPath =
            multiRelease || rootModuleDescriptor
                ? MultiReleaseLibraryProjection.create(
                    snapshot.filePath(),
                    snapshot.coordinate(),
                    analysisLibraryDirectory,
                    runtimeRelease)
                : snapshot.filePath();
        analysisLibraries.add(analysisPath);
        skippedPrograms.add(new SkippedProgram(analysisPath, TrimPaths.classNames(analysisPath)));
      } else {
        analysisLibraries.add(snapshot.filePath());
      }
    }
    final Set<String> unchangedPassThroughClassNames = new LinkedHashSet<>();
    skippedPrograms.stream()
        .flatMap(program -> program.classNames().stream())
        .forEach(unchangedPassThroughClassNames::add);
    validatePassThroughOwnership(skippedPrograms, analysisLibraries, duplicates);
    return new AnalysisLibraries(
        analysisLibraries, skippedPrograms, unchangedPassThroughClassNames);
  }

  /* package */ record SkippedProgram(Path path, Set<String> classNames) {
    SkippedProgram {
      classNames = Set.copyOf(classNames);
    }
  }

  /* package */ static void validatePassThroughOwnership(
      final List<SkippedProgram> programs,
      final List<Path> libraries,
      final DuplicateClassPolicy duplicates)
      throws IOException {
    for (final SkippedProgram program : programs) {
      for (final Path sibling : libraries) {
        validateSiblingOwnership(program, sibling, duplicates);
      }
    }
  }

  /* package */ static void validateSiblingOwnership(
      final SkippedProgram program, final Path sibling, final DuplicateClassPolicy duplicates)
      throws IOException {
    if (sibling.equals(program.path())) {
      return;
    }
    final Set<String> ambiguous = new HashSet<>(program.classNames());
    ambiguous.retainAll(TrimPaths.classNames(sibling));
    ambiguous.removeIf(duplicates::tolerates);
    if (!ambiguous.isEmpty()) {
      throw new IOException(
          "Duplicate class ownership makes pass-through unresolved-link tolerance ambiguous: "
              + ambiguous);
    }
  }
}
