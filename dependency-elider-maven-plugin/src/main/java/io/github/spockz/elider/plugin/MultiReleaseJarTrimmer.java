/* WHY: Selects tier-aware analysis when versioned implementations can affect
 * the dependency closure. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.project.MavenProject;

/** Selects tier-aware analysis when versioned implementations can affect closure. */
final class MultiReleaseJarTrimmer {
  private MultiReleaseJarTrimmer() {}

  /* package */ record TieringDecision(boolean required, boolean hasVerticalShadingCandidate) {}

  /* package */ static TrimAnalysisResult analyzeInMemory(
      final TrimRequest request,
      final Map<TrimArtifactRootKey, Set<String>> discoveredRoots,
      final Set<ArtifactCoordinate> forcedUnchanged)
      throws IOException, MojoFailureException {
    final TieringDecision decision = tieringDecision(request, forcedUnchanged);
    if (!decision.required()) {
      return SingleReleaseTrimAnalyzer.analyzeInMemorySingleRelease(
          request, discoveredRoots, forcedUnchanged);
    }
    return analyzeInMemoryTiered(request, discoveredRoots, forcedUnchanged, decision);
  }

  private static TieringDecision tieringDecision(
      final TrimRequest request, final Set<ArtifactCoordinate> forcedUnchanged) throws IOException {
    if (!request.policy().trimEnabled()) {
      return new TieringDecision(false, false);
    }
    final TrimPassThroughPlan passThrough = TrimPassThroughPlanner.passThroughPlan(request);
    final boolean otherTrimCandidate = hasOtherTrimCandidate(passThrough, forcedUnchanged);
    final boolean unchangedMrjarProgram =
        hasUnchangedMultiReleaseProgram(request, passThrough, forcedUnchanged);
    final boolean verticalCandidate =
        hasVerticalShadingCandidate(request, passThrough, forcedUnchanged);
    return new TieringDecision(
        verticalCandidate || (otherTrimCandidate && unchangedMrjarProgram), verticalCandidate);
  }

  private static boolean hasOtherTrimCandidate(
      final TrimPassThroughPlan passThrough, final Set<ArtifactCoordinate> forcedUnchanged)
      throws IOException {
    for (final ElisionAnalysisModel.ArtifactSnapshot snapshot : passThrough.retained()) {
      if (!forcedUnchanged.contains(snapshot.coordinate())
          && !isMultiReleaseArchive(snapshot.filePath())) {
        return true;
      }
    }
    return false;
  }

  private static boolean hasUnchangedMultiReleaseProgram(
      final TrimRequest request,
      final TrimPassThroughPlan passThrough,
      final Set<ArtifactCoordinate> forcedUnchanged)
      throws IOException {
    for (final ElisionAnalysisModel.ArtifactSnapshot snapshot : passThrough.retainedLibraries()) {
      if (!isMultiReleaseArchive(snapshot.filePath())) {
        continue;
      }
      final boolean forced = forcedUnchanged.contains(snapshot.coordinate());
      final boolean skipped =
          passThrough
              .skippedArtifactIdentities()
              .contains(TrimPassThroughPlanner.artifactIdentity(snapshot.coordinate()));
      if (forced
          || skipped
          || MavenDependencyTrimmer.MRJAR_PASS_THROUGH.equals(request.policy().mrjarStrategy())) {
        return true;
      }
    }
    return false;
  }

  private static boolean hasVerticalShadingCandidate(
      final TrimRequest request,
      final TrimPassThroughPlan passThrough,
      final Set<ArtifactCoordinate> forcedUnchanged)
      throws IOException {
    if (!MavenDependencyTrimmer.MRJAR_VERTICAL_SHADING.equals(request.policy().mrjarStrategy())) {
      return false;
    }
    for (final ElisionAnalysisModel.ArtifactSnapshot snapshot : passThrough.retained()) {
      if (!forcedUnchanged.contains(snapshot.coordinate())
          && isMultiReleaseArchive(snapshot.filePath())) {
        return true;
      }
    }
    return false;
  }

  private static boolean isMultiReleaseArchive(final Path path) throws IOException {
    return MultiReleaseClassInventory.hasUnsupportedVersionedClasses(path);
  }

  private static TrimAnalysisResult analyzeInMemoryTiered(
      final TrimRequest request,
      final Map<TrimArtifactRootKey, Set<String>> discoveredRoots,
      final Set<ArtifactCoordinate> forcedUnchanged,
      final TieringDecision decision)
      throws IOException, MojoFailureException {
    final MavenProject project = request.project();
    final List<String> compilerOptions =
        MavenCompilerSettings.platformReleaseOptions(project, request.session());
    final Path javaHome =
        Path.of(System.getProperty(MavenDependencyTrimmer.JAVA_HOME_PROPERTY))
            .toAbsolutePath()
            .normalize();
    final int release = TrimPlatform.releaseFromOptions(compilerOptions, javaHome);
    final int runtimeRelease = Runtime.version().feature();
    if (release > runtimeRelease && decision.hasVerticalShadingCandidate()) {
      throw new IOException(
          "Compiler release " + release + " exceeds Maven runtime release " + runtimeRelease);
    }
    if (release > runtimeRelease) {
      return SingleReleaseTrimAnalyzer.analyzeInMemorySingleRelease(
          request, discoveredRoots, forcedUnchanged);
    }
    return MultiReleaseTierAnalyzer.analyze(
        request, discoveredRoots, forcedUnchanged, release, runtimeRelease, javaHome);
  }
}
