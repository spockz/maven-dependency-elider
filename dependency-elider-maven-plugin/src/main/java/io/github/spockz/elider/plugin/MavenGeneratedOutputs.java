/* WHY: Clears stale SBOM and VEX files only when their bytes match recorded plugin output.
 */

package io.github.spockz.elider.plugin;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import org.apache.maven.model.Build;
import org.apache.maven.project.MavenProject;

/** Tracks and safely clears plugin-owned generated SBOM and VEX outputs. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class MavenGeneratedOutputs {
  private MavenGeneratedOutputs() {}

  static void clearPrevious(final MavenProject project, final Collection<Path> allowedOutputs)
      throws IOException {
    if (project == null) {
      return;
    }
    MavenGeneratedOutputManifest.clear(manifestPath(project), allowedOutputs);
  }

  static void record(final MavenProject project, final Collection<Path> generated)
      throws IOException {
    MavenGeneratedOutputManifest.write(manifestPath(project), generated);
  }

  static Optional<String> unchangedOwnedOutputDigest(final MavenProject project, final Path output)
      throws IOException {
    return MavenGeneratedOutputManifest.unchangedOwnedOutputDigest(
        manifestPath(project), output.toAbsolutePath().normalize());
  }

  static List<Path> currentOutputPaths(
      final MavenProject project, final File sbom, final File baseline, final File vex) {
    if (project == null) {
      return List.of();
    }
    return generatedOutputPaths(project, sbom, baseline, vex, true);
  }

  static List<Path> generatedOutputPaths(
      final MavenProject project,
      final File sbom,
      final File baseline,
      final File vex,
      final boolean vexWasWritten) {
    final List<Path> outputs =
        new ArrayList<>(
            List.of(
                outputFile(sbom, project, "dependency-elider-sbom.cdx.json").toPath(),
                outputFile(baseline, project, "baseline-sbom.cdx.json").toPath()));
    if (vexWasWritten) {
      outputs.add(outputFile(vex, project, "dependency-elider.openvex.json").toPath());
    }
    outputs.addAll(MavenSbomWriter.stagedPaths(project));
    return List.copyOf(outputs);
  }

  static File outputFile(
      final File configured, final MavenProject project, final String defaultName) {
    if (configured != null) {
      return configured;
    }
    return buildDirectory(project).resolve(defaultName).toFile();
  }

  private static Path buildDirectory(final MavenProject project) {
    final Build build = project.getBuild();
    final String configuredDirectory = build == null ? null : build.getDirectory();
    if (configuredDirectory != null) {
      return Path.of(configuredDirectory);
    }
    return projectDirectory(project).resolve("target");
  }

  @SuppressWarnings("PMD.LawOfDemeter")
  private static Path projectDirectory(final MavenProject project) {
    final File projectDirectory = project.getBasedir();
    if (projectDirectory == null) {
      return Path.of(".");
    }
    return Path.of(projectDirectory.getPath());
  }

  static Path manifestPath(final MavenProject project) {
    final Path directory = buildDirectory(project);
    final Path manifest = directory.resolve("dependency-elider-generated-outputs.json");
    return manifest.toAbsolutePath().normalize();
  }
}
