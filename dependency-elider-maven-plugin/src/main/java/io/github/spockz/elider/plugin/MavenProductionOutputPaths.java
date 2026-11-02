// WHY: Resolves configured and Maven-default production outputs consistently.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.plugin.ElisionAnalysisModel.AnalysisOptions;
import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import org.apache.maven.project.MavenProject;

/** Resolves production output directories from Maven configuration. */
final class MavenProductionOutputPaths {
  private MavenProductionOutputPaths() {
    throw new AssertionError("No instances");
  }

  static File resolve(final MavenProject project, final AnalysisOptions options)
      throws IOException {
    final boolean productionClassesComplete = options.completeness().productionClassesComplete();
    final String selectedOutput =
        selectedOutput(project, options.productionOutput(), productionClassesComplete);
    if (selectedOutput == null || selectedOutput.isBlank()) {
      if (productionClassesComplete) {
        throw new IOException(
            "elide.productionClassesComplete=true requires a nonblank production class output "
                + "directory");
      }
      return null;
    }
    final Path output = Path.of(selectedOutput);
    if (output.isAbsolute()) {
      return output.normalize().toFile();
    }
    return relativeProductionOutput(project, output);
  }

  private static String selectedOutput(
      final MavenProject project,
      final File configuredOutput,
      final boolean productionClassesComplete) {
    if (configuredOutput != null) {
      return configuredOutput.getPath();
    }
    if (!productionClassesComplete || project.getBuild() == null) {
      return null;
    }
    return project.getBuild().getOutputDirectory();
  }

  @SuppressWarnings("PMD.LawOfDemeter") // MavenProject supplies the base for relative paths.
  private static File relativeProductionOutput(final MavenProject project, final Path output)
      throws IOException {
    final File projectBase = project.getBasedir();
    if (projectBase == null) {
      throw new IOException(
          "Cannot resolve relative production output without a Maven project base");
    }
    final Path projectBasePath = projectBase.toPath();
    final Path resolvedOutput = projectBasePath.resolve(output);
    return resolvedOutput.toAbsolutePath().normalize().toFile();
  }
}
