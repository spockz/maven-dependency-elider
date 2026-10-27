/* WHY: Keeps SBOM and VEX serialization outside the lifecycle Mojo's orchestration method. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactFileRef;
import io.github.spockz.elider.model.VexAttestation;
import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import org.apache.maven.project.MavenProject;

/** Writes and stages generated vulnerability evidence for a trimmed Maven project. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class MavenTrimOutputWriter {
  private MavenTrimOutputWriter() {}

  static void write(
      final MavenProject project,
      final File configuredSbom,
      final File configuredBaseline,
      final File configuredVex,
      final MavenElisionService.ApplyPlan plan,
      final MavenElisionService.Analysis analysis,
      final List<ArtifactFileRef> baselineInventory,
      final List<VexAttestation> attestations)
      throws IOException {
    final File sbom =
        MavenGeneratedOutputs.outputFile(
            configuredSbom, project, "dependency-elider-sbom.cdx.json");
    final File baseline =
        MavenGeneratedOutputs.outputFile(configuredBaseline, project, "baseline-sbom.cdx.json");
    final File vex =
        MavenGeneratedOutputs.outputFile(configuredVex, project, "dependency-elider.openvex.json");
    MavenSbomWriter.writeBaseline(project, baseline.toPath(), baselineInventory, analysis);
    MavenSbomWriter.write(project, sbom.toPath(), plan, analysis, attestations);
    writeVexIfProven(project, vex.toPath(), plan, analysis, attestations);
    MavenSbomWriter.stage(project, sbom.toPath());
    MavenGeneratedOutputs.record(
        project,
        MavenGeneratedOutputs.generatedOutputPaths(
            project, configuredSbom, configuredBaseline, configuredVex, !attestations.isEmpty()));
  }

  private static void writeVexIfProven(
      final MavenProject project,
      final Path output,
      final MavenElisionService.ApplyPlan plan,
      final MavenElisionService.Analysis analysis,
      final List<VexAttestation> attestations)
      throws IOException {
    if (!attestations.isEmpty()) {
      MavenSbomWriter.writeOpenVex(project, output, plan, analysis, attestations);
    }
  }
}
