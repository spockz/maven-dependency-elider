/* WHY: Keeps Maven inventory construction aligned with the plugin's post-trim artifact decision. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.metadata.CycloneDxSbomGenerator;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ArtifactFileRef;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.IOException;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.project.MavenProject;

/** Writes an SBOM from Maven's post-trim retained dependency inventory. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class MavenSbomWriter {
  private MavenSbomWriter() {}

  // Maven Artifact exposes its inventory path only through getFile().
  @SuppressWarnings("PMD.LawOfDemeter")
  static void write(
      final MavenProject project,
      final Path output,
      final MavenElisionService.ApplyPlan plan,
      final MavenElisionService.Analysis analysis)
      throws IOException {
    final List<ArtifactFileRef> inventory = new ArrayList<>();
    final Map<ArtifactCoordinate, Path> trimmedPaths = new ConcurrentHashMap<>();
    for (final ArtifactTrimRecord record : analysis.trimRecords()) {
      trimmedPaths.put(record.coordinate(), record.trimmedPath());
    }
    for (final Artifact artifact : plan.resolvedArtifacts()) {
      final java.io.File artifactFile = artifact.getFile();
      if (artifactFile != null) {
        final ArtifactCoordinate coordinate = coordinate(artifact);
        final Path inventoryPath = trimmedPaths.getOrDefault(coordinate, artifactFile.toPath());
        inventory.add(ArtifactFileRef.fromPath(coordinate, inventoryPath));
      }
    }
    final String name = project.getName() == null ? project.getArtifactId() : project.getName();
    final CycloneDxSbomGenerator.RootIdentity root =
        new CycloneDxSbomGenerator.RootIdentity(
            project.getGroupId(), project.getArtifactId(), project.getVersion(), name);
    final CycloneDxSbomGenerator.DocumentMetadata metadata =
        new CycloneDxSbomGenerator.DocumentMetadata(
            "urn:uuid:" + UUID.randomUUID(),
            1,
            Instant.now(),
            "dependency-elider-maven-plugin",
            "0.1.0-SNAPSHOT");
    new CycloneDxSbomGenerator()
        .write(
            output,
            root,
            inventory,
            analysis.effectiveDecision(),
            metadata,
            analysis.trimRecords());
  }

  private static ArtifactCoordinate coordinate(final Artifact artifact) {
    return new ArtifactCoordinate(
        artifact.getGroupId(),
        artifact.getArtifactId(),
        artifact.getVersion(),
        artifact.getType(),
        artifact.getClassifier(),
        artifact.getScope());
  }
}
