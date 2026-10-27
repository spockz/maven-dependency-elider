/* WHY: Keeps Maven inventory construction aligned with the plugin's post-trim artifact decision. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.metadata.CycloneDxSbomGenerator;
import io.github.spockz.elider.metadata.OpenVexGenerator;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ArtifactFileRef;
import io.github.spockz.elider.model.VexAttestation;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
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
    write(project, output, plan, analysis, List.of());
  }

  static void write(
      final MavenProject project,
      final Path output,
      final MavenElisionService.ApplyPlan plan,
      final MavenElisionService.Analysis analysis,
      final Collection<VexAttestation> attestations)
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
    new CycloneDxSbomGenerator()
        .write(
            output,
            root(project),
            inventory,
            analysis.effectiveDecision(),
            metadata(),
            analysis.trimRecords(),
            attestations);
  }

  static void writeBaseline(
      final MavenProject project,
      final Path output,
      final List<ArtifactFileRef> originalInventory,
      final MavenElisionService.Analysis analysis)
      throws IOException {
    final Map<ArtifactCoordinate, Path> originals = new ConcurrentHashMap<>();
    for (final ArtifactTrimRecord record : analysis.trimRecords()) {
      originals.put(record.coordinate(), record.originalPath());
    }
    final List<ArtifactFileRef> inventory = new ArrayList<>();
    for (final ArtifactFileRef ref : originalInventory) {
      inventory.add(
          ArtifactFileRef.fromPath(
              ref.coordinate(), originals.getOrDefault(ref.coordinate(), ref.filePath())));
    }
    new CycloneDxSbomGenerator().writeBaseline(output, root(project), inventory, metadata());
  }

  static List<ArtifactFileRef> captureOriginalInventory(final MavenProject project)
      throws IOException {
    final List<ArtifactFileRef> inventory = new ArrayList<>();
    for (final Artifact artifact : project.getArtifacts()) {
      final java.io.File artifactFile = artifact.getFile();
      if (artifactFile != null) {
        inventory.add(ArtifactFileRef.fromPath(coordinate(artifact), artifactFile.toPath()));
      }
    }
    return List.copyOf(inventory);
  }

  static void writeOpenVex(
      final MavenProject project,
      final Path output,
      final MavenElisionService.ApplyPlan plan,
      final MavenElisionService.Analysis analysis,
      final Collection<VexAttestation> attestations)
      throws IOException {
    new OpenVexGenerator()
        .write(
            output,
            root(project),
            postInventory(plan, analysis),
            attestations,
            new OpenVexGenerator.DocumentMetadata(
                "urn:uuid:" + UUID.randomUUID(), "Dependency Elider", "Tool", Instant.now(), 1));
  }

  static void stage(final MavenProject project, final Path sbomFile) throws IOException {
    if (project.getBuild() == null || project.getBuild().getOutputDirectory() == null) {
      return;
    }
    final Path outputDirectory = Path.of(project.getBuild().getOutputDirectory());
    copy(sbomFile, outputDirectory.resolve("META-INF/sbom/application.cdx.json"));
    copy(sbomFile, outputDirectory.resolve("META-INF/native-image/sbom.json"));
  }

  private static void copy(final Path source, final Path destination) throws IOException {
    final Path absolute = destination.toAbsolutePath();
    Files.createDirectories(absolute.getParent());
    Files.copy(source, absolute, StandardCopyOption.REPLACE_EXISTING);
  }

  private static List<ArtifactFileRef> postInventory(
      final MavenElisionService.ApplyPlan plan, final MavenElisionService.Analysis analysis)
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
    return List.copyOf(inventory);
  }

  private static CycloneDxSbomGenerator.RootIdentity root(final MavenProject project) {
    final String name = project.getName() == null ? project.getArtifactId() : project.getName();
    return new CycloneDxSbomGenerator.RootIdentity(
        project.getGroupId(), project.getArtifactId(), project.getVersion(), name);
  }

  private static CycloneDxSbomGenerator.DocumentMetadata metadata() {
    return new CycloneDxSbomGenerator.DocumentMetadata(
        "urn:uuid:" + UUID.randomUUID(),
        1,
        Instant.now(),
        "dependency-elider-maven-plugin",
        "0.1.0-SNAPSHOT");
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
