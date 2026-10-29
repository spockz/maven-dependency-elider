/* WHY: Captures retained artifacts for the shared output and proof inventory. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ArtifactFileRef;
import io.github.spockz.elider.model.PreconditionClassInventory.Provider;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.maven.artifact.Artifact;

/** Captures retained artifact paths after trim outputs have been selected. */
@SuppressWarnings({
  "PMD.CommentDefaultAccessModifier",
  "PMD.LawOfDemeter",
  "PMD.UseConcurrentHashMap"
})
final class MavenPreconditionArtifactInventory {
  private MavenPreconditionArtifactInventory() {}

  static List<ArtifactFileRef> capture(
      final MavenElisionService.ApplyPlan plan,
      final MavenElisionService.Analysis analysis,
      final boolean strict)
      throws IOException {
    final Map<ArtifactCoordinate, Path> trimmedPaths = trimmedPaths(analysis.trimRecords(), strict);
    final List<ArtifactFileRef> files = new ArrayList<>();
    for (final Artifact artifact : plan.resolvedArtifacts()) {
      final ArtifactFileRef file = captureArtifact(artifact, trimmedPaths, strict);
      if (file != null) {
        files.add(file);
      }
    }
    files.sort(Comparator.comparing(file -> exactIdentity(file.coordinate())));
    return List.copyOf(files);
  }

  static List<Provider> dependencyProviders(final List<ArtifactFileRef> artifactFiles)
      throws IOException {
    final List<Provider> providers = new ArrayList<>();
    for (final ArtifactFileRef artifact : artifactFiles) {
      if (!"jar".equals(artifact.coordinate().type())) {
        throw new IOException("Unsupported retained class-provider type: " + artifact.coordinate());
      }
      providers.add(Provider.dependencyArchive(artifact.coordinate(), artifact.filePath()));
    }
    return List.copyOf(providers);
  }

  static List<String> identity(final List<ArtifactFileRef> files) {
    return files.stream()
        .map(
            file ->
                exactIdentity(file.coordinate())
                    + "\0"
                    + file.filePath().toAbsolutePath().normalize()
                    + "\0"
                    + file.lastModified()
                    + "\0"
                    + file.fileSize())
        .sorted()
        .toList();
  }

  static String exactIdentity(final ArtifactCoordinate coordinate) {
    return coordinate.groupId()
        + ":"
        + coordinate.artifactId()
        + ":"
        + coordinate.type()
        + ":"
        + coordinate.classifier()
        + ":"
        + coordinate.version();
  }

  private static Map<ArtifactCoordinate, Path> trimmedPaths(
      final List<ArtifactTrimRecord> records, final boolean strict) throws IOException {
    final Map<ArtifactCoordinate, Path> paths = new HashMap<>();
    for (final ArtifactTrimRecord record : records) {
      if (strict && paths.putIfAbsent(record.coordinate(), record.trimmedPath()) != null) {
        throw new IOException("Duplicate effective trim record: " + record.coordinate().toId());
      }
      paths.put(record.coordinate(), record.trimmedPath());
    }
    return paths;
  }

  private static ArtifactFileRef captureArtifact(
      final Artifact artifact,
      final Map<ArtifactCoordinate, Path> trimmedPaths,
      final boolean strict)
      throws IOException {
    final java.io.File currentFile = artifact.getFile();
    if (currentFile == null) {
      if (strict) {
        throw new IOException("Retained Maven artifact has no file: " + artifact.getId());
      }
      return null;
    }
    final ArtifactCoordinate coordinate = MavenElisionService.toCoordinate(artifact);
    final Path path = trimmedPaths.getOrDefault(coordinate, currentFile.toPath());
    return ArtifactFileRef.fromPath(coordinate, strict ? canonicalRegularFile(path) : path);
  }

  private static Path canonicalRegularFile(final Path path) throws IOException {
    final Path absolute = path.toAbsolutePath().normalize();
    if (Files.isSymbolicLink(absolute) || !Files.isRegularFile(absolute)) {
      throw new IOException("Maven class provider is not a regular canonical file: " + absolute);
    }
    final Path canonical = absolute.toRealPath();
    if (!canonical.equals(absolute)) {
      throw new IOException("Maven class provider path is not canonical: " + absolute);
    }
    return canonical;
  }
}
