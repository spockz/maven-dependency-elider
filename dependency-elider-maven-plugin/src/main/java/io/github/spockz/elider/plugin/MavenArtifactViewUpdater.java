/* WHY: Validates trim records against Maven's distinct artifact objects before
 * changing file pointers. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.apache.maven.artifact.Artifact;

/** Applies validated trim paths to Maven artifact views. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class MavenArtifactViewUpdater {
  private MavenArtifactViewUpdater() {}

  static void apply(
      final MavenElisionService.ApplyPlan plan, final List<ArtifactTrimRecord> records)
      throws IOException {
    final Map<ArtifactIdentity, ArtifactTrimRecord> recordsByIdentity = new ConcurrentHashMap<>();
    for (final ArtifactTrimRecord record : records) {
      final ArtifactIdentity identity = ArtifactIdentity.from(record.coordinate());
      if (recordsByIdentity.putIfAbsent(identity, record) != null) {
        throw new IOException("Multiple trim records have the same Maven identity: " + identity);
      }
    }
    final List<Artifact> allViews =
        identityDistinct(plan.resolvedArtifacts(), plan.directArtifacts());
    final Set<ArtifactIdentity> matchedResolved = new HashSet<>();
    validateArtifactPaths(allViews, recordsByIdentity, matchedResolved);
    if (!matchedResolved.containsAll(recordsByIdentity.keySet())) {
      final Set<ArtifactIdentity> missing = new HashSet<>(recordsByIdentity.keySet());
      missing.removeAll(matchedResolved);
      throw new IOException("Trim records have no resolved Maven artifacts: " + missing);
    }
    applyRecords(allViews, recordsByIdentity);
  }

  @SafeVarargs
  private static List<Artifact> identityDistinct(final Collection<Artifact>... views) {
    final Set<Artifact> seen = Collections.newSetFromMap(new IdentityHashMap<>());
    final List<Artifact> result = new ArrayList<>();
    for (final Collection<Artifact> view : views) {
      for (final Artifact artifact : view) {
        if (seen.add(artifact)) {
          result.add(artifact);
        }
      }
    }
    return result;
  }

  // Maven Artifact exposes its path only through getFile().
  @SuppressWarnings("PMD.LawOfDemeter")
  private static void validateArtifactPaths(
      final List<Artifact> artifacts,
      final Map<ArtifactIdentity, ArtifactTrimRecord> recordsByIdentity,
      final Set<ArtifactIdentity> matched)
      throws IOException {
    for (final Artifact artifact : artifacts) {
      final ArtifactIdentity identity = ArtifactIdentity.from(artifact);
      final ArtifactTrimRecord record = recordsByIdentity.get(identity);
      if (record != null) {
        if (artifact.getFile() == null) {
          throw new IOException("Artifact path changed before applying trim: " + identity);
        }
        final java.nio.file.Path currentPath = artifact.getFile().toPath();
        if (!currentPath.toAbsolutePath().normalize().equals(record.originalPath())) {
          throw new IOException("Artifact path changed before applying trim: " + identity);
        }
        matched.add(identity);
      }
    }
  }

  private static void applyRecords(
      final List<Artifact> artifacts,
      final Map<ArtifactIdentity, ArtifactTrimRecord> recordsByIdentity) {
    for (final Artifact artifact : artifacts) {
      final ArtifactTrimRecord record = recordsByIdentity.get(ArtifactIdentity.from(artifact));
      if (record != null) {
        artifact.setFile(record.trimmedPath().toFile());
      }
    }
  }

  private record ArtifactIdentity(
      String groupId, String artifactId, String version, String type, String classifier) {
    private static ArtifactIdentity from(final Artifact artifact) {
      return new ArtifactIdentity(
          artifact.getGroupId(),
          artifact.getArtifactId(),
          artifact.getVersion(),
          artifact.getType(),
          artifact.getClassifier() == null ? "" : artifact.getClassifier());
    }

    private static ArtifactIdentity from(final ArtifactCoordinate coordinate) {
      return new ArtifactIdentity(
          coordinate.groupId(),
          coordinate.artifactId(),
          coordinate.version(),
          coordinate.type(),
          coordinate.classifier());
    }
  }
}
